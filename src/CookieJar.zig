//! Coroutine-safe RFC 6265 HTTP Cookie Jar.
//!
//! Stores cookies received via `Set-Cookie` response headers and computes the
//! matching `Cookie` request header for subsequent requests and redirect hops.
//! Enforces RFC 6265 domain-matching, host-only isolation, path-matching,
//! `Secure` scheme gating, `Max-Age` > `Expires` precedence, and longest-path ordering.

const std = @import("std");
const Allocator = std.mem.Allocator;

const zio = @import("zio");
const http = @import("http.zig");

const CookieJar = @This();

pub const Cookie = struct {
    name: []u8,
    value: []u8,
    /// ASCII-lowercased domain without leading dot.
    domain: []u8,
    /// True when `Set-Cookie` omitted `Domain`; matches only the exact request host.
    host_only: bool,
    path: []u8,
    secure: bool,
    http_only: bool,
    /// Unix timestamp in seconds when this cookie expires (`null` = session cookie).
    expires_epoch_s: ?i64,
    /// Monotonic insertion sequence for deterministic oldest-first global eviction.
    seq: u64 = 0,

    fn deinit(self: *Cookie, gpa: Allocator) void {
        gpa.free(self.name);
        gpa.free(self.value);
        gpa.free(self.domain);
        gpa.free(self.path);
        self.* = undefined;
    }

    fn isExpired(self: *const Cookie, now_epoch_s: i64) bool {
        const exp = self.expires_epoch_s orelse return false;
        return exp <= now_epoch_s;
    }
};

/// Borrowed/serializable cookie snapshot used by `add`, `exportJsonAlloc`, and `importJson`.
pub const CookieEntry = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    host_only: bool = true,
    path: []const u8 = "/",
    secure: bool = false,
    http_only: bool = false,
    expires_epoch_s: ?i64 = null,
};

pub const Limits = struct {
    /// Maximum total cookies retained across all domains (RFC 6265 §6.1 baseline).
    max_cookies: usize = 3000,
    /// Maximum cookies retained per domain (oldest evicted first when exceeded).
    max_cookies_per_domain: usize = 50,
    /// Maximum byte length of a single `Set-Cookie` header (name + value + attrs).
    max_cookie_bytes: usize = 4096,
    /// Optional caller-supplied public suffix check (e.g. full Mozilla PSL).
    /// When `null`, rejects single-label TLDs and a built-in table of common
    /// multi-label public suffixes (`co.uk`, `com.cn`, `github.io`, etc.).
    is_public_suffix: ?*const fn (domain: []const u8) bool = null,
};

const DomainBucket = struct {
    key: []u8,
    cookies: std.ArrayList(Cookie) = .empty,

    fn deinit(self: *DomainBucket, gpa: Allocator) void {
        for (self.cookies.items) |*c| c.deinit(gpa);
        self.cookies.deinit(gpa);
        gpa.free(self.key);
        self.* = undefined;
    }
};

gpa: Allocator,
limits: Limits = .{},
mutex: zio.Mutex = .init,
/// Indexed by lowercased cookie domain so request matching runs in O(domain labels).
by_domain: std.StringHashMapUnmanaged(DomainBucket) = .empty,
total_count: usize = 0,
next_seq: u64 = 1,

pub fn init(gpa: Allocator) CookieJar {
    return .{ .gpa = gpa };
}

pub fn initWithLimits(gpa: Allocator, limits: Limits) CookieJar {
    return .{ .gpa = gpa, .limits = limits };
}

pub fn deinit(self: *CookieJar) void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var it = self.by_domain.valueIterator();
    while (it.next()) |bucket| {
        bucket.deinit(self.gpa);
    }
    self.by_domain.deinit(self.gpa);
    self.by_domain = .empty;
    self.total_count = 0;
}

/// Removes all stored cookies.
pub fn clear(self: *CookieJar) void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var it = self.by_domain.valueIterator();
    while (it.next()) |bucket| {
        bucket.deinit(self.gpa);
    }
    self.by_domain.clearRetainingCapacity();
    self.total_count = 0;
}

/// Returns the number of currently stored (non-expired) cookies.
pub fn count(self: *CookieJar) usize {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    return self.countAt(now_s);
}

/// Same as `count`, using an explicit Unix timestamp (seconds).
pub fn countAt(self: *CookieJar, now_epoch_s: i64) usize {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    self.purgeAllExpiredLocked(now_epoch_s);
    return self.total_count;
}

/// Returns an owned copy of the first non-expired cookie matching `(domain, name)`.
/// Caller frees the returned slice.
pub fn getValueAlloc(self: *CookieJar, gpa: Allocator, domain: []const u8, name: []const u8) Allocator.Error!?[]u8 {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    return self.getValueAllocAt(gpa, domain, name, now_s);
}

/// Same as `getValueAlloc`, using an explicit Unix timestamp (seconds).
pub fn getValueAllocAt(
    self: *CookieJar,
    gpa: Allocator,
    domain: []const u8,
    name: []const u8,
    now_epoch_s: i64,
) Allocator.Error!?[]u8 {
    var lower_buf: [http.Origin.max_host_len]u8 = undefined;
    const key = lowercaseToBuf(domain, &lower_buf) orelse return null;

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    const bucket = self.by_domain.getPtr(key) orelse return null;
    self.purgeBucketExpiredLocked(bucket, now_epoch_s);
    if (bucket.cookies.items.len == 0) {
        self.removeEmptyBucketLocked(key);
        return null;
    }

    for (bucket.cookies.items) |*c| {
        if (std.mem.eql(u8, c.name, name)) {
            return try gpa.dupe(u8, c.value);
        }
    }
    return null;
}

/// Removes a cookie matching `(domain, name, path)`. Returns true if removed.
pub fn remove(self: *CookieJar, domain: []const u8, name: []const u8, path: []const u8) bool {
    var lower_buf: [http.Origin.max_host_len]u8 = undefined;
    const key = lowercaseToBuf(domain, &lower_buf) orelse return false;

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    const bucket = self.by_domain.getPtr(key) orelse return false;
    for (bucket.cookies.items, 0..) |*c, idx| {
        if (std.mem.eql(u8, c.name, name) and std.mem.eql(u8, c.path, path)) {
            c.deinit(self.gpa);
            _ = bucket.cookies.orderedRemove(idx);
            self.total_count -= 1;
            if (bucket.cookies.items.len == 0) {
                self.removeEmptyBucketLocked(key);
            }
            return true;
        }
    }
    return false;
}

/// Programmatically inserts or replaces a cookie entry (e.g. seeding auth state
/// or restoring persisted cookies).
pub fn add(self: *CookieJar, entry: CookieEntry) Allocator.Error!void {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    try self.addAt(entry, now_s);
}

/// Same as `add`, using an explicit Unix timestamp (seconds).
pub fn addAt(self: *CookieJar, entry: CookieEntry, now_epoch_s: i64) Allocator.Error!void {
    if (entry.name.len == 0 or entry.domain.len == 0) return;

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    const stripped = if (entry.domain[0] == '.') entry.domain[1..] else entry.domain;
    if (stripped.len == 0) return;
    const path = if (entry.path.len > 0 and entry.path[0] == '/') entry.path else "/";

    try self.upsertLocked(
        entry.name,
        entry.value,
        stripped,
        entry.host_only,
        path,
        entry.secure,
        entry.http_only,
        entry.expires_epoch_s,
        now_epoch_s,
    );
}

/// Serializes all non-expired cookies into a JSON array (`[]CookieEntry`).
/// Caller owns and frees the returned slice.
pub fn exportJsonAlloc(self: *CookieJar, gpa: Allocator) Allocator.Error![]u8 {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    return self.exportJsonAllocAt(gpa, now_s);
}

/// Same as `exportJsonAlloc`, using an explicit Unix timestamp (seconds).
pub fn exportJsonAllocAt(self: *CookieJar, gpa: Allocator, now_epoch_s: i64) Allocator.Error![]u8 {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    self.purgeAllExpiredLocked(now_epoch_s);

    var entries: std.ArrayList(CookieEntry) = .empty;
    defer entries.deinit(gpa);
    try entries.ensureTotalCapacity(gpa, self.total_count);

    var it = self.by_domain.valueIterator();
    while (it.next()) |bucket| {
        for (bucket.cookies.items) |*c| {
            entries.appendAssumeCapacity(.{
                .name = c.name,
                .value = c.value,
                .domain = c.domain,
                .host_only = c.host_only,
                .path = c.path,
                .secure = c.secure,
                .http_only = c.http_only,
                .expires_epoch_s = c.expires_epoch_s,
            });
        }
    }

    return gpa.print("{f}", .{std.json.fmt(entries.items, .{})});
}

/// Restores cookies from a JSON array previously produced by `exportJsonAlloc`.
pub fn importJson(self: *CookieJar, json_bytes: []const u8) !void {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    try self.importJsonAt(json_bytes, now_s);
}

/// Same as `importJson`, using an explicit Unix timestamp (seconds).
pub fn importJsonAt(self: *CookieJar, json_bytes: []const u8, now_epoch_s: i64) !void {
    const parsed = try std.json.parseFromSlice([]CookieEntry, self.gpa, json_bytes, .{});
    defer parsed.deinit();

    for (parsed.value) |entry| {
        try self.addAt(entry, now_epoch_s);
    }
}

/// Parses and stores all valid `Set-Cookie` headers from a response received
/// from `(origin, request_path)`.
pub fn storeFromHeaders(
    self: *CookieJar,
    origin: http.Origin,
    request_path: []const u8,
    headers: *const http.Headers,
) Allocator.Error!void {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    try self.storeFromHeadersAt(origin, request_path, headers, now_s);
}

/// Same as `storeFromHeaders`, using an explicit Unix timestamp (seconds) for
/// deterministic expiration testing.
pub fn storeFromHeadersAt(
    self: *CookieJar,
    origin: http.Origin,
    request_path: []const u8,
    headers: *const http.Headers,
    now_epoch_s: i64,
) Allocator.Error!void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var it = headers.valueIterator("Set-Cookie");
    while (it.next()) |raw_header| {
        try self.storeSingleLocked(origin, request_path, raw_header, now_epoch_s);
    }
}

/// Builds the RFC 6265 §5.4 `Cookie` header value (`"a=1; b=2"`) for a request
/// to `(origin, request_path)`, or returns `null` if no cookies match.
/// Caller owns and frees the returned slice.
pub fn cookieHeaderAlloc(
    self: *CookieJar,
    gpa: Allocator,
    origin: http.Origin,
    request_path: []const u8,
) Allocator.Error!?[]u8 {
    const now_s: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    return self.cookieHeaderAllocAt(gpa, origin, request_path, now_s);
}

/// Same as `cookieHeaderAlloc`, using an explicit Unix timestamp (seconds).
pub fn cookieHeaderAllocAt(
    self: *CookieJar,
    gpa: Allocator,
    origin: http.Origin,
    request_path: []const u8,
    now_epoch_s: i64,
) Allocator.Error!?[]u8 {
    var lower_buf: [http.Origin.max_host_len]u8 = undefined;
    const host_lower = lowercaseToBuf(origin.host, &lower_buf) orelse return null;
    const path_only = stripQuery(request_path);
    const is_ip = isIpLiteral(host_lower);

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var matched: std.ArrayList(*const Cookie) = .empty;
    defer matched.deinit(gpa);

    // Probe exact host bucket first, then parent domain labels (O(labels) lookups).
    var candidate: []const u8 = host_lower;
    var exact = true;
    while (true) {
        if (self.by_domain.getPtr(candidate)) |bucket| {
            self.purgeBucketExpiredLocked(bucket, now_epoch_s);
            if (bucket.cookies.items.len == 0) {
                self.removeEmptyBucketLocked(candidate);
            } else {
                for (bucket.cookies.items) |*c| {
                    if (c.secure and origin.scheme != .https) continue;
                    if (!exact and c.host_only) continue;
                    if (!pathMatches(path_only, c.path)) continue;
                    try matched.append(gpa, c);
                }
            }
        }
        if (is_ip) break;
        const dot = std.mem.findScalar(u8, candidate, '.') orelse break;
        candidate = candidate[dot + 1 ..];
        if (candidate.len == 0) break;
        exact = false;
    }

    if (matched.items.len == 0) return null;

    // RFC 6265 §5.4 step 2: longer paths first, then earlier creation order (seq).
    const SortCtx = struct {
        pub fn lessThan(_: @This(), a: *const Cookie, b: *const Cookie) bool {
            if (a.path.len != b.path.len) return a.path.len > b.path.len;
            return a.seq < b.seq;
        }
    };
    std.mem.sort(*const Cookie, matched.items, SortCtx{}, SortCtx.lessThan);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    for (matched.items, 0..) |c, i| {
        if (i > 0) try out.appendSlice(gpa, "; ");
        try out.appendSlice(gpa, c.name);
        try out.append(gpa, '=');
        try out.appendSlice(gpa, c.value);
    }

    return try out.toOwnedSlice(gpa);
}

fn storeSingleLocked(
    self: *CookieJar,
    origin: http.Origin,
    request_path: []const u8,
    raw: []const u8,
    now_epoch_s: i64,
) Allocator.Error!void {
    if (raw.len > self.limits.max_cookie_bytes) return;

    var parts = std.mem.splitScalar(u8, raw, ';');
    const name_value = parts.next() orelse return;
    const eq = std.mem.findScalar(u8, name_value, '=') orelse return;

    const name = trimOws(name_value[0..eq]);
    const value = trimOws(name_value[eq + 1 ..]);
    if (name.len == 0) return;

    var domain_attr: ?[]const u8 = null;
    var path_attr: ?[]const u8 = null;
    var max_age: ?i64 = null;
    var expires: ?i64 = null;
    var secure = false;
    var http_only = false;

    while (parts.next()) |raw_attr| {
        const attr = trimOws(raw_attr);
        if (attr.len == 0) continue;

        if (std.mem.findScalar(u8, attr, '=')) |a_eq| {
            const k = trimOws(attr[0..a_eq]);
            const v = trimOws(attr[a_eq + 1 ..]);
            if (std.ascii.eqlIgnoreCase(k, "Domain")) {
                if (v.len > 0) domain_attr = v;
            } else if (std.ascii.eqlIgnoreCase(k, "Path")) {
                if (v.len > 0 and v[0] == '/') path_attr = v;
            } else if (std.ascii.eqlIgnoreCase(k, "Max-Age")) {
                if (std.fmt.parseInt(i64, v, 10)) |secs| {
                    max_age = secs;
                } else |_| {}
            } else if (std.ascii.eqlIgnoreCase(k, "Expires")) {
                if (http.parseHttpDate(v)) |ts| {
                    expires = ts;
                }
            }
        } else {
            if (std.ascii.eqlIgnoreCase(attr, "Secure")) {
                secure = true;
            } else if (std.ascii.eqlIgnoreCase(attr, "HttpOnly")) {
                http_only = true;
            }
        }
    }

    // Determine domain and host_only per RFC 6265 §5.3.
    var host_only = true;
    var target_domain_slice: []const u8 = origin.host;

    if (domain_attr) |raw_dom| {
        const stripped = if (raw_dom.len > 0 and raw_dom[0] == '.') raw_dom[1..] else raw_dom;
        if (stripped.len == 0) return;
        // Reject cross-domain setting and refuse non-exact public suffixes (prevents supercookies).
        if (!domainMatches(origin.host, stripped)) return;
        if (!std.ascii.eqlIgnoreCase(origin.host, stripped) and self.isPublicSuffix(stripped)) {
            return;
        }
        // IP addresses can only match host-only.
        if (isIpLiteral(origin.host)) {
            if (!std.ascii.eqlIgnoreCase(origin.host, stripped)) return;
            host_only = true;
        } else {
            host_only = false;
        }
        target_domain_slice = stripped;
    }

    const effective_path = path_attr orelse defaultPath(stripQuery(request_path));

    // RFC 6265 §5.3: Max-Age takes precedence over Expires.
    const expires_epoch_s: ?i64 = if (max_age) |ma|
        if (ma <= 0) 0 else now_epoch_s +| ma
    else
        expires;

    try self.upsertLocked(
        name,
        value,
        target_domain_slice,
        host_only,
        effective_path,
        secure,
        http_only,
        expires_epoch_s,
        now_epoch_s,
    );
}

fn upsertLocked(
    self: *CookieJar,
    name: []const u8,
    value: []const u8,
    target_domain: []const u8,
    host_only: bool,
    effective_path: []const u8,
    secure: bool,
    http_only: bool,
    expires_epoch_s: ?i64,
    now_epoch_s: i64,
) Allocator.Error!void {
    var lower_buf: [http.Origin.max_host_len]u8 = undefined;
    const domain_key = lowercaseToBuf(target_domain, &lower_buf) orelse return;

    // Remove any existing cookie with the same (name, domain, path).
    if (self.by_domain.getPtr(domain_key)) |bucket| {
        for (bucket.cookies.items, 0..) |*existing, idx| {
            if (std.mem.eql(u8, existing.name, name) and
                std.mem.eql(u8, existing.path, effective_path))
            {
                existing.deinit(self.gpa);
                _ = bucket.cookies.orderedRemove(idx);
                self.total_count -= 1;
                if (bucket.cookies.items.len == 0) {
                    self.removeEmptyBucketLocked(domain_key);
                }
                break;
            }
        }
    }

    // If already expired (e.g. Max-Age=0 deletion), removal above is complete.
    if (expires_epoch_s) |exp| {
        if (exp <= now_epoch_s) return;
    }

    if (self.limits.max_cookies == 0 or self.limits.max_cookies_per_domain == 0) return;

    // Enforce per-domain and global capacity caps by evicting oldest entries.
    self.enforceLimitsLocked(domain_key, now_epoch_s);

    const owned_name = try self.gpa.dupe(u8, name);
    errdefer self.gpa.free(owned_name);
    const owned_value = try self.gpa.dupe(u8, value);
    errdefer self.gpa.free(owned_value);
    const owned_domain = try self.gpa.dupe(u8, domain_key);
    errdefer self.gpa.free(owned_domain);
    const owned_path = try self.gpa.dupe(u8, effective_path);
    errdefer self.gpa.free(owned_path);

    const bucket = try self.getOrCreateBucketLocked(domain_key);
    const seq = self.next_seq;
    self.next_seq += 1;

    try bucket.cookies.append(self.gpa, .{
        .name = owned_name,
        .value = owned_value,
        .domain = owned_domain,
        .host_only = host_only,
        .path = owned_path,
        .secure = secure,
        .http_only = http_only,
        .expires_epoch_s = expires_epoch_s,
        .seq = seq,
    });
    self.total_count += 1;
}

fn getOrCreateBucketLocked(self: *CookieJar, domain_key: []const u8) Allocator.Error!*DomainBucket {
    if (self.by_domain.getPtr(domain_key)) |b| return b;

    const owned_key = try self.gpa.dupe(u8, domain_key);
    errdefer self.gpa.free(owned_key);

    try self.by_domain.put(self.gpa, owned_key, .{ .key = owned_key });
    return self.by_domain.getPtr(owned_key).?;
}

fn removeEmptyBucketLocked(self: *CookieJar, domain_key: []const u8) void {
    if (self.by_domain.fetchRemove(domain_key)) |kv| {
        var bucket = kv.value;
        bucket.deinit(self.gpa);
    }
}

fn enforceLimitsLocked(self: *CookieJar, domain_key: []const u8, now_epoch_s: i64) void {
    if (self.by_domain.getPtr(domain_key)) |bucket| {
        self.purgeBucketExpiredLocked(bucket, now_epoch_s);
        while (bucket.cookies.items.len >= self.limits.max_cookies_per_domain) {
            bucket.cookies.items[0].deinit(self.gpa);
            _ = bucket.cookies.orderedRemove(0);
            self.total_count -= 1;
        }
        if (bucket.cookies.items.len == 0) {
            self.removeEmptyBucketLocked(domain_key);
        }
    }

    if (self.total_count >= self.limits.max_cookies) {
        self.purgeAllExpiredLocked(now_epoch_s);
    }

    // Evict globally oldest cookie (smallest `seq`) until under global cap.
    while (self.total_count >= self.limits.max_cookies) {
        var oldest_bucket: ?*DomainBucket = null;
        var oldest_seq: u64 = std.math.maxInt(u64);

        var it = self.by_domain.valueIterator();
        while (it.next()) |bucket| {
            if (bucket.cookies.items.len == 0) continue;
            // Each domain bucket's cookies are append-ordered, so index 0 is oldest.
            const head_seq = bucket.cookies.items[0].seq;
            if (head_seq < oldest_seq) {
                oldest_seq = head_seq;
                oldest_bucket = bucket;
            }
        }
        const victim = oldest_bucket orelse break;
        const victim_key = victim.key;
        victim.cookies.items[0].deinit(self.gpa);
        _ = victim.cookies.orderedRemove(0);
        self.total_count -= 1;
        if (victim.cookies.items.len == 0) {
            self.removeEmptyBucketLocked(victim_key);
        }
    }
}

fn isPublicSuffix(self: *const CookieJar, domain: []const u8) bool {
    if (std.mem.findScalar(u8, domain, '.') == null) return true;
    if (self.limits.is_public_suffix) |custom| return custom(domain);

    var lower_buf: [http.Origin.max_host_len]u8 = undefined;
    const lower = lowercaseToBuf(domain, &lower_buf) orelse return false;

    const common_public_suffixes = std.StaticStringMap(void).initComptime(.{
        .{ "co.uk", {} },       .{ "org.uk", {} },        .{ "ac.uk", {} },
        .{ "gov.uk", {} },      .{ "com.cn", {} },        .{ "net.cn", {} },
        .{ "org.cn", {} },      .{ "gov.cn", {} },        .{ "com.au", {} },
        .{ "net.au", {} },      .{ "org.au", {} },        .{ "edu.au", {} },
        .{ "co.jp", {} },       .{ "ne.jp", {} },         .{ "or.jp", {} },
        .{ "com.br", {} },      .{ "com.hk", {} },        .{ "com.tw", {} },
        .{ "com.sg", {} },      .{ "co.kr", {} },         .{ "co.in", {} },
        .{ "co.nz", {} },       .{ "github.io", {} },     .{ "pages.dev", {} },
        .{ "vercel.app", {} },  .{ "netlify.app", {} },   .{ "herokuapp.com", {} },
        .{ "appspot.com", {} }, .{ "amazonaws.com", {} },
    });
    return common_public_suffixes.has(lower);
}

fn purgeBucketExpiredLocked(self: *CookieJar, bucket: *DomainBucket, now_epoch_s: i64) void {
    var write_idx: usize = 0;
    for (bucket.cookies.items) |*c| {
        if (c.isExpired(now_epoch_s)) {
            c.deinit(self.gpa);
            self.total_count -= 1;
        } else {
            bucket.cookies.items[write_idx] = c.*;
            write_idx += 1;
        }
    }
    bucket.cookies.items.len = write_idx;
}

fn purgeAllExpiredLocked(self: *CookieJar, now_epoch_s: i64) void {
    var empty_keys: [16][]const u8 = undefined;
    while (true) {
        var n_empty: usize = 0;
        var it = self.by_domain.valueIterator();
        while (it.next()) |bucket| {
            self.purgeBucketExpiredLocked(bucket, now_epoch_s);
            if (bucket.cookies.items.len == 0 and n_empty < empty_keys.len) {
                empty_keys[n_empty] = bucket.key;
                n_empty += 1;
            }
        }
        if (n_empty == 0) break;
        for (empty_keys[0..n_empty]) |k| {
            self.removeEmptyBucketLocked(k);
        }
    }
}

/// RFC 6265 §5.1.3 domain-match (case-insensitive): exact match OR suffix preceded by `.`.
pub fn domainMatches(request_host: []const u8, cookie_domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(request_host, cookie_domain)) return true;
    if (isIpLiteral(request_host)) return false;
    if (request_host.len <= cookie_domain.len) return false;
    const prefix_len = request_host.len - cookie_domain.len;
    if (request_host[prefix_len - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(request_host[prefix_len..], cookie_domain);
}

/// RFC 6265 §5.1.4 path-match.
pub fn pathMatches(request_path: []const u8, cookie_path: []const u8) bool {
    const req = if (request_path.len == 0) "/" else request_path;
    if (std.mem.eql(u8, req, cookie_path)) return true;
    if (std.mem.startsWith(u8, req, cookie_path)) {
        if (cookie_path.len > 0 and cookie_path[cookie_path.len - 1] == '/') return true;
        if (req.len > cookie_path.len and req[cookie_path.len] == '/') return true;
    }
    return false;
}

/// RFC 6265 §5.1.4 default-path algorithm.
pub fn defaultPath(request_path: []const u8) []const u8 {
    if (request_path.len == 0 or request_path[0] != '/') return "/";
    const last_slash = std.mem.findScalarLast(u8, request_path, '/') orelse return "/";
    if (last_slash == 0) return "/";
    return request_path[0..last_slash];
}

fn stripQuery(target: []const u8) []const u8 {
    if (std.mem.findScalar(u8, target, '?')) |idx| return target[0..idx];
    return target;
}

fn isIpLiteral(host: []const u8) bool {
    if (std.mem.findScalar(u8, host, ':') != null) return true;
    _ = std.Io.net.IpAddress.parseIp4(host, 0) catch return false;
    return true;
}

fn trimOws(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t");
}

fn lowercaseToBuf(s: []const u8, buf: *[http.Origin.max_host_len]u8) ?[]const u8 {
    if (s.len > buf.len) return null;
    for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..s.len];
}

// ===========================================================================
// Unit Tests
// ===========================================================================

const Client = @import("Client.zig");
const MockTransport = @import("testing/MockTransport.zig");

test "CookieJar enforces host-only, domain/path matching, Secure gating, Max-Age precedence, and deletion" {
    const gpa = std.testing.allocator;
    var jar = CookieJar.init(gpa);
    defer jar.deinit();

    const now: i64 = 1_700_000_000;
    const api_https: http.Origin = .{ .scheme = .https, .host = "api.example.com", .port = 443 };
    const api_http: http.Origin = .{ .scheme = .http, .host = "api.example.com", .port = 80 };
    const sub_https: http.Origin = .{ .scheme = .https, .host = "sub.api.example.com", .port = 443 };
    const root_https: http.Origin = .{ .scheme = .https, .host = "example.com", .port = 443 };

    var resp_headers: http.Headers = .empty;
    defer resp_headers.deinit(gpa);

    // 1. Host-only session cookie (default path from /v1/auth/login => /v1/auth)
    try resp_headers.append(gpa, "Set-Cookie", "host_tok=abc; HttpOnly");
    // 2. Domain + Secure cookie for .example.com at /
    try resp_headers.append(gpa, "Set-Cookie", "shared=1; Domain=.example.com; Path=/; Secure; Max-Age=3600");
    // 3. Path-specific cookie (/v1) to verify longest-path ordering
    try resp_headers.append(gpa, "Set-Cookie", "scoped=deep; Domain=example.com; Path=/v1");
    // 4. Forged cross-domain cookie (must be ignored!)
    try resp_headers.append(gpa, "Set-Cookie", "evil=1; Domain=other.com");
    // 5. Forged TLD cookie (must be ignored!)
    try resp_headers.append(gpa, "Set-Cookie", "tld=1; Domain=com");

    try jar.storeFromHeadersAt(api_https, "/v1/auth/login", &resp_headers, now);
    try std.testing.expectEqual(@as(usize, 3), jar.countAt(now));

    // Exact HTTPS request to /v1/auth/profile matches all 3, ordered longest path first!
    {
        const hdr = (try jar.cookieHeaderAllocAt(gpa, api_https, "/v1/auth/profile", now)).?;
        defer gpa.free(hdr);
        try std.testing.expectEqualStrings("host_tok=abc; scoped=deep; shared=1", hdr);
    }

    // Plain HTTP omits `Secure` cookie (`shared=1`), keeps non-secure ones
    {
        const hdr = (try jar.cookieHeaderAllocAt(gpa, api_http, "/v1/auth/profile", now)).?;
        defer gpa.free(hdr);
        try std.testing.expectEqualStrings("host_tok=abc; scoped=deep", hdr);
    }

    // Subdomain does NOT receive host_only cookie (`host_tok`), DOES receive domain cookies
    {
        const hdr = (try jar.cookieHeaderAllocAt(gpa, sub_https, "/v1/items", now)).?;
        defer gpa.free(hdr);
        try std.testing.expectEqualStrings("scoped=deep; shared=1", hdr);
    }

    // Path prefix boundary: `/v10` must NOT match Path=`/v1`!
    {
        const hdr = (try jar.cookieHeaderAllocAt(gpa, root_https, "/v10", now)).?;
        defer gpa.free(hdr);
        try std.testing.expectEqualStrings("shared=1", hdr);
    }

    // Max-Age=0 deletes existing cookie immediately (taking precedence over future Expires)
    var del_headers: http.Headers = .empty;
    defer del_headers.deinit(gpa);
    try del_headers.append(gpa, "Set-Cookie", "shared=gone; Domain=example.com; Path=/; Max-Age=0; Expires=Wed, 21-Oct-2099 07:28:00 GMT");
    try jar.storeFromHeadersAt(api_https, "/", &del_headers, now);

    const after_del = try jar.cookieHeaderAllocAt(gpa, root_https, "/", now);
    try std.testing.expectEqual(@as(?[]u8, null), after_del);
}

test "Client with CookieJar carries Set-Cookie across same-origin redirect and isolates cross-origin redirect" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock = MockTransport.init(gpa);
    defer mock.deinit();

    // Hop 1: POST /login sets session cookie and redirects to /dashboard on same host
    try mock.pushResponse(.{
        .status = .see_other,
        .headers = &.{
            .{ .name = "Set-Cookie", .value = "sid=secret42; Path=/; Secure" },
            .{ .name = "Location", .value = "/dashboard" },
        },
    });
    // Hop 2: /dashboard redirects cross-origin to https://partner.b.com/landing
    try mock.pushResponse(.{
        .status = .found,
        .headers = &.{.{ .name = "Location", .value = "https://partner.b.com/landing" }},
    });
    // Hop 3: final 200 OK
    try mock.pushResponse(.{ .status = .ok, .body = "landed" });

    var jar = CookieJar.init(gpa);
    defer jar.deinit();

    var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{
        .cookie_jar = &jar,
    });
    defer client.deinit();

    var res = try client.fetch(.{
        .method = .POST,
        .url = "https://auth.a.com/login",
        .body = .{ .bytes = "u=alice" },
    });
    defer res.deinit();

    try std.testing.expectEqualStrings("landed", res.body);
    try std.testing.expectEqual(@as(usize, 3), mock.requests().len);

    // Hop 1 had no cookie yet
    try std.testing.expect(!mock.requests()[0].headers.has("Cookie"));
    // Hop 2 (same-origin /dashboard) automatically sent Set-Cookie from Hop 1!
    try std.testing.expectEqualStrings("sid=secret42", mock.requests()[1].headers.get("Cookie").?);
    // Hop 3 (cross-origin partner.b.com) MUST NOT receive auth.a.com's cookie!
    try std.testing.expect(!mock.requests()[2].headers.has("Cookie"));
}

test "CookieJar rejects multi-label public suffixes, oversized cookies, and enforces capacity limits" {
    const gpa = std.testing.allocator;
    var jar = CookieJar.initWithLimits(gpa, .{
        .max_cookies = 3,
        .max_cookies_per_domain = 2,
        .max_cookie_bytes = 64,
    });
    defer jar.deinit();

    const now: i64 = 1_700_000_000;
    const uk_site: http.Origin = .{ .scheme = .https, .host = "shop.co.uk", .port = 443 };
    const gh_site: http.Origin = .{ .scheme = .https, .host = "alice.github.io", .port = 443 };

    var hdrs: http.Headers = .empty;
    defer hdrs.deinit(gpa);
    // Multi-label public suffixes MUST be blocked to prevent supercookies
    try hdrs.append(gpa, "Set-Cookie", "super1=1; Domain=co.uk");
    try hdrs.append(gpa, "Set-Cookie", "super2=1; Domain=github.io");
    // Oversized cookie (> 64 bytes) MUST be ignored
    try hdrs.append(gpa, "Set-Cookie", "huge=0123456789012345678901234567890123456789012345678901234567890123456789");
    try jar.storeFromHeadersAt(uk_site, "/", &hdrs, now);
    try jar.storeFromHeadersAt(gh_site, "/", &hdrs, now);
    try std.testing.expectEqual(@as(usize, 0), jar.countAt(now));

    // Per-domain cap = 2 evicts oldest cookie on same domain
    var dom_hdrs: http.Headers = .empty;
    defer dom_hdrs.deinit(gpa);
    try dom_hdrs.append(gpa, "Set-Cookie", "c1=1; Path=/");
    try dom_hdrs.append(gpa, "Set-Cookie", "c2=2; Path=/");
    try dom_hdrs.append(gpa, "Set-Cookie", "c3=3; Path=/");
    try jar.storeFromHeadersAt(uk_site, "/", &dom_hdrs, now);
    try std.testing.expectEqual(@as(usize, 2), jar.countAt(now));

    const header = (try jar.cookieHeaderAllocAt(gpa, uk_site, "/", now)).?;
    defer gpa.free(header);
    try std.testing.expectEqualStrings("c2=2; c3=3", header);

    // Global cap = 3 across domains evicts oldest across domains (c2 on shop.co.uk)
    const other_site: http.Origin = .{ .scheme = .https, .host = "other.example.com", .port = 443 };
    var other_hdrs: http.Headers = .empty;
    defer other_hdrs.deinit(gpa);
    try other_hdrs.append(gpa, "Set-Cookie", "o1=1; Path=/");
    try other_hdrs.append(gpa, "Set-Cookie", "o2=2; Path=/");
    try jar.storeFromHeadersAt(other_site, "/", &other_hdrs, now);
    try std.testing.expectEqual(@as(usize, 3), jar.countAt(now));
    try std.testing.expectEqual(@as(?[]u8, null), try jar.getValueAllocAt(gpa, "shop.co.uk", "c2", now));
}

test "CookieJar supports getValueAlloc, remove, add, and JSON export/import persistence" {
    const gpa = std.testing.allocator;
    const now: i64 = 1_700_000_000;

    var jar = CookieJar.init(gpa);
    defer jar.deinit();

    try jar.addAt(.{
        .name = "session",
        .value = "tok-123",
        .domain = "api.example.com",
        .host_only = true,
        .path = "/",
        .secure = true,
        .expires_epoch_s = now + 3600,
    }, now);
    try jar.addAt(.{
        .name = "theme",
        .value = "dark",
        .domain = "example.com",
        .host_only = false,
        .path = "/",
    }, now);

    const val = (try jar.getValueAllocAt(gpa, "API.EXAMPLE.COM", "session", now)).?;
    defer gpa.free(val);
    try std.testing.expectEqualStrings("tok-123", val);

    const exported = try jar.exportJsonAllocAt(gpa, now);
    defer gpa.free(exported);

    var restored = CookieJar.init(gpa);
    defer restored.deinit();
    try restored.importJsonAt(exported, now);
    try std.testing.expectEqual(@as(usize, 2), restored.countAt(now));

    const hdr = (try restored.cookieHeaderAllocAt(
        gpa,
        .{ .scheme = .https, .host = "api.example.com", .port = 443 },
        "/v1",
        now,
    )).?;
    defer gpa.free(hdr);
    try std.testing.expectEqualStrings("session=tok-123; theme=dark", hdr);

    try std.testing.expect(restored.remove("api.example.com", "session", "/"));
    try std.testing.expect(!restored.remove("api.example.com", "session", "/"));
    try std.testing.expectEqual(@as(usize, 1), restored.countAt(now));
}

test "fuzz CookieJar.storeFromHeadersAt handles arbitrary Set-Cookie bytes without panic or leak" {
    const Fuzz = struct {
        fn run(_: void, smith: *std.testing.Smith) !void {
            var buf: [256]u8 = undefined;
            const n = smith.sliceWithHash(&buf, 0xc00c);
            const raw = buf[0..n];

            // Strip CR/LF/NUL/CTLs so we test CookieJar parsing on any valid HTTP header value.
            var clean: [256]u8 = undefined;
            var len: usize = 0;
            for (raw) |c| {
                if (c >= 0x20 and c <= 0x7E) {
                    clean[len] = c;
                    len += 1;
                }
            }

            const gpa = std.testing.allocator;
            var hdrs: http.Headers = .empty;
            defer hdrs.deinit(gpa);
            hdrs.append(gpa, "Set-Cookie", clean[0..len]) catch return;

            var jar = CookieJar.init(gpa);
            defer jar.deinit();
            const origin: http.Origin = .{ .scheme = .https, .host = "app.example.com", .port = 443 };
            try jar.storeFromHeadersAt(origin, "/v1/login", &hdrs, 1_700_000_000);
            if (try jar.cookieHeaderAllocAt(gpa, origin, "/v1/me", 1_700_000_000)) |h| {
                gpa.free(h);
            }
        }
    };

    try std.testing.fuzz({}, Fuzz.run, .{
        .corpus = &.{
            "sid=abc; Path=/; Secure; HttpOnly; Max-Age=60",
            "a=1; Domain=.example.com; Expires=Sun, 06-Nov-2099 08:49:37 GMT",
            "===;;;Domain=.;Path=;Max-Age=notanumber",
        },
    });
}
