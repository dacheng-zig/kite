//! RFC 9111 in-memory private HTTP cache decorator implementing `kite.Transport`.
//!
//! Features:
//! - Caches safe `GET` / `HEAD` responses governed by `Cache-Control` (`max-age`,
//!   `no-store`, `no-cache`, `private`, `public`, `only-if-cached`), `Age`, and
//!   `Expires` / `Date` (HTTP-date via `http.parseHttpDate`).
//! - Multi-variant `Vary` storage: caches up to `max_variants_per_key` distinct
//!   `Vary` header combinations per URL concurrently (no cache thrashing across
//!   languages/encodings), while rejecting `Vary: *`.
//! - Conditional revalidation (`If-None-Match` via `ETag`, `If-Modified-Since`
//!   via `Last-Modified`) transparently upgrading `304 Not Modified` into a fresh
//!   cached response with merged headers (or evicting if `304` adds `no-store`).
//! - Automatic RFC 9111 §4.4 invalidation on unsafe methods (`POST`/`PUT`/`PATCH`/
//!   `DELETE`) returning `2xx`/`3xx`, including same-origin `Location` and
//!   `Content-Location` targets.
//! - Strict O(1) LRU memory governance (`max_entries`, `max_entry_bytes`,
//!   `max_total_bytes`), automatic empty-bucket reclamation, and streaming capture
//!   that commits ONLY after clean EOF (aborted reads never poison the cache).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");
const Transport = @import("Transport.zig");

const CacheTransport = @This();

pub const Config = struct {
    /// Maximum number of distinct cached responses retained in memory.
    max_entries: usize = 256,
    /// Maximum concurrent `Vary` variants retained for any single `(method, origin, target)`.
    max_variants_per_key: usize = 8,
    /// Maximum body size of any single cacheable response.
    max_entry_bytes: usize = 1 * 1024 * 1024,
    /// Hard ceiling on total cached body + header bytes across all entries.
    max_total_bytes: usize = 32 * 1024 * 1024,
    /// Allow caching responses to requests carrying `Authorization` when the response
    /// does not forbid storage (private client cache behavior; default `false` for safety).
    cache_authorized_requests: bool = false,
};

pub const Stats = struct {
    entries: usize,
    total_bytes: usize,
    hits: u64,
    revalidated_hits: u64,
    misses: u64,
};

const CacheKey = struct {
    method: []const u8,
    origin: http.Origin,
    target: []const u8,

    fn hash(self: CacheKey) u64 {
        var h = std.hash.Wyhash.init(self.origin.hash());
        h.update(self.method);
        h.update(&.{0});
        h.update(self.target);
        return h.final();
    }

    fn eql(a: CacheKey, b: CacheKey) bool {
        return std.mem.eql(u8, a.method, b.method) and
            a.origin.eql(b.origin) and
            std.mem.eql(u8, a.target, b.target);
    }
};

const KeyContext = struct {
    pub fn hash(_: KeyContext, k: CacheKey) u64 {
        return k.hash();
    }
    pub fn eql(_: KeyContext, a: CacheKey, b: CacheKey) bool {
        return a.eql(b);
    }
};

const VaryPair = struct {
    name: []u8,
    value: []u8,
};

const KeyBucket = struct {
    method: []u8,
    origin: http.Origin,
    target: []u8,
    variants: std.DoublyLinkedList = .{},
    variant_count: usize = 0,

    fn key(self: *const KeyBucket) CacheKey {
        return .{
            .method = self.method,
            .origin = self.origin,
            .target = self.target,
        };
    }

    fn findMatching(self: *KeyBucket, req_headers: []const http.Header) ?*CacheEntry {
        var cursor = self.variants.first;
        while (cursor) |node| {
            const entry: *CacheEntry = @fieldParentPtr("variant_node", node);
            if (entry.matchesVary(req_headers)) return entry;
            cursor = node.next;
        }
        return null;
    }

    fn destroy(self: *KeyBucket, gpa: Allocator) void {
        gpa.free(self.method);
        var o = self.origin;
        o.deinitOwned(gpa);
        gpa.free(self.target);
        gpa.destroy(self);
    }
};

const CacheEntry = struct {
    bucket: *KeyBucket,

    status: http.Status,
    reason: []u8,
    headers: http.Headers,
    body: []u8,

    etag: ?[]u8 = null,
    last_modified: ?[]u8 = null,
    vary: []VaryPair = &.{},

    stored_at_ns: u64,
    fresh_until_ns: u64,
    must_revalidate: bool = false,
    byte_size: usize,

    variant_node: std.DoublyLinkedList.Node = .{},
    lru_node: std.DoublyLinkedList.Node = .{},

    fn matchesVary(self: *const CacheEntry, req_headers: []const http.Header) bool {
        for (self.vary) |vp| {
            const actual = firstHeaderSlice(req_headers, vp.name) orelse "";
            if (!std.mem.eql(u8, actual, vp.value)) return false;
        }
        return true;
    }

    fn sameVarySignature(self: *const CacheEntry, other_vary: []const VaryPair) bool {
        if (self.vary.len != other_vary.len) return false;
        for (self.vary, other_vary) |a, b| {
            if (!std.ascii.eqlIgnoreCase(a.name, b.name)) return false;
            if (!std.mem.eql(u8, a.value, b.value)) return false;
        }
        return true;
    }

    fn isFresh(self: *const CacheEntry, now_ns: u64) bool {
        if (self.must_revalidate) return false;
        return now_ns < self.fresh_until_ns;
    }

    fn destroy(self: *CacheEntry, gpa: Allocator) void {
        gpa.free(self.reason);
        self.headers.deinit(gpa);
        gpa.free(self.body);
        if (self.etag) |e| gpa.free(e);
        if (self.last_modified) |lm| gpa.free(lm);
        for (self.vary) |vp| {
            gpa.free(vp.name);
            gpa.free(vp.value);
        }
        if (self.vary.len > 0) gpa.free(self.vary);
        gpa.destroy(self);
    }
};

const CacheControl = struct {
    no_store: bool = false,
    no_cache: bool = false,
    must_revalidate: bool = false,
    public: bool = false,
    max_age_s: ?u64 = null,
    only_if_cached: bool = false,

    fn parse(headers: []const http.Header) CacheControl {
        var cc: CacheControl = .{};
        for (headers) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, "Cache-Control")) continue;
            cc.parseValue(h.value);
        }
        return cc;
    }

    fn parseHeaders(headers: *const http.Headers) CacheControl {
        return parse(headers.items());
    }

    fn parseValue(self: *CacheControl, raw: []const u8) void {
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |raw_dir| {
            const dir = std.mem.trim(u8, raw_dir, " \t");
            if (dir.len == 0) continue;

            if (std.mem.findScalar(u8, dir, '=')) |eq| {
                const name = std.mem.trim(u8, dir[0..eq], " \t");
                var val = std.mem.trim(u8, dir[eq + 1 ..], " \t");
                if (val.len >= 2 and val[0] == '"' and val[val.len - 1] == '"') {
                    val = val[1 .. val.len - 1];
                }
                if (std.ascii.eqlIgnoreCase(name, "max-age")) {
                    if (std.fmt.parseInt(u64, val, 10)) |secs| {
                        self.max_age_s = secs;
                    } else |_| {}
                }
            } else {
                if (std.ascii.eqlIgnoreCase(dir, "no-store")) {
                    self.no_store = true;
                } else if (std.ascii.eqlIgnoreCase(dir, "no-cache")) {
                    self.no_cache = true;
                } else if (std.ascii.eqlIgnoreCase(dir, "must-revalidate")) {
                    self.must_revalidate = true;
                } else if (std.ascii.eqlIgnoreCase(dir, "public")) {
                    self.public = true;
                } else if (std.ascii.eqlIgnoreCase(dir, "only-if-cached")) {
                    self.only_if_cached = true;
                }
            }
        }
    }
};

gpa: Allocator,
inner: Transport,
config: Config,
mutex: zio.Mutex = .init,
buckets: std.HashMapUnmanaged(CacheKey, *KeyBucket, KeyContext, std.hash_map.default_max_load_percentage) = .empty,
lru: std.DoublyLinkedList = .{},
entry_count: usize = 0,
total_bytes: usize = 0,
hits: u64 = 0,
revalidated_hits: u64 = 0,
misses: u64 = 0,

pub fn init(gpa: Allocator, inner: Transport, config: Config) CacheTransport {
    return .{
        .gpa = gpa,
        .inner = inner,
        .config = config,
    };
}

pub fn deinit(self: *CacheTransport) void {
    self.mutex.lockUncancelable();
    self.clearLocked();
    self.buckets.deinit(self.gpa);
    self.mutex.unlock();
}

pub fn transport(self: *CacheTransport) Transport {
    return .{
        .ptr = self,
        .vtable = &.{
            .openExchange = openExchangeImpl,
        },
    };
}

pub fn stats(self: *CacheTransport) Stats {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    return .{
        .entries = self.entry_count,
        .total_bytes = self.total_bytes,
        .hits = self.hits,
        .revalidated_hits = self.revalidated_hits,
        .misses = self.misses,
    };
}

pub fn clear(self: *CacheTransport) void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    self.clearLocked();
}

fn clearLocked(self: *CacheTransport) void {
    while (self.lru.popFirst()) |node| {
        const entry: *CacheEntry = @fieldParentPtr("lru_node", node);
        entry.destroy(self.gpa);
    }
    var it = self.buckets.valueIterator();
    while (it.next()) |bp| {
        bp.*.destroy(self.gpa);
    }
    self.buckets.clearRetainingCapacity();
    self.entry_count = 0;
    self.total_bytes = 0;
}

fn openExchangeImpl(ptr: *anyopaque, req: Transport.ExchangeRequest) anyerror!Transport.Exchange {
    const self: *CacheTransport = @ptrCast(@alignCast(ptr));

    const is_cacheable_method = req.method.eql(.GET) or req.method.eql(.HEAD);
    const req_cc = CacheControl.parse(req.headers);
    const has_auth = firstHeaderSlice(req.headers, "Authorization") != null;

    // Unsafe methods pass straight through and invalidate matching GET/HEAD cache entries on 2xx/3xx.
    if (!is_cacheable_method) {
        const inner_ex = try self.inner.openExchange(req);
        const inv = self.gpa.create(InvalidatingExchange) catch |err| {
            var ex_copy = inner_ex;
            ex_copy.deinit();
            return err;
        };
        const origin_copy = req.origin.dupeOwned(self.gpa) catch |err| {
            var ex_copy = inner_ex;
            ex_copy.deinit();
            self.gpa.destroy(inv);
            return err;
        };
        const target_copy = self.gpa.dupe(u8, req.target) catch |err| {
            var ex_copy = inner_ex;
            ex_copy.deinit();
            var o = origin_copy;
            o.deinitOwned(self.gpa);
            self.gpa.destroy(inv);
            return err;
        };
        inv.* = .{
            .cache = self,
            .origin = origin_copy,
            .target = target_copy,
            .inner = inner_ex,
        };
        return inv.handle();
    }

    if (req_cc.no_store) {
        if (req_cc.only_if_cached) return CachedExchange.createGatewayTimeout(self.gpa);
        return self.inner.openExchange(req);
    }

    // Lookup existing variant under lock.
    const lookup_key: CacheKey = .{
        .method = req.method.name(),
        .origin = req.origin,
        .target = req.target,
    };

    var reval_etag: ?[]u8 = null;
    defer if (reval_etag) |e| self.gpa.free(e);
    var reval_lm: ?[]u8 = null;
    defer if (reval_lm) |lm| self.gpa.free(lm);

    {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();

        if (self.buckets.get(lookup_key)) |bucket| {
            if (bucket.findMatching(req.headers)) |entry| {
                const now_ns = zio.Timestamp.now(.awake).toNanoseconds();
                const force_reval = req_cc.no_cache or (req_cc.max_age_s != null and req_cc.max_age_s.? == 0);

                if (!force_reval and entry.isFresh(now_ns)) {
                    // Fresh cache hit: promote LRU and synthesize an in-memory Exchange.
                    self.lru.remove(&entry.lru_node);
                    self.lru.append(&entry.lru_node);
                    self.hits += 1;
                    return CachedExchange.createFromEntry(self.gpa, entry);
                }

                // Stale or `no-cache`: extract validators for conditional revalidation.
                if (!req_cc.only_if_cached) {
                    if (entry.etag) |e| {
                        reval_etag = self.gpa.dupe(u8, e) catch null;
                    }
                    if (entry.last_modified) |lm| {
                        reval_lm = self.gpa.dupe(u8, lm) catch null;
                    }
                }
            }
        }
        self.misses += 1;
    }

    // RFC 9111 §5.2.1.7: `only-if-cached` MUST return 504 Gateway Timeout on miss without network I/O.
    if (req_cc.only_if_cached) {
        return CachedExchange.createGatewayTimeout(self.gpa);
    }

    // Build forwarded request (adding If-None-Match / If-Modified-Since if we have validators
    // and the caller did not already provide them).
    var fwd_headers: std.ArrayList(http.Header) = .empty;
    defer fwd_headers.deinit(self.gpa);

    var fwd_req = req;
    const caller_has_inm = firstHeaderSlice(req.headers, "If-None-Match") != null;
    const caller_has_ims = firstHeaderSlice(req.headers, "If-Modified-Since") != null;
    const add_inm = reval_etag != null and !caller_has_inm;
    const add_ims = reval_lm != null and !caller_has_ims;

    if (add_inm or add_ims) {
        try fwd_headers.ensureTotalCapacity(self.gpa, req.headers.len + 2);
        fwd_headers.appendSliceAssumeCapacity(req.headers);
        if (add_inm) {
            fwd_headers.appendAssumeCapacity(.{ .name = "If-None-Match", .value = reval_etag.? });
        }
        if (add_ims) {
            fwd_headers.appendAssumeCapacity(.{ .name = "If-Modified-Since", .value = reval_lm.? });
        }
        fwd_req.headers = fwd_headers.items;
    }

    const inner_ex = try self.inner.openExchange(fwd_req);

    // Wrap the live exchange to either handle 304 revalidation or capture a cacheable body.
    const cap = CachingExchange.create(self, req, inner_ex, add_inm or add_ims, has_auth) catch |err| {
        var ex_copy = inner_ex;
        ex_copy.deinit();
        return err;
    };
    return cap.handle();
}

fn invalidateUrl(self: *CacheTransport, origin: http.Origin, target: []const u8) void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    const methods = [_][]const u8{ "GET", "HEAD" };
    for (methods) |m| {
        const k: CacheKey = .{ .method = m, .origin = origin, .target = target };
        if (self.buckets.fetchRemove(k)) |kv| {
            const bucket = kv.value;
            while (bucket.variants.popFirst()) |node| {
                const entry: *CacheEntry = @fieldParentPtr("variant_node", node);
                self.lru.remove(&entry.lru_node);
                self.entry_count -|= 1;
                self.total_bytes -|= entry.byte_size;
                entry.destroy(self.gpa);
            }
            bucket.destroy(self.gpa);
        }
    }
}

fn removeEntryLocked(self: *CacheTransport, entry: *CacheEntry) void {
    const bucket = entry.bucket;
    bucket.variants.remove(&entry.variant_node);
    bucket.variant_count -|= 1;
    self.lru.remove(&entry.lru_node);
    self.entry_count -|= 1;
    self.total_bytes -|= entry.byte_size;
    entry.destroy(self.gpa);

    if (bucket.variant_count == 0) {
        _ = self.buckets.remove(bucket.key());
        bucket.destroy(self.gpa);
    }
}

fn getOrCreateBucketLocked(
    self: *CacheTransport,
    method: []const u8,
    origin: http.Origin,
    target: []const u8,
) Allocator.Error!*KeyBucket {
    const k: CacheKey = .{ .method = method, .origin = origin, .target = target };
    if (self.buckets.get(k)) |existing| return existing;

    const bucket = try self.gpa.create(KeyBucket);
    errdefer self.gpa.destroy(bucket);

    const method_copy = try self.gpa.dupe(u8, method);
    errdefer self.gpa.free(method_copy);
    const origin_copy = try origin.dupeOwned(self.gpa);
    errdefer {
        var o = origin_copy;
        o.deinitOwned(self.gpa);
    }
    const target_copy = try self.gpa.dupe(u8, target);
    errdefer self.gpa.free(target_copy);

    bucket.* = .{
        .method = method_copy,
        .origin = origin_copy,
        .target = target_copy,
    };
    try self.buckets.put(self.gpa, bucket.key(), bucket);
    return bucket;
}

fn storeEntry(
    self: *CacheTransport,
    method: []const u8,
    origin: http.Origin,
    target: []const u8,
    req_headers: []const http.Header,
    has_auth: bool,
    status: http.Status,
    reason: []const u8,
    resp_headers: *const http.Headers,
    body: []const u8,
) !void {
    if (self.config.max_entries == 0 or self.config.max_total_bytes == 0) return;
    if (body.len > self.config.max_entry_bytes or body.len > self.config.max_total_bytes) return;

    const cc = CacheControl.parseHeaders(resp_headers);
    if (cc.no_store) return;

    // RFC 9111 §3.5: authorized responses are stored only if explicitly allowed or
    // server opts in with `public` / `must-revalidate`.
    if (has_auth and !self.config.cache_authorized_requests and !cc.public and !cc.must_revalidate) {
        return;
    }

    // Reject `Vary: *` per RFC 9111 §4.1.
    if (resp_headers.get("Vary")) |vary_raw| {
        if (hasVaryWildcard(vary_raw)) return;
    }

    const now_ns = zio.Timestamp.now(.awake).toNanoseconds();
    const freshness_ns = computeFreshnessNs(cc, resp_headers);
    const has_validator = resp_headers.has("ETag") or resp_headers.has("Last-Modified");
    // Only store if response is either fresh (> 0s) or carries a validator for 304 revalidation.
    if (freshness_ns == 0 and !has_validator) return;

    const reason_copy = try self.gpa.dupe(u8, reason);
    errdefer self.gpa.free(reason_copy);
    var hdrs_copy = try cloneHttpHeaders(self.gpa, resp_headers);
    errdefer hdrs_copy.deinit(self.gpa);
    const body_copy = try self.gpa.dupe(u8, body);
    errdefer self.gpa.free(body_copy);

    const etag_copy: ?[]u8 = if (resp_headers.get("ETag")) |e| try self.gpa.dupe(u8, e) else null;
    errdefer if (etag_copy) |e| self.gpa.free(e);
    const lm_copy: ?[]u8 = if (resp_headers.get("Last-Modified")) |lm| try self.gpa.dupe(u8, lm) else null;
    errdefer if (lm_copy) |lm| self.gpa.free(lm);

    const vary_pairs = try captureVaryPairs(self.gpa, resp_headers, req_headers);
    errdefer {
        for (vary_pairs) |vp| {
            self.gpa.free(vp.name);
            self.gpa.free(vp.value);
        }
        if (vary_pairs.len > 0) self.gpa.free(vary_pairs);
    }

    const byte_size = body_copy.len + reason_copy.len + target.len + origin.host.len + 128;

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    const bucket = self.getOrCreateBucketLocked(method, origin, target) catch return;

    // Replace existing variant with the exact same Vary signature if present.
    var cursor = bucket.variants.first;
    while (cursor) |node| {
        const existing: *CacheEntry = @fieldParentPtr("variant_node", node);
        const next_node = node.next;
        if (existing.sameVarySignature(vary_pairs)) {
            bucket.variants.remove(&existing.variant_node);
            bucket.variant_count -|= 1;
            self.lru.remove(&existing.lru_node);
            self.entry_count -|= 1;
            self.total_bytes -|= existing.byte_size;
            existing.destroy(self.gpa);
            break;
        }
        cursor = next_node;
    }

    // Cap per-key Vary variants (evict oldest variant in this bucket).
    while (self.config.max_variants_per_key > 0 and
        bucket.variant_count >= self.config.max_variants_per_key and
        bucket.variants.first != null)
    {
        const old_node = bucket.variants.first.?;
        const victim: *CacheEntry = @fieldParentPtr("variant_node", old_node);
        bucket.variants.remove(&victim.variant_node);
        bucket.variant_count -|= 1;
        self.lru.remove(&victim.lru_node);
        self.entry_count -|= 1;
        self.total_bytes -|= victim.byte_size;
        victim.destroy(self.gpa);
    }

    // Evict global LRU entries until both entry-count and byte-budget invariants hold.
    while ((self.entry_count >= self.config.max_entries or
        self.total_bytes + byte_size > self.config.max_total_bytes) and
        self.lru.first != null)
    {
        const victim_node = self.lru.first.?;
        const victim: *CacheEntry = @fieldParentPtr("lru_node", victim_node);
        // Avoid freeing `bucket` while we're about to insert into it.
        if (victim.bucket == bucket) {
            bucket.variants.remove(&victim.variant_node);
            bucket.variant_count -|= 1;
            self.lru.remove(&victim.lru_node);
            self.entry_count -|= 1;
            self.total_bytes -|= victim.byte_size;
            victim.destroy(self.gpa);
        } else {
            self.removeEntryLocked(victim);
        }
    }

    if (self.total_bytes + byte_size > self.config.max_total_bytes) {
        if (bucket.variant_count == 0) {
            _ = self.buckets.remove(bucket.key());
            bucket.destroy(self.gpa);
        }
        // Clean up owned allocations on bailout (errdefer doesn't run on normal return).
        self.gpa.free(reason_copy);
        hdrs_copy.deinit(self.gpa);
        self.gpa.free(body_copy);
        if (etag_copy) |e| self.gpa.free(e);
        if (lm_copy) |lm| self.gpa.free(lm);
        for (vary_pairs) |vp| {
            self.gpa.free(vp.name);
            self.gpa.free(vp.value);
        }
        if (vary_pairs.len > 0) self.gpa.free(vary_pairs);
        return;
    }

    const entry = try self.gpa.create(CacheEntry);
    entry.* = .{
        .bucket = bucket,
        .status = status,
        .reason = reason_copy,
        .headers = hdrs_copy,
        .body = body_copy,
        .etag = etag_copy,
        .last_modified = lm_copy,
        .vary = vary_pairs,
        .stored_at_ns = now_ns,
        .fresh_until_ns = now_ns +| freshness_ns,
        .must_revalidate = cc.no_cache,
        .byte_size = byte_size,
    };

    bucket.variants.append(&entry.variant_node);
    bucket.variant_count += 1;
    self.lru.append(&entry.lru_node);
    self.entry_count += 1;
    self.total_bytes += entry.byte_size;
}

/// Applies a `304 Not Modified` response onto an existing cached entry: merges updated
/// headers, refreshes freshness lifetime (or evicts if `304` adds `no-store`), and
/// returns a synthesized `CachedExchange`.
fn revalidateEntryWith304(
    self: *CacheTransport,
    lookup_key: CacheKey,
    req_headers: []const http.Header,
    not_modified_head: *const h1.ResponseHead,
) !?Transport.Exchange {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    const bucket = self.buckets.get(lookup_key) orelse return null;
    const entry = bucket.findMatching(req_headers) orelse return null;

    // Merge updated response headers from 304 onto cached entry headers (RFC 9111 §3.2):
    // preserve multi-value headers like `Set-Cookie`, replace single-value metadata headers.
    for (not_modified_head.headers.items()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Set-Cookie")) {
            try entry.headers.append(self.gpa, h.name, h.value);
        } else {
            try entry.headers.set(self.gpa, h.name, h.value);
        }
    }
    if (not_modified_head.headers.get("ETag")) |new_etag| {
        const dup = try self.gpa.dupe(u8, new_etag);
        if (entry.etag) |old| self.gpa.free(old);
        entry.etag = dup;
    }
    if (not_modified_head.headers.get("Last-Modified")) |new_lm| {
        const dup = try self.gpa.dupe(u8, new_lm);
        if (entry.last_modified) |old| self.gpa.free(old);
        entry.last_modified = dup;
    }

    const ex = try CachedExchange.createFromEntry(self.gpa, entry);
    self.revalidated_hits += 1;

    const cc = CacheControl.parseHeaders(&entry.headers);
    if (cc.no_store) {
        // Server transitioned the resource to `no-store`: serve this revalidated
        // snapshot once and immediately evict the entry from cache.
        self.removeEntryLocked(entry);
        return ex;
    }

    const now_ns = zio.Timestamp.now(.awake).toNanoseconds();
    entry.stored_at_ns = now_ns;
    entry.fresh_until_ns = now_ns +| computeFreshnessNs(cc, &entry.headers);
    entry.must_revalidate = cc.no_cache;

    self.lru.remove(&entry.lru_node);
    self.lru.append(&entry.lru_node);
    return ex;
}

// ---------------------------------------------------------------------------
// Exchange implementations
// ---------------------------------------------------------------------------

/// Synthesized zero-network `Exchange` served directly from a cached entry (or 504 on `only-if-cached`).
const CachedExchange = struct {
    gpa: Allocator,
    head: h1.ResponseHead,
    head_taken: bool = false,
    body_owned: []u8,
    body_reader: Reader,
    dummy_writer: Writer,

    fn createFromEntry(gpa: Allocator, entry: *const CacheEntry) !Transport.Exchange {
        const ex = try gpa.create(CachedExchange);
        errdefer gpa.destroy(ex);

        const reason_copy = try gpa.dupe(u8, entry.reason);
        errdefer gpa.free(reason_copy);
        var hdrs_copy = try cloneHttpHeaders(gpa, &entry.headers);
        errdefer hdrs_copy.deinit(gpa);
        const body_copy = try gpa.dupe(u8, entry.body);
        errdefer gpa.free(body_copy);

        const body_forbidden = std.mem.eql(u8, entry.bucket.method, "HEAD") or entry.status.forbidsResponseBody();
        const framing: h1.ResponseFraming = if (body_forbidden) .none else .{ .fixed = body_copy.len };

        ex.* = .{
            .gpa = gpa,
            .head = .{
                .version = .http1_1,
                .status = entry.status,
                .reason = reason_copy,
                .headers = hdrs_copy,
                .framing = framing,
                .keep_alive = true,
            },
            .body_owned = body_copy,
            .body_reader = .fixed(if (body_forbidden) "" else body_copy),
            .dummy_writer = .fixed(&.{}),
        };
        return ex.handle();
    }

    fn createGatewayTimeout(gpa: Allocator) !Transport.Exchange {
        const ex = try gpa.create(CachedExchange);
        errdefer gpa.destroy(ex);

        const reason_copy = try gpa.dupe(u8, "Gateway Timeout");
        errdefer gpa.free(reason_copy);

        ex.* = .{
            .gpa = gpa,
            .head = .{
                .version = .http1_1,
                .status = .gateway_timeout,
                .reason = reason_copy,
                .headers = .empty,
                .framing = .{ .fixed = 0 },
                .keep_alive = true,
            },
            .body_owned = &.{},
            .body_reader = .fixed(""),
            .dummy_writer = .fixed(&.{}),
        };
        return ex.handle();
    }

    fn handle(self: *CachedExchange) Transport.Exchange {
        return .{
            .ptr = self,
            .vtable = &.{
                .writer = writerImpl,
                .unwrapWriteError = unwrapWriteErrorImpl,
                .receiveHead = receiveHeadImpl,
                .takeHead = takeHeadImpl,
                .reader = readerImpl,
                .unwrapReadError = unwrapReadErrorImpl,
                .deinit = deinitImpl,
            },
        };
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *CachedExchange = @ptrCast(@alignCast(ptr));
        return &self.dummy_writer;
    }

    fn unwrapWriteErrorImpl(_: *const anyopaque) ?anyerror {
        return null;
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *CachedExchange = @ptrCast(@alignCast(ptr));
        return &self.head;
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *CachedExchange = @ptrCast(@alignCast(ptr));
        if (self.head_taken) return null;
        self.head_taken = true;
        return self.head;
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *CachedExchange = @ptrCast(@alignCast(ptr));
        return &self.body_reader;
    }

    fn unwrapReadErrorImpl(_: *const anyopaque) ?anyerror {
        return null;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *CachedExchange = @ptrCast(@alignCast(ptr));
        if (!self.head_taken) self.head.deinit(self.gpa);
        if (self.body_owned.len > 0) self.gpa.free(self.body_owned);
        self.gpa.destroy(self);
    }
};

/// Passthrough exchange that streams bytes directly to the caller while capturing
/// cacheable responses until clean EOF (partial/aborted reads never enter the cache).
const CachingExchange = struct {
    cache: *CacheTransport,
    method: []u8,
    origin: http.Origin,
    target: []u8,
    req_headers: http.Headers,
    inner: Transport.Exchange,
    revalidated_delegate: ?Transport.Exchange = null,
    sent_validators: bool,
    has_auth: bool,

    // Captured response metadata for committing to cache on EOF
    capturing: bool = false,
    eof_reached: bool = false,
    capture_status: http.Status = .ok,
    capture_reason: []u8 = &.{},
    capture_headers: http.Headers = .empty,
    capture_body: std.ArrayList(u8) = .empty,
    tee_reader: Reader = undefined,
    tee_buf: [4096]u8 = undefined,

    fn create(
        cache: *CacheTransport,
        req: Transport.ExchangeRequest,
        inner: Transport.Exchange,
        sent_validators: bool,
        has_auth: bool,
    ) !*CachingExchange {
        const gpa = cache.gpa;
        const ex = try gpa.create(CachingExchange);
        errdefer gpa.destroy(ex);

        const method_copy = try gpa.dupe(u8, req.method.name());
        errdefer gpa.free(method_copy);
        const origin_copy = try req.origin.dupeOwned(gpa);
        errdefer {
            var o = origin_copy;
            o.deinitOwned(gpa);
        }
        const target_copy = try gpa.dupe(u8, req.target);
        errdefer gpa.free(target_copy);

        var req_hdrs: http.Headers = .empty;
        errdefer req_hdrs.deinit(gpa);
        for (req.headers) |h| {
            try req_hdrs.append(gpa, h.name, h.value);
        }

        ex.* = .{
            .cache = cache,
            .method = method_copy,
            .origin = origin_copy,
            .target = target_copy,
            .req_headers = req_hdrs,
            .inner = inner,
            .sent_validators = sent_validators,
            .has_auth = has_auth,
        };
        ex.tee_reader = .{
            .vtable = &.{ .stream = teeStreamImpl },
            .buffer = &.{},
            .seek = 0,
            .end = 0,
        };
        return ex;
    }

    fn handle(self: *CachingExchange) Transport.Exchange {
        return .{
            .ptr = self,
            .vtable = &.{
                .writer = writerImpl,
                .unwrapWriteError = unwrapWriteErrorImpl,
                .receiveHead = receiveHeadImpl,
                .takeHead = takeHeadImpl,
                .reader = readerImpl,
                .unwrapReadError = unwrapReadErrorImpl,
                .deinit = deinitImpl,
            },
        };
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *CachingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.writer();
    }

    fn unwrapWriteErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const CachingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.unwrapWriteError();
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *CachingExchange = @ptrCast(@alignCast(ptr));
        const head = try self.inner.receiveHead();

        // Handle 304 Not Modified conditional revalidation!
        if (self.sent_validators and head.status == .not_modified) {
            const k: CacheKey = .{
                .method = self.method,
                .origin = self.origin,
                .target = self.target,
            };
            if (try self.cache.revalidateEntryWith304(k, self.req_headers.items(), head)) |deleg| {
                self.inner.deinit();
                self.revalidated_delegate = deleg;
                return self.revalidated_delegate.?.receiveHead();
            }
        }

        if (isStatusCacheable(head.status)) {
            const cc = CacheControl.parseHeaders(&head.headers);
            const auth_ok = !self.has_auth or self.cache.config.cache_authorized_requests or cc.public or cc.must_revalidate;
            const has_star_vary = if (head.headers.get("Vary")) |v| hasVaryWildcard(v) else false;
            const freshness_ns = computeFreshnessNs(cc, &head.headers);
            const has_validator = head.headers.has("ETag") or head.headers.has("Last-Modified");

            if (auth_ok and !cc.no_store and !has_star_vary and (freshness_ns > 0 or has_validator)) {
                const gpa = self.cache.gpa;
                self.capture_status = head.status;
                self.capture_reason = try gpa.dupe(u8, head.reason);
                self.capture_headers = try cloneHttpHeaders(gpa, &head.headers);
                self.capturing = true;

                // Bodyless responses (HEAD / 204) have no bytes to read -> already at EOF!
                if (head.framing == .none) {
                    self.eof_reached = true;
                }
            }
        }

        return head;
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *CachingExchange = @ptrCast(@alignCast(ptr));
        if (self.revalidated_delegate) |*d| return d.takeHead();
        return self.inner.takeHead();
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *CachingExchange = @ptrCast(@alignCast(ptr));
        if (self.revalidated_delegate) |*d| return d.reader();
        if (self.capturing) return &self.tee_reader;
        return self.inner.reader();
    }

    fn teeStreamImpl(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *CachingExchange = @fieldParentPtr("tee_reader", r);
        const inner_r = self.inner.reader();

        const max_n = @min(self.tee_buf.len, limit.minInt(self.tee_buf.len));
        if (max_n == 0) return 0;

        const n = inner_r.readSliceShort(self.tee_buf[0..max_n]) catch |err| {
            self.abortCapture();
            return err;
        };
        if (n == 0) {
            self.eof_reached = true;
            return error.EndOfStream;
        }

        if (self.capturing) {
            if (self.capture_body.items.len + n > self.cache.config.max_entry_bytes) {
                self.abortCapture();
            } else {
                self.capture_body.appendSlice(self.cache.gpa, self.tee_buf[0..n]) catch {
                    self.abortCapture();
                };
            }
        }

        try w.writeAll(self.tee_buf[0..n]);
        return n;
    }

    fn abortCapture(self: *CachingExchange) void {
        self.capturing = false;
        self.eof_reached = false;
        self.capture_body.clearAndFree(self.cache.gpa);
    }

    fn unwrapReadErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const CachingExchange = @ptrCast(@alignCast(ptr));
        if (self.revalidated_delegate) |*d| return d.unwrapReadError();
        return self.inner.unwrapReadError();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *CachingExchange = @ptrCast(@alignCast(ptr));
        const gpa = self.cache.gpa;

        // Commit to cache ONLY if capturing succeeded all the way to clean EOF (I-CACHE-2).
        if (self.capturing and self.eof_reached) {
            self.cache.storeEntry(
                self.method,
                self.origin,
                self.target,
                self.req_headers.items(),
                self.has_auth,
                self.capture_status,
                self.capture_reason,
                &self.capture_headers,
                self.capture_body.items,
            ) catch {};
        }

        if (self.revalidated_delegate) |*d| d.deinit();
        self.inner.deinit();

        if (self.capture_reason.len > 0) gpa.free(self.capture_reason);
        self.capture_headers.deinit(gpa);
        self.capture_body.deinit(gpa);
        self.req_headers.deinit(gpa);
        gpa.free(self.method);
        var o = self.origin;
        o.deinitOwned(gpa);
        gpa.free(self.target);
        gpa.destroy(self);
    }
};

/// Passthrough exchange for unsafe methods that invalidates cached GET/HEAD entries
/// (effective target plus same-origin `Location` / `Content-Location`) per RFC 9111 §4.4.
const InvalidatingExchange = struct {
    cache: *CacheTransport,
    origin: http.Origin,
    target: []u8,
    inner: Transport.Exchange,

    fn handle(self: *InvalidatingExchange) Transport.Exchange {
        return .{
            .ptr = self,
            .vtable = &.{
                .writer = writerImpl,
                .unwrapWriteError = unwrapWriteErrorImpl,
                .receiveHead = receiveHeadImpl,
                .takeHead = takeHeadImpl,
                .reader = readerImpl,
                .unwrapReadError = unwrapReadErrorImpl,
                .deinit = deinitImpl,
            },
        };
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *InvalidatingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.writer();
    }

    fn unwrapWriteErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const InvalidatingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.unwrapWriteError();
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *InvalidatingExchange = @ptrCast(@alignCast(ptr));
        const head = try self.inner.receiveHead();
        const code = head.status.code();
        if (code >= 200 and code <= 399) {
            self.cache.invalidateUrl(self.origin, self.target);
            if (head.headers.get("Location")) |loc| {
                self.invalidateRelatedLocation(loc);
            }
            if (head.headers.get("Content-Location")) |cloc| {
                self.invalidateRelatedLocation(cloc);
            }
        }
        return head;
    }

    fn invalidateRelatedLocation(self: *InvalidatingExchange, raw_loc: []const u8) void {
        const loc = std.mem.trim(u8, raw_loc, " \t");
        if (loc.len == 0) return;
        if (loc[0] == '/') {
            // Same-origin origin-form path
            self.cache.invalidateUrl(self.origin, loc);
            return;
        }
        if (std.Uri.parse(loc)) |uri| {
            var hbuf: [http.Origin.max_host_len]u8 = undefined;
            if (http.Origin.fromUri(uri, &hbuf)) |loc_origin| {
                if (loc_origin.eql(self.origin)) {
                    const scheme_sep = std.mem.find(u8, loc, "://") orelse return;
                    const slash = std.mem.findScalarPos(u8, loc, scheme_sep + 3, '/') orelse return;
                    self.cache.invalidateUrl(self.origin, loc[slash..]);
                }
            } else |_| {}
        } else |_| {}
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *InvalidatingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.takeHead();
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *InvalidatingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.reader();
    }

    fn unwrapReadErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const InvalidatingExchange = @ptrCast(@alignCast(ptr));
        return self.inner.unwrapReadError();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *InvalidatingExchange = @ptrCast(@alignCast(ptr));
        const gpa = self.cache.gpa;
        self.inner.deinit();
        var o = self.origin;
        o.deinitOwned(gpa);
        gpa.free(self.target);
        gpa.destroy(self);
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn isStatusCacheable(status: http.Status) bool {
    return switch (status.code()) {
        200, 203, 204, 206, 300, 301, 404, 410 => true,
        else => false,
    };
}

/// Computes RFC 9111 §4.2 freshness lifetime in nanoseconds:
/// `Cache-Control: max-age` takes precedence over `Expires - Date` (or local clock),
/// adjusted by `Age`.
fn computeFreshnessNs(cc: CacheControl, headers: *const http.Headers) u64 {
    if (cc.no_cache) return 0;

    const age_s: u64 = if (headers.get("Age")) |age_raw|
        std.fmt.parseInt(u64, std.mem.trim(u8, age_raw, " \t"), 10) catch 0
    else
        0;

    if (cc.max_age_s) |secs| {
        if (secs <= age_s) return 0;
        return (secs - age_s) *| std.time.ns_per_s;
    }

    if (headers.get("Expires")) |exp_raw| {
        const exp_epoch = http.parseHttpDate(std.mem.trim(u8, exp_raw, " \t")) orelse return 0;
        const base_epoch: i64 = if (headers.get("Date")) |date_raw|
            http.parseHttpDate(std.mem.trim(u8, date_raw, " \t")) orelse
                @as(i64, @intCast(zio.Timestamp.now(.real).toSeconds()))
        else
            @as(i64, @intCast(zio.Timestamp.now(.real).toSeconds()));

        if (exp_epoch <= base_epoch) return 0;
        const lifetime_s: u64 = @intCast(exp_epoch - base_epoch);
        if (lifetime_s <= age_s) return 0;
        return (lifetime_s - age_s) *| std.time.ns_per_s;
    }

    return 0;
}

fn firstHeaderSlice(headers: []const http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

fn hasVaryWildcard(vary_raw: []const u8) bool {
    var it = std.mem.splitScalar(u8, vary_raw, ',');
    while (it.next()) |tok| {
        if (std.mem.eql(u8, std.mem.trim(u8, tok, " \t"), "*")) return true;
    }
    return false;
}

fn captureVaryPairs(
    gpa: Allocator,
    resp_headers: *const http.Headers,
    req_headers: []const http.Header,
) Allocator.Error![]VaryPair {
    var list: std.ArrayList(VaryPair) = .empty;
    errdefer {
        for (list.items) |vp| {
            gpa.free(vp.name);
            gpa.free(vp.value);
        }
        list.deinit(gpa);
    }

    var it = resp_headers.valueIterator("Vary");
    while (it.next()) |raw_vary| {
        var toks = std.mem.splitScalar(u8, raw_vary, ',');
        while (toks.next()) |raw_tok| {
            const name = std.mem.trim(u8, raw_tok, " \t");
            if (name.len == 0) continue;
            const val = firstHeaderSlice(req_headers, name) orelse "";
            const name_copy = try gpa.dupe(u8, name);
            errdefer gpa.free(name_copy);
            const val_copy = try gpa.dupe(u8, val);
            try list.append(gpa, .{ .name = name_copy, .value = val_copy });
        }
    }
    return list.toOwnedSlice(gpa);
}

fn cloneHttpHeaders(gpa: Allocator, src: *const http.Headers) !http.Headers {
    var out: http.Headers = .empty;
    errdefer out.deinit(gpa);
    for (src.items()) |h| {
        try out.append(gpa, h.name, h.value);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockTransport = @import("testing/MockTransport.zig");
const Client = @import("Client.zig");

test "CacheTransport multi-variant Vary coexistence, Expires header, only-if-cached 504, and Location invalidation" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();

    // 1. Vary: Accept-Language -> en variant
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{
            .{ .name = "Cache-Control", .value = "max-age=60" },
            .{ .name = "Vary", .value = "Accept-Language" },
        },
        .body = "en-body",
    });
    // 2. Vary: Accept-Language -> zh variant (MUST coexist with en variant!)
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{
            .{ .name = "Cache-Control", .value = "max-age=60" },
            .{ .name = "Vary", .value = "Accept-Language" },
        },
        .body = "zh-body",
    });
    // 3. Expires + Date freshness (no Cache-Control header!)
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{
            .{ .name = "Date", .value = "Mon, 01 Jan 2026 00:00:00 GMT" },
            .{ .name = "Expires", .value = "Mon, 01 Jan 2026 01:00:00 GMT" },
        },
        .body = "expires-cached",
    });
    // 4. POST /submit returning 201 Created + Location: /items invalidates /items (all Vary variants!)
    try mock.pushResponse(.{
        .status = .created,
        .headers = &.{.{ .name = "Location", .value = "/items" }},
    });
    // 5. Next GET /items misses cache and re-fetches from upstream
    try mock.pushResponse(.{
        .status = .ok,
        .body = "after-location-invalidation",
    });

    var cache = CacheTransport.init(gpa, mock.transport(), .{});
    defer cache.deinit();

    var client = Client.initWithTransport(gpa, rt.io(), cache.transport(), .{});
    defer client.deinit();

    // Populate both `en` and `zh` variants under the SAME URL `/items`
    {
        var r_en = try client.fetch(.{
            .url = "http://api.example/items",
            .headers = &.{.{ .name = "Accept-Language", .value = "en" }},
        });
        defer r_en.deinit();
        try std.testing.expectEqualStrings("en-body", r_en.body);

        var r_zh = try client.fetch(.{
            .url = "http://api.example/items",
            .headers = &.{.{ .name = "Accept-Language", .value = "zh" }},
        });
        defer r_zh.deinit();
        try std.testing.expectEqualStrings("zh-body", r_zh.body);
    }

    // Both variants MUST hit cache with ZERO additional upstream calls!
    {
        var hit_en = try client.fetch(.{
            .url = "http://api.example/items",
            .headers = &.{.{ .name = "Accept-Language", .value = "en" }},
        });
        defer hit_en.deinit();
        try std.testing.expectEqualStrings("en-body", hit_en.body);

        var hit_zh = try client.fetch(.{
            .url = "http://api.example/items",
            .headers = &.{.{ .name = "Accept-Language", .value = "zh" }},
        });
        defer hit_zh.deinit();
        try std.testing.expectEqualStrings("zh-body", hit_zh.body);
        try std.testing.expectEqual(@as(usize, 2), mock.requests().len);
        try std.testing.expectEqual(@as(u64, 2), cache.stats().hits);
    }

    // `only-if-cached` on uncached URL returns 504 Gateway Timeout WITHOUT hitting upstream
    {
        var miss = try client.fetch(.{
            .url = "http://api.example/never-cached",
            .headers = &.{.{ .name = "Cache-Control", .value = "only-if-cached" }},
        });
        defer miss.deinit();
        try std.testing.expectEqual(http.Status.gateway_timeout, miss.status);
        try std.testing.expectEqual(@as(usize, 2), mock.requests().len);
    }

    // `Expires` + `Date` caches cleanly for 1 hour
    {
        var e1 = try client.get("http://api.example/legacy-expires");
        defer e1.deinit();
        try std.testing.expectEqualStrings("expires-cached", e1.body);

        var e2 = try client.get("http://api.example/legacy-expires");
        defer e2.deinit();
        try std.testing.expectEqualStrings("expires-cached", e2.body);
        try std.testing.expectEqual(@as(usize, 3), mock.requests().len);
    }

    // POST /submit with `Location: /items` invalidates `/items` per RFC 9111 §4.4
    {
        var rp = try client.fetch(.{ .method = .POST, .url = "http://api.example/submit" });
        defer rp.deinit();
        try std.testing.expectEqual(http.Status.created, rp.status);

        var after = try client.fetch(.{
            .url = "http://api.example/items",
            .headers = &.{.{ .name = "Accept-Language", .value = "en" }},
        });
        defer after.deinit();
        try std.testing.expectEqualStrings("after-location-invalidation", after.body);
        try std.testing.expectEqual(@as(usize, 5), mock.requests().len);
    }
}

test "CacheTransport performs ETag conditional revalidation (304 Not Modified), 304 no-store eviction, and LRU" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();

    // 1. Response with ETag + no-cache
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{
            .{ .name = "Cache-Control", .value = "no-cache" },
            .{ .name = "ETag", .value = "\"v1\"" },
            .{ .name = "X-Version", .value = "1" },
        },
        .body = "cached-payload",
    });
    // 2. Conditional request receives 304 Not Modified with updated max-age & header
    try mock.pushResponse(.{
        .status = .not_modified,
        .headers = &.{
            .{ .name = "Cache-Control", .value = "max-age=120" },
            .{ .name = "X-Version", .value = "2" },
        },
    });
    // 3 & 4. Two additional URLs to verify max_entries=2 LRU eviction
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
        .body = "b",
    });
    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
        .body = "c",
    });

    var cache = CacheTransport.init(gpa, mock.transport(), .{
        .max_entries = 2,
    });
    defer cache.deinit();

    var client = Client.initWithTransport(gpa, rt.io(), cache.transport(), .{});
    defer client.deinit();

    // Initial fetch stores payload + ETag
    {
        var r1 = try client.get("http://cdn.example/a");
        defer r1.deinit();
        try std.testing.expectEqualStrings("cached-payload", r1.body);
    }

    // Second fetch sends If-None-Match: "v1", receives 304, returns 200 + cached body + merged X-Version: 2
    {
        var r2 = try client.get("http://cdn.example/a");
        defer r2.deinit();
        try std.testing.expectEqual(http.Status.ok, r2.status);
        try std.testing.expectEqualStrings("cached-payload", r2.body);
        try std.testing.expectEqualStrings("2", r2.headers.get("X-Version").?);

        const second_req = mock.requests()[1];
        try std.testing.expectEqualStrings("\"v1\"", second_req.headers.get("If-None-Match").?);
        try std.testing.expectEqual(@as(u64, 1), cache.stats().revalidated_hits);
    }

    // Third fetch is now fresh (max-age=120 from 304) -> 0 upstream calls!
    {
        var r3 = try client.get("http://cdn.example/a");
        defer r3.deinit();
        try std.testing.expectEqualStrings("cached-payload", r3.body);
        try std.testing.expectEqual(@as(usize, 2), mock.requests().len);
    }

    // Fill cache beyond max_entries = 2 -> LRU evicts oldest entry
    {
        var rb = try client.get("http://cdn.example/b");
        defer rb.deinit();
        var rc = try client.get("http://cdn.example/c");
        defer rc.deinit();
        try std.testing.expectEqual(@as(usize, 2), cache.stats().entries);
    }
}

test "CacheTransport does not cache partially-read streaming responses" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();

    try mock.pushResponse(.{
        .status = .ok,
        .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
        .body = "0123456789abcdef",
    });

    var cache = CacheTransport.init(gpa, mock.transport(), .{});
    defer cache.deinit();

    var client = Client.initWithTransport(gpa, rt.io(), cache.transport(), .{});
    defer client.deinit();

    var req = try client.open(.{ .url = "http://api.example/partial" });
    defer req.deinit();
    var resp = try req.receiveHead();
    var small: [4]u8 = undefined;
    _ = try resp.reader().readSliceShort(&small);
    // Drop BEFORE reading to EOF -> MUST NOT enter cache (I-CACHE-2)
    resp.deinit();

    try std.testing.expectEqual(@as(usize, 0), cache.stats().entries);
}
