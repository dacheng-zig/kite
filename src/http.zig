//! Core HTTP/1.1 domain value types and RFC 9110/9112 invariants.
//!
//! Zero socket and zero zio dependencies: every type here is pure value/memory
//! logic that can be tested deterministically in isolation.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

/// HTTP request method with RFC 9110 §9.2 semantics.
/// Supports all standard methods (`.GET`, `.POST`, `.QUERY`, ...) plus arbitrary
/// RFC 9110 extension methods via `.custom("PURGE")`.
pub const Method = struct {
    raw: []const u8,

    pub const GET: Method = .{ .raw = "GET" };
    pub const HEAD: Method = .{ .raw = "HEAD" };
    pub const POST: Method = .{ .raw = "POST" };
    pub const PUT: Method = .{ .raw = "PUT" };
    pub const DELETE: Method = .{ .raw = "DELETE" };
    pub const CONNECT: Method = .{ .raw = "CONNECT" };
    pub const OPTIONS: Method = .{ .raw = "OPTIONS" };
    pub const TRACE: Method = .{ .raw = "TRACE" };
    pub const PATCH: Method = .{ .raw = "PATCH" };
    pub const QUERY: Method = .{ .raw = "QUERY" };

    /// Constructs a custom HTTP method (e.g. `.custom("PURGE")`, `.custom("PROPFIND")`).
    /// Validated as an RFC 9110 token when serialized by `h1.writeRequestHead`.
    pub fn custom(raw_name: []const u8) Method {
        return .{ .raw = raw_name };
    }

    const parse_map = std.StaticStringMap(Method).initComptime(.{
        .{ "GET", GET },
        .{ "HEAD", HEAD },
        .{ "POST", POST },
        .{ "PUT", PUT },
        .{ "DELETE", DELETE },
        .{ "CONNECT", CONNECT },
        .{ "OPTIONS", OPTIONS },
        .{ "TRACE", TRACE },
        .{ "PATCH", PATCH },
        .{ "QUERY", QUERY },
    });

    pub fn name(self: Method) []const u8 {
        return self.raw;
    }

    pub fn parse(raw_name: []const u8) ?Method {
        return parse_map.get(raw_name);
    }

    /// Parses either a standard method or any valid RFC 9110 token as a custom method.
    pub fn parseAny(raw_name: []const u8) ?Method {
        if (parse_map.get(raw_name)) |m| return m;
        validateHeaderName(raw_name) catch return null;
        return .{ .raw = raw_name };
    }

    pub fn eql(self: Method, other: Method) bool {
        return std.mem.eql(u8, self.raw, other.raw);
    }

    /// RFC 9110 §9.2.1: Request methods are considered "safe" if their defined
    /// semantics are essentially read-only.
    pub fn isSafe(self: Method) bool {
        return self.eql(GET) or self.eql(HEAD) or self.eql(OPTIONS) or self.eql(TRACE) or self.eql(QUERY);
    }

    /// RFC 9110 §9.2.2: A request method is idempotent if multiple identical
    /// requests have the same intended effect on the server as a single request.
    /// Governs whether retrying on a stale pooled connection is allowed.
    pub fn isIdempotent(self: Method) bool {
        return self.isSafe() or self.eql(PUT) or self.eql(DELETE);
    }

    /// RFC 9112 §6.3: Any response to a HEAD request never has a message body.
    pub fn forbidsResponseBody(self: Method) bool {
        return self.eql(HEAD);
    }

    /// True for standard methods where HTTP/1.1 servers/proxies expect an explicit
    /// `Content-Length: 0` when the request carries an empty body.
    pub fn expectsContentLengthZero(self: Method) bool {
        return self.eql(POST) or self.eql(PUT) or self.eql(PATCH) or self.eql(QUERY);
    }
};

/// HTTP status code (RFC 9110 §15). Open enum allows non-standard 3-digit codes.
pub const Status = enum(u16) {
    @"continue" = 100,
    switching_protocols = 101,
    early_hints = 103,

    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,

    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    temporary_redirect = 307,
    permanent_redirect = 308,

    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    content_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    unprocessable_content = 422,
    too_many_requests = 429,

    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,

    _,

    pub fn fromInt(raw: u16) error{InvalidStatusCode}!Status {
        // RFC 9112 §4: status-code is a 3-digit integer (100..=999).
        if (raw < 100 or raw > 999) return error.InvalidStatusCode;
        return @fromBackingInt(raw);
    }

    pub fn code(self: Status) u16 {
        return @backingInt(self);
    }

    pub fn isInformational(self: Status) bool {
        const c = self.code();
        return c >= 100 and c <= 199;
    }

    pub fn isSuccess(self: Status) bool {
        const c = self.code();
        return c >= 200 and c <= 299;
    }

    /// True for status codes that instruct an automatic Location redirect
    /// (distinct from 304 Not Modified or 300 Multiple Choices).
    pub fn isRedirect(self: Status) bool {
        return switch (self) {
            .moved_permanently,
            .found,
            .see_other,
            .temporary_redirect,
            .permanent_redirect,
            => true,
            else => false,
        };
    }

    /// RFC 9112 §6.3: 1xx, 204, and 304 responses must not contain a message body.
    pub fn forbidsResponseBody(self: Status) bool {
        return self.isInformational() or self == .no_content or self == .not_modified;
    }

    pub fn reasonPhrase(self: Status) []const u8 {
        return switch (self) {
            .@"continue" => "Continue",
            .switching_protocols => "Switching Protocols",
            .early_hints => "Early Hints",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .content_too_large => "Content Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .unprocessable_content => "Unprocessable Content",
            .too_many_requests => "Too Many Requests",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            _ => "",
        };
    }
};

pub const Scheme = enum {
    http,
    https,

    pub fn defaultPort(self: Scheme) u16 {
        return switch (self) {
            .http => 80,
            .https => 443,
        };
    }

    pub fn parse(raw: []const u8) error{UnsupportedScheme}!Scheme {
        if (std.ascii.eqlIgnoreCase(raw, "http")) return .http;
        if (std.ascii.eqlIgnoreCase(raw, "https")) return .https;
        return error.UnsupportedScheme;
    }
};

/// Normalized communication & security boundary: `(scheme, host, effective_port)`.
///
/// Used as the authoritative key for both connection pooling and
/// cross-origin credential stripping during redirects.
///
/// `host` is stored without brackets for IPv6 literals (e.g. `::1`) and
/// compared/hashed case-insensitively on ASCII.
pub const Origin = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,

    /// Maximum host length we accept into a stack/fixed decode buffer.
    pub const max_host_len = std.Io.net.HostName.max_len;

    pub const ParseError = error{
        UnsupportedScheme,
        MissingHost,
        InvalidHost,
        HostTooLong,
    };

    /// Extracts and validates an `Origin` from a parsed `std.Uri`.
    /// Returned `host` may slice into either `uri` or `host_buf`.
    pub fn fromUri(uri: std.Uri, host_buf: *[max_host_len]u8) ParseError!Origin {
        const scheme = try Scheme.parse(uri.scheme);
        const component = uri.host orelse return error.MissingHost;
        const raw_host = component.toRaw(host_buf) catch |err| switch (err) {
            error.NoSpaceLeft => return error.HostTooLong,
        };
        if (raw_host.len == 0) return error.MissingHost;

        const host = stripIpv6Brackets(raw_host);
        try validateHost(host);

        return .{
            .scheme = scheme,
            .host = host,
            .port = uri.port orelse scheme.defaultPort(),
        };
    }

    /// Allocates an owned copy of `host` normalized to ASCII lowercase.
    pub fn dupeOwned(self: Origin, gpa: Allocator) Allocator.Error!Origin {
        const lowered = try gpa.alloc(u8, self.host.len);
        for (self.host, 0..) |c, i| {
            lowered[i] = std.ascii.toLower(c);
        }
        return .{
            .scheme = self.scheme,
            .host = lowered,
            .port = self.port,
        };
    }

    pub fn deinitOwned(self: *Origin, gpa: Allocator) void {
        gpa.free(self.host);
        self.* = undefined;
    }

    pub fn isIpv6(self: Origin) bool {
        return std.mem.findScalar(u8, self.host, ':') != null;
    }

    /// Two Origins are equal iff scheme, ASCII-lowercased host, and effective port match.
    pub fn eql(a: Origin, b: Origin) bool {
        return a.scheme == b.scheme and
            a.port == b.port and
            std.ascii.eqlIgnoreCase(a.host, b.host);
    }

    /// Case-insensitive hash consistent with `eql`, ready for HashMap keying.
    pub fn hash(self: Origin) u64 {
        var hasher = std.hash.Wyhash.init(0);
        const tag: u8 = @backingInt(self.scheme);
        hasher.update(&.{tag});
        hasher.update(std.mem.asBytes(&self.port));
        var lower_buf: [64]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.host.len) {
            const chunk_len = @min(lower_buf.len, self.host.len - offset);
            for (self.host[offset..][0..chunk_len], 0..) |c, i| {
                lower_buf[i] = std.ascii.toLower(c);
            }
            hasher.update(lower_buf[0..chunk_len]);
            offset += chunk_len;
        }
        return hasher.final();
    }

    /// Writes the canonical HTTP/1.1 `Host` header value (RFC 9110 §7.2):
    /// wraps IPv6 literals in `[...]`, omits default port (80 / 443).
    pub fn writeHostHeader(self: Origin, w: *Writer) Writer.Error!void {
        if (self.isIpv6()) {
            try w.writeByte('[');
            try w.writeAll(self.host);
            try w.writeByte(']');
        } else {
            try w.writeAll(self.host);
        }
        if (self.port != self.scheme.defaultPort()) {
            try w.print(":{d}", .{self.port});
        }
    }

    fn stripIpv6Brackets(raw: []const u8) []const u8 {
        if (raw.len >= 2 and raw[0] == '[' and raw[raw.len - 1] == ']') {
            return raw[1 .. raw.len - 1];
        }
        return raw;
    }

    fn validateHost(host: []const u8) ParseError!void {
        if (host.len == 0) return error.MissingHost;
        if (std.mem.findScalar(u8, host, ':') != null) {
            _ = std.Io.net.IpAddress.parseIp6(host, 0) catch return error.InvalidHost;
            return;
        }
        std.Io.net.HostName.validate(host) catch |err| switch (err) {
            error.NameTooLong => return error.HostTooLong,
            error.InvalidHostName => return error.InvalidHost,
        };
    }
};

/// A single HTTP header name/value pair.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HeaderError = error{
    InvalidHeaderName,
    InvalidHeaderValue,
};

/// Validates an HTTP header field-name against RFC 9110 §5.6.2 (`1*tchar`).
/// Rejects empty names, whitespace, `:`, CR/LF, NUL, and non-token characters.
pub fn validateHeaderName(name: []const u8) HeaderError!void {
    if (name.len == 0) return error.InvalidHeaderName;
    for (name) |c| {
        if (!isTokenChar(c)) return error.InvalidHeaderName;
    }
}

/// Validates an HTTP header field-value against RFC 9110 §5.5.
/// Strictly rejects CR (`\r`), LF (`\n`), NUL (`\x00`), and control characters
/// to prevent CRLF header injection.
pub fn validateHeaderValue(value: []const u8) HeaderError!void {
    for (value) |c| {
        const valid = (c >= 0x20 and c <= 0x7E) or c == '\t' or c >= 0x80;
        if (!valid) return error.InvalidHeaderValue;
    }
}

/// RFC 9110 §5.6.2 token character (`tchar`).
pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// Owned, order-preserving, multi-value HTTP header collection.
///
/// Design choices:
/// - Preserves duplicate field names (never naively comma-joins `Set-Cookie`).
/// - Lookups and removals are ASCII case-insensitive per RFC 9110 §5.1.
/// - Every `append`/`set` validates name & value upfront (CRLF injection defense) and
///   duplicates strings via the provided `Allocator`, so callers need not keep
///   source buffers alive after mutation.
pub const Headers = struct {
    list: std.ArrayList(Header) = .empty,

    pub const empty: Headers = .{};

    pub fn deinit(self: *Headers, gpa: Allocator) void {
        for (self.list.items) |h| {
            gpa.free(h.name);
            gpa.free(h.value);
        }
        self.list.deinit(gpa);
        self.* = .empty;
    }

    pub fn items(self: *const Headers) []const Header {
        return self.list.items;
    }

    pub fn len(self: *const Headers) usize {
        return self.list.items.len;
    }

    /// Appends a new header entry without removing existing entries of the same name.
    pub fn append(self: *Headers, gpa: Allocator, name: []const u8, value: []const u8) (Allocator.Error || HeaderError)!void {
        try validateHeaderName(name);
        try validateHeaderValue(value);

        const owned_name = try gpa.dupe(u8, name);
        errdefer gpa.free(owned_name);
        const owned_value = try gpa.dupe(u8, value);
        errdefer gpa.free(owned_value);

        try self.list.append(gpa, .{
            .name = owned_name,
            .value = owned_value,
        });
    }

    /// Replaces all existing entries matching `name` (case-insensitive) with a single entry.
    pub fn set(self: *Headers, gpa: Allocator, name: []const u8, value: []const u8) (Allocator.Error || HeaderError)!void {
        try validateHeaderName(name);
        try validateHeaderValue(value);

        // Allocate before mutating so OOM leaves existing headers untouched.
        const owned_name = try gpa.dupe(u8, name);
        errdefer gpa.free(owned_name);
        const owned_value = try gpa.dupe(u8, value);
        errdefer gpa.free(owned_value);
        try self.list.ensureUnusedCapacity(gpa, 1);

        _ = self.removeAll(gpa, name);
        self.list.appendAssumeCapacity(.{
            .name = owned_name,
            .value = owned_value,
        });
    }

    /// Removes all entries matching `name` (case-insensitive). Returns count removed.
    pub fn removeAll(self: *Headers, gpa: Allocator, name: []const u8) usize {
        var write_idx: usize = 0;
        var removed: usize = 0;
        for (self.list.items) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) {
                gpa.free(h.name);
                gpa.free(h.value);
                removed += 1;
            } else {
                self.list.items[write_idx] = h;
                write_idx += 1;
            }
        }
        self.list.items.len = write_idx;
        return removed;
    }

    /// Returns the first value matching `name` (case-insensitive), or `null`.
    pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
        for (self.list.items) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn has(self: *const Headers, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Iterates over all values for a given header name (case-insensitive),
    /// preserving insertion order (essential for `Set-Cookie` and duplicate `Content-Length`).
    pub fn valueIterator(self: *const Headers, name: []const u8) ValueIterator {
        return .{
            .items = self.list.items,
            .name = name,
            .index = 0,
        };
    }

    pub const ValueIterator = struct {
        items: []const Header,
        name: []const u8,
        index: usize,

        pub fn next(self: *ValueIterator) ?[]const u8 {
            while (self.index < self.items.len) {
                const h = self.items[self.index];
                self.index += 1;
                if (std.ascii.eqlIgnoreCase(h.name, self.name)) {
                    return h.value;
                }
            }
            return null;
        }
    };
};

/// Parses HTTP-date formats (RFC 9110 §5.6.7 & RFC 6265 §5.1.1) into Unix epoch seconds:
/// - IMF-fixdate: `"Sun, 06 Nov 1994 08:49:37 GMT"`
/// - Netscape / RFC 850 hyphenated (4-digit or 2-digit year):
///   `"Sun, 06-Nov-1994 08:49:37 GMT"` / `"Sunday, 06-Nov-94 08:49:37 GMT"`
/// - ANSI C `asctime()`: `"Sun Nov  6 08:49:37 1994"`
pub fn parseHttpDate(raw: []const u8) ?i64 {
    const s = std.mem.trim(u8, raw, " \t");
    if (parseImfFixdate(s)) |ts| return ts;

    // Netscape / RFC 850: "<day-name>, DD-Mon-YYYY HH:MM:SS GMT" or "...-YY ..."
    if (std.mem.find(u8, s, ", ")) |comma| {
        const rest = s[comma + 2 ..];
        // "06-Nov-1994 08:49:37 GMT" (24 bytes) or "06-Nov-94 08:49:37 GMT" (22 bytes)
        if (rest.len == 24 and rest[2] == '-' and rest[6] == '-' and rest[11] == ' ' and
            rest[14] == ':' and rest[17] == ':' and rest[20] == ' ' and
            std.mem.eql(u8, rest[21..24], "GMT"))
        {
            return buildEpoch(
                rest[0..2],
                rest[3..6],
                rest[7..11],
                rest[12..14],
                rest[15..17],
                rest[18..20],
            );
        }
        if (rest.len == 22 and rest[2] == '-' and rest[6] == '-' and rest[9] == ' ' and
            rest[12] == ':' and rest[15] == ':' and rest[18] == ' ' and
            std.mem.eql(u8, rest[19..22], "GMT"))
        {
            const yy = std.fmt.parseInt(u16, rest[7..9], 10) catch return null;
            const full_year: u16 = if (yy >= 70) 1900 + yy else 2000 + yy;
            return buildEpochYear(
                rest[0..2],
                rest[3..6],
                full_year,
                rest[10..12],
                rest[13..15],
                rest[16..18],
            );
        }
    }

    // ANSI C asctime(): "Sun Nov  6 08:49:37 1994" (24 bytes)
    if (s.len == 24 and s[3] == ' ' and s[7] == ' ' and s[10] == ' ' and
        s[13] == ':' and s[16] == ':' and s[19] == ' ')
    {
        const day_slice = std.mem.trimStart(u8, s[8..10], " ");
        return buildEpoch(
            day_slice,
            s[4..7],
            s[20..24],
            s[11..13],
            s[14..16],
            s[17..19],
        );
    }

    return null;
}

/// Parses RFC 9110 §5.6.7 IMF-fixdate: `"Day, DD Mon YYYY HH:MM:SS GMT"` into Unix seconds.
pub fn parseImfFixdate(s: []const u8) ?i64 {
    if (s.len != 29) return null;
    if (s[3] != ',' or s[4] != ' ' or s[7] != ' ' or s[11] != ' ' or
        s[16] != ' ' or s[19] != ':' or s[22] != ':' or s[25] != ' ')
    {
        return null;
    }
    if (!std.mem.eql(u8, s[26..29], "GMT")) return null;
    return buildEpoch(s[5..7], s[8..11], s[12..16], s[17..19], s[20..22], s[23..25]);
}

fn buildEpoch(
    day_s: []const u8,
    mon_s: []const u8,
    year_s: []const u8,
    hour_s: []const u8,
    min_s: []const u8,
    sec_s: []const u8,
) ?i64 {
    const year = std.fmt.parseInt(u16, year_s, 10) catch return null;
    return buildEpochYear(day_s, mon_s, year, hour_s, min_s, sec_s);
}

fn buildEpochYear(
    day_s: []const u8,
    mon_s: []const u8,
    year: u16,
    hour_s: []const u8,
    min_s: []const u8,
    sec_s: []const u8,
) ?i64 {
    const day = std.fmt.parseInt(u8, day_s, 10) catch return null;
    const month = parseMonth(mon_s) orelse return null;
    const hour = std.fmt.parseInt(u8, hour_s, 10) catch return null;
    const min = std.fmt.parseInt(u8, min_s, 10) catch return null;
    const sec = std.fmt.parseInt(u8, sec_s, 10) catch return null;

    if (year < 1970 or day < 1 or day > daysInMonth(year, month)) return null;
    if (hour > 23 or min > 59 or sec > 60) return null;

    // Howard Hinnant's civil-from-days inverse algorithm (days since 1970-01-01).
    const y: i64 = @as(i64, year) - @as(i64, @intFromBool(month <= 2));
    const era = @divFloor(y, 400);
    const yoe: u64 = @intCast(y - era * 400);
    const m: u64 = month;
    const doy = (153 * (if (m > 2) m - 3 else m + 9) + 2) / 5 + day - 1;
    const doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const days = era * 146097 + @as(i64, @intCast(doe)) - 719468;

    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, min) * 60 + @as(i64, sec);
}

fn parseMonth(mon: []const u8) ?u8 {
    const months = std.StaticStringMap(u8).initComptime(.{
        .{ "Jan", 1 }, .{ "Feb", 2 },  .{ "Mar", 3 },  .{ "Apr", 4 },
        .{ "May", 5 }, .{ "Jun", 6 },  .{ "Jul", 7 },  .{ "Aug", 8 },
        .{ "Sep", 9 }, .{ "Oct", 10 }, .{ "Nov", 11 }, .{ "Dec", 12 },
    });
    return months.get(mon);
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if ((year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)) 29 else 28,
        else => 0,
    };
}

// ===========================================================================
// Unit Tests (zero socket, deterministic, verified under testing.allocator)
// ===========================================================================

test "Method semantics match RFC 9110 §9.2" {
    try std.testing.expect(Method.GET.isSafe());
    try std.testing.expect(Method.GET.isIdempotent());
    try std.testing.expect(!Method.GET.forbidsResponseBody());

    try std.testing.expect(Method.HEAD.isSafe());
    try std.testing.expect(Method.HEAD.isIdempotent());
    try std.testing.expect(Method.HEAD.forbidsResponseBody());

    try std.testing.expect(!Method.PUT.isSafe());
    try std.testing.expect(Method.PUT.isIdempotent());

    try std.testing.expect(!Method.DELETE.isSafe());
    try std.testing.expect(Method.DELETE.isIdempotent());

    try std.testing.expect(!Method.POST.isSafe());
    try std.testing.expect(!Method.POST.isIdempotent());

    try std.testing.expect(!Method.PATCH.isSafe());
    try std.testing.expect(!Method.PATCH.isIdempotent());

    try std.testing.expect(Method.POST.eql(Method.parse("POST").?));
    try std.testing.expectEqual(@as(?Method, null), Method.parse("post"));
    try std.testing.expectEqualStrings("DELETE", Method.DELETE.name());

    const purge = Method.parseAny("PURGE").?;
    try std.testing.expectEqualStrings("PURGE", purge.name());
    try std.testing.expect(!purge.isSafe());
    try std.testing.expect(!purge.isIdempotent());
    try std.testing.expect(purge.eql(.custom("PURGE")));
    try std.testing.expectEqual(@as(?Method, null), Method.parseAny("BAD METHOD"));
    try std.testing.expectEqual(@as(?Method, null), Method.parseAny("BAD\r\nX"));
}

test "parseHttpDate supports IMF-fixdate, RFC 850, Netscape hyphenated, and asctime" {
    const expected: i64 = 784_111_777; // 1994-11-06T08:49:37Z
    try std.testing.expectEqual(expected, parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT").?);
    try std.testing.expectEqual(expected, parseHttpDate("Sun, 06-Nov-1994 08:49:37 GMT").?);
    try std.testing.expectEqual(expected, parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT").?);
    try std.testing.expectEqual(expected, parseHttpDate("Sun Nov  6 08:49:37 1994").?);
    // 2-digit year 00..69 maps to 2000..2069
    try std.testing.expectEqual(
        parseHttpDate("Fri, 01 Jan 2030 00:00:00 GMT").?,
        parseHttpDate("Tuesday, 01-Jan-30 00:00:00 GMT").?,
    );
    try std.testing.expectEqual(@as(?i64, null), parseHttpDate("not-a-date"));
}

test "Status validation, classes, and body-forbidding rules" {
    const ok = try Status.fromInt(200);
    try std.testing.expectEqual(Status.ok, ok);
    try std.testing.expectEqual(@as(u16, 200), ok.code());
    try std.testing.expect(ok.isSuccess());
    try std.testing.expect(!ok.forbidsResponseBody());

    // 1xx, 204, 304 forbid response bodies
    try std.testing.expect((try Status.fromInt(100)).forbidsResponseBody());
    try std.testing.expect((try Status.fromInt(103)).forbidsResponseBody());
    try std.testing.expect(Status.no_content.forbidsResponseBody());
    try std.testing.expect(Status.not_modified.forbidsResponseBody());

    // 304 is NOT an automatic redirect; 301/302/303/307/308 are.
    try std.testing.expect(!Status.not_modified.isRedirect());
    try std.testing.expect(Status.moved_permanently.isRedirect());
    try std.testing.expect(Status.found.isRedirect());
    try std.testing.expect(Status.see_other.isRedirect());
    try std.testing.expect(Status.temporary_redirect.isRedirect());
    try std.testing.expect(Status.permanent_redirect.isRedirect());

    // Non-standard 3-digit codes are preserved via open enum
    const teapot = try Status.fromInt(418);
    try std.testing.expectEqual(@as(u16, 418), teapot.code());
    try std.testing.expectEqualStrings("", teapot.reasonPhrase());

    // Out-of-range codes are rejected
    try std.testing.expectError(error.InvalidStatusCode, Status.fromInt(99));
    try std.testing.expectError(error.InvalidStatusCode, Status.fromInt(1000));
}

test "Origin normalization, equality, hashing, and Host formatting" {
    var buf1: [Origin.max_host_len]u8 = undefined;
    var buf2: [Origin.max_host_len]u8 = undefined;
    var buf3: [Origin.max_host_len]u8 = undefined;

    const uri1 = try std.Uri.parse("http://Example.COM:80/path");
    const uri2 = try std.Uri.parse("HTTP://example.com/other");
    const uri3 = try std.Uri.parse("https://example.com/path");

    const o1 = try Origin.fromUri(uri1, &buf1);
    const o2 = try Origin.fromUri(uri2, &buf2);
    const o3 = try Origin.fromUri(uri3, &buf3);

    // Same scheme, case-insensitive host, default port 80 => same Origin
    try std.testing.expect(o1.eql(o2));
    try std.testing.expectEqual(o1.hash(), o2.hash());

    // http vs https => different Origin (prevents pool mixup & triggers cross-origin credential strip)
    try std.testing.expect(!o1.eql(o3));

    // Host header formatting: omit default port, include non-default port
    var out_buf: [128]u8 = undefined;
    var w: Writer = .fixed(&out_buf);
    try o2.writeHostHeader(&w);
    try std.testing.expectEqualStrings("example.com", w.buffered());

    var buf4: [Origin.max_host_len]u8 = undefined;
    const o4 = try Origin.fromUri(try std.Uri.parse("http://example.com:8080/x"), &buf4);
    w = .fixed(&out_buf);
    try o4.writeHostHeader(&w);
    try std.testing.expectEqualStrings("example.com:8080", w.buffered());

    // IPv6 literal handling: stored without brackets, formatted with brackets
    var buf6: [Origin.max_host_len]u8 = undefined;
    const o6 = try Origin.fromUri(try std.Uri.parse("http://[::1]:8080/"), &buf6);
    try std.testing.expectEqualStrings("::1", o6.host);
    try std.testing.expect(o6.isIpv6());
    w = .fixed(&out_buf);
    try o6.writeHostHeader(&w);
    try std.testing.expectEqualStrings("[::1]:8080", w.buffered());

    // Owned copy lowercases host and frees cleanly
    var owned = try o1.dupeOwned(std.testing.allocator);
    defer owned.deinitOwned(std.testing.allocator);
    try std.testing.expectEqualStrings("example.com", owned.host);
    try std.testing.expect(owned.eql(o1));
}

test "Origin rejects unsupported schemes, missing hosts, and invalid hosts" {
    var buf: [Origin.max_host_len]u8 = undefined;

    try std.testing.expectError(
        error.UnsupportedScheme,
        Origin.fromUri(try std.Uri.parse("ftp://example.com/file"), &buf),
    );
    try std.testing.expectError(
        error.MissingHost,
        Origin.fromUri(try std.Uri.parse("http:///only-path"), &buf),
    );
    try std.testing.expectError(
        error.InvalidHost,
        Origin.fromUri(.{ .scheme = "http", .host = .{ .raw = "bad host" } }, &buf),
    );
    try std.testing.expectError(
        error.InvalidHost,
        Origin.fromUri(.{ .scheme = "http", .host = .{ .raw = "evil.com\r\nX: 1" } }, &buf),
    );
}

test "Headers preserves multi-value order, matches case-insensitively, and blocks CRLF injection" {
    const gpa = std.testing.allocator;
    var headers: Headers = .empty;
    defer headers.deinit(gpa);

    try headers.append(gpa, "Set-Cookie", "a=1; Path=/");
    try headers.append(gpa, "Content-Type", "application/json");
    try headers.append(gpa, "set-cookie", "b=2; HttpOnly");

    // Case-insensitive first lookup
    try std.testing.expectEqualStrings("application/json", headers.get("content-type").?);
    try std.testing.expectEqualStrings("a=1; Path=/", headers.get("SET-COOKIE").?);
    try std.testing.expect(headers.has("Content-Type"));
    try std.testing.expect(!headers.has("Authorization"));

    // Multi-value iteration keeps every Set-Cookie separate and in order
    var it = headers.valueIterator("Set-Cookie");
    try std.testing.expectEqualStrings("a=1; Path=/", it.next().?);
    try std.testing.expectEqualStrings("b=2; HttpOnly", it.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());

    // set() replaces ALL existing occurrences of the same header name
    try headers.set(gpa, "Set-Cookie", "only=one");
    try std.testing.expectEqual(@as(usize, 2), headers.len());
    var it2 = headers.valueIterator("set-cookie");
    try std.testing.expectEqualStrings("only=one", it2.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), it2.next());

    // removeAll() strips all matching entries and preserves remaining order
    try std.testing.expectEqual(@as(usize, 1), headers.removeAll(gpa, "CONTENT-TYPE"));
    try std.testing.expect(!headers.has("Content-Type"));
    try std.testing.expectEqual(@as(usize, 1), headers.len());

    // CRLF injection and illegal header names MUST be rejected upfront
    try std.testing.expectError(error.InvalidHeaderValue, headers.append(gpa, "X-Trace", "ok\r\nEvil: 1"));
    try std.testing.expectError(error.InvalidHeaderValue, headers.append(gpa, "X-Trace", "ok\nEvil: 1"));
    try std.testing.expectError(error.InvalidHeaderValue, headers.append(gpa, "X-Trace", "bad\x00null"));
    try std.testing.expectError(error.InvalidHeaderName, headers.append(gpa, "", "v"));
    try std.testing.expectError(error.InvalidHeaderName, headers.append(gpa, "Bad Name", "v"));
    try std.testing.expectError(error.InvalidHeaderName, headers.append(gpa, "Bad:Name", "v"));
    try std.testing.expectError(error.InvalidHeaderName, headers.append(gpa, "Bad\r\nName", "v"));
}
