//! Single physical TCP/TLS connection with single-allocation pinned buffers.
//!
//! Design choices:
//! - Packs struct state, lowercased host bytes, socket I/O buffers, and TLS
//!   cipher/plaintext buffers into ONE aligned heap allocation (`*Connection`).
//!   This keeps zio coroutine stack frames tiny (protecting the 256 KiB default
//!   stack) and guarantees internal `std.Io.Reader`/`Writer` and
//!   `std.crypto.tls.Client` pointers never dangle due to value moves.
//! - Owns error unwrapping (`unwrapReadError`/`unwrapWriteError`) so callers
//!   and `zio.withTimeout` always recover the real underlying error (`Canceled`,
//!   `ConnectionResetByPeer`, TLS alerts) erased by `std.Io.Reader`/`Writer`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const assert = std.debug.assert;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");

const Connection = @This();

pub const default_read_buffer_size: usize = 8 * 1024;
pub const default_write_buffer_size: usize = 4 * 1024;
pub const tls_buffer_size: usize = tls.Client.min_buffer_len;

/// Thread-safe, lazily-loaded system root CA certificate bundle shared across
/// all HTTPS connections belonging to a `Client` or `Pool`.
pub const CaStore = struct {
    lock: std.Io.RwLock = .init,
    bundle: Certificate.Bundle = .empty,
    loaded: bool = false,

    pub const init: CaStore = .{};

    pub fn deinit(self: *CaStore, gpa: Allocator) void {
        self.bundle.deinit(gpa);
        self.* = .init;
    }

    /// Scans system root certificates once on first HTTPS handshake.
    /// Plain HTTP users never pay certificate scan latency or memory cost.
    pub fn ensureLoaded(self: *CaStore, gpa: Allocator, io: std.Io) !void {
        try self.lock.lockShared(io);
        if (self.loaded) {
            self.lock.unlockShared(io);
            return;
        }
        self.lock.unlockShared(io);

        try self.lock.lock(io);
        defer self.lock.unlock(io);
        if (self.loaded) return;

        const now = std.Io.Clock.real.now(io);
        try self.bundle.rescan(gpa, io, now);
        self.loaded = true;
    }

    /// Forces a fresh rescan of system root certificates (useful for long-running
    /// daemons that need to pick up OS CA bundle rotations without restarting).
    pub fn reloadSystem(self: *CaStore, gpa: Allocator, io: std.Io) !void {
        try self.lock.lock(io);
        defer self.lock.unlock(io);

        const now = std.Io.Clock.real.now(io);
        try self.bundle.rescan(gpa, io, now);
        self.loaded = true;
    }

    /// Loads one or more PEM-encoded X.509 certificates from an in-memory buffer
    /// (e.g. `@embedFile("corp-ca.pem")`) into this CA store.
    pub fn addCertsFromPem(self: *CaStore, gpa: Allocator, io: std.Io, pem_bytes: []const u8) !void {
        try self.lock.lock(io);
        defer self.lock.unlock(io);

        const now_sec = std.Io.Clock.real.now(io).toSeconds();
        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";
        const b64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

        var start_index: usize = 0;
        var added: usize = 0;
        while (std.mem.findPos(u8, pem_bytes, start_index, begin_marker)) |begin_pos| {
            const cert_start = begin_pos + begin_marker.len;
            const cert_end = std.mem.findPos(u8, pem_bytes, cert_start, end_marker) orelse
                return error.MissingEndCertificateMarker;
            start_index = cert_end + end_marker.len;

            const encoded = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");
            const max_decoded = (encoded.len / 4 + 1) * 3;
            try self.bundle.bytes.ensureUnusedCapacity(gpa, max_decoded);

            const decoded_start: u32 = @intCast(self.bundle.bytes.items.len);
            errdefer self.bundle.bytes.items.len = decoded_start;
            const dest = self.bundle.bytes.allocatedSlice()[decoded_start..];
            const decoded_len = try b64.decode(dest, encoded);
            try validateDerSequence(dest[0..decoded_len]);
            self.bundle.bytes.items.len += decoded_len;
            try self.bundle.parseCert(gpa, decoded_start, now_sec);
            added += 1;
        }
        if (added == 0) return error.NoCertificatesFound;
        self.loaded = true;
    }

    /// Minimal ASN.1 DER outer SEQUENCE sanity check before handing bytes to
    /// `std.crypto.Certificate.parse` (guards against panics on truncated DER).
    fn validateDerSequence(der: []const u8) error{InvalidCertificateDer}!void {
        if (der.len < 4 or der[0] != 0x30) return error.InvalidCertificateDer;
        const len_byte = der[1];
        if (len_byte < 0x80) {
            if (2 + @as(usize, len_byte) > der.len) return error.InvalidCertificateDer;
        } else {
            const num_octets = len_byte & 0x7F;
            if (num_octets == 0 or num_octets > 4 or 2 + num_octets >= der.len) {
                return error.InvalidCertificateDer;
            }
            var content_len: usize = 0;
            for (der[2 .. 2 + num_octets]) |b| {
                content_len = (content_len << 8) | b;
            }
            if (2 + num_octets + content_len > der.len) return error.InvalidCertificateDer;
        }
    }

    /// Loads PEM-encoded CA certificates from an absolute file path on disk.
    pub fn addCertsFromFile(self: *CaStore, gpa: Allocator, io: std.Io, abs_file_path: []const u8) !void {
        try self.lock.lock(io);
        defer self.lock.unlock(io);

        const now = std.Io.Clock.real.now(io);
        try self.bundle.addCertsFromFilePathAbsolute(gpa, io, now, abs_file_path);
        self.loaded = true;
    }
};

pub const TlsConfig = union(enum) {
    /// Verify server certificate chain and hostname against lazily-loaded system root CAs.
    system: *CaStore,
    /// Verify server certificate chain and hostname against a caller-populated `CaStore`
    /// (loaded via `addCertsFromPem` / `addCertsFromFile` without scanning system roots).
    custom_ca: *CaStore,
    /// Disable CA and hostname verification. Intended strictly for local testing.
    no_verification,
};

/// Proxy configuration supporting HTTP forward proxies (`http://`), HTTPS
/// TLS-to-proxy (`https://`), and SOCKS5 / SOCKS5h (`socks5://`, `socks5h://`).
///
/// - `http://` / `https://` proxies:
///   - For `http://` targets: sends absolute-form request targets (`GET http://host:port/path HTTP/1.1`),
///     pooled by proxy origin (encrypted with TLS to the proxy when `scheme == .https`).
///   - For `https://` targets: establishes a tunnel via `CONNECT host:port HTTP/1.1`
///     (over plain TCP for `http://` proxy, or over outer TLS for `https://` proxy)
///     and upgrades the tunnel in-place with target TLS.
/// - `socks5://` / `socks5h://` proxies:
///   - Performs RFC 1928 handshake (with optional RFC 1929 username/password auth).
///   - `socks5h://` sends hostnames directly (`ATYP=0x03`) so DNS is resolved by the proxy.
///   - `socks5://` resolves hostnames locally and connects using IP literals.
pub const ProxyConfig = struct {
    pub const Scheme = enum {
        http,
        https,
        socks5,
        socks5h,

        pub fn defaultPort(self: Scheme) u16 {
            return switch (self) {
                .http => 80,
                .https => 443,
                .socks5, .socks5h => 1080,
            };
        }

        pub fn isSocks5(self: Scheme) bool {
            return self == .socks5 or self == .socks5h;
        }

        pub fn parse(raw: []const u8) error{UnsupportedProxyScheme}!Scheme {
            if (std.ascii.eqlIgnoreCase(raw, "http")) return .http;
            if (std.ascii.eqlIgnoreCase(raw, "https")) return .https;
            if (std.ascii.eqlIgnoreCase(raw, "socks5")) return .socks5;
            if (std.ascii.eqlIgnoreCase(raw, "socks5h")) return .socks5h;
            return error.UnsupportedProxyScheme;
        }
    };

    scheme: Scheme = .http,
    host: []const u8,
    port: u16,
    /// Optional `Proxy-Authorization` header value for HTTP/HTTPS proxies (e.g. `"Basic ..."`).
    authorization: ?[]const u8 = null,
    /// Optional RFC 1929 username for SOCKS5/SOCKS5h proxies.
    username: ?[]const u8 = null,
    /// Optional RFC 1929 password for SOCKS5/SOCKS5h proxies.
    password: ?[]const u8 = null,
    /// Optional TLS configuration for `https://` proxy servers (`null` reuses the request's `tls` config).
    tls: ?TlsConfig = null,
    /// Hosts/suffixes that bypass this proxy (supports `*`, exact host, `.suffix`, `host:port`).
    no_proxy: []const []const u8 = &.{},

    /// Heap-owned proxy configuration returned by `ProxyConfig.fromEnv()`.
    pub const Owned = struct {
        scheme: Scheme = .http,
        host: []u8,
        port: u16,
        authorization: ?[]u8 = null,
        username: ?[]u8 = null,
        password: ?[]u8 = null,
        no_proxy_entries: [][]u8 = &.{},

        pub fn config(self: *const Owned) ProxyConfig {
            return .{
                .scheme = self.scheme,
                .host = self.host,
                .port = self.port,
                .authorization = self.authorization,
                .username = self.username,
                .password = self.password,
                .no_proxy = self.no_proxy_entries,
            };
        }

        pub fn deinit(self: *Owned, gpa: Allocator) void {
            gpa.free(self.host);
            if (self.authorization) |a| gpa.free(a);
            if (self.username) |u| gpa.free(u);
            if (self.password) |p| gpa.free(p);
            for (self.no_proxy_entries) |e| gpa.free(e);
            if (self.no_proxy_entries.len > 0) gpa.free(self.no_proxy_entries);
            self.* = undefined;
        }
    };

    /// Parses standard proxy environment variables (`HTTPS_PROXY`/`https_proxy` or
    /// `HTTP_PROXY`/`http_proxy`, plus `ALL_PROXY` and `NO_PROXY`/`no_proxy`) from `env_map`.
    /// Supports `http://`, `https://`, `socks5://`, and `socks5h://` proxy URLs.
    /// Returns `null` if no proxy variable is set for `scheme`.
    pub fn fromEnv(
        gpa: Allocator,
        env_map: *const std.process.Environ.Map,
        scheme: http.Scheme,
    ) !?Owned {
        const raw_url = switch (scheme) {
            .https => env_map.get("HTTPS_PROXY") orelse env_map.get("https_proxy") orelse
                env_map.get("ALL_PROXY") orelse env_map.get("all_proxy"),
            .http => env_map.get("HTTP_PROXY") orelse env_map.get("http_proxy") orelse
                env_map.get("ALL_PROXY") orelse env_map.get("all_proxy"),
            .http_unix => return null,
        } orelse return null;

        const trimmed = std.mem.trim(u8, raw_url, " \t");
        if (trimmed.len == 0) return null;

        // Allow bare "host:port" by prepending "http://".
        var prefixed: ?[]u8 = null;
        defer if (prefixed) |p| gpa.free(p);
        const parse_str = if (std.mem.find(u8, trimmed, "://") == null) blk: {
            prefixed = try gpa.print("http://{s}", .{trimmed});
            break :blk prefixed.?;
        } else trimmed;

        const uri = try std.Uri.parse(parse_str);
        const proxy_scheme = try Scheme.parse(uri.scheme);
        const host_comp = uri.host orelse return error.MissingHost;
        var hbuf: [http.Origin.max_host_len]u8 = undefined;
        const raw_host = host_comp.toRaw(&hbuf) catch return error.HostTooLong;
        const stripped_host = if (raw_host.len >= 2 and raw_host[0] == '[' and raw_host[raw_host.len - 1] == ']')
            raw_host[1 .. raw_host.len - 1]
        else
            raw_host;
        if (stripped_host.len == 0) return error.MissingHost;

        const host_owned = try gpa.alloc(u8, stripped_host.len);
        errdefer gpa.free(host_owned);
        copyLowercase(host_owned, stripped_host);

        const proxy_port = uri.port orelse proxy_scheme.defaultPort();

        var auth_owned: ?[]u8 = null;
        errdefer if (auth_owned) |a| gpa.free(a);
        var user_owned: ?[]u8 = null;
        errdefer if (user_owned) |u| gpa.free(u);
        var pass_owned: ?[]u8 = null;
        errdefer if (pass_owned) |p| gpa.free(p);

        if (uri.user) |user_comp| {
            var ubuf: [256]u8 = undefined;
            var pbuf: [256]u8 = undefined;
            const user = try user_comp.toRaw(&ubuf);
            const pass = if (uri.password) |pc| try pc.toRaw(&pbuf) else "";

            if (proxy_scheme.isSocks5()) {
                user_owned = try gpa.dupe(u8, user);
                pass_owned = try gpa.dupe(u8, pass);
            } else {
                const raw_cred = try gpa.print("{s}:{s}", .{ user, pass });
                defer gpa.free(raw_cred);

                const enc_len = std.base64.standard.Encoder.calcSize(raw_cred.len);
                const auth = try gpa.alloc(u8, "Basic ".len + enc_len);
                @memcpy(auth[0.."Basic ".len], "Basic ");
                _ = std.base64.standard.Encoder.encode(auth["Basic ".len..], raw_cred);
                auth_owned = auth;
            }
        }

        var no_proxy_list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (no_proxy_list.items) |e| gpa.free(e);
            no_proxy_list.deinit(gpa);
        }
        if (env_map.get("NO_PROXY") orelse env_map.get("no_proxy")) |raw_np| {
            var it = std.mem.splitScalar(u8, raw_np, ',');
            while (it.next()) |raw_entry| {
                const entry = std.mem.trim(u8, raw_entry, " \t");
                if (entry.len == 0) continue;
                try no_proxy_list.append(gpa, try gpa.dupe(u8, entry));
            }
        }

        return .{
            .scheme = proxy_scheme,
            .host = host_owned,
            .port = proxy_port,
            .authorization = auth_owned,
            .username = user_owned,
            .password = pass_owned,
            .no_proxy_entries = try no_proxy_list.toOwnedSlice(gpa),
        };
    }

    /// Returns true if `origin` matches any rule in `no_proxy` and should connect directly.
    /// Unix domain socket origins always bypass proxies.
    pub fn bypasses(self: ProxyConfig, target_origin: http.Origin) bool {
        if (target_origin.scheme == .http_unix) return true;
        for (self.no_proxy) |raw_rule| {
            const rule = std.mem.trim(u8, raw_rule, " \t");
            if (rule.len == 0) continue;
            if (std.mem.eql(u8, rule, "*")) return true;

            var rule_host = rule;
            var rule_port: ?u16 = null;
            if (rule[0] == '[') {
                if (std.mem.findScalar(u8, rule, ']')) |end_bracket| {
                    rule_host = rule[1..end_bracket];
                    if (end_bracket + 1 < rule.len and rule[end_bracket + 1] == ':') {
                        rule_port = std.fmt.parseInt(u16, rule[end_bracket + 2 ..], 10) catch continue;
                    }
                }
            } else if (std.mem.findScalarLast(u8, rule, ':')) |colon| {
                if (std.mem.findScalar(u8, rule[0..colon], ':') == null) {
                    rule_host = rule[0..colon];
                    rule_port = std.fmt.parseInt(u16, rule[colon + 1 ..], 10) catch continue;
                }
            }

            if (rule_port) |p| {
                if (p != target_origin.port) continue;
            }

            const suffix = if (rule_host.len > 0 and rule_host[0] == '.') rule_host[1..] else rule_host;
            if (suffix.len == 0) continue;

            if (std.ascii.eqlIgnoreCase(target_origin.host, suffix)) return true;
            if (target_origin.host.len > suffix.len) {
                const prefix_len = target_origin.host.len - suffix.len;
                if (target_origin.host[prefix_len - 1] == '.' and
                    std.ascii.eqlIgnoreCase(target_origin.host[prefix_len..], suffix))
                {
                    return true;
                }
            }
        }
        return false;
    }
};

/// Post-DNS IP address filter hook invoked right before TCP connect.
/// Prevents SSRF and DNS-rebinding attacks by validating resolved IP addresses
/// rather than trusting hostname strings alone.
pub const AddressFilter = struct {
    ctx: ?*anyopaque = null,
    allow: *const fn (ctx: ?*anyopaque, addr: zio.net.IpAddress) bool,
};

/// Returns true if `addr` is loopback, private (RFC 1918 / ULA), link-local
/// (including cloud metadata `169.254.169.254`), CGNAT (`100.64.0.0/10`),
/// unspecified (`0.0.0.0` / `::`), multicast, or an IPv4-mapped IPv6 wrapper
/// of any such address.
pub fn isPrivateOrLoopback(addr: zio.net.IpAddress) bool {
    return switch (addr.getFamily()) {
        .ipv4 => isPrivateIpv4(@bitCast(addr.in.addr)),
        .ipv6 => isPrivateIpv6(addr.in6.addr),
    };
}

/// Ready-to-use `AddressFilter` that blocks loopback, link-local, RFC 1918,
/// CGNAT, ULA, and multicast addresses (SSRF protection for server-side fetches).
pub fn blockPrivateAddresses() AddressFilter {
    const Impl = struct {
        fn allow(_: ?*anyopaque, addr: zio.net.IpAddress) bool {
            return !isPrivateOrLoopback(addr);
        }
    };
    return .{ .allow = Impl.allow };
}

fn isPrivateIpv4(b: [4]u8) bool {
    return b[0] == 0 or // 0.0.0.0/8 (unspecified / current network)
        b[0] == 10 or // 10.0.0.0/8 (RFC 1918)
        b[0] == 127 or // 127.0.0.0/8 (loopback)
        (b[0] == 100 and (b[1] & 0xC0) == 64) or // 100.64.0.0/10 (CGNAT)
        (b[0] == 169 and b[1] == 254) or // 169.254.0.0/16 (link-local / cloud metadata)
        (b[0] == 172 and (b[1] & 0xF0) == 16) or // 172.16.0.0/12 (RFC 1918)
        (b[0] == 192 and b[1] == 168) or // 192.168.0.0/16 (RFC 1918)
        b[0] >= 224; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + broadcast
}

fn isPrivateIpv6(b: [16]u8) bool {
    // Unspecified (::) or loopback (::1)
    const zeros: [15]u8 = @splat(0);
    const zero_prefix = std.mem.eql(u8, b[0..15], &zeros);
    if (zero_prefix and (b[15] == 0 or b[15] == 1)) return true;

    // IPv4-mapped IPv6 (::ffff:a.b.c.d)
    const v4_mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (std.mem.eql(u8, b[0..12], &v4_mapped_prefix)) {
        return isPrivateIpv4(b[12..16].*);
    }

    // Unique local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8)
    if ((b[0] & 0xFE) == 0xFC) return true;
    if (b[0] == 0xFE and (b[1] & 0xC0) == 0x80) return true;
    if (b[0] == 0xFF) return true;

    return false;
}

/// Phase breakdown recorded when a fresh `Connection` is dialed.
pub const ConnectTimings = struct {
    dns_ns: u64 = 0,
    tcp_ns: u64 = 0,
    tls_ns: u64 = 0,
};

pub const ConnectOptions = struct {
    io: std.Io,
    tls: TlsConfig,
    proxy: ?ProxyConfig = null,
    /// Optional Unix domain socket path that overrides TCP dialing for plain HTTP
    /// requests (similar to `curl --unix-socket`), preserving the logical URL `Host`.
    unix_socket_path: ?[]const u8 = null,
    /// When true and routing plain `.http` through an HTTP/HTTPS proxy (e.g. `ws://`
    /// upgrade), establish a raw `CONNECT` tunnel instead of HTTP forward-proxying.
    force_connect_tunnel: bool = false,
    /// Optional post-DNS IP address filter (e.g. `Connection.blockPrivateAddresses()`).
    address_filter: ?AddressFilter = null,
    /// RFC 8305 Happy Eyeballs stagger delay between dual-stack address attempts.
    happy_eyeballs_delay: zio.Duration = .fromMilliseconds(250),
    read_buffer_size: usize = default_read_buffer_size,
    write_buffer_size: usize = default_write_buffer_size,
};

const Kind = enum {
    plain,
    tls,
    tunnel_tls,
};

stream: zio.net.Stream,
stream_reader: zio.net.Stream.Reader,
stream_writer: zio.net.Stream.Writer,
/// Intrusive linked-list hook for the per-origin LIFO idle stack in `Pool`.
origin_node: std.DoublyLinkedList.Node = .{},
/// Intrusive linked-list hook for the global LRU idle eviction list in `Pool`.
global_idle_node: std.DoublyLinkedList.Node = .{},
kind: Kind,
scheme: http.Scheme,
port: u16,
host_len: u16,
read_buffer_size: usize,
write_buffer_size: usize,
created_at: zio.Timestamp,
last_used_at: zio.Timestamp,
connect_timings: ConnectTimings = .{},
/// True once this connection has been checked out from the pool after prior use.
reused: bool = false,
/// True when this connection routes through an HTTP forward proxy.
proxied: bool = false,
/// Marked true whenever the connection is tainted and must be destroyed instead of pooled.
closing: bool = false,

const Plain = struct {
    connection: Connection,

    fn allocLen(host_len: usize, read_buf_size: usize, write_buf_size: usize) usize {
        return @sizeOf(Plain) + host_len + read_buf_size + write_buf_size;
    }

    fn create(
        gpa: Allocator,
        origin_val: http.Origin,
        stream: zio.net.Stream,
        now: zio.Timestamp,
        read_buf_size: usize,
        write_buf_size: usize,
        proxied: bool,
    ) Allocator.Error!*Plain {
        const len = allocLen(origin_val.host.len, read_buf_size, write_buf_size);
        const base = try gpa.alignedAlloc(u8, .of(Plain), len);
        errdefer gpa.free(base);

        const host_buf = base[@sizeOf(Plain)..][0..origin_val.host.len];
        const read_buf = host_buf.ptr[host_buf.len..][0..read_buf_size];
        const write_buf = read_buf.ptr[read_buf.len..][0..write_buf_size];
        assert(base.ptr + len == write_buf.ptr + write_buf.len);

        if (origin_val.scheme == .http_unix) {
            @memcpy(host_buf, origin_val.host);
        } else {
            copyLowercase(host_buf, origin_val.host);
        }

        const plain: *Plain = @ptrCast(base);
        plain.* = .{
            .connection = .{
                .stream = stream,
                .stream_reader = stream.reader(read_buf),
                .stream_writer = stream.writer(write_buf),
                .kind = .plain,
                .scheme = origin_val.scheme,
                .port = origin_val.port,
                .host_len = @intCast(origin_val.host.len),
                .read_buffer_size = read_buf_size,
                .write_buffer_size = write_buf_size,
                .created_at = now,
                .last_used_at = now,
                .proxied = proxied,
            },
        };
        return plain;
    }

    fn destroy(self: *Plain, gpa: Allocator) void {
        const c = &self.connection;
        const len = allocLen(c.host_len, c.read_buffer_size, c.write_buffer_size);
        const base: [*]align(@alignOf(Plain)) u8 = @ptrCast(self);
        gpa.free(base[0..len]);
    }

    fn hostSlice(self: *const Plain) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[@sizeOf(Plain)..][0..self.connection.host_len];
    }
};

fn buildTlsClientOptions(
    gpa: Allocator,
    io: std.Io,
    tls_cfg: TlsConfig,
    explicit_host: []const u8,
    read_buffer: []u8,
    write_buffer: []u8,
    entropy: *const [tls.Client.Options.entropy_len]u8,
    realtime_now: std.Io.Timestamp,
) !tls.Client.Options {
    switch (tls_cfg) {
        .system => |ca_store| try ca_store.ensureLoaded(gpa, io),
        .custom_ca, .no_verification => {},
    }
    return switch (tls_cfg) {
        .system, .custom_ca => |ca_store| .{
            .host = .{ .explicit = explicit_host },
            .ca = .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &ca_store.lock,
                .bundle = &ca_store.bundle,
            } },
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .entropy = entropy,
            .realtime_now = realtime_now,
            // Many real-world HTTPS servers close TCP without TLS close_notify;
            // HTTP Content-Length / Chunked framing detects truncation at layer 7.
            .allow_truncation_attacks = true,
        },
        .no_verification => .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .entropy = entropy,
            .realtime_now = realtime_now,
            .allow_truncation_attacks = true,
        },
    };
}

const Tls = struct {
    client: tls.Client,
    connection: Connection,

    const TunnelBeforeTls = union(enum) {
        none,
        http_connect: struct { target: http.Origin, proxy: ProxyConfig },
        socks5: struct { target: http.Origin, proxy: ProxyConfig },
    };

    fn allocLen(host_len: usize, read_buf_size: usize, write_buf_size: usize) usize {
        const tls_read_buf_len = tls_buffer_size + read_buf_size;
        return @sizeOf(Tls) + host_len + tls_read_buf_len + tls_buffer_size + write_buf_size + tls_buffer_size;
    }

    fn create(
        gpa: Allocator,
        bucket_origin: http.Origin,
        stream: zio.net.Stream,
        now: zio.Timestamp,
        opts: ConnectOptions,
        tls_cfg: TlsConfig,
        tunnel_mode: TunnelBeforeTls,
        proxied: bool,
    ) !*Tls {
        const len = allocLen(bucket_origin.host.len, opts.read_buffer_size, opts.write_buffer_size);
        const base = try gpa.alignedAlloc(u8, .of(Tls), len);
        errdefer gpa.free(base);

        const host_buf = base[@sizeOf(Tls)..][0..bucket_origin.host.len];
        const tls_read_buf_len = tls_buffer_size + opts.read_buffer_size;
        const tls_read_buf = host_buf.ptr[host_buf.len..][0..tls_read_buf_len];
        const tls_write_buf = tls_read_buf.ptr[tls_read_buf.len..][0..tls_buffer_size];
        const socket_write_buf = tls_write_buf.ptr[tls_write_buf.len..][0..opts.write_buffer_size];
        const socket_read_buf = socket_write_buf.ptr[socket_write_buf.len..][0..tls_buffer_size];
        assert(base.ptr + len == socket_read_buf.ptr + socket_read_buf.len);

        copyLowercase(host_buf, bucket_origin.host);

        const tls_conn: *Tls = @ptrCast(base);
        // Pin the underlying socket reader/writer inside the heap allocation BEFORE
        // starting any proxy tunnel or TLS handshake so internal pointers stay stable.
        tls_conn.connection = .{
            .stream = stream,
            .stream_reader = stream.reader(socket_read_buf),
            .stream_writer = stream.writer(tls_write_buf),
            .kind = .tls,
            .scheme = bucket_origin.scheme,
            .port = bucket_origin.port,
            .host_len = @intCast(bucket_origin.host.len),
            .read_buffer_size = opts.read_buffer_size,
            .write_buffer_size = opts.write_buffer_size,
            .created_at = now,
            .last_used_at = now,
            .proxied = proxied,
        };

        switch (tunnel_mode) {
            .none => {},
            .http_connect => |hc| {
                const t_tunnel = zio.Timestamp.now(.awake);
                try establishConnectTunnelOnStream(
                    gpa,
                    &tls_conn.connection.stream_reader.interface,
                    &tls_conn.connection.stream_writer.interface,
                    null,
                    &tls_conn.connection,
                    hc.target,
                    hc.proxy,
                );
                tls_conn.connection.connect_timings.tcp_ns +|=
                    zio.Timestamp.now(.awake).toNanoseconds() -| t_tunnel.toNanoseconds();
            },
            .socks5 => |s5| {
                const t_tunnel = zio.Timestamp.now(.awake);
                try establishSocks5Tunnel(
                    &tls_conn.connection.stream_reader.interface,
                    &tls_conn.connection.stream_writer.interface,
                    &tls_conn.connection,
                    s5.target,
                    s5.proxy,
                    opts.address_filter,
                );
                tls_conn.connection.connect_timings.tcp_ns +|=
                    zio.Timestamp.now(.awake).toNanoseconds() -| t_tunnel.toNanoseconds();
            },
        }

        const t_tls_start = zio.Timestamp.now(.awake);
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try zio.randomSecure(&entropy);

        const realtime_now = std.Io.Clock.real.now(opts.io);
        const tls_opts = try buildTlsClientOptions(
            gpa,
            opts.io,
            tls_cfg,
            host_buf,
            tls_read_buf,
            socket_write_buf,
            &entropy,
            realtime_now,
        );

        tls_conn.client = tls.Client.init(
            &tls_conn.connection.stream_reader.interface,
            &tls_conn.connection.stream_writer.interface,
            tls_opts,
        ) catch |err| switch (err) {
            error.WriteFailed => return tls_conn.connection.stream_writer.err orelse error.WriteFailed,
            error.ReadFailed => return tls_conn.connection.stream_reader.err orelse error.ReadFailed,
            else => |e| return e,
        };
        tls_conn.connection.connect_timings.tls_ns =
            zio.Timestamp.now(.awake).toNanoseconds() -| t_tls_start.toNanoseconds();

        return tls_conn;
    }

    fn destroy(self: *Tls, gpa: Allocator) void {
        const c = &self.connection;
        const len = allocLen(c.host_len, c.read_buffer_size, c.write_buffer_size);
        const base: [*]align(@alignOf(Tls)) u8 = @ptrCast(self);
        gpa.free(base[0..len]);
    }

    fn hostSlice(self: *const Tls) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[@sizeOf(Tls)..][0..self.connection.host_len];
    }
};

/// Double-TLS connection (`https://` proxy outer TLS + `CONNECT` + target inner TLS)
/// packed into a single heap-pinned allocation to protect `zio` coroutine stacks.
const TunnelTls = struct {
    outer: tls.Client,
    inner: tls.Client,
    connection: Connection,

    fn allocLen(host_len: usize, read_buf_size: usize, write_buf_size: usize) usize {
        const outer_tls_read_len = tls_buffer_size + tls_buffer_size;
        const inner_tls_read_len = tls_buffer_size + read_buf_size;
        return @sizeOf(TunnelTls) + host_len +
            tls_buffer_size + // outer socket read
            tls_buffer_size + // outer socket write
            outer_tls_read_len + // outer TLS plaintext read (feeds CONNECT & inner TLS)
            tls_buffer_size + // outer TLS plaintext write (fed by CONNECT & inner TLS)
            inner_tls_read_len + // inner TLS plaintext read (application reader)
            write_buf_size; // inner TLS plaintext write (application writer)
    }

    fn create(
        gpa: Allocator,
        target_origin: http.Origin,
        proxy: ProxyConfig,
        stream: zio.net.Stream,
        now: zio.Timestamp,
        opts: ConnectOptions,
    ) !*TunnelTls {
        const len = allocLen(target_origin.host.len, opts.read_buffer_size, opts.write_buffer_size);
        const base = try gpa.alignedAlloc(u8, .of(TunnelTls), len);
        errdefer gpa.free(base);

        const host_buf = base[@sizeOf(TunnelTls)..][0..target_origin.host.len];
        const socket_read_buf = host_buf.ptr[host_buf.len..][0..tls_buffer_size];
        const socket_write_buf = socket_read_buf.ptr[socket_read_buf.len..][0..tls_buffer_size];
        const outer_tls_read_buf = socket_write_buf.ptr[socket_write_buf.len..][0 .. tls_buffer_size * 2];
        const outer_tls_write_buf = outer_tls_read_buf.ptr[outer_tls_read_buf.len..][0..tls_buffer_size];
        const inner_tls_read_buf = outer_tls_write_buf.ptr[outer_tls_write_buf.len..][0 .. tls_buffer_size + opts.read_buffer_size];
        const inner_tls_write_buf = inner_tls_read_buf.ptr[inner_tls_read_buf.len..][0..opts.write_buffer_size];
        assert(base.ptr + len == inner_tls_write_buf.ptr + inner_tls_write_buf.len);

        copyLowercase(host_buf, target_origin.host);

        const tunnel: *TunnelTls = @ptrCast(base);
        tunnel.connection = .{
            .stream = stream,
            .stream_reader = stream.reader(socket_read_buf),
            .stream_writer = stream.writer(socket_write_buf),
            .kind = .tunnel_tls,
            .scheme = .https,
            .port = target_origin.port,
            .host_len = @intCast(target_origin.host.len),
            .read_buffer_size = opts.read_buffer_size,
            .write_buffer_size = opts.write_buffer_size,
            .created_at = now,
            .last_used_at = now,
            .proxied = true,
        };

        const t_tls_start = zio.Timestamp.now(.awake);

        // 1. Establish outer TLS session with the HTTPS proxy server.
        var proxy_host_lower: [http.Origin.max_host_len]u8 = undefined;
        if (proxy.host.len > proxy_host_lower.len) return error.HostTooLong;
        copyLowercase(proxy_host_lower[0..proxy.host.len], proxy.host);

        var outer_entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try zio.randomSecure(&outer_entropy);
        const realtime_now = std.Io.Clock.real.now(opts.io);

        const outer_tls_opts = try buildTlsClientOptions(
            gpa,
            opts.io,
            proxy.tls orelse opts.tls,
            proxy_host_lower[0..proxy.host.len],
            outer_tls_read_buf,
            outer_tls_write_buf,
            &outer_entropy,
            realtime_now,
        );

        tunnel.outer = tls.Client.init(
            &tunnel.connection.stream_reader.interface,
            &tunnel.connection.stream_writer.interface,
            outer_tls_opts,
        ) catch |err| switch (err) {
            error.WriteFailed => return tunnel.connection.stream_writer.err orelse error.WriteFailed,
            error.ReadFailed => return tunnel.connection.stream_reader.err orelse error.ReadFailed,
            else => |e| return e,
        };

        // 2. Issue HTTP CONNECT inside the outer TLS tunnel.
        try establishConnectTunnelOnStream(
            gpa,
            &tunnel.outer.reader,
            &tunnel.outer.writer,
            &tunnel.outer,
            &tunnel.connection,
            target_origin,
            proxy,
        );

        // 3. Establish inner end-to-end TLS session with the destination origin.
        var inner_entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try zio.randomSecure(&inner_entropy);

        const inner_tls_opts = try buildTlsClientOptions(
            gpa,
            opts.io,
            opts.tls,
            host_buf,
            inner_tls_read_buf,
            inner_tls_write_buf,
            &inner_entropy,
            realtime_now,
        );

        tunnel.inner = tls.Client.init(
            &tunnel.outer.reader,
            &tunnel.outer.writer,
            inner_tls_opts,
        ) catch |err| switch (err) {
            error.WriteFailed => return tunnel.connection.stream_writer.err orelse error.WriteFailed,
            error.ReadFailed => {
                if (tunnel.outer.read_err) |e| return e;
                return tunnel.connection.stream_reader.err orelse error.ReadFailed;
            },
            else => |e| return e,
        };

        tunnel.connection.connect_timings.tls_ns =
            zio.Timestamp.now(.awake).toNanoseconds() -| t_tls_start.toNanoseconds();

        return tunnel;
    }

    fn destroy(self: *TunnelTls, gpa: Allocator) void {
        const c = &self.connection;
        const len = allocLen(c.host_len, c.read_buffer_size, c.write_buffer_size);
        const base: [*]align(@alignOf(TunnelTls)) u8 = @ptrCast(self);
        gpa.free(base[0..len]);
    }

    fn hostSlice(self: *const TunnelTls) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[@sizeOf(TunnelTls)..][0..self.connection.host_len];
    }
};

/// Resolves DNS (if needed), establishes a TCP/UDS connection via zio (directly or
/// via configured HTTP/HTTPS/SOCKS5 proxy unless bypassed by `no_proxy`), performs
/// any proxy tunnel + TLS handshake(s), and returns a heap-pinned `*Connection`.
pub fn connect(gpa: Allocator, origin_val: http.Origin, opts: ConnectOptions) !*Connection {
    // Unix domain socket path via either `http+unix://` URL scheme or explicit `unix_socket_path`.
    const uds_path: ?[]const u8 = if (origin_val.scheme == .http_unix)
        origin_val.host
    else if (opts.unix_socket_path) |p| blk: {
        if (origin_val.scheme != .http) return error.UnsupportedScheme;
        break :blk p;
    } else null;

    if (uds_path) |path| {
        var timings: ConnectTimings = .{};
        const stream = try dialUnixSocket(path, &timings);
        errdefer stream.close();
        const now = zio.Timestamp.now(.awake);
        const plain = try Plain.create(
            gpa,
            origin_val,
            stream,
            now,
            opts.read_buffer_size,
            opts.write_buffer_size,
            false,
        );
        plain.connection.connect_timings = timings;
        return &plain.connection;
    }

    const active_proxy: ?ProxyConfig = if (opts.proxy) |p|
        if (p.bypasses(origin_val)) null else p
    else
        null;

    var effective_opts = opts;
    effective_opts.proxy = active_proxy;

    var timings: ConnectTimings = .{};
    const stream = if (active_proxy) |proxy|
        try dialHostPort(proxy.host, proxy.port, opts.happy_eyeballs_delay, opts.address_filter, &timings)
    else
        try dialHostPort(origin_val.host, origin_val.port, opts.happy_eyeballs_delay, opts.address_filter, &timings);
    errdefer stream.close();

    const now = zio.Timestamp.now(.awake);

    switch (origin_val.scheme) {
        .http => {
            if (active_proxy) |proxy| {
                switch (proxy.scheme) {
                    .http => {
                        if (opts.force_connect_tunnel) {
                            const plain = try Plain.create(
                                gpa,
                                origin_val,
                                stream,
                                now,
                                opts.read_buffer_size,
                                opts.write_buffer_size,
                                true,
                            );
                            errdefer plain.destroy(gpa);
                            const t_tunnel = zio.Timestamp.now(.awake);
                            try establishConnectTunnelOnStream(
                                gpa,
                                &plain.connection.stream_reader.interface,
                                &plain.connection.stream_writer.interface,
                                null,
                                &plain.connection,
                                origin_val,
                                proxy,
                            );
                            timings.tcp_ns +|= zio.Timestamp.now(.awake).toNanoseconds() -| t_tunnel.toNanoseconds();
                            plain.connection.connect_timings = timings;
                            return &plain.connection;
                        }
                        // Plain HTTP forward-proxy sockets serve any destination via absolute-form
                        // targets, so key them under the proxy's Origin for cross-domain pool reuse.
                        const proxy_origin: http.Origin = .{
                            .scheme = .http,
                            .host = proxy.host,
                            .port = proxy.port,
                        };
                        const plain = try Plain.create(
                            gpa,
                            proxy_origin,
                            stream,
                            now,
                            opts.read_buffer_size,
                            opts.write_buffer_size,
                            true,
                        );
                        plain.connection.connect_timings = timings;
                        return &plain.connection;
                    },
                    .https => {
                        // HTTPS TLS-to-proxy: either plain HTTP forward-proxying over outer TLS,
                        // or an explicit `CONNECT` tunnel inside outer TLS (e.g. `ws://` upgrade).
                        const proxy_origin: http.Origin = .{
                            .scheme = .https,
                            .host = proxy.host,
                            .port = proxy.port,
                        };
                        const tls_conn = try Tls.create(
                            gpa,
                            proxy_origin,
                            stream,
                            now,
                            effective_opts,
                            proxy.tls orelse opts.tls,
                            .none,
                            true,
                        );
                        errdefer tls_conn.destroy(gpa);
                        if (opts.force_connect_tunnel) {
                            const t_tunnel = zio.Timestamp.now(.awake);
                            try establishConnectTunnelOnStream(
                                gpa,
                                &tls_conn.client.reader,
                                &tls_conn.client.writer,
                                &tls_conn.client,
                                &tls_conn.connection,
                                origin_val,
                                proxy,
                            );
                            timings.tcp_ns +|= zio.Timestamp.now(.awake).toNanoseconds() -| t_tunnel.toNanoseconds();
                        }
                        tls_conn.connection.connect_timings.dns_ns = timings.dns_ns;
                        tls_conn.connection.connect_timings.tcp_ns +|= timings.tcp_ns;
                        return &tls_conn.connection;
                    },
                    .socks5, .socks5h => {
                        // SOCKS5 tunnel bound to this exact target origin (never shared across targets).
                        const plain = try Plain.create(
                            gpa,
                            origin_val,
                            stream,
                            now,
                            opts.read_buffer_size,
                            opts.write_buffer_size,
                            true,
                        );
                        errdefer plain.destroy(gpa);
                        const t_s5 = zio.Timestamp.now(.awake);
                        try establishSocks5Tunnel(
                            &plain.connection.stream_reader.interface,
                            &plain.connection.stream_writer.interface,
                            &plain.connection,
                            origin_val,
                            proxy,
                            opts.address_filter,
                        );
                        timings.tcp_ns +|= zio.Timestamp.now(.awake).toNanoseconds() -| t_s5.toNanoseconds();
                        plain.connection.connect_timings = timings;
                        return &plain.connection;
                    },
                }
            }

            const plain = try Plain.create(
                gpa,
                origin_val,
                stream,
                now,
                opts.read_buffer_size,
                opts.write_buffer_size,
                false,
            );
            plain.connection.connect_timings = timings;
            return &plain.connection;
        },
        .https => {
            if (active_proxy) |proxy| {
                switch (proxy.scheme) {
                    .http => {
                        const tls_conn = try Tls.create(
                            gpa,
                            origin_val,
                            stream,
                            now,
                            effective_opts,
                            opts.tls,
                            .{ .http_connect = .{ .target = origin_val, .proxy = proxy } },
                            true,
                        );
                        tls_conn.connection.connect_timings.dns_ns = timings.dns_ns;
                        tls_conn.connection.connect_timings.tcp_ns +|= timings.tcp_ns;
                        return &tls_conn.connection;
                    },
                    .https => {
                        const tunnel = try TunnelTls.create(gpa, origin_val, proxy, stream, now, effective_opts);
                        tunnel.connection.connect_timings.dns_ns = timings.dns_ns;
                        tunnel.connection.connect_timings.tcp_ns +|= timings.tcp_ns;
                        return &tunnel.connection;
                    },
                    .socks5, .socks5h => {
                        const tls_conn = try Tls.create(
                            gpa,
                            origin_val,
                            stream,
                            now,
                            effective_opts,
                            opts.tls,
                            .{ .socks5 = .{ .target = origin_val, .proxy = proxy } },
                            true,
                        );
                        tls_conn.connection.connect_timings.dns_ns = timings.dns_ns;
                        tls_conn.connection.connect_timings.tcp_ns +|= timings.tcp_ns;
                        return &tls_conn.connection;
                    },
                }
            }

            const tls_conn = try Tls.create(
                gpa,
                origin_val,
                stream,
                now,
                effective_opts,
                opts.tls,
                .none,
                false,
            );
            tls_conn.connection.connect_timings.dns_ns = timings.dns_ns;
            tls_conn.connection.connect_timings.tcp_ns +|= timings.tcp_ns;
            return &tls_conn.connection;
        },
        .http_unix => unreachable,
    }
}

fn dialUnixSocket(path: []const u8, timings: *ConnectTimings) !zio.net.Stream {
    if (!zio.net.has_unix_sockets) return error.UnixSocketsUnsupported;
    const t_start = zio.Timestamp.now(.awake);
    const addr = try zio.net.UnixAddress.init(path);
    const stream = try addr.connect(.{});
    timings.tcp_ns = zio.Timestamp.now(.awake).toNanoseconds() -| t_start.toNanoseconds();
    return stream;
}

/// Closes the underlying socket and frees the pinned connection allocation.
/// Safe to invoke inside `defer` even when the current coroutine is canceled.
pub fn destroy(self: *Connection, gpa: Allocator) void {
    self.stream.close();
    switch (self.kind) {
        .plain => {
            const plain: *Plain = @fieldParentPtr("connection", self);
            plain.destroy(gpa);
        },
        .tls => {
            const tls_conn: *Tls = @fieldParentPtr("connection", self);
            tls_conn.destroy(gpa);
        },
        .tunnel_tls => {
            const tunnel: *TunnelTls = @fieldParentPtr("connection", self);
            tunnel.destroy(gpa);
        },
    }
}

pub fn host(self: *const Connection) []const u8 {
    return switch (self.kind) {
        .plain => {
            const plain: *const Plain = @fieldParentPtr("connection", self);
            return plain.hostSlice();
        },
        .tls => {
            const tls_conn: *const Tls = @fieldParentPtr("connection", self);
            return tls_conn.hostSlice();
        },
        .tunnel_tls => {
            const tunnel: *const TunnelTls = @fieldParentPtr("connection", self);
            return tunnel.hostSlice();
        },
    };
}

pub fn origin(self: *const Connection) http.Origin {
    return .{
        .scheme = self.scheme,
        .host = self.host(),
        .port = self.port,
    };
}

/// Returns the plaintext application reader (socket reader for plain connections,
/// decrypted TLS reader for single/double TLS connections).
pub fn reader(self: *Connection) *Reader {
    return switch (self.kind) {
        .plain => &self.stream_reader.interface,
        .tls => {
            const tls_conn: *Tls = @fieldParentPtr("connection", self);
            return &tls_conn.client.reader;
        },
        .tunnel_tls => {
            const tunnel: *TunnelTls = @fieldParentPtr("connection", self);
            return &tunnel.inner.reader;
        },
    };
}

/// Returns the plaintext application writer (socket writer for plain connections,
/// encrypted TLS writer for single/double TLS connections).
pub fn writer(self: *Connection) *Writer {
    return switch (self.kind) {
        .plain => &self.stream_writer.interface,
        .tls => {
            const tls_conn: *Tls = @fieldParentPtr("connection", self);
            return &tls_conn.client.writer;
        },
        .tunnel_tls => {
            const tunnel: *TunnelTls = @fieldParentPtr("connection", self);
            return &tunnel.inner.writer;
        },
    };
}

/// Flushes every TLS framing layer (inner -> outer) and the underlying socket buffer.
pub fn flush(self: *Connection) !void {
    switch (self.kind) {
        .plain => {
            self.stream_writer.interface.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
        },
        .tls => {
            const tls_conn: *Tls = @fieldParentPtr("connection", self);
            tls_conn.client.writer.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
            self.stream_writer.interface.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
        },
        .tunnel_tls => {
            const tunnel: *TunnelTls = @fieldParentPtr("connection", self);
            tunnel.inner.writer.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
            tunnel.outer.writer.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
            self.stream_writer.interface.flush() catch {
                return self.unwrapWriteError() orelse error.WriteFailed;
            };
        },
    }
}

/// Recovers the concrete underlying read error (inner/outer TLS alert or socket
/// `Canceled`/`ConnectionResetByPeer`) after `reader()` returned `error.ReadFailed`.
pub fn unwrapReadError(self: *const Connection) ?anyerror {
    switch (self.kind) {
        .plain => {},
        .tls => {
            const tls_conn: *const Tls = @fieldParentPtr("connection", self);
            if (tls_conn.client.read_err) |e| return e;
        },
        .tunnel_tls => {
            const tunnel: *const TunnelTls = @fieldParentPtr("connection", self);
            if (tunnel.inner.read_err) |e| return e;
            if (tunnel.outer.read_err) |e| return e;
        },
    }
    if (self.stream_reader.err) |e| return e;
    return null;
}

/// Recovers the concrete underlying write error after `writer()` returned `error.WriteFailed`.
pub fn unwrapWriteError(self: *const Connection) ?anyerror {
    if (self.stream_writer.err) |e| return e;
    return null;
}

/// Configures a per-read idle timeout on the underlying socket reader (guards
/// streaming downloads against Slowloris stalls). Reset to `.none` before pooling.
pub fn setReadIdleTimeout(self: *Connection, timeout: zio.Timeout) void {
    self.stream_reader.timeout = timeout;
}

pub fn markUsed(self: *Connection, now: zio.Timestamp) void {
    self.last_used_at = now;
}

/// Returns true if the connection has exceeded either its idle budget or its
/// total lifetime budget (guards against stale sockets and DNS rotation).
pub fn isExpired(
    self: *const Connection,
    now: zio.Timestamp,
    max_idle: ?zio.Duration,
    max_lifetime: ?zio.Duration,
) bool {
    if (max_idle) |idle_limit| {
        if (now.value -| self.last_used_at.value >= idle_limit.value) return true;
    }
    if (max_lifetime) |life_limit| {
        if (now.value -| self.created_at.value >= life_limit.value) return true;
    }
    return false;
}

/// Sends RFC 9110 §9.3.6 `CONNECT host:port HTTP/1.1` over either the raw proxy
/// socket or an outer TLS proxy stream, and verifies a `2xx` tunnel response.
fn establishConnectTunnelOnStream(
    gpa: Allocator,
    r: *Reader,
    w: *Writer,
    outer_tls: ?*tls.Client,
    conn: *Connection,
    target_origin: http.Origin,
    proxy: ProxyConfig,
) !void {
    var authority_buf: [http.Origin.max_host_len + 16]u8 = undefined;
    var aw: Writer = .fixed(&authority_buf);
    if (target_origin.isIpv6()) {
        try aw.print("[{s}]:{d}", .{ target_origin.host, target_origin.port });
    } else {
        try aw.print("{s}:{d}", .{ target_origin.host, target_origin.port });
    }
    const authority = aw.buffered();

    var hdrs: [2]http.Header = undefined;
    var hdr_len: usize = 0;
    hdrs[hdr_len] = .{ .name = "Host", .value = authority };
    hdr_len += 1;
    if (proxy.authorization) |auth| {
        hdrs[hdr_len] = .{ .name = "Proxy-Authorization", .value = auth };
        hdr_len += 1;
    }

    h1.writeRequestHead(w, .{
        .method = .CONNECT,
        .origin = target_origin,
        .target = authority,
        .headers = hdrs[0..hdr_len],
    }) catch |err| switch (err) {
        error.WriteFailed => return conn.stream_writer.err orelse error.WriteFailed,
        else => return err,
    };
    w.flush() catch {
        return conn.stream_writer.err orelse error.WriteFailed;
    };
    if (outer_tls != null) {
        // Flush ciphertext buffered by the outer TLS layer out to the TCP socket.
        conn.stream_writer.interface.flush() catch {
            return conn.stream_writer.err orelse error.WriteFailed;
        };
    }

    var head = h1.readResponseHead(gpa, r, .CONNECT, .{}) catch |err| switch (err) {
        error.ReadFailed => {
            if (outer_tls) |ot| {
                if (ot.read_err) |e| return e;
            }
            return conn.stream_reader.err orelse error.ReadFailed;
        },
        else => return err,
    };
    defer head.deinit(gpa);

    if (head.status.code() == 407) return error.ProxyAuthRequired;
    if (!head.status.isSuccess()) return error.ProxyConnectFailed;
}

/// Performs RFC 1928 SOCKS5 (and optional RFC 1929 username/password) handshake
/// to establish a TCP tunnel to `target_origin`.
///
/// - `socks5h`: transmits domain names directly (`ATYP = 0x03`) without local DNS lookup.
/// - `socks5`: resolves domain names locally and transmits IPv4/IPv6 (`ATYP = 0x01`/`0x04`).
fn establishSocks5Tunnel(
    r: *Reader,
    w: *Writer,
    conn: *Connection,
    target_origin: http.Origin,
    proxy: ProxyConfig,
    address_filter: ?AddressFilter,
) !void {
    const has_auth = proxy.username != null;
    if (has_auth) {
        const user = proxy.username.?;
        const pass = proxy.password orelse "";
        if (user.len > 255 or pass.len > 255) return error.InvalidProxyCredentials;
        w.writeAll(&.{ 0x05, 0x02, 0x00, 0x02 }) catch {
            return conn.stream_writer.err orelse error.WriteFailed;
        };
    } else {
        w.writeAll(&.{ 0x05, 0x01, 0x00 }) catch {
            return conn.stream_writer.err orelse error.WriteFailed;
        };
    }
    w.flush() catch {
        return conn.stream_writer.err orelse error.WriteFailed;
    };

    var method_resp: [2]u8 = undefined;
    readExactUnwrapped(r, conn, &method_resp) catch |err| return err;
    if (method_resp[0] != 0x05) return error.ProxyConnectFailed;

    switch (method_resp[1]) {
        0x00 => {}, // No authentication required
        0x02 => {
            // RFC 1929 Username/Password subnegotiation
            const user = proxy.username orelse return error.ProxyAuthRequired;
            const pass = proxy.password orelse "";
            var auth_buf: [2 + 255 + 1 + 255]u8 = undefined;
            auth_buf[0] = 0x01;
            auth_buf[1] = @intCast(user.len);
            @memcpy(auth_buf[2..][0..user.len], user);
            const pass_off = 2 + user.len;
            auth_buf[pass_off] = @intCast(pass.len);
            @memcpy(auth_buf[pass_off + 1 ..][0..pass.len], pass);
            const total_len = pass_off + 1 + pass.len;

            w.writeAll(auth_buf[0..total_len]) catch {
                return conn.stream_writer.err orelse error.WriteFailed;
            };
            w.flush() catch {
                return conn.stream_writer.err orelse error.WriteFailed;
            };

            var auth_resp: [2]u8 = undefined;
            try readExactUnwrapped(r, conn, &auth_resp);
            if (auth_resp[0] != 0x01 or auth_resp[1] != 0x00) {
                return error.ProxyAuthRequired;
            }
        },
        0xFF => return error.ProxyAuthRequired,
        else => return error.ProxyConnectFailed,
    }

    // Build RFC 1928 CONNECT request: [VER=5, CMD=1(CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT]
    var req_buf: [4 + 1 + 255 + 2]u8 = undefined;
    req_buf[0] = 0x05;
    req_buf[1] = 0x01;
    req_buf[2] = 0x00;
    var req_len: usize = 3;

    if (zio.net.IpAddress.parseIp(target_origin.host, target_origin.port)) |ip_addr| {
        if (address_filter) |f| {
            if (!f.allow(f.ctx, ip_addr)) return error.AddressBlocked;
        }
        req_len = encodeSocks5Ip(&req_buf, req_len, ip_addr);
    } else |_| {
        if (proxy.scheme == .socks5h) {
            if (target_origin.host.len == 0 or target_origin.host.len > 255) {
                return error.HostTooLong;
            }
            req_buf[req_len] = 0x03;
            req_buf[req_len + 1] = @intCast(target_origin.host.len);
            @memcpy(req_buf[req_len + 2 ..][0..target_origin.host.len], target_origin.host);
            req_len += 2 + target_origin.host.len;
        } else {
            // `socks5` resolves hostname locally via DNS before sending IP to proxy.
            const hn = try zio.net.HostName.init(target_origin.host);
            var lookup_buf: [32]zio.net.HostName.LookupResult = undefined;
            const count = try hn.lookup(&lookup_buf, .{ .port = target_origin.port });
            var ordered: [32]zio.net.IpAddress = undefined;
            const raw_count = interleaveDualStack(lookup_buf[0..count], &ordered);
            if (raw_count == 0) return error.UnknownHostName;
            var chosen: ?zio.net.IpAddress = null;
            for (ordered[0..raw_count]) |candidate| {
                if (address_filter) |f| {
                    if (!f.allow(f.ctx, candidate)) continue;
                }
                chosen = candidate;
                break;
            }
            const ip = chosen orelse return error.AddressBlocked;
            req_len = encodeSocks5Ip(&req_buf, req_len, ip);
        }
    }

    std.mem.writeInt(u16, req_buf[req_len..][0..2], target_origin.port, .big);
    req_len += 2;

    w.writeAll(req_buf[0..req_len]) catch {
        return conn.stream_writer.err orelse error.WriteFailed;
    };
    w.flush() catch {
        return conn.stream_writer.err orelse error.WriteFailed;
    };

    // Read RFC 1928 reply header: [VER, REP, RSV, ATYP]
    var rep_hdr: [4]u8 = undefined;
    try readExactUnwrapped(r, conn, &rep_hdr);
    if (rep_hdr[0] != 0x05) return error.ProxyConnectFailed;
    if (rep_hdr[1] != 0x00) return error.ProxyConnectFailed;

    // Drain BND.ADDR + BND.PORT so the stream is aligned at byte 0 of tunnel payload.
    const skip_len: usize = switch (rep_hdr[3]) {
        0x01 => 4 + 2, // IPv4 + port
        0x04 => 16 + 2, // IPv6 + port
        0x03 => blk: {
            var dlen: [1]u8 = undefined;
            try readExactUnwrapped(r, conn, &dlen);
            break :blk @as(usize, dlen[0]) + 2;
        },
        else => return error.ProxyConnectFailed,
    };
    var discard_buf: [258]u8 = undefined;
    try readExactUnwrapped(r, conn, discard_buf[0..skip_len]);
}

fn encodeSocks5Ip(buf: []u8, offset: usize, ip_addr: zio.net.IpAddress) usize {
    switch (ip_addr.getFamily()) {
        .ipv4 => {
            buf[offset] = 0x01;
            const bytes: [4]u8 = @bitCast(ip_addr.in.addr);
            @memcpy(buf[offset + 1 ..][0..4], &bytes);
            return offset + 5;
        },
        .ipv6 => {
            buf[offset] = 0x04;
            @memcpy(buf[offset + 1 ..][0..16], &ip_addr.in6.addr);
            return offset + 17;
        },
    }
}

fn readExactUnwrapped(r: *Reader, conn: *const Connection, dest: []u8) !void {
    r.readSliceAll(dest) catch |err| switch (err) {
        error.EndOfStream => return error.ProxyConnectFailed,
        error.ReadFailed => return conn.stream_reader.err orelse error.ReadFailed,
    };
}

fn dialHostPort(
    host_str: []const u8,
    port_num: u16,
    stagger_delay: zio.Duration,
    address_filter: ?AddressFilter,
    timings: *ConnectTimings,
) !zio.net.Stream {
    // Fast path for numeric IPv4/IPv6 literals: skip DNS resolution completely.
    if (zio.net.IpAddress.parseIp(host_str, port_num)) |ip_addr| {
        if (address_filter) |f| {
            if (!f.allow(f.ctx, ip_addr)) return error.AddressBlocked;
        }
        const t_tcp = zio.Timestamp.now(.awake);
        const stream = try ip_addr.connect(.{});
        timings.tcp_ns = zio.Timestamp.now(.awake).toNanoseconds() -| t_tcp.toNanoseconds();
        return stream;
    } else |_| {}

    const t_dns = zio.Timestamp.now(.awake);
    const hn = try zio.net.HostName.init(host_str);
    var lookup_buf: [32]zio.net.HostName.LookupResult = undefined;
    const count = try hn.lookup(&lookup_buf, .{ .port = port_num });
    timings.dns_ns = zio.Timestamp.now(.awake).toNanoseconds() -| t_dns.toNanoseconds();

    var ordered: [32]zio.net.IpAddress = undefined;
    const raw_count = interleaveDualStack(lookup_buf[0..count], &ordered);
    if (raw_count == 0) return error.UnknownHostName;

    var addr_count: usize = 0;
    if (address_filter) |f| {
        for (ordered[0..raw_count]) |addr| {
            if (f.allow(f.ctx, addr)) {
                ordered[addr_count] = addr;
                addr_count += 1;
            }
        }
        if (addr_count == 0) return error.AddressBlocked;
    } else {
        addr_count = raw_count;
    }

    const t_tcp = zio.Timestamp.now(.awake);
    const stream = if (addr_count == 1)
        try ordered[0].connect(.{})
    else
        try happyEyeballsConnect(ordered[0..addr_count], stagger_delay);
    timings.tcp_ns = zio.Timestamp.now(.awake).toNanoseconds() -| t_tcp.toNanoseconds();
    return stream;
}

/// RFC 8305 §4 address interleaving: alternates IPv6 and IPv4 addresses so
/// dual-stack Happy Eyeballs races both address families cleanly.
pub fn interleaveDualStack(
    results: []const zio.net.HostName.LookupResult,
    out: []zio.net.IpAddress,
) usize {
    var v6: [32]zio.net.IpAddress = undefined;
    var v4: [32]zio.net.IpAddress = undefined;
    var n6: usize = 0;
    var n4: usize = 0;

    for (results) |entry| {
        switch (entry) {
            .address => |addr| switch (addr.getFamily()) {
                .ipv6 => if (n6 < v6.len) {
                    v6[n6] = addr;
                    n6 += 1;
                },
                .ipv4 => if (n4 < v4.len) {
                    v4[n4] = addr;
                    n4 += 1;
                },
            },
            .canonical_name => {},
        }
    }

    var written: usize = 0;
    var idx6: usize = 0;
    var idx4: usize = 0;
    while (written < out.len and (idx6 < n6 or idx4 < n4)) {
        if (idx6 < n6) {
            out[written] = v6[idx6];
            written += 1;
            idx6 += 1;
        }
        if (written < out.len and idx4 < n4) {
            out[written] = v4[idx4];
            written += 1;
            idx4 += 1;
        }
    }
    return written;
}

/// RFC 8305 Happy Eyeballs concurrent connection racer:
/// Launches address attempts staggered by `stagger_delay`; the first connected
/// stream wins immediately, all losing dials are canceled, and any late-connecting
/// loser socket is closed cleanly with zero leaks.
pub fn happyEyeballsConnect(
    addrs: []const zio.net.IpAddress,
    stagger_delay: zio.Duration,
) !zio.net.Stream {
    assert(addrs.len > 0);
    if (addrs.len == 1) return addrs[0].connect(.{});

    const RaceState = struct {
        mutex: zio.Mutex = .init,
        cond: zio.Condition = .init,
        winner: ?zio.net.Stream = null,
        last_err: ?anyerror = null,
        finished: usize = 0,
        total: usize,

        fn attempt(self: *@This(), addr: zio.net.IpAddress) void {
            if (addr.connect(.{})) |stream| {
                self.mutex.lockUncancelable();
                const claimed = (self.winner == null);
                if (claimed) {
                    self.winner = stream;
                }
                self.finished += 1;
                self.cond.broadcast();
                self.mutex.unlock();

                if (!claimed) stream.close();
            } else |err| {
                self.mutex.lockUncancelable();
                if (self.winner == null and err != error.Canceled) {
                    self.last_err = err;
                }
                self.finished += 1;
                self.cond.broadcast();
                self.mutex.unlock();
            }
        }
    };

    var state: RaceState = .{ .total = addrs.len };
    var group: zio.Group = .init;
    defer {
        group.cancel();
        // If caller was canceled after a winner was already stored, close it cleanly.
        state.mutex.lockUncancelable();
        if (state.winner) |s| {
            state.winner = null;
            state.mutex.unlock();
            s.close();
        } else {
            state.mutex.unlock();
        }
    }

    var launched: usize = 0;
    while (true) {
        if (launched < addrs.len) {
            try group.spawn(RaceState.attempt, .{ &state, addrs[launched] });
            launched += 1;
        }

        try state.mutex.lock();
        defer state.mutex.unlock();

        if (state.winner) |stream| {
            state.winner = null;
            return stream;
        }
        if (state.finished >= addrs.len) {
            return state.last_err orelse error.ConnectionRefused;
        }

        if (launched < addrs.len) {
            // Wait up to stagger_delay (or until an earlier attempt finishes/wins).
            state.cond.waitTimeout(&state.mutex, .{ .duration = stagger_delay }) catch |err| switch (err) {
                error.Timeout => {},
                error.Canceled => return error.Canceled,
            };
        } else {
            try state.cond.wait(&state.mutex);
        }
    }
}

fn copyLowercase(dst: []u8, src: []const u8) void {
    assert(dst.len == src.len);
    for (src, 0..) |c, i| {
        dst[i] = std.ascii.toLower(c);
    }
}

// ===========================================================================
// Integration & Unit Tests (100% offline, deterministic, 0 memory leaks)
// ===========================================================================

const MockServer = @import("testing/MockServer.zig");

test "Connection plain HTTP/1.1 keep-alive roundtrip (fixed then chunked) over MockServer" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const Handler = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            // Serve two back-to-back requests on the same TCP connection.
            for (0..2) |idx| {
                // Drain until end of request headers ("\r\n\r\n").
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }

                if (idx == 0) {
                    w.interface.writeAll(
                        "HTTP/1.1 200 OK\r\n" ++
                            "Content-Length: 5\r\n" ++
                            "\r\n" ++
                            "first",
                    ) catch return;
                } else {
                    w.interface.writeAll(
                        "HTTP/1.1 200 OK\r\n" ++
                            "Transfer-Encoding: chunked\r\n" ++
                            "Connection: close\r\n" ++
                            "\r\n" ++
                            "6\r\nsecond\r\n0\r\n\r\n",
                    ) catch return;
                }
                w.interface.flush() catch return;
            }
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, Handler.handle);
    defer srv.stop();

    var ca_store: CaStore = .init;
    defer ca_store.deinit(gpa);

    const conn = try Connection.connect(gpa, srv.origin(), .{
        .io = rt.io(),
        .tls = .{ .system = &ca_store },
    });
    defer conn.destroy(gpa);

    // Request 1 (Fixed Content-Length)
    try h1.writeRequestHead(conn.writer(), .{
        .method = .GET,
        .origin = conn.origin(),
        .target = "/one",
    });
    try conn.flush();

    var head1 = try h1.readResponseHead(gpa, conn.reader(), .GET, .{});
    defer head1.deinit(gpa);
    try std.testing.expectEqual(http.Status.ok, head1.status);
    try std.testing.expect(head1.keep_alive);

    var body_buf1: [64]u8 = undefined;
    var body1: h1.BodyReader = undefined;
    body1.init(conn.reader(), head1.framing, &body_buf1);
    const payload1 = try body1.interface.allocRemaining(gpa, .limited(1024));
    defer gpa.free(payload1);
    try std.testing.expectEqualStrings("first", payload1);
    try std.testing.expect(body1.isComplete());

    // Request 2 on the EXACT SAME connection (Chunked + Connection: close)
    try h1.writeRequestHead(conn.writer(), .{
        .method = .GET,
        .origin = conn.origin(),
        .target = "/two",
    });
    try conn.flush();

    var head2 = try h1.readResponseHead(gpa, conn.reader(), .GET, .{});
    defer head2.deinit(gpa);
    try std.testing.expectEqual(http.Status.ok, head2.status);
    try std.testing.expect(!head2.keep_alive);

    var body_buf2: [64]u8 = undefined;
    var body2: h1.BodyReader = undefined;
    body2.init(conn.reader(), head2.framing, &body_buf2);
    const payload2 = try body2.interface.allocRemaining(gpa, .limited(1024));
    defer gpa.free(payload2);
    try std.testing.expectEqualStrings("second", payload2);
    try std.testing.expect(body2.isComplete());
}

test "Connection unwrapReadError translates zio.withTimeout into error.Timeout" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const StallingHandler = struct {
        fn handle(_: ?*anyopaque, _: zio.net.Stream) void {
            zio.sleep(.fromSeconds(5)) catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, StallingHandler.handle);
    defer srv.stop();

    var ca_store: CaStore = .init;
    defer ca_store.deinit(gpa);

    const conn = try Connection.connect(gpa, srv.origin(), .{
        .io = rt.io(),
        .tls = .{ .system = &ca_store },
    });
    defer conn.destroy(gpa);

    const ReadHeadOp = struct {
        fn run(alloc: Allocator, c: *Connection) !h1.ResponseHead {
            return h1.readResponseHead(alloc, c.reader(), .GET, .{}) catch |err| switch (err) {
                error.ReadFailed => return c.unwrapReadError() orelse error.ReadFailed,
                else => return err,
            };
        }
    };

    const res = zio.withTimeout(.fromMilliseconds(30), ReadHeadOp.run, .{ gpa, conn });
    try std.testing.expectError(error.Timeout, res);
}

test "CaStore lazily loads system root certificates and HTTPS handshake fails cleanly against plain peer" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var ca_store: CaStore = .init;
    defer ca_store.deinit(gpa);
    try std.testing.expect(!ca_store.loaded);
    try ca_store.ensureLoaded(gpa, rt.io());
    try std.testing.expect(ca_store.loaded);
    try std.testing.expect(ca_store.bundle.bytes.items.len > 0);

    // Connect HTTPS to a plain-text server sending garbage -> must fail cleanly with 0 leaks.
    const PlainRejectHandler = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var wbuf: [64]u8 = undefined;
            var w = stream.writer(&wbuf);
            w.interface.writeAll("HTTP/1.1 400 Bad Request\r\n\r\n") catch {};
            w.interface.flush() catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, PlainRejectHandler.handle);
    defer srv.stop();

    const https_origin: http.Origin = .{
        .scheme = .https,
        .host = "127.0.0.1",
        .port = srv.port(),
    };
    const res = Connection.connect(gpa, https_origin, .{
        .io = rt.io(),
        .tls = .no_verification,
    });
    try std.testing.expect(std.meta.isError(res));
}

test "Connection isExpired enforces max_idle and max_lifetime budgets" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const NoopHandler = struct {
        fn handle(_: ?*anyopaque, _: zio.net.Stream) void {
            zio.sleep(.fromSeconds(5)) catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, NoopHandler.handle);
    defer srv.stop();

    var ca_store: CaStore = .init;
    defer ca_store.deinit(gpa);

    const conn = try Connection.connect(gpa, srv.origin(), .{
        .io = rt.io(),
        .tls = .{ .system = &ca_store },
    });
    defer conn.destroy(gpa);

    const t0 = conn.created_at;
    const t_plus_10s = zio.Timestamp.fromNanoseconds(t0.toNanoseconds() + 10 * zio.time.ns_per_s);
    const t_plus_70s = zio.Timestamp.fromNanoseconds(t0.toNanoseconds() + 70 * zio.time.ns_per_s);

    // Fresh connection is not expired at +10s with 60s idle / 300s lifetime
    try std.testing.expect(!conn.isExpired(t_plus_10s, .fromSeconds(60), .fromSeconds(300)));

    // Exceeding idle limit triggers expiration
    try std.testing.expect(conn.isExpired(t_plus_70s, .fromSeconds(60), .fromSeconds(300)));

    // Marking used resets idle clock, but max_lifetime still triggers once total age hits limit
    conn.markUsed(t_plus_70s);
    const t_plus_80s = zio.Timestamp.fromNanoseconds(t0.toNanoseconds() + 80 * zio.time.ns_per_s);
    try std.testing.expect(!conn.isExpired(t_plus_80s, .fromSeconds(60), .fromSeconds(300)));
    try std.testing.expect(conn.isExpired(t_plus_80s, .fromSeconds(60), .fromSeconds(75)));
}

test "ProxyConfig NO_PROXY matching and fromEnv parsing" {
    const gpa = std.testing.allocator;

    const proxy: ProxyConfig = .{
        .host = "proxy.corp.local",
        .port = 8080,
        .no_proxy = &.{ "localhost", ".internal.corp", "10.0.0.1:9000" },
    };

    try std.testing.expect(proxy.bypasses(.{ .scheme = .http, .host = "localhost", .port = 80 }));
    try std.testing.expect(proxy.bypasses(.{ .scheme = .https, .host = "api.internal.corp", .port = 443 }));
    try std.testing.expect(proxy.bypasses(.{ .scheme = .http, .host = "internal.corp", .port = 80 }));
    try std.testing.expect(!proxy.bypasses(.{ .scheme = .http, .host = "notinternal.corp", .port = 80 }));
    try std.testing.expect(proxy.bypasses(.{ .scheme = .http, .host = "10.0.0.1", .port = 9000 }));
    try std.testing.expect(!proxy.bypasses(.{ .scheme = .http, .host = "10.0.0.1", .port = 80 }));
    try std.testing.expect(!proxy.bypasses(.{ .scheme = .https, .host = "example.com", .port = 443 }));

    var env_map: std.process.Environ.Map = .init(gpa);
    defer env_map.deinit();
    try env_map.put("HTTPS_PROXY", "http://alice:s3cr3t@proxy.local:3128");
    try env_map.put("NO_PROXY", "localhost, .corp.internal");

    var owned = (try ProxyConfig.fromEnv(gpa, &env_map, .https)).?;
    defer owned.deinit(gpa);
    const cfg = owned.config();
    try std.testing.expectEqualStrings("proxy.local", cfg.host);
    try std.testing.expectEqual(@as(u16, 3128), cfg.port);
    try std.testing.expectEqualStrings("Basic YWxpY2U6czNjcjN0", cfg.authorization.?);
    try std.testing.expect(cfg.bypasses(.{ .scheme = .https, .host = "db.corp.internal", .port = 443 }));
    try std.testing.expect(!cfg.bypasses(.{ .scheme = .https, .host = "github.com", .port = 443 }));
}

test "Happy Eyeballs interleaves IPv6/IPv4 and falls back to working peer" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Verify RFC 8305 interleaving: [v6, v6, v4, v4] -> [v6, v4, v6, v4]
    const v6_a = try zio.net.IpAddress.parseIp6("::1", 80);
    const v6_b = try zio.net.IpAddress.parseIp6("::2", 80);
    const v4_a = try zio.net.IpAddress.parseIp4("127.0.0.1", 80);
    const v4_b = try zio.net.IpAddress.parseIp4("127.0.0.2", 80);

    const lookup = [_]zio.net.HostName.LookupResult{
        .{ .address = v6_a },
        .{ .address = v6_b },
        .{ .address = v4_a },
        .{ .address = v4_b },
    };
    var out: [4]zio.net.IpAddress = undefined;
    try std.testing.expectEqual(@as(usize, 4), interleaveDualStack(&lookup, &out));
    try std.testing.expectEqual(zio.net.IpAddress.Family.ipv6, out[0].getFamily());
    try std.testing.expectEqual(zio.net.IpAddress.Family.ipv4, out[1].getFamily());
    try std.testing.expectEqual(zio.net.IpAddress.Family.ipv6, out[2].getFamily());
    try std.testing.expectEqual(zio.net.IpAddress.Family.ipv4, out[3].getFamily());

    // Race a closed port against a live MockServer -> winner succeeds cleanly with 0 leaks.
    const QuickServer = struct {
        fn handle(_: ?*anyopaque, _: zio.net.Stream) void {
            zio.sleep(.fromMilliseconds(50)) catch {};
        }
    };
    var srv: MockServer = undefined;
    try srv.start(null, QuickServer.handle);
    defer srv.stop();

    const dead_addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 1);
    const live_addr = try zio.net.IpAddress.parseIp4("127.0.0.1", srv.port());

    const stream = try happyEyeballsConnect(&.{ dead_addr, live_addr }, .fromMilliseconds(20));
    defer stream.close();
}

test "isPrivateOrLoopback classifies SSRF targets and CaStore.addCertsFromPem rolls back on malformed PEM" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Private / loopback / metadata addresses MUST be detected
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("127.0.0.1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("10.0.0.1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("172.16.5.4", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("192.168.1.1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("169.254.169.254", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("100.64.0.1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("::1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("fc00::1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("fe80::1", 80)));
    try std.testing.expect(isPrivateOrLoopback(try zio.net.IpAddress.parseIp("::ffff:127.0.0.1", 80)));

    // Public addresses MUST be allowed
    try std.testing.expect(!isPrivateOrLoopback(try zio.net.IpAddress.parseIp("1.1.1.1", 443)));
    try std.testing.expect(!isPrivateOrLoopback(try zio.net.IpAddress.parseIp("93.184.216.34", 443)));
    try std.testing.expect(!isPrivateOrLoopback(try zio.net.IpAddress.parseIp("2606:4700:4700::1111", 443)));

    // blockPrivateAddresses rejects dialing loopback before touching the network
    var ca_store: CaStore = .init;
    defer ca_store.deinit(gpa);
    try std.testing.expectError(
        error.AddressBlocked,
        connect(gpa, .{ .scheme = .http, .host = "127.0.0.1", .port = 80 }, .{
            .io = rt.io(),
            .tls = .{ .system = &ca_store },
            .address_filter = blockPrivateAddresses(),
        }),
    );

    // Malformed PEM cert (truncated DER or bad base64) returns an error without
    // panicking and rolls back bundle.bytes.items.len cleanly.
    const bad_der_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    try std.testing.expectError(
        error.InvalidCertificateDer,
        ca_store.addCertsFromPem(gpa, rt.io(), bad_der_pem),
    );
    try std.testing.expectEqual(@as(usize, 0), ca_store.bundle.bytes.items.len);

    const bad_b64_pem = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    try std.testing.expectError(
        error.InvalidCharacter,
        ca_store.addCertsFromPem(gpa, rt.io(), bad_b64_pem),
    );
    try std.testing.expectEqual(@as(usize, 0), ca_store.bundle.bytes.items.len);
}

test "ProxyConfig.fromEnv parses https, socks5, and socks5h proxy URLs" {
    const gpa = std.testing.allocator;

    // 1. https:// proxy with default port 443 and Basic auth
    {
        var env_map: std.process.Environ.Map = .init(gpa);
        defer env_map.deinit();
        try env_map.put("HTTPS_PROXY", "https://bob:pw@secure-proxy.corp");

        var owned = (try ProxyConfig.fromEnv(gpa, &env_map, .https)).?;
        defer owned.deinit(gpa);
        const cfg = owned.config();
        try std.testing.expectEqual(ProxyConfig.Scheme.https, cfg.scheme);
        try std.testing.expectEqualStrings("secure-proxy.corp", cfg.host);
        try std.testing.expectEqual(@as(u16, 443), cfg.port);
        try std.testing.expect(cfg.authorization != null);
        try std.testing.expectEqual(@as(?[]const u8, null), cfg.username);
    }

    // 2. socks5h:// proxy with default port 1080 and RFC 1929 credentials (no Proxy-Authorization)
    {
        var env_map: std.process.Environ.Map = .init(gpa);
        defer env_map.deinit();
        try env_map.put("ALL_PROXY", "socks5h://alice:secret@socks.internal");

        var owned = (try ProxyConfig.fromEnv(gpa, &env_map, .http)).?;
        defer owned.deinit(gpa);
        const cfg = owned.config();
        try std.testing.expectEqual(ProxyConfig.Scheme.socks5h, cfg.scheme);
        try std.testing.expectEqualStrings("socks.internal", cfg.host);
        try std.testing.expectEqual(@as(u16, 1080), cfg.port);
        try std.testing.expectEqual(@as(?[]const u8, null), cfg.authorization);
        try std.testing.expectEqualStrings("alice", cfg.username.?);
        try std.testing.expectEqualStrings("secret", cfg.password.?);
    }
}

test "SOCKS5 and SOCKS5h tunnel handshake: no-auth, RFC 1929 auth, remote DNS, and errors" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const Socks5Mock = struct {
        require_auth: bool = false,
        expected_user: []const u8 = "alice",
        expected_pass: []const u8 = "secret",
        reject_connect: bool = false,
        saw_domain_atyp: std.atomic.Value(bool) = .init(false),
        saw_proxy_auth_header: std.atomic.Value(bool) = .init(false),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            // Step 1: Greeting [VER, NMETHODS, METHODS...]
            var hdr: [2]u8 = undefined;
            sr.interface.readSliceAll(&hdr) catch return;
            if (hdr[0] != 0x05) return;
            var methods: [255]u8 = undefined;
            sr.interface.readSliceAll(methods[0..hdr[1]]) catch return;

            if (self.require_auth) {
                var supports_userpass = false;
                for (methods[0..hdr[1]]) |m| {
                    if (m == 0x02) supports_userpass = true;
                }
                if (!supports_userpass) {
                    sw.interface.writeAll(&.{ 0x05, 0xFF }) catch return;
                    sw.interface.flush() catch return;
                    return;
                }
                sw.interface.writeAll(&.{ 0x05, 0x02 }) catch return;
                sw.interface.flush() catch return;

                // RFC 1929 subnegotiation
                var u_hdr: [2]u8 = undefined;
                sr.interface.readSliceAll(&u_hdr) catch return;
                var user_buf: [255]u8 = undefined;
                sr.interface.readSliceAll(user_buf[0..u_hdr[1]]) catch return;
                var p_len: [1]u8 = undefined;
                sr.interface.readSliceAll(&p_len) catch return;
                var pass_buf: [255]u8 = undefined;
                sr.interface.readSliceAll(pass_buf[0..p_len[0]]) catch return;

                const ok = u_hdr[0] == 0x01 and
                    std.mem.eql(u8, user_buf[0..u_hdr[1]], self.expected_user) and
                    std.mem.eql(u8, pass_buf[0..p_len[0]], self.expected_pass);
                sw.interface.writeAll(&.{ 0x01, if (ok) 0x00 else 0x01 }) catch return;
                sw.interface.flush() catch return;
                if (!ok) return;
            } else {
                sw.interface.writeAll(&.{ 0x05, 0x00 }) catch return;
                sw.interface.flush() catch return;
            }

            // Step 2: CONNECT request
            var req_hdr: [4]u8 = undefined;
            sr.interface.readSliceAll(&req_hdr) catch return;
            if (req_hdr[0] != 0x05 or req_hdr[1] != 0x01) return;

            var host_copy: [256]u8 = undefined;
            var host_len: usize = 0;
            switch (req_hdr[3]) {
                0x01 => {
                    var ip4: [4]u8 = undefined;
                    sr.interface.readSliceAll(&ip4) catch return;
                },
                0x03 => {
                    self.saw_domain_atyp.store(true, .release);
                    var dlen: [1]u8 = undefined;
                    sr.interface.readSliceAll(&dlen) catch return;
                    host_len = dlen[0];
                    sr.interface.readSliceAll(host_copy[0..host_len]) catch return;
                },
                0x04 => {
                    var ip6: [16]u8 = undefined;
                    sr.interface.readSliceAll(&ip6) catch return;
                },
                else => return,
            }
            var port_bytes: [2]u8 = undefined;
            sr.interface.readSliceAll(&port_bytes) catch return;

            if (self.reject_connect) {
                sw.interface.writeAll(&.{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch return;
                sw.interface.flush() catch return;
                return;
            }

            // Reply success (BND 127.0.0.1:0) and act as the tunneled HTTP server directly.
            sw.interface.writeAll(&.{ 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }) catch return;
            sw.interface.flush() catch return;

            // Read HTTP request head inside tunnel and echo the request line + tunneled domain.
            var req_line: [256]u8 = undefined;
            var req_line_len: usize = 0;
            var first = true;
            while (true) {
                const line = sr.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
                if (first) {
                    first = false;
                    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
                    req_line_len = @min(trimmed.len, req_line.len);
                    @memcpy(req_line[0..req_line_len], trimmed[0..req_line_len]);
                } else if (std.ascii.startsWithIgnoreCase(line, "proxy-authorization:")) {
                    self.saw_proxy_auth_header.store(true, .release);
                }
            }

            const body_domain = if (host_len > 0) host_copy[0..host_len] else "ip";
            var resp_body: [512]u8 = undefined;
            const body = std.fmt.bufPrint(&resp_body, "{s}|{s}", .{ req_line[0..req_line_len], body_domain }) catch return;
            sw.interface.print(
                "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                .{ body.len, body },
            ) catch return;
            sw.interface.flush() catch return;
        }
    };

    // 1. socks5h with RFC 1929 auth + unresolvable local domain (proves remote DNS & zero Proxy-Authorization leak)
    {
        var mock: Socks5Mock = .{ .require_auth = true };
        var srv: MockServer = undefined;
        try srv.start(&mock, Socks5Mock.handle);
        defer srv.stop();

        const conn = try connect(gpa, .{
            .scheme = .http,
            .host = "nonexistent.invalid.test",
            .port = 8080,
        }, .{
            .io = rt.io(),
            .tls = .no_verification,
            .proxy = .{
                .scheme = .socks5h,
                .host = "127.0.0.1",
                .port = srv.port(),
                .username = "alice",
                .password = "secret",
            },
        });
        defer conn.destroy(gpa);

        try h1.writeRequestHead(conn.writer(), .{
            .method = .GET,
            .origin = .{ .scheme = .http, .host = "nonexistent.invalid.test", .port = 8080 },
            .target = "/hello",
        });
        try conn.flush();

        var head = try h1.readResponseHead(gpa, conn.reader(), .GET, .{});
        defer head.deinit(gpa);
        try std.testing.expectEqual(http.Status.ok, head.status);

        var br_buf: [256]u8 = undefined;
        var body_reader: h1.BodyReader = undefined;
        body_reader.init(conn.reader(), head.framing, &br_buf);
        var body_buf: [256]u8 = undefined;
        const n = try body_reader.interface.readSliceShort(&body_buf);
        try std.testing.expectEqualStrings("GET /hello HTTP/1.1|nonexistent.invalid.test", body_buf[0..n]);
        try std.testing.expect(mock.saw_domain_atyp.load(.acquire));
        try std.testing.expect(!mock.saw_proxy_auth_header.load(.acquire));

        // Wrong password MUST fail with ProxyAuthRequired
        try std.testing.expectError(
            error.ProxyAuthRequired,
            connect(gpa, .{ .scheme = .http, .host = "nonexistent.invalid.test", .port = 80 }, .{
                .io = rt.io(),
                .tls = .no_verification,
                .proxy = .{
                    .scheme = .socks5h,
                    .host = "127.0.0.1",
                    .port = srv.port(),
                    .username = "alice",
                    .password = "wrong",
                },
            }),
        );
    }

    // 2. SOCKS5 CONNECT refusal (REP=0x05) returns error.ProxyConnectFailed with 0 leaks
    {
        var mock: Socks5Mock = .{ .reject_connect = true };
        var srv: MockServer = undefined;
        try srv.start(&mock, Socks5Mock.handle);
        defer srv.stop();

        try std.testing.expectError(
            error.ProxyConnectFailed,
            connect(gpa, .{ .scheme = .http, .host = "127.0.0.1", .port = 80 }, .{
                .io = rt.io(),
                .tls = .no_verification,
                .proxy = .{
                    .scheme = .socks5,
                    .host = "127.0.0.1",
                    .port = srv.port(),
                },
            }),
        );
    }
}

test "HTTPS TLS-to-proxy initiates TLS ClientHello to proxy for both HTTP and HTTPS targets" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const TlsProbeProxy = struct {
        saw_client_hello: std.atomic.Value(u32) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [512]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var rec: [6]u8 = undefined;
            sr.interface.readSliceAll(&rec) catch return;
            // TLS Record ContentType 0x16 (Handshake), HandshakeType 0x01 (ClientHello)
            if (rec[0] == 0x16 and rec[5] == 0x01) {
                _ = self.saw_client_hello.fetchAdd(1, .acq_rel);
            }
            // Drain the remainder of the TLS record so closing sends a clean TCP FIN.
            const rec_len = std.mem.readInt(u16, rec[3..5], .big);
            if (rec_len > 1) {
                var rem: usize = rec_len - 1;
                var scratch: [256]u8 = undefined;
                while (rem > 0) {
                    const take = @min(rem, scratch.len);
                    sr.interface.readSliceAll(scratch[0..take]) catch break;
                    rem -= take;
                }
            }
        }
    };

    var probe: TlsProbeProxy = .{};
    var srv: MockServer = undefined;
    try srv.start(&probe, TlsProbeProxy.handle);
    defer srv.stop();

    // 1. Plain HTTP target over https:// proxy (single-layer TLS to proxy)
    try std.testing.expectError(
        error.TlsConnectionTruncated,
        connect(gpa, .{ .scheme = .http, .host = "upstream.example", .port = 80 }, .{
            .io = rt.io(),
            .tls = .no_verification,
            .proxy = .{
                .scheme = .https,
                .host = "127.0.0.1",
                .port = srv.port(),
            },
        }),
    );

    // 2. HTTPS target over https:// proxy (TunnelTls double-TLS allocation & cleanup)
    try std.testing.expectError(
        error.TlsConnectionTruncated,
        connect(gpa, .{ .scheme = .https, .host = "upstream.example", .port = 443 }, .{
            .io = rt.io(),
            .tls = .no_verification,
            .proxy = .{
                .scheme = .https,
                .host = "127.0.0.1",
                .port = srv.port(),
            },
        }),
    );

    try std.testing.expectEqual(@as(u32, 2), probe.saw_client_hello.load(.acquire));
}
