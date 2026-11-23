//! High-level async HTTP/1.1 client facade.
//!
//! Orchestrates logical requests across:
//! - Automatic redirects (301/302/303/307/308, RFC 3986 relative resolution,
//!   cross-origin stripping of `Authorization`, `Cookie`, `Proxy-Authorization`)
//! - Transparent content decompression (`gzip`, `deflate`, `zstd`) using
//!   heap-pinned decompression buffers (keeping zio coroutine stacks small)
//! - Scoped total / connect / response-header timeouts via `zio.withTimeout`
//! - Dual API: one-shot `fetch()` (buffered with default 16 MiB OOM cap) and
//!   streaming `open()` -> `PendingRequest` -> `StreamResponse`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const flate = std.compress.flate;
const zstd = std.compress.zstd;

const kite_build_options = @import("kite_build_options");
const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");
const Pool = @import("Pool.zig");
const Transport = @import("Transport.zig");
const CookieJar = @import("CookieJar.zig");

const Client = @This();

pub const default_max_body_bytes: usize = 16 * 1024 * 1024;
const redirect_drain_limit: usize = 4 * 1024;

pub const MaxBody = union(enum) {
    /// Uses `Client.Config.default_max_body_bytes` (default 16 MiB).
    default,
    /// Explicit byte cap for this `fetch()` call.
    limited: usize,
    /// Disables the buffered body cap for this call.
    unlimited,
};

pub const RedirectDecision = enum {
    /// Proceed with following the redirect.
    follow,
    /// Stop following and return the 3xx response directly to the caller.
    stop,
};

pub const RedirectInfo = struct {
    status: http.Status,
    from_url: []const u8,
    to_url: []const u8,
    to_origin: http.Origin,
    /// 1-based redirect hop count.
    hops: u8,
};

/// Optional callback invoked before following each HTTP redirect.
/// Return `.follow` to proceed, `.stop` to return the 3xx response directly,
/// or an error (e.g. `error.RedirectBlocked`) to abort the request.
pub const CheckRedirect = struct {
    ctx: ?*anyopaque = null,
    check: *const fn (ctx: ?*anyopaque, info: RedirectInfo) anyerror!RedirectDecision,
};

pub const Config = struct {
    connect_timeout: zio.Timeout = .fromSeconds(5),
    response_header_timeout: zio.Timeout = .fromSeconds(10),
    /// Per-read idle timeout while streaming a response body (guards against Slowloris).
    read_idle_timeout: zio.Timeout = .none,
    /// Total deadline covering redirects, headers, and body reading in `fetch()`.
    default_timeout: zio.Timeout = .fromSeconds(30),
    /// Maximum automatic redirect hops (0 disables redirect following).
    max_redirects: u8 = 10,
    /// Optional redirect policy hook (e.g. block cross-domain or private-host redirects).
    check_redirect: ?CheckRedirect = null,
    /// Automatically send `Accept-Encoding: gzip, deflate, zstd` (unless caller
    /// set `Accept-Encoding`) and transparently decompress matching responses.
    auto_decompress: bool = true,
    /// Default body size cap for `fetch()` (`null` = unlimited).
    default_max_body_bytes: ?usize = default_max_body_bytes,
    /// Default `User-Agent` header sent when caller did not specify one (`null` omits it).
    user_agent: ?[]const u8 = kite_build_options.name ++ "/" ++ kite_build_options.version,
    /// Optional RFC 6265 cookie jar shared across requests and redirect hops.
    cookie_jar: ?*CookieJar = null,
    parse_options: h1.ParseOptions = .{},
    pool: Pool.Config = .{},
};

pub const RequestOptions = struct {
    method: http.Method = .GET,
    url: []const u8,
    headers: []const http.Header = &.{},
    body: Transport.RequestBody = .none,
    /// In `fetch()`: overrides `Config.default_timeout` for the full request + redirects + body read.
    /// In `open()`: when explicitly set, enforces a shared deadline across `open()` and `receiveHead()`
    /// (including redirects); body streaming after `receiveHead()` uses `read_idle_timeout` or
    /// caller-scoped `zio.withTimeout`.
    timeout: ?zio.Timeout = null,
    /// Overrides `Config.connect_timeout` for this request.
    connect_timeout: ?zio.Timeout = null,
    /// Overrides `Config.response_header_timeout` for this request.
    response_header_timeout: ?zio.Timeout = null,
    /// Overrides `Config.read_idle_timeout` for this request.
    read_idle_timeout: ?zio.Timeout = null,
    /// When non-null on a body-bearing request, sends `Expect: 100-continue` and waits
    /// up to this duration for `100 Continue` or an early rejection before sending the body.
    expect_continue_timeout: ?zio.Timeout = null,
    /// Overrides `Config.max_redirects` for this request.
    max_redirects: ?u8 = null,
    /// Overrides `Config.check_redirect` for this request.
    check_redirect: ?CheckRedirect = null,
    /// Overrides `Config.auto_decompress` for this request.
    auto_decompress: ?bool = null,
    /// Overrides `Config.default_max_body_bytes` for `fetch()`.
    max_body_bytes: MaxBody = .default,
    /// Sends `Connection: close` and disables keep-alive reuse for this request.
    close_connection: bool = false,
};

pub const FormField = struct {
    name: []const u8,
    value: []const u8,
};

/// Buffered response returned by `Client.fetch()`.
///
/// The underlying network connection has already been returned to the pool (or
/// closed) before `fetch()` returns; `deinit()` simply frees owned memory.
pub const Response = struct {
    gpa: Allocator,
    status: http.Status,
    reason: []const u8,
    headers: http.Headers,
    body: []u8,
    final_url: []u8,
    /// True when Kite transparently decompressed the response body (in which case
    /// the original `Content-Encoding` and compressed `Content-Length` headers
    /// have been removed from `headers`).
    decompressed: bool = false,

    pub fn deinit(self: *Response) void {
        self.gpa.free(self.reason);
        self.headers.deinit(self.gpa);
        self.gpa.free(self.body);
        self.gpa.free(self.final_url);
        self.* = undefined;
    }

    /// Parses the buffered response body as JSON using `std.json.parseFromSlice`.
    pub fn json(
        self: *const Response,
        comptime T: type,
        gpa: Allocator,
        options: std.json.ParseOptions,
    ) !std.json.Parsed(T) {
        return std.json.parseFromSlice(T, gpa, self.body, options);
    }
};

/// Heap-pinned transparent decompressor wrapping an `Exchange`'s body reader.
///
/// Design details:
/// - Allocated strictly when a response actually carries compressed content so
///   uncompressed responses pay zero window memory and coroutine stacks stay tiny.
/// - Exposes a thin `wrapper: Reader` that automatically probes the underlying
///   HTTP `BodyReader` on decompressor EOF so `gzip + chunked` responses consume
///   the trailing `0\r\n\r\n` terminator even when callers read manually via
///   `StreamResponse.reader()` instead of `readAll()`.
/// - Auto-detects RFC 1950 zlib vs raw deflate streams for `Content-Encoding: deflate`.
const Decompressor = struct {
    gpa: Allocator,
    kind: Kind,
    underlying: *Reader,
    window: []u8,
    impl: Impl,
    drained_eof: bool = false,
    wrapper: Reader,

    const Kind = enum {
        gzip,
        deflate,
        zstd,
    };

    const Impl = union(enum) {
        deflate_pending,
        flate: flate.Decompress,
        zstd: zstd.Decompress,
        empty_eof,
    };

    fn parseContentEncoding(headers: *const http.Headers) ?Kind {
        const raw = headers.get("Content-Encoding") orelse return null;
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, "gzip") or std.ascii.eqlIgnoreCase(trimmed, "x-gzip")) {
            return .gzip;
        }
        if (std.ascii.eqlIgnoreCase(trimmed, "deflate")) return .deflate;
        if (std.ascii.eqlIgnoreCase(trimmed, "zstd")) return .zstd;
        return null;
    }

    fn isZlibHeader(header: *const [2]u8) bool {
        const cmf = header[0];
        const flg = header[1];
        // RFC 1950 §2.2: CM == 8 (deflate), CINFO <= 7, and (CMF * 256 + FLG) % 31 == 0.
        return (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and
            ((@as(u16, cmf) * 256 + @as(u16, flg)) % 31 == 0);
    }

    fn create(gpa: Allocator, input: *Reader, kind: Kind) Allocator.Error!*Decompressor {
        const window_len: usize = switch (kind) {
            .gzip, .deflate => flate.max_window_len,
            .zstd => zstd.default_window_len + zstd.block_size_max,
        };
        const window = try gpa.alloc(u8, window_len);
        errdefer gpa.free(window);

        const dec = try gpa.create(Decompressor);
        dec.* = .{
            .gpa = gpa,
            .kind = kind,
            .underlying = input,
            .window = window,
            .impl = switch (kind) {
                .gzip => .{ .flate = .init(input, .gzip, window) },
                // Lazily detect RFC 1950 zlib vs raw deflate on first body read so
                // `receiveHead()` never blocks on body bytes or swallows read errors.
                .deflate => .deflate_pending,
                .zstd => .{ .zstd = .init(input, window, .{ .verify_checksum = true }) },
            },
            .wrapper = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
        return dec;
    }

    fn drainUnderlyingEof(self: *Decompressor) void {
        if (!self.drained_eof) {
            self.drained_eof = true;
            // Pull the trailing zero-payload chunk terminator (`0\r\n\r\n`) so
            // keep-alive connections remain reusable for streaming readers too.
            var probe: [1]u8 = undefined;
            _ = self.underlying.readSliceShort(&probe) catch {};
        }
    }

    fn reader(self: *Decompressor) *Reader {
        return &self.wrapper;
    }

    fn streamImpl(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *Decompressor = @alignCast(@fieldParentPtr("wrapper", r));

        if (self.impl == .empty_eof) return error.EndOfStream;

        if (self.impl == .deflate_pending) {
            const header = self.underlying.peek(2) catch |err| switch (err) {
                error.EndOfStream => {
                    if (self.underlying.bufferedLen() == 0) {
                        self.impl = .empty_eof;
                        self.drainUnderlyingEof();
                        return error.EndOfStream;
                    }
                    // Single trailing byte: let raw deflate surface the truncation error cleanly.
                    self.impl = .{ .flate = .init(self.underlying, .raw, self.window) };
                    return self.impl.flate.reader.stream(w, limit);
                },
                error.ReadFailed => return error.ReadFailed,
            };
            const container: flate.Container = if (isZlibHeader(header[0..2])) .zlib else .raw;
            self.impl = .{ .flate = .init(self.underlying, container, self.window) };
        }

        const inner: *Reader = switch (self.impl) {
            .flate => |*f| &f.reader,
            .zstd => |*z| &z.reader,
            .deflate_pending, .empty_eof => unreachable,
        };

        return inner.stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => {
                self.drainUnderlyingEof();
                return error.EndOfStream;
            },
            else => |e| return e,
        };
    }

    fn unwrapError(self: *const Decompressor) ?anyerror {
        return switch (self.impl) {
            .flate => |*f| f.err,
            .zstd => |*z| z.err,
            .deflate_pending, .empty_eof => null,
        };
    }

    fn destroy(self: *Decompressor) void {
        const gpa = self.gpa;
        gpa.free(self.window);
        gpa.destroy(self);
    }
};

/// Active streaming response holding a linear `Transport.Exchange` lease.
///
/// Always `defer stream.deinit()`. Dropping before reading the body to EOF
/// automatically discards the underlying connection instead of returning it dirty.
pub const StreamResponse = struct {
    gpa: Allocator,
    exchange: Transport.Exchange,
    head: *const h1.ResponseHead,
    final_url: []u8,
    decompressor: ?*Decompressor = null,

    pub fn status(self: *const StreamResponse) http.Status {
        return self.head.status;
    }

    pub fn reason(self: *const StreamResponse) []const u8 {
        return self.head.reason;
    }

    pub fn headers(self: *const StreamResponse) *const http.Headers {
        return &self.head.headers;
    }

    /// True if `reader()` transparently decompresses the wire response body.
    pub fn isDecompressed(self: *const StreamResponse) bool {
        return self.decompressor != null;
    }

    pub fn reader(self: *StreamResponse) *Reader {
        if (self.decompressor) |dec| return dec.reader();
        return self.exchange.reader();
    }

    pub fn unwrapReadError(self: *const StreamResponse) ?anyerror {
        if (self.decompressor) |dec| {
            if (dec.unwrapError()) |de_err| {
                if (de_err != error.ReadFailed) return de_err;
            }
        }
        return self.exchange.unwrapReadError();
    }

    /// Reads the entire remaining stream into an owned slice, enforcing `max_bytes`.
    pub fn readAll(self: *StreamResponse, gpa: Allocator, max_bytes: ?usize) ![]u8 {
        var out: Writer.Allocating = .init(gpa);
        errdefer out.deinit();

        const r = self.reader();
        var buf: [4096]u8 = undefined;

        while (true) {
            const n = r.readSliceShort(&buf) catch |err| switch (err) {
                error.ReadFailed => return self.unwrapReadError() orelse error.ReadFailed,
            };
            if (n == 0) break;

            if (max_bytes) |limit| {
                if (out.written().len + n > limit) return error.BodyTooLarge;
            }
            try out.writer.writeAll(buf[0..n]);
        }

        return out.toOwnedSlice();
    }

    pub fn deinit(self: *StreamResponse) void {
        if (self.decompressor) |dec| {
            dec.destroy();
            self.decompressor = null;
        }
        self.exchange.deinit();
        if (self.final_url.len > 0) {
            self.gpa.free(self.final_url);
            self.final_url = &.{};
        }
    }
};

/// In-flight streaming request returned by `Client.open()`.
///
/// For streaming bodies (`stream_fixed` / `stream_chunked`), write via `writer()`
/// and then call `receiveHead()` (which auto-finishes the request body and transfers
/// ownership of the connection lease into `StreamResponse`).
pub const PendingRequest = struct {
    client: *Client,
    exchange: ?Transport.Exchange,
    current_url: []u8,
    method: http.Method,
    headers: http.Headers,
    body: Transport.RequestBody,
    connect_timeout: zio.Timeout,
    response_header_timeout: zio.Timeout,
    read_idle_timeout: zio.Timeout,
    expect_continue_timeout: ?zio.Timeout,
    open_deadline: ?zio.Timestamp = null,
    max_redirects: u8,
    check_redirect: ?CheckRedirect = null,
    auto_decompress: bool,
    caller_set_accept_encoding: bool,
    caller_set_cookie: bool,
    close_connection: bool,

    pub fn writer(self: *PendingRequest) *Writer {
        return self.exchange.?.writer();
    }

    pub fn unwrapWriteError(self: *const PendingRequest) ?anyerror {
        const ex = &(self.exchange orelse return null);
        return ex.unwrapWriteError();
    }

    /// Finishes sending any open request body, follows redirects according to
    /// RFC 9110 §15.4, sets up transparent decompression when negotiated, and
    /// transfers ownership of the connection lease to the returned `StreamResponse`.
    pub fn receiveHead(self: *PendingRequest) !StreamResponse {
        if (self.open_deadline) |dl| {
            return zio.withTimeout(.{ .deadline = dl }, receiveHeadInner, .{self});
        }
        return self.receiveHeadInner();
    }

    fn receiveHeadInner(self: *PendingRequest) !StreamResponse {
        var hops: u8 = 0;

        while (true) {
            var ex = self.exchange orelse return error.AlreadyReceived;
            const head = ex.receiveHead() catch |err| {
                self.exchange = ex;
                return err;
            };

            // Persist any Set-Cookie headers into the optional CookieJar before
            // deciding whether to follow a redirect so login-then-redirect works seamlessly.
            if (self.client.config.cookie_jar) |jar| {
                const cur_uri = try std.Uri.parse(self.current_url);
                var cur_hbuf: [http.Origin.max_host_len]u8 = undefined;
                const cur_origin = try http.Origin.fromUri(cur_uri, &cur_hbuf);
                const cur_target = try extractRequestTarget(self.current_url);
                try jar.storeFromHeaders(cur_origin, cur_target, &head.headers);
            }

            if (head.status.isRedirect() and self.max_redirects > 0) {
                if (head.headers.get("Location")) |location| {
                    if (hops >= self.max_redirects) {
                        self.exchange = ex;
                        return error.TooManyRedirects;
                    }
                    hops += 1;

                    const follow_next = try self.prepareRedirectHop(head.status, location, hops);
                    if (follow_next) |next| {
                        // Drain small redirect body so the previous connection can return to pool.
                        drainSmallBody(&ex);
                        ex.deinit();
                        self.exchange = null;

                        self.client.gpa.free(self.current_url);
                        self.current_url = next.url;
                        self.method = next.method;
                        self.body = next.body;

                        self.exchange = try self.openHopExchange(next.origin, next.target);
                        continue;
                    }
                    // `check_redirect` returned `.stop`: fall through and return this 3xx response.
                }
            }

            // Final non-redirect response: linearly transfer Exchange and URL to StreamResponse.
            self.exchange = null;
            errdefer ex.deinit();

            const final_url = self.current_url;
            self.current_url = &.{};
            errdefer self.client.gpa.free(final_url);

            var dec: ?*Decompressor = null;
            errdefer if (dec) |d| d.destroy();

            const has_body = switch (head.framing) {
                .none => false,
                .fixed => |n| n > 0,
                .chunked, .close_delimited => true,
            };
            if (self.auto_decompress and !self.caller_set_accept_encoding and has_body) {
                if (Decompressor.parseContentEncoding(&head.headers)) |kind| {
                    dec = try Decompressor.create(self.client.gpa, ex.reader(), kind);
                }
            }

            return .{
                .gpa = self.client.gpa,
                .exchange = ex,
                .head = head,
                .final_url = final_url,
                .decompressor = dec,
            };
        }
    }

    pub fn deinit(self: *PendingRequest) void {
        if (self.exchange) |*ex| {
            ex.deinit();
            self.exchange = null;
        }
        if (self.current_url.len > 0) {
            self.client.gpa.free(self.current_url);
            self.current_url = &.{};
        }
        self.headers.deinit(self.client.gpa);
    }

    const NextHop = struct {
        url: []u8,
        origin: http.Origin,
        target: []const u8,
        method: http.Method,
        body: Transport.RequestBody,
    };

    fn prepareRedirectHop(self: *PendingRequest, status: http.Status, location: []const u8, hops: u8) !?NextHop {
        const gpa = self.client.gpa;

        const prev_uri = try std.Uri.parse(self.current_url);
        var prev_host_buf: [http.Origin.max_host_len]u8 = undefined;
        const prev_origin = try http.Origin.fromUri(prev_uri, &prev_host_buf);

        const next_url = try resolveRedirectUrl(gpa, prev_uri, location);
        errdefer gpa.free(next_url);

        const next_uri = try std.Uri.parse(next_url);
        var next_host_buf: [http.Origin.max_host_len]u8 = undefined;
        const next_origin = try http.Origin.fromUri(next_uri, &next_host_buf);

        // Security invariant (I-UDS-2): never allow a network HTTP/HTTPS response to
        // redirect into a local Unix domain socket (prevents SSRF -> local daemon escalation).
        if (prev_origin.scheme != .http_unix and next_origin.scheme == .http_unix) {
            return error.UnixSocketRedirectBlocked;
        }

        if (self.check_redirect) |hook| {
            const decision = try hook.check(hook.ctx, .{
                .status = status,
                .from_url = self.current_url,
                .to_url = next_url,
                .to_origin = next_origin,
                .hops = hops,
            });
            if (decision == .stop) {
                gpa.free(next_url);
                return null;
            }
        }

        // RFC 9110 §15.4 method and body transition rules:
        // - 301/302: rewrite POST -> GET and drop body; preserve other methods.
        // - 303: rewrite any non-GET/HEAD -> GET and drop body.
        // - 307/308: strictly preserve method and body.
        const convert_to_get = switch (status) {
            .moved_permanently, .found => self.method.eql(.POST),
            .see_other => !self.method.eql(.GET) and !self.method.eql(.HEAD),
            .temporary_redirect, .permanent_redirect => false,
            else => false,
        };

        const next_method: http.Method = if (convert_to_get) .GET else self.method;
        const next_body: Transport.RequestBody = if (convert_to_get) .none else self.body;

        if (!next_body.isRewindable()) {
            return error.CannotReplayBody;
        }

        if (convert_to_get) {
            _ = self.headers.removeAll(gpa, "Content-Type");
            _ = self.headers.removeAll(gpa, "Content-Encoding");
            _ = self.headers.removeAll(gpa, "Content-Language");
            _ = self.headers.removeAll(gpa, "Content-Location");
        }

        // Security invariant: strip sensitive credentials on cross-origin redirect.
        if (!prev_origin.eql(next_origin)) {
            _ = self.headers.removeAll(gpa, "Authorization");
            _ = self.headers.removeAll(gpa, "Cookie");
            _ = self.headers.removeAll(gpa, "Proxy-Authorization");
            self.caller_set_cookie = false;
        }

        // Remove any explicit Host header so the new Origin's canonical Host is emitted.
        _ = self.headers.removeAll(gpa, "Host");

        const next_target = try extractRequestTarget(next_url);

        // Refresh jar-managed Cookie header for the next hop's exact (origin, path).
        if (self.client.config.cookie_jar) |jar| {
            if (!self.caller_set_cookie) {
                _ = self.headers.removeAll(gpa, "Cookie");
                if (try jar.cookieHeaderAlloc(gpa, next_origin, next_target)) |cookie_val| {
                    defer gpa.free(cookie_val);
                    try self.headers.append(gpa, "Cookie", cookie_val);
                }
            }
        }

        return .{
            .url = next_url,
            .origin = next_origin,
            .target = next_target,
            .method = next_method,
            .body = next_body,
        };
    }

    fn openHopExchange(self: *PendingRequest, origin: http.Origin, target: []const u8) !Transport.Exchange {
        return self.client.activeTransport().openExchange(.{
            .method = self.method,
            .origin = origin,
            .target = target,
            .headers = self.headers.items(),
            .body = self.body,
            .parse_options = self.client.config.parse_options,
            .connect_timeout = self.connect_timeout,
            .response_header_timeout = self.response_header_timeout,
            .read_idle_timeout = self.read_idle_timeout,
            .expect_continue_timeout = self.expect_continue_timeout,
            .close_connection = self.close_connection,
        });
    }
};

gpa: Allocator,
config: Config,
pool: Pool,
custom_transport: ?Transport = null,

/// Initializes a `Client` backed by its own built-in `Pool`.
/// Safe to return by value (never stores internal self-pointers).
pub fn init(gpa: Allocator, io: std.Io, config: Config) Client {
    return .{
        .gpa = gpa,
        .config = config,
        .pool = Pool.init(gpa, io, config.pool),
        .custom_transport = null,
    };
}

/// Initializes a `Client` backed by a caller-supplied `Transport` (e.g. `MockTransport`
/// for offline tests or a `RetryTransport` decorator).
pub fn initWithTransport(gpa: Allocator, io: std.Io, tr: Transport, config: Config) Client {
    return .{
        .gpa = gpa,
        .config = config,
        .pool = Pool.init(gpa, io, config.pool),
        .custom_transport = tr,
    };
}

pub fn deinit(self: *Client) void {
    self.pool.deinit();
    self.* = undefined;
}

pub fn activeTransport(self: *Client) Transport {
    if (self.custom_transport) |tr| return tr;
    return self.pool.transport();
}

/// Opens a streaming HTTP request. Caller must `defer req.deinit()`.
pub fn open(self: *Client, opts: RequestOptions) !PendingRequest {
    const deadline: ?zio.Timestamp = if (opts.timeout) |t| switch (t) {
        .none => null,
        .duration => |d| .{ .value = zio.Timestamp.now(.awake).value +| d.value },
        .deadline => |dl| dl,
    } else null;

    if (deadline) |dl| {
        return zio.withTimeout(.{ .deadline = dl }, openInner, .{ self, opts, deadline });
    }
    return self.openInner(opts, null);
}

fn openInner(self: *Client, opts: RequestOptions, open_deadline: ?zio.Timestamp) !PendingRequest {
    const uri = try std.Uri.parse(opts.url);
    var host_buf: [http.Origin.max_host_len]u8 = undefined;
    const origin = try http.Origin.fromUri(uri, &host_buf);

    const url_copy = try normalizeUrl(self.gpa, opts.url);
    errdefer self.gpa.free(url_copy);

    const auto_decompress = opts.auto_decompress orelse self.config.auto_decompress;
    var headers: http.Headers = .empty;
    errdefer headers.deinit(self.gpa);

    var caller_set_accept_encoding = false;
    var caller_set_user_agent = false;
    var caller_set_cookie = false;
    for (opts.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Accept-Encoding")) caller_set_accept_encoding = true;
        if (std.ascii.eqlIgnoreCase(h.name, "User-Agent")) caller_set_user_agent = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Cookie")) caller_set_cookie = true;
        try headers.append(self.gpa, h.name, h.value);
    }

    if (auto_decompress and !caller_set_accept_encoding) {
        try headers.append(self.gpa, "Accept-Encoding", "gzip, deflate, zstd");
    }
    if (!caller_set_user_agent) {
        if (self.config.user_agent) |ua| {
            try headers.append(self.gpa, "User-Agent", ua);
        }
    }

    const connect_timeout = opts.connect_timeout orelse self.config.connect_timeout;
    const response_header_timeout = opts.response_header_timeout orelse self.config.response_header_timeout;
    const read_idle_timeout = opts.read_idle_timeout orelse self.config.read_idle_timeout;

    const target = try extractRequestTarget(url_copy);
    if (self.config.cookie_jar) |jar| {
        if (!caller_set_cookie) {
            if (try jar.cookieHeaderAlloc(self.gpa, origin, target)) |cookie_val| {
                defer self.gpa.free(cookie_val);
                try headers.append(self.gpa, "Cookie", cookie_val);
            }
        }
    }
    const exchange = try self.activeTransport().openExchange(.{
        .method = opts.method,
        .origin = origin,
        .target = target,
        .headers = headers.items(),
        .body = opts.body,
        .parse_options = self.config.parse_options,
        .connect_timeout = connect_timeout,
        .response_header_timeout = response_header_timeout,
        .read_idle_timeout = read_idle_timeout,
        .expect_continue_timeout = opts.expect_continue_timeout,
        .close_connection = opts.close_connection,
    });

    return .{
        .client = self,
        .exchange = exchange,
        .current_url = url_copy,
        .method = opts.method,
        .headers = headers,
        .body = opts.body,
        .connect_timeout = connect_timeout,
        .response_header_timeout = response_header_timeout,
        .read_idle_timeout = read_idle_timeout,
        .expect_continue_timeout = opts.expect_continue_timeout,
        .open_deadline = open_deadline,
        .max_redirects = opts.max_redirects orelse self.config.max_redirects,
        .check_redirect = opts.check_redirect orelse self.config.check_redirect,
        .auto_decompress = auto_decompress,
        .caller_set_accept_encoding = caller_set_accept_encoding,
        .caller_set_cookie = caller_set_cookie,
        .close_connection = opts.close_connection,
    };
}

/// Executes a complete HTTP request (including redirects, decompression, and
/// total timeout) and returns an owned buffered `Response`.
pub fn fetch(self: *Client, opts: RequestOptions) !Response {
    const total_timeout = opts.timeout orelse self.config.default_timeout;
    return zio.withTimeout(total_timeout, fetchInner, .{ self, opts });
}

fn fetchInner(self: *Client, opts: RequestOptions) !Response {
    var req = try self.openInner(opts, null);
    defer req.deinit();

    var stream = try req.receiveHead();
    defer stream.deinit();

    const max_bytes: ?usize = switch (opts.max_body_bytes) {
        .default => self.config.default_max_body_bytes,
        .limited => |n| n,
        .unlimited => null,
    };

    const body = try stream.readAll(self.gpa, max_bytes);
    errdefer self.gpa.free(body);

    const was_decompressed = stream.isDecompressed();

    // Move final_url and parsed ResponseHead directly into Response (zero redundant copies).
    const final_url = stream.final_url;
    stream.final_url = &.{};
    errdefer self.gpa.free(final_url);

    if (stream.exchange.takeHead()) |moved_head| {
        var hdrs = moved_head.headers;
        if (was_decompressed) {
            _ = hdrs.removeAll(self.gpa, "Content-Encoding");
            _ = hdrs.removeAll(self.gpa, "Content-Length");
        }
        return .{
            .gpa = self.gpa,
            .status = moved_head.status,
            .reason = moved_head.reason,
            .headers = hdrs,
            .body = body,
            .final_url = final_url,
            .decompressed = was_decompressed,
        };
    }

    const reason = try self.gpa.dupe(u8, stream.reason());
    errdefer self.gpa.free(reason);

    var headers: http.Headers = .empty;
    errdefer headers.deinit(self.gpa);
    for (stream.headers().items()) |h| {
        if (was_decompressed and
            (std.ascii.eqlIgnoreCase(h.name, "Content-Encoding") or
                std.ascii.eqlIgnoreCase(h.name, "Content-Length")))
        {
            continue;
        }
        try headers.append(self.gpa, h.name, h.value);
    }

    return .{
        .gpa = self.gpa,
        .status = stream.status(),
        .reason = reason,
        .headers = headers,
        .body = body,
        .final_url = final_url,
        .decompressed = was_decompressed,
    };
}

/// Convenience shortcut for a plain `GET` request.
pub fn get(self: *Client, url: []const u8) !Response {
    return self.fetch(.{ .method = .GET, .url = url });
}

/// Convenience shortcut that serializes `payload` as JSON and sends `POST` with
/// `Content-Type: application/json`.
pub fn postJson(
    self: *Client,
    url: []const u8,
    payload: anytype,
    extra_headers: []const http.Header,
) !Response {
    const json_body = try self.gpa.print("{f}", .{std.json.fmt(payload, .{})});
    defer self.gpa.free(json_body);

    var combined: std.ArrayList(http.Header) = .empty;
    defer combined.deinit(self.gpa);
    try combined.ensureTotalCapacity(self.gpa, extra_headers.len + 1);

    var has_ct = false;
    for (extra_headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) has_ct = true;
        combined.appendAssumeCapacity(h);
    }
    if (!has_ct) {
        combined.appendAssumeCapacity(.{ .name = "Content-Type", .value = "application/json" });
    }

    return self.fetch(.{
        .method = .POST,
        .url = url,
        .headers = combined.items,
        .body = .{ .bytes = json_body },
    });
}

/// Builds an owned `Authorization: Basic ...` header value. Caller frees returned slice.
pub fn basicAuthValue(gpa: Allocator, username: []const u8, password: []const u8) Allocator.Error![]u8 {
    const raw = try gpa.print("{s}:{s}", .{ username, password });
    defer gpa.free(raw);

    const enc_len = std.base64.standard.Encoder.calcSize(raw.len);
    const out = try gpa.alloc(u8, "Basic ".len + enc_len);
    @memcpy(out[0.."Basic ".len], "Basic ");
    _ = std.base64.standard.Encoder.encode(out["Basic ".len..], raw);
    return out;
}

/// Builds an owned `Authorization: Bearer ...` header value. Caller frees returned slice.
pub fn bearerAuthValue(gpa: Allocator, token: []const u8) Allocator.Error![]u8 {
    return gpa.print("Bearer {s}", .{token});
}

/// Encodes key/value pairs into an owned `application/x-www-form-urlencoded` string
/// (usable as either a URL query string or POST form body).
pub fn encodeForm(gpa: Allocator, fields: []const FormField) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    for (fields, 0..) |field, i| {
        if (i > 0) try out.append(gpa, '&');
        try appendPercentEncoded(&out, gpa, field.name);
        try out.append(gpa, '=');
        try appendPercentEncoded(&out, gpa, field.value);
    }
    return out.toOwnedSlice(gpa);
}

fn appendPercentEncoded(out: *std.ArrayList(u8), gpa: Allocator, input: []const u8) Allocator.Error!void {
    const hex = "0123456789ABCDEF";
    for (input) |c| {
        const unreserved = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved) {
            try out.append(gpa, c);
        } else {
            try out.appendSlice(gpa, &.{ '%', hex[c >> 4], hex[c & 0x0F] });
        }
    }
}

fn drainSmallBody(ex: *Transport.Exchange) void {
    const r = ex.reader();
    var buf: [512]u8 = undefined;
    var drained: usize = 0;
    while (drained < redirect_drain_limit) {
        const n = r.readSliceShort(&buf) catch return;
        if (n == 0) return;
        drained += n;
    }
}

/// Copies `url` while stripping any `#fragment` and inserting `/` before `?`
/// when the path is empty (e.g. `http://example.com?a=1` -> `http://example.com/?a=1`),
/// ensuring origin-form request-target extraction is always a zero-copy slice.
fn normalizeUrl(gpa: Allocator, url: []const u8) ![]u8 {
    const no_frag = if (std.mem.findScalar(u8, url, '#')) |idx| url[0..idx] else url;
    const scheme_sep = std.mem.find(u8, no_frag, "://") orelse return error.InvalidUri;
    const after_scheme = no_frag[scheme_sep + 3 ..];

    if (std.mem.findAny(u8, after_scheme, "/?")) |idx| {
        if (after_scheme[idx] == '?') {
            const split = scheme_sep + 3 + idx;
            return gpa.print("{s}/{s}", .{ no_frag[0..split], no_frag[split..] });
        }
    }
    return gpa.dupe(u8, no_frag);
}

/// Extracts the origin-form request-target (`/path?query`) from a normalized URL.
fn extractRequestTarget(normalized_url: []const u8) ![]const u8 {
    const scheme_sep = std.mem.find(u8, normalized_url, "://") orelse return error.InvalidUri;
    const after_scheme = normalized_url[scheme_sep + 3 ..];
    if (std.mem.findScalar(u8, after_scheme, '/')) |idx| {
        return after_scheme[idx..];
    }
    return "/";
}

/// Resolves an absolute or relative `Location` header against `base` per RFC 3986 §5.2.
/// Tolerates unescaped spaces in real-world `Location` headers by encoding them as `%20`.
fn resolveRedirectUrl(gpa: Allocator, base: std.Uri, location: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, location, " \t");
    if (trimmed.len == 0) return error.InvalidRedirectLocation;

    var space_count: usize = 0;
    for (trimmed) |c| {
        if (c == ' ') space_count += 1;
    }

    const sanitized_len = trimmed.len + space_count * 2;
    const buf_len = sanitized_len + 256 + base.path.percent_encoded.len;
    const scratch = try gpa.alloc(u8, buf_len);
    defer gpa.free(scratch);

    if (space_count == 0) {
        @memcpy(scratch[0..trimmed.len], trimmed);
    } else {
        var pos: usize = 0;
        for (trimmed) |c| {
            if (c == ' ') {
                @memcpy(scratch[pos .. pos + 3], "%20");
                pos += 3;
            } else {
                scratch[pos] = c;
                pos += 1;
            }
        }
    }
    var aux: []u8 = scratch;
    const resolved = try base.resolveInPlace(sanitized_len, &aux);

    // Format normalized absolute URL without fragment (and ensure empty path with query gets `/`).
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();

    try out.writer.print("{s}://", .{resolved.scheme});
    if (resolved.host) |h| {
        if (std.ascii.eqlIgnoreCase(resolved.scheme, "http+unix")) {
            try out.writer.writeAll(h.percent_encoded);
        } else {
            var hbuf: [http.Origin.max_host_len]u8 = undefined;
            const host_raw = try h.toRaw(&hbuf);
            if (std.mem.findScalar(u8, host_raw, ':') != null and host_raw[0] != '[') {
                try out.writer.print("[{s}]", .{host_raw});
            } else {
                try out.writer.writeAll(host_raw);
            }
        }
    }
    if (resolved.port) |p| {
        try out.writer.print(":{d}", .{p});
    }
    if (resolved.path.isEmpty()) {
        try out.writer.writeByte('/');
    } else {
        try resolved.path.formatEscaped(&out.writer);
    }
    if (resolved.query) |q| {
        try out.writer.writeByte('?');
        try q.formatEscaped(&out.writer);
    }
    return out.toOwnedSlice();
}

// ===========================================================================
// Unit & Integration Tests (MockTransport + real loopback MockServer)
// ===========================================================================

const MockTransport = @import("testing/MockTransport.zig");
const MockServer = @import("testing/MockServer.zig");

test "Client redirect matrix: 302 POST->GET, 307 preserves POST, cross-origin strips Authorization/Cookie" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Scenario A: POST https://auth.a.com/login -> 302 relative /step2 (same origin, keeps Auth, drops POST body)
    //          -> 302 https://app.b.com/home (cross origin, strips Authorization & Cookie) -> 200 OK
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "../step2?ok=1" }},
        });
        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "https://app.b.com/home" }},
        });
        try mock.pushResponse(.{
            .status = .ok,
            .body = "welcome",
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var res = try client.fetch(.{
            .method = .POST,
            .url = "https://auth.a.com/v1/login",
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer secret-token" },
                .{ .name = "Cookie", .value = "sid=123" },
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "X-Trace", .value = "trace-1" },
            },
            .body = .{ .bytes = "{\"user\":\"alice\"}" },
        });
        defer res.deinit();

        try std.testing.expectEqual(http.Status.ok, res.status);
        try std.testing.expectEqualStrings("welcome", res.body);
        try std.testing.expectEqualStrings("https://app.b.com/home", res.final_url);

        const reqs = mock.requests();
        try std.testing.expectEqual(@as(usize, 3), reqs.len);

        // Hop 1: original POST with credentials & body
        try std.testing.expectEqual(http.Method.POST, reqs[0].method);
        try std.testing.expectEqualStrings("/v1/login", reqs[0].target);
        try std.testing.expectEqualStrings("{\"user\":\"alice\"}", reqs[0].body);

        // Hop 2: same-origin relative redirect => converted to GET, body & Content-Type dropped, Auth kept!
        try std.testing.expectEqual(http.Method.GET, reqs[1].method);
        try std.testing.expectEqualStrings("/step2?ok=1", reqs[1].target);
        try std.testing.expectEqualStrings("", reqs[1].body);
        try std.testing.expect(!reqs[1].headers.has("Content-Type"));
        try std.testing.expectEqualStrings("Bearer secret-token", reqs[1].headers.get("Authorization").?);
        try std.testing.expectEqualStrings("sid=123", reqs[1].headers.get("Cookie").?);

        // Hop 3: cross-origin redirect => Authorization & Cookie STRIPPED, X-Trace preserved!
        try std.testing.expectEqual(http.Method.GET, reqs[2].method);
        try std.testing.expectEqualStrings("app.b.com", reqs[2].origin.host);
        try std.testing.expect(!reqs[2].headers.has("Authorization"));
        try std.testing.expect(!reqs[2].headers.has("Cookie"));
        try std.testing.expectEqualStrings("trace-1", reqs[2].headers.get("X-Trace").?);
    }

    // Scenario B: 307 Temporary Redirect strictly preserves POST method and body
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        try mock.pushResponse(.{
            .status = .temporary_redirect,
            .headers = &.{.{ .name = "Location", .value = "/v2/items" }},
        });
        try mock.pushResponse(.{ .status = .created, .body = "created" });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var res = try client.fetch(.{
            .method = .POST,
            .url = "https://api.example.com/v1/items",
            .body = .{ .bytes = "payload=42" },
        });
        defer res.deinit();

        try std.testing.expectEqual(http.Status.created, res.status);
        try std.testing.expectEqual(http.Method.POST, mock.requests()[1].method);
        try std.testing.expectEqualStrings("payload=42", mock.requests()[1].body);
    }

    // Scenario C: Redirect loop hits max_redirects -> error.TooManyRedirects
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        for (0..4) |_| {
            try mock.pushResponse(.{
                .status = .found,
                .headers = &.{.{ .name = "Location", .value = "/loop" }},
            });
        }

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{ .max_redirects = 2 });
        defer client.deinit();

        try std.testing.expectError(
            error.TooManyRedirects,
            client.get("https://example.com/loop"),
        );
    }
}

test "Client transparent gzip/deflate decompression respects manual Accept-Encoding and enforces max_body_bytes" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Helper to produce valid gzip and deflate (zlib) payloads using std.compress.flate.
    const CompressHelper = struct {
        fn compress(alloc: Allocator, input: []const u8, container: flate.Container) ![]u8 {
            var out: Writer.Allocating = .init(alloc);
            errdefer out.deinit();
            var buf: [256]u8 = undefined;
            var raw = try flate.Compress.Raw.init(&out.writer, &buf, container);
            try raw.writer.writeAll(input);
            try raw.finish();
            return out.toOwnedSlice();
        }
    };

    const plaintext =
        "Hello Kite compressed HTTP response! " ++
        "Hello Kite compressed HTTP response! " ++
        "Hello Kite compressed HTTP response! " ++
        "Hello Kite compressed HTTP response! ";
    const gzipped = try CompressHelper.compress(gpa, plaintext, .gzip);
    defer gpa.free(gzipped);
    const deflated = try CompressHelper.compress(gpa, plaintext, .zlib);
    defer gpa.free(deflated);

    // 1. Auto-decompresses gzip & deflate when caller does not specify Accept-Encoding
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        try mock.pushResponse(.{
            .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }},
            .body = gzipped,
        });
        try mock.pushResponse(.{
            .headers = &.{.{ .name = "Content-Encoding", .value = "deflate" }},
            .body = deflated,
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var r1 = try client.get("https://example.com/gz");
        defer r1.deinit();
        try std.testing.expectEqualStrings(plaintext, r1.body);
        try std.testing.expect(mock.requests()[0].headers.has("Accept-Encoding"));

        var r2 = try client.get("https://example.com/df");
        defer r2.deinit();
        try std.testing.expectEqualStrings(plaintext, r2.body);
    }

    // 2. When caller explicitly sets Accept-Encoding, raw compressed bytes are preserved untouched
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        try mock.pushResponse(.{
            .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }},
            .body = gzipped,
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var res = try client.fetch(.{
            .url = "https://example.com/raw-gz",
            .headers = &.{.{ .name = "Accept-Encoding", .value = "gzip" }},
        });
        defer res.deinit();
        try std.testing.expectEqualSlices(u8, gzipped, res.body);
    }

    // 3. max_body_bytes protects against OOM on oversized responses
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        try mock.pushResponse(.{ .body = plaintext });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        try std.testing.expectError(error.BodyTooLarge, client.fetch(.{
            .url = "https://example.com/big",
            .max_body_bytes = .{ .limited = 32 },
        }));
    }
}

test "Client end-to-end over real zio MockServer: JSON POST, gzip+chunked keep-alive reuse, and total timeout" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const E2eServer = struct {
        accepted: std.atomic.Value(usize) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = self.accepted.fetchAdd(1, .acq_rel);

            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
                var content_len: usize = 0;
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                    if (std.ascii.startsWithIgnoreCase(line, "Content-Length:")) {
                        const val = std.mem.trim(u8, line["Content-Length:".len..], " \t\r\n");
                        content_len = std.fmt.parseInt(usize, val, 10) catch 0;
                    }
                }
                if (content_len > 0) {
                    var discard_buf: [256]u8 = undefined;
                    var left = content_len;
                    while (left > 0) {
                        const step = @min(left, discard_buf.len);
                        r.interface.readSliceAll(discard_buf[0..step]) catch return;
                        left -= step;
                    }
                }

                if (std.mem.startsWith(u8, req_line, "GET /slow ")) {
                    zio.sleep(.fromSeconds(5)) catch {};
                    return;
                }

                if (std.mem.startsWith(u8, req_line, "GET /gz-chunked ")) {
                    // Build a real gzipped payload and send it over Transfer-Encoding: chunked.
                    var gz_storage: [256]u8 = undefined;
                    var gz_out: Writer = .fixed(&gz_storage);
                    var cbuf: [128]u8 = undefined;
                    var raw = flate.Compress.Raw.init(&gz_out, &cbuf, .gzip) catch return;
                    raw.writer.writeAll("chunked-gzip-ok") catch return;
                    raw.finish() catch return;
                    const gz = gz_out.buffered();

                    w.interface.print(
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n",
                        .{gz.len},
                    ) catch return;
                    w.interface.writeAll(gz) catch return;
                    w.interface.writeAll("\r\n0\r\n\r\n") catch return;
                    w.interface.flush() catch return;
                    continue;
                }

                // Echo a JSON response for POST /json
                const json_resp = "{\"ok\":true,\"count\":7}";
                w.interface.print(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                    .{ json_resp.len, json_resp },
                ) catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var e2e: E2eServer = .{};
    var srv: MockServer = undefined;
    try srv.start(&e2e, E2eServer.handle);
    defer srv.stop();

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    // 1. Compressed + Chunked response still drains `0\r\n\r\n` so the socket stays pooled!
    const url_gz = try gpa.print("http://127.0.0.1:{d}/gz-chunked", .{srv.port()});
    defer gpa.free(url_gz);
    {
        var res = try client.get(url_gz);
        defer res.deinit();
        try std.testing.expectEqual(http.Status.ok, res.status);
        try std.testing.expectEqualStrings("chunked-gzip-ok", res.body);
    }

    // 2. JSON POST reuses the EXACT SAME keep-alive TCP connection!
    const url_json = try gpa.print("http://127.0.0.1:{d}/json", .{srv.port()});
    defer gpa.free(url_json);
    {
        const Payload = struct { name: []const u8 };
        const Reply = struct { ok: bool, count: u32 };

        var res = try client.postJson(url_json, Payload{ .name = "kite" }, &.{});
        defer res.deinit();

        const parsed = try res.json(Reply, gpa, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.ok);
        try std.testing.expectEqual(@as(u32, 7), parsed.value.count);
    }
    // Both requests shared 1 single TCP connection!
    try std.testing.expectEqual(@as(usize, 1), e2e.accepted.load(.acquire));

    // 3. Total request timeout interrupts a stalled server cleanly.
    const url_slow = try gpa.print("http://127.0.0.1:{d}/slow", .{srv.port()});
    defer gpa.free(url_slow);
    try std.testing.expectError(error.Timeout, client.fetch(.{
        .url = url_slow,
        .timeout = .fromMilliseconds(30),
    }));
}

test "Client auth and form encoding helpers" {
    const gpa = std.testing.allocator;

    const basic = try Client.basicAuthValue(gpa, "aladdin", "opensesame");
    defer gpa.free(basic);
    try std.testing.expectEqualStrings("Basic YWxhZGRpbjpvcGVuc2VzYW1l", basic);

    const bearer = try Client.bearerAuthValue(gpa, "tok_123");
    defer gpa.free(bearer);
    try std.testing.expectEqualStrings("Bearer tok_123", bearer);

    const encoded = try Client.encodeForm(gpa, &.{
        .{ .name = "q", .value = "hello world&more=1" },
        .{ .name = "lang", .value = "zig" },
    });
    defer gpa.free(encoded);
    try std.testing.expectEqualStrings("q=hello%20world%26more%3D1&lang=zig", encoded);

    // Empty-path URL with query and fragment normalizes to valid origin-form target
    const norm = try normalizeUrl(gpa, "https://example.com?a=1#section");
    defer gpa.free(norm);
    try std.testing.expectEqualStrings("https://example.com/?a=1", norm);
    try std.testing.expectEqualStrings("/?a=1", try extractRequestTarget(norm));
}

test "Client auto-detects raw deflate and preserves keep-alive when manually streaming gzip+chunked" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // 1. Raw deflate (no zlib header) under Content-Encoding: deflate decodes cleanly
    {
        var raw_out: Writer.Allocating = .init(gpa);
        defer raw_out.deinit();
        var cbuf: [256]u8 = undefined;
        var comp = try flate.Compress.Raw.init(&raw_out.writer, &cbuf, .raw);
        try comp.writer.writeAll("raw-deflate-payload");
        try comp.finish();

        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        try mock.pushResponse(.{
            .headers = &.{.{ .name = "Content-Encoding", .value = "deflate" }},
            .body = raw_out.written(),
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var res = try client.get("https://example.com/raw-deflate");
        defer res.deinit();
        try std.testing.expectEqualStrings("raw-deflate-payload", res.body);
    }

    // 2. Manual StreamResponse.reader() loop on gzip+chunked MUST still return socket to pool!
    {
        const GzChunkServer = struct {
            accepted: std.atomic.Value(usize) = .init(0),

            fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                _ = self.accepted.fetchAdd(1, .acq_rel);

                var rbuf: [512]u8 = undefined;
                var wbuf: [512]u8 = undefined;
                var r = stream.reader(&rbuf);
                var w = stream.writer(&wbuf);

                while (true) {
                    while (true) {
                        const line = r.interface.takeDelimiterInclusive('\n') catch return;
                        if (std.mem.eql(u8, line, "\r\n")) break;
                    }
                    var gz_storage: [256]u8 = undefined;
                    var gz_out: Writer = .fixed(&gz_storage);
                    var cbuf: [128]u8 = undefined;
                    var raw = flate.Compress.Raw.init(&gz_out, &cbuf, .gzip) catch return;
                    raw.writer.writeAll("streamed-gz") catch return;
                    raw.finish() catch return;
                    const gz = gz_out.buffered();

                    w.interface.print(
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n",
                        .{gz.len},
                    ) catch return;
                    w.interface.writeAll(gz) catch return;
                    w.interface.writeAll("\r\n0\r\n\r\n") catch return;
                    w.interface.flush() catch return;
                }
            }
        };

        var st: GzChunkServer = .{};
        var srv: MockServer = undefined;
        try srv.start(&st, GzChunkServer.handle);
        defer srv.stop();

        var client = Client.init(gpa, rt.io(), .{});
        defer client.deinit();

        const url = try gpa.print("http://127.0.0.1:{d}/gz", .{srv.port()});
        defer gpa.free(url);

        for (0..2) |_| {
            var req = try client.open(.{ .method = .GET, .url = url });
            defer req.deinit();
            var stream = try req.receiveHead();
            defer stream.deinit();

            var out_buf: [64]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const n = try stream.reader().readSliceShort(out_buf[total..]);
                if (n == 0) break;
                total += n;
            }
            try std.testing.expectEqualStrings("streamed-gz", out_buf[0..total]);
        }

        // Both manual streaming reads shared 1 single keep-alive TCP connection!
        try std.testing.expectEqual(@as(usize, 1), st.accepted.load(.acquire));
    }
}

test "Client CheckRedirect, Location spaces, lazy deflate, decompressed header strip, and open timeout" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // 1. Decompressed fetch() strips Content-Encoding & Content-Length and sets res.decompressed = true,
    //    and lazy deflate handles 0-byte compressed chunked body cleanly without blocking receiveHead().
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        var def_storage: [128]u8 = undefined;
        var def_out: Writer = .fixed(&def_storage);
        var cbuf: [128]u8 = undefined;
        var comp = try flate.Compress.Raw.init(&def_out, &cbuf, .zlib);
        try comp.writer.writeAll("decoded-ok");
        try comp.finish();

        try mock.pushResponse(.{
            .status = .ok,
            .headers = &.{
                .{ .name = "Content-Encoding", .value = "deflate" },
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = def_out.buffered(),
        });
        // Empty chunked deflate body -> must return "" cleanly instead of failing!
        try mock.pushResponse(.{
            .status = .ok,
            .headers = &.{.{ .name = "Content-Encoding", .value = "deflate" }},
            .body = "",
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        var res1 = try client.get("https://example.com/z");
        defer res1.deinit();
        try std.testing.expectEqualStrings("decoded-ok", res1.body);
        try std.testing.expect(res1.decompressed);
        try std.testing.expect(!res1.headers.has("Content-Encoding"));
        try std.testing.expect(!res1.headers.has("Content-Length"));
        try std.testing.expectEqualStrings("text/plain", res1.headers.get("Content-Type").?);

        var res2 = try client.get("https://example.com/empty-deflate");
        defer res2.deinit();
        try std.testing.expectEqualStrings("", res2.body);
    }

    // 2. CheckRedirect hook (.stop returns 302 directly; error aborts) + unescaped spaces in Location
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "/files/my report.pdf" }},
        });
        try mock.pushResponse(.{ .status = .ok, .body = "pdf-bytes" });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        // Unescaped space in Location is percent-encoded cleanly
        var res_space = try client.get("https://example.com/dl");
        defer res_space.deinit();
        try std.testing.expectEqualStrings("https://example.com/files/my%20report.pdf", res_space.final_url);
        try std.testing.expectEqualStrings("pdf-bytes", res_space.body);

        // CheckRedirect returning .stop returns the 302 response directly
        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "http://169.254.169.254/latest/meta-data" }},
        });
        const StopHook = struct {
            fn check(_: ?*anyopaque, info: RedirectInfo) anyerror!RedirectDecision {
                if (std.mem.eql(u8, info.to_origin.host, "169.254.169.254")) return .stop;
                return .follow;
            }
        };
        var res_stop = try client.fetch(.{
            .url = "https://example.com/ssrf",
            .check_redirect = .{ .check = StopHook.check },
        });
        defer res_stop.deinit();
        try std.testing.expectEqual(http.Status.found, res_stop.status);

        // CheckRedirect returning an error aborts the request immediately
        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "http://127.0.0.1/admin" }},
        });
        const BlockHook = struct {
            fn check(_: ?*anyopaque, info: RedirectInfo) anyerror!RedirectDecision {
                if (std.mem.eql(u8, info.to_origin.host, "127.0.0.1")) return error.RedirectBlocked;
                return .follow;
            }
        };
        try std.testing.expectError(
            error.RedirectBlocked,
            client.fetch(.{
                .url = "https://example.com/ssrf2",
                .check_redirect = .{ .check = BlockHook.check },
            }),
        );
    }

    // 3. open(.{ .timeout = ... }) enforces deadline across open() + receiveHead()
    {
        const SlowHeadServer = struct {
            fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
                var rbuf: [256]u8 = undefined;
                var r = stream.reader(&rbuf);
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                zio.sleep(.fromMilliseconds(200)) catch return;
            }
        };

        var srv: MockServer = undefined;
        try srv.start(null, SlowHeadServer.handle);
        defer srv.stop();

        var client = Client.init(gpa, rt.io(), .{
            .response_header_timeout = .fromSeconds(5),
        });
        defer client.deinit();

        const url = try gpa.print("http://127.0.0.1:{d}/slow", .{srv.port()});
        defer gpa.free(url);

        var req = try client.open(.{
            .url = url,
            .timeout = .fromMilliseconds(25),
        });
        defer req.deinit();

        try std.testing.expectError(error.Timeout, req.receiveHead());
    }
}

test "Unix domain socket: http+unix URL, explicit unix_socket_path, Keep-Alive, and redirect security" {
    if (!zio.net.has_unix_sockets) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Create a unique short path under /tmp (macOS sun_path max is 104 bytes).
    var rand_bytes: [6]u8 = undefined;
    try zio.randomSecure(&rand_bytes);
    const hex = std.fmt.bytesToHex(rand_bytes, .lower);
    var path_buf: [64]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&path_buf, "/tmp/kite-uds-{s}.sock", .{hex});
    std.Io.Dir.cwd().deleteFile(rt.io(), sock_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(rt.io(), sock_path) catch {};

    const UdsServer = struct {
        server: zio.net.Server,
        group: zio.Group = .init,
        stopped: std.atomic.Value(bool) = .init(false),
        accepts: std.atomic.Value(u32) = .init(0),
        requests: std.atomic.Value(u32) = .init(0),

        fn acceptLoop(self: *@This()) void {
            while (!self.stopped.load(.acquire)) {
                const stream = self.server.accept(.{}) catch break;
                _ = self.accepts.fetchAdd(1, .acq_rel);
                self.group.spawn(handleConn, .{ self, stream }) catch stream.close();
            }
        }

        fn handleConn(self: *@This(), stream: zio.net.Stream) void {
            defer stream.close();
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            while (true) {
                var host_buf: [128]u8 = undefined;
                var host_len: usize = 0;
                var first_line_seen = false;
                while (true) {
                    const line = sr.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                    if (!first_line_seen) {
                        first_line_seen = true;
                        continue;
                    }
                    if (std.ascii.startsWithIgnoreCase(line, "host:")) {
                        const v = std.mem.trim(u8, line[5..], " \t\r\n");
                        host_len = @min(v.len, host_buf.len);
                        @memcpy(host_buf[0..host_len], v[0..host_len]);
                    }
                }
                _ = self.requests.fetchAdd(1, .acq_rel);
                const host_val = host_buf[0..host_len];
                sw.interface.print(
                    "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n{s}",
                    .{ host_val.len, host_val },
                ) catch return;
                sw.interface.flush() catch return;
            }
        }
    };

    const addr = try zio.net.UnixAddress.init(sock_path);
    var uds_srv: UdsServer = .{
        .server = try addr.listen(.{}),
    };
    try uds_srv.group.spawn(UdsServer.acceptLoop, .{&uds_srv});
    defer {
        uds_srv.stopped.store(true, .release);
        uds_srv.group.cancel();
        uds_srv.server.close();
    }

    // 1. `http+unix://` URL routing bypasses configured proxy & reuses Keep-Alive socket.
    {
        var client = Client.init(gpa, rt.io(), .{
            .pool = .{
                // Deliberately unreachable proxy to prove UDS always bypasses proxies.
                .proxy = .{ .host = "127.0.0.1", .port = 1 },
            },
        });
        defer client.deinit();

        const url = try gpa.print("http+unix://%2Ftmp%2Fkite-uds-{s}.sock/v1/ping", .{hex});
        defer gpa.free(url);

        var r1 = try client.get(url);
        defer r1.deinit();
        try std.testing.expectEqual(http.Status.ok, r1.status);
        try std.testing.expectEqualStrings("localhost", r1.body);

        var r2 = try client.get(url);
        defer r2.deinit();
        try std.testing.expectEqual(http.Status.ok, r2.status);
        try std.testing.expectEqualStrings("localhost", r2.body);

        // Reused the single UDS connection across both requests.
        try std.testing.expectEqual(@as(u32, 1), uds_srv.accepts.load(.acquire));
        try std.testing.expectEqual(@as(u32, 2), uds_srv.requests.load(.acquire));
    }

    // 2. Explicit `Pool.Config.unix_socket_path` preserves logical URL `Host` header.
    {
        var client = Client.init(gpa, rt.io(), .{
            .pool = .{ .unix_socket_path = sock_path },
        });
        defer client.deinit();

        var res = try client.get("http://docker.local/v1.43/info");
        defer res.deinit();
        try std.testing.expectEqual(http.Status.ok, res.status);
        try std.testing.expectEqualStrings("docker.local", res.body);
    }

    // 3. Security invariant (I-UDS-2): network HTTP 302 redirecting to `http+unix://` MUST be blocked.
    {
        var mock: MockTransport = .init(gpa);
        defer mock.deinit();
        try mock.pushResponse(.{
            .status = .found,
            .headers = &.{.{ .name = "Location", .value = "http+unix://%2Fvar%2Frun%2Fdocker.sock/info" }},
        });

        var client = Client.initWithTransport(gpa, rt.io(), mock.transport(), .{});
        defer client.deinit();

        try std.testing.expectError(
            error.UnixSocketRedirectBlocked,
            client.get("http://untrusted.example/redirect"),
        );
    }
}
