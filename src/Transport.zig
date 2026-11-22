//! Thin single-exchange transport boundary (`Transport` & `Exchange`).
//!
//! Decouples high-level HTTP client policy (redirects, decompression, cookies,
//! retries) from physical connection pooling and wire execution. Mirrors the
//! fat-pointer vtable idiom of `std.Io` and `std.mem.Allocator`.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");

const Transport = @This();

/// Zero-allocation timing and outcome snapshot emitted per physical HTTP exchange
/// when an optional `Trace` callback is configured.
pub const ExchangeMetrics = struct {
    method: http.Method,
    origin: http.Origin,
    target: []const u8,
    reused_connection: bool,
    proxied: bool,
    /// Time spent resolving DNS for a fresh connection (0 for IP literals or reused connections).
    dns_ns: u64 = 0,
    /// Time spent completing the TCP dial (and HTTP proxy CONNECT tunnel if HTTPS via proxy).
    tcp_ns: u64 = 0,
    /// Time spent completing the TLS handshake (0 for plain HTTP or reused connections).
    tls_ns: u64 = 0,
    /// Total time spent acquiring a pool slot and establishing the connection (wait + DNS + TCP + TLS).
    connect_ns: u64,
    /// Time from finishing request head write to receiving final (non-1xx) response headers.
    ttfb_ns: u64,
    /// Total exchange duration from `openExchange` to `deinit`.
    total_ns: u64,
    status: ?http.Status,
    err: ?anyerror,
};

/// Optional observability hook invoked once each physical exchange completes or aborts.
pub const Trace = struct {
    ctx: ?*anyopaque = null,
    on_exchange: *const fn (ctx: ?*anyopaque, metrics: ExchangeMetrics) void,

    pub fn record(self: Trace, metrics: ExchangeMetrics) void {
        self.on_exchange(self.ctx, metrics);
    }
};

/// Request payload mode for a single physical HTTP exchange.
pub const RequestBody = union(enum) {
    none,
    bytes: []const u8,
    stream_fixed: u64,
    stream_chunked,

    /// True iff the payload can be sent again from byte 0 (needed for stale-connection
    /// retry or 307/308 redirects).
    pub fn isRewindable(self: RequestBody) bool {
        return switch (self) {
            .none, .bytes => true,
            .stream_fixed, .stream_chunked => false,
        };
    }

    pub fn toRequestFraming(self: RequestBody) h1.RequestFraming {
        return switch (self) {
            .none => .none,
            .bytes => |b| if (b.len == 0) .none else .{ .content_length = b.len },
            .stream_fixed => |len| .{ .content_length = len },
            .stream_chunked => .chunked,
        };
    }
};

/// Parameters describing one physical HTTP roundtrip.
pub const ExchangeRequest = struct {
    method: http.Method,
    origin: http.Origin,
    /// Origin-form request-target (e.g. "/v1/items?a=1"). Empty defaults to "/".
    target: []const u8 = "/",
    headers: []const http.Header = &.{},
    body: RequestBody = .none,
    parse_options: h1.ParseOptions = .{},
    /// Timeout scoped to TCP/TLS dial + pool wait when opening the connection.
    connect_timeout: zio.Timeout = .none,
    /// Timeout scoped to waiting for response status-line and headers.
    response_header_timeout: zio.Timeout = .none,
    /// Per-read idle timeout while streaming the response body (guards against Slowloris).
    read_idle_timeout: zio.Timeout = .none,
    /// When non-null on a body-bearing request, sends `Expect: 100-continue` and waits
    /// at most this duration for `100 Continue` or an early rejection before sending the body.
    expect_continue_timeout: ?zio.Timeout = null,
    /// When true, sends `Connection: close` and never returns the socket to the pool.
    close_connection: bool = false,
};

/// Handle to one active HTTP/1.1 exchange owning a linear connection lease.
///
/// Always `defer exchange.deinit()`. Calling `deinit()` more than once is a safe no-op.
pub const Exchange = struct {
    ptr: ?*anyopaque,
    vtable: *const Exchange.VTable,

    pub const VTable = struct {
        writer: *const fn (ptr: *anyopaque) *Writer,
        unwrapWriteError: *const fn (ptr: *const anyopaque) ?anyerror,
        receiveHead: *const fn (ptr: *anyopaque) anyerror!*const h1.ResponseHead,
        /// Moves ownership of the parsed `ResponseHead` out of the exchange (avoiding
        /// redundant header/reason cloning in buffered `Client.fetch()`).
        takeHead: *const fn (ptr: *anyopaque) ?h1.ResponseHead,
        reader: *const fn (ptr: *anyopaque) *Reader,
        unwrapReadError: *const fn (ptr: *const anyopaque) ?anyerror,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    /// Returns the framed request body writer (valid for streaming body modes
    /// before `receiveHead()` is called).
    pub fn writer(self: *Exchange) *Writer {
        return self.vtable.writer(self.ptr.?);
    }

    /// Recovers the concrete error after `writer()` returned `error.WriteFailed`.
    pub fn unwrapWriteError(self: *const Exchange) ?anyerror {
        const p = self.ptr orelse return null;
        return self.vtable.unwrapWriteError(p);
    }

    /// Automatically finishes any open request body stream, flushes the request,
    /// performs a transparent stale-connection retry when safe, and returns the
    /// final (non-1xx) response head.
    pub fn receiveHead(self: *Exchange) anyerror!*const h1.ResponseHead {
        return self.vtable.receiveHead(self.ptr.?);
    }

    /// Moves ownership of the received `ResponseHead` out of this exchange so
    /// buffered callers (`Client.fetch`) avoid cloning headers and reason strings.
    /// After `takeHead()` returns a value, the caller owns calling `head.deinit(gpa)`.
    pub fn takeHead(self: *Exchange) ?h1.ResponseHead {
        const p = self.ptr orelse return null;
        return self.vtable.takeHead(p);
    }

    /// Returns the framed response body reader (valid after `receiveHead()` succeeds).
    pub fn reader(self: *Exchange) *Reader {
        return self.vtable.reader(self.ptr.?);
    }

    /// Recovers the concrete error after `reader()` returned `error.ReadFailed`.
    pub fn unwrapReadError(self: *const Exchange) ?anyerror {
        const p = self.ptr orelse return null;
        return self.vtable.unwrapReadError(p);
    }

    /// Releases or discards the underlying connection and frees exchange state.
    /// Safe to call multiple times (idempotent).
    pub fn deinit(self: *Exchange) void {
        const p = self.ptr orelse return;
        self.ptr = null;
        self.vtable.deinit(p);
    }
};

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    openExchange: *const fn (ptr: *anyopaque, req: ExchangeRequest) anyerror!Exchange,
};

pub fn openExchange(self: Transport, req: ExchangeRequest) anyerror!Exchange {
    return self.vtable.openExchange(self.ptr, req);
}
