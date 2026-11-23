//! Server-Sent Events (`text/event-stream`, WHATWG HTML Living Standard §9.2) client.
//!
//! Provides two composable layers:
//! - `sse.Reader`: pure Sans-IO incremental parser operating on any `*std.Io.Reader`
//!   with zero socket/zio dependencies, full BOM / CRLF / CR / LF / chunk-split
//!   support, and bounded `max_line_bytes` / `max_event_bytes` OOM caps.
//! - `sse.Stream`: high-level `kite.Client` session supporting GET and POST+body
//!   (e.g. LLM token streams & MCP Streamable HTTP), `Content-Type` validation,
//!   `204 No Content` termination, and optional `Last-Event-ID` / `retry:` auto-reconnect.

const std = @import("std");
const Allocator = std.mem.Allocator;
const IoReader = std.Io.Reader;
const IoWriter = std.Io.Writer;

const zio = @import("zio");
const http = @import("http.zig");
const Transport = @import("Transport.zig");
const RetryTransport = @import("RetryTransport.zig");
const Client = @import("Client.zig");

const utf8_bom = [3]u8{ 0xEF, 0xBB, 0xBF };

/// Read-only view of one dispatched SSE event.
///
/// Slices borrow internal buffers owned by `sse.Reader` / `sse.Stream` and remain
/// valid until the next `next()` call or `deinit()`. Call `dupe()` to retain an
/// event across iterations.
pub const Event = struct {
    /// Event type (`"message"` when the stream omitted an `event:` field).
    event: []const u8,
    /// Dispatched data payload (multi-line `data:` values joined with `'\n'`,
    /// trailing newline stripped per WHATWG §9.2.6).
    data: []const u8,
    /// Snapshot of the stream's current `last_event_id` (empty if unset or cleared).
    id: []const u8,
    /// Server-supplied reconnection time in milliseconds if a valid `retry:` field
    /// was observed on or before this event.
    retry_ms: ?u64,

    pub fn dupe(self: Event, gpa: Allocator) Allocator.Error!OwnedEvent {
        const ev_copy = try gpa.dupe(u8, self.event);
        errdefer gpa.free(ev_copy);
        const data_copy = try gpa.dupe(u8, self.data);
        errdefer gpa.free(data_copy);
        const id_copy = try gpa.dupe(u8, self.id);
        return .{
            .gpa = gpa,
            .event = ev_copy,
            .data = data_copy,
            .id = id_copy,
            .retry_ms = self.retry_ms,
        };
    }
};

/// Heap-owned copy of an `Event` returned by `Event.dupe()`.
pub const OwnedEvent = struct {
    gpa: Allocator,
    event: []u8,
    data: []u8,
    id: []u8,
    retry_ms: ?u64,

    pub fn deinit(self: *OwnedEvent) void {
        self.gpa.free(self.event);
        self.gpa.free(self.data);
        self.gpa.free(self.id);
        self.* = undefined;
    }
};

/// Sans-IO incremental SSE parser implementing WHATWG HTML Living Standard §9.2.6.
///
/// Zero socket and zero zio dependencies; works over any `*std.Io.Reader`
/// including arbitrary 1-byte chunk splits.
pub const Reader = struct {
    pub const Options = struct {
        /// Hard cap on any single SSE line (guards against unbounded lines without EOL).
        max_line_bytes: usize = 256 * 1024,
        /// Hard cap on accumulated `data:` bytes for a single undispatched event.
        max_event_bytes: usize = 4 * 1024 * 1024,
        /// Initial `last_event_id` value (empty by default).
        initial_last_event_id: []const u8 = "",
        /// Initial reconnection delay in milliseconds before any server `retry:` field.
        default_retry_ms: u64 = 3000,
    };

    pub const Error = error{
        LineTooLong,
        EventTooLarge,
        ReadFailed,
        OutOfMemory,
    };

    gpa: Allocator,
    input: *IoReader,
    opts: Options,

    line_buf: std.ArrayList(u8) = .empty,
    data_buf: std.ArrayList(u8) = .empty,
    event_buf: std.ArrayList(u8) = .empty,
    last_event_id_buf: std.ArrayList(u8) = .empty,

    has_data: bool = false,
    retry_ms: u64,
    has_server_retry: bool = false,

    /// Stream-start BOM state: 0..2 while matching leading `0xEF 0xBB 0xBF`, 3 once done.
    bom_state: u8 = 0,
    /// True if the previous byte ended a line with `'\r'` so an immediately following `'\n'`
    /// must be swallowed as part of the same CRLF line ending.
    pending_cr: bool = false,
    /// Set on returning an event so the next `next()` clears the previous event's buffers.
    needs_dispatch_clear: bool = false,

    pub fn init(gpa: Allocator, input: *IoReader, opts: Options) Allocator.Error!Reader {
        var r: Reader = .{
            .gpa = gpa,
            .input = input,
            .opts = opts,
            .retry_ms = opts.default_retry_ms,
        };
        errdefer r.deinit();
        if (opts.initial_last_event_id.len > 0) {
            try r.last_event_id_buf.appendSlice(gpa, opts.initial_last_event_id);
        }
        return r;
    }

    pub fn deinit(self: *Reader) void {
        self.line_buf.deinit(self.gpa);
        self.data_buf.deinit(self.gpa);
        self.event_buf.deinit(self.gpa);
        self.last_event_id_buf.deinit(self.gpa);
        self.* = undefined;
    }

    /// Rebinds the parser to a fresh stream (e.g. after reconnecting), discarding any
    /// partial line/event draft while preserving `last_event_id` and `retry_ms`.
    pub fn resetInput(self: *Reader, new_input: *IoReader) void {
        self.input = new_input;
        self.line_buf.clearRetainingCapacity();
        self.data_buf.clearRetainingCapacity();
        self.event_buf.clearRetainingCapacity();
        self.has_data = false;
        self.bom_state = 0;
        self.pending_cr = false;
        self.needs_dispatch_clear = false;
    }

    pub fn lastEventId(self: *const Reader) []const u8 {
        return self.last_event_id_buf.items;
    }

    pub fn retryMs(self: *const Reader) u64 {
        return self.retry_ms;
    }

    /// Reads and parses the underlying stream until the next complete SSE event is
    /// dispatched by an empty line, or returns `null` at clean EOF.
    ///
    /// Per WHATWG §9.2.6, any trailing undispatched data buffer at EOF without a
    /// terminating blank line is discarded.
    pub fn next(self: *Reader) Error!?Event {
        if (self.needs_dispatch_clear) {
            self.data_buf.clearRetainingCapacity();
            self.event_buf.clearRetainingCapacity();
            self.has_data = false;
            self.needs_dispatch_clear = false;
        }

        while (true) {
            // Fast path: once BOM & any split-CRLF state are settled, scan the buffered
            // slice in bulk with `std.mem.findAny` instead of byte-by-byte reads.
            if (self.bom_state == utf8_bom.len and !self.pending_cr) {
                const avail = self.input.peekGreedy(1) catch |err| switch (err) {
                    error.EndOfStream => return self.finishAtEof(),
                    error.ReadFailed => return error.ReadFailed,
                };
                if (std.mem.findAny(u8, avail, "\r\n")) |idx| {
                    if (idx > 0) try self.appendLineSlice(avail[0..idx]);
                    const eol = avail[idx];
                    if (eol == '\r') {
                        if (idx + 1 < avail.len and avail[idx + 1] == '\n') {
                            self.input.toss(idx + 2);
                        } else {
                            self.input.toss(idx + 1);
                            self.pending_cr = true;
                        }
                    } else {
                        self.input.toss(idx + 1);
                    }
                    if (try self.processLine()) |ev| {
                        self.needs_dispatch_clear = true;
                        return ev;
                    }
                    continue;
                } else {
                    try self.appendLineSlice(avail);
                    self.input.toss(avail.len);
                    continue;
                }
            }

            const b = self.input.takeByte() catch |err| switch (err) {
                error.EndOfStream => return self.finishAtEof(),
                error.ReadFailed => return error.ReadFailed,
            };

            // Strip at most one leading UTF-8 BOM (0xEF 0xBB 0xBF) at stream start.
            if (self.bom_state < utf8_bom.len) {
                if (b == utf8_bom[self.bom_state]) {
                    self.bom_state += 1;
                    continue;
                }
                const matched = self.bom_state;
                self.bom_state = utf8_bom.len;
                if (matched > 0) {
                    try self.appendLineSlice(utf8_bom[0..matched]);
                }
            }

            if (self.pending_cr) {
                self.pending_cr = false;
                if (b == '\n') continue;
            }

            if (b == '\r' or b == '\n') {
                if (b == '\r') self.pending_cr = true;
                if (try self.processLine()) |ev| {
                    self.needs_dispatch_clear = true;
                    return ev;
                }
                continue;
            }

            try self.appendLineByte(b);
        }
    }

    fn finishAtEof(self: *Reader) ?Event {
        // Discard any partial line or undispatched event draft per WHATWG §9.2.6.
        self.line_buf.clearRetainingCapacity();
        self.data_buf.clearRetainingCapacity();
        self.event_buf.clearRetainingCapacity();
        self.has_data = false;
        return null;
    }

    fn appendLineByte(self: *Reader, b: u8) Error!void {
        if (self.line_buf.items.len >= self.opts.max_line_bytes) return error.LineTooLong;
        try self.line_buf.append(self.gpa, b);
    }

    fn appendLineSlice(self: *Reader, bytes: []const u8) Error!void {
        if (self.line_buf.items.len + bytes.len > self.opts.max_line_bytes) return error.LineTooLong;
        try self.line_buf.appendSlice(self.gpa, bytes);
    }

    fn processLine(self: *Reader) Error!?Event {
        const line = self.line_buf.items;
        defer self.line_buf.clearRetainingCapacity();

        // Empty line: dispatch event if any `data:` field was seen.
        if (line.len == 0) {
            if (!self.has_data) {
                self.event_buf.clearRetainingCapacity();
                return null;
            }
            // Remove the single trailing '\n' appended by the last `data:` field.
            if (self.data_buf.items.len > 0 and self.data_buf.items[self.data_buf.items.len - 1] == '\n') {
                self.data_buf.items.len -= 1;
            }
            const ev_type = if (self.event_buf.items.len > 0) self.event_buf.items else "message";
            return .{
                .event = ev_type,
                .data = self.data_buf.items,
                .id = self.last_event_id_buf.items,
                .retry_ms = if (self.has_server_retry) self.retry_ms else null,
            };
        }

        // Comment line (`: ...`) is ignored.
        if (line[0] == ':') return null;

        var field: []const u8 = line;
        var value: []const u8 = "";
        if (std.mem.findScalar(u8, line, ':')) |colon| {
            field = line[0..colon];
            value = line[colon + 1 ..];
            // Strip at most one leading U+0020 SPACE from field value.
            if (value.len > 0 and value[0] == ' ') {
                value = value[1..];
            }
        }

        if (std.mem.eql(u8, field, "data")) {
            const needed = self.data_buf.items.len + value.len + 1;
            if (needed > self.opts.max_event_bytes) return error.EventTooLarge;
            try self.data_buf.appendSlice(self.gpa, value);
            try self.data_buf.append(self.gpa, '\n');
            self.has_data = true;
        } else if (std.mem.eql(u8, field, "event")) {
            if (value.len > self.opts.max_line_bytes) return error.LineTooLong;
            self.event_buf.clearRetainingCapacity();
            try self.event_buf.appendSlice(self.gpa, value);
        } else if (std.mem.eql(u8, field, "id")) {
            // WHATWG §9.2.6: ignore `id` if it contains U+0000 NULL.
            if (std.mem.findScalar(u8, value, 0) == null) {
                self.last_event_id_buf.clearRetainingCapacity();
                try self.last_event_id_buf.appendSlice(self.gpa, value);
            }
        } else if (std.mem.eql(u8, field, "retry")) {
            if (parseAsciiDigitsU64(value)) |ms| {
                self.retry_ms = ms;
                self.has_server_retry = true;
            }
        }
        // Unknown fields are silently ignored per specification.
        return null;
    }
};

fn parseAsciiDigitsU64(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var acc: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        acc = std.math.mul(u64, acc, 10) catch return null;
        acc = std.math.add(u64, acc, c - '0') catch return null;
    }
    return acc;
}

/// Checks whether a `Content-Type` header value has media type `text/event-stream`
/// (case-insensitive, ignoring optional `; charset=...` parameters).
pub fn isEventStreamContentType(content_type: []const u8) bool {
    const semi = std.mem.findScalar(u8, content_type, ';') orelse content_type.len;
    const media_type = std.mem.trim(u8, content_type[0..semi], " \t");
    return std.ascii.eqlIgnoreCase(media_type, "text/event-stream");
}

/// High-level SSE session built on `kite.Client`.
///
/// Supports GET and POST+body (e.g. LLM completions & MCP Streamable HTTP),
/// validates status & `Content-Type`, handles `204 No Content` clean termination,
/// and optionally reconnects with `Last-Event-ID` and server-provided `retry:`.
pub const Stream = struct {
    pub const ConnectOptions = struct {
        method: http.Method = .GET,
        url: []const u8,
        headers: []const http.Header = &.{},
        /// Optional request body (must be `.none` or `.bytes` if `auto_reconnect == true`).
        body: Transport.RequestBody = .none,
        timeout: ?zio.Timeout = null,
        connect_timeout: ?zio.Timeout = null,
        response_header_timeout: ?zio.Timeout = null,
        read_idle_timeout: ?zio.Timeout = null,
        max_redirects: ?u8 = null,
        check_redirect: ?Client.CheckRedirect = null,
        /// Defaults to `false` so intermediaries do not buffer compressed SSE chunks;
        /// set `true` to negotiate gzip/deflate/zstd decompression.
        auto_decompress: bool = false,
        /// Reject responses whose `Content-Type` is not `text/event-stream`.
        validate_content_type: bool = true,
        /// Automatically reconnect after unexpected stream EOF / transient read errors
        /// using `Last-Event-ID` and server `retry:` delay (stopped cleanly on `204`).
        auto_reconnect: bool = false,
        /// When `auto_reconnect == true`, also retry transient upstream statuses
        /// (`429`, `502`, `503`, `504`) honoring `Retry-After` (capped by `max_retry_ms`).
        reconnect_on_transient_status: bool = true,
        /// Maximum number of reconnect attempts (`null` = unlimited until canceled or `204`).
        max_reconnects: ?u32 = null,
        /// Initial `Last-Event-ID` sent on the first request if non-empty.
        initial_last_event_id: []const u8 = "",
        /// Default reconnect delay before server sends `retry:`.
        default_retry_ms: u64 = 3000,
        /// Upper bound on server-supplied `retry:` / `Retry-After` sleep duration.
        max_retry_ms: u64 = 60_000,
        /// Optional diagnostic sink populated with the HTTP status code when the server
        /// rejects the SSE stream with `error.UnexpectedStatus`.
        rejected_status: ?*http.Status = null,
        reader_options: Reader.Options = .{},
    };

    client: *Client,
    gpa: Allocator,
    method: http.Method,
    url: []u8,
    owned_headers: []http.Header,
    owned_body: ?[]u8,
    timeout: ?zio.Timeout,
    connect_timeout: ?zio.Timeout,
    response_header_timeout: ?zio.Timeout,
    read_idle_timeout: ?zio.Timeout,
    max_redirects: ?u8,
    check_redirect: ?Client.CheckRedirect,
    auto_decompress: bool,
    validate_content_type: bool,
    auto_reconnect: bool,
    reconnect_on_transient_status: bool,
    max_reconnects: ?u32,
    max_retry_ms: u64,
    rejected_status: ?*http.Status,

    response: ?Client.StreamResponse = null,
    parser: Reader,
    ended: bool = false,
    reconnects: u32 = 0,
    last_status: http.Status = .ok,

    /// Connects to an SSE endpoint using `client` and validates the HTTP handshake.
    /// Always `defer stream.deinit()`.
    pub fn connect(client: *Client, opts: ConnectOptions) !Stream {
        if (opts.auto_reconnect and !opts.body.isRewindable()) {
            return error.CannotReplayBody;
        }
        const gpa = client.gpa;

        var stream: Stream = blk: {
            const url_copy = try gpa.dupe(u8, opts.url);
            errdefer gpa.free(url_copy);

            const hdrs_copy = try cloneHeaders(gpa, opts.headers);
            errdefer freeHeaders(gpa, hdrs_copy);

            const body_copy: ?[]u8 = switch (opts.body) {
                .none => null,
                .bytes => |b| try gpa.dupe(u8, b),
                .stream_fixed, .stream_chunked => return error.UnsupportedStreamingBody,
            };
            errdefer if (body_copy) |b| gpa.free(b);

            var r_opts = opts.reader_options;
            if (r_opts.initial_last_event_id.len == 0 and opts.initial_last_event_id.len > 0) {
                r_opts.initial_last_event_id = opts.initial_last_event_id;
            }
            if (opts.default_retry_ms != 3000 and r_opts.default_retry_ms == 3000) {
                r_opts.default_retry_ms = opts.default_retry_ms;
            }

            // Temporary dummy reader until openOnce binds the live response reader.
            var dummy: IoReader = .fixed(&.{});
            const parser = try Reader.init(gpa, &dummy, r_opts);

            break :blk .{
                .client = client,
                .gpa = gpa,
                .method = opts.method,
                .url = url_copy,
                .owned_headers = hdrs_copy,
                .owned_body = body_copy,
                .timeout = opts.timeout,
                .connect_timeout = opts.connect_timeout,
                .response_header_timeout = opts.response_header_timeout,
                .read_idle_timeout = opts.read_idle_timeout,
                .max_redirects = opts.max_redirects,
                .check_redirect = opts.check_redirect,
                .auto_decompress = opts.auto_decompress,
                .validate_content_type = opts.validate_content_type,
                .auto_reconnect = opts.auto_reconnect,
                .reconnect_on_transient_status = opts.reconnect_on_transient_status,
                .max_reconnects = opts.max_reconnects,
                .max_retry_ms = opts.max_retry_ms,
                .rejected_status = opts.rejected_status,
                .parser = parser,
            };
        };
        errdefer stream.deinit();

        try stream.openOnce();
        return stream;
    }

    pub fn deinit(self: *Stream) void {
        if (self.response) |*resp| {
            resp.deinit();
            self.response = null;
        }
        self.parser.deinit();
        if (self.owned_body) |b| self.gpa.free(b);
        freeHeaders(self.gpa, self.owned_headers);
        self.gpa.free(self.url);
        self.* = undefined;
    }

    pub fn status(self: *const Stream) http.Status {
        return self.last_status;
    }

    pub fn headers(self: *const Stream) ?*const http.Headers {
        if (self.response) |*resp| return resp.headers();
        return null;
    }

    pub fn lastEventId(self: *const Stream) []const u8 {
        return self.parser.lastEventId();
    }

    pub fn retryMs(self: *const Stream) u64 {
        return self.parser.retryMs();
    }

    /// Reads the next SSE event from the stream.
    ///
    /// Returns `null` on clean stream termination (EOF when `auto_reconnect == false`,
    /// or `204 No Content` from the server). Returned slices stay valid until the next
    /// `next()` call or `deinit()`.
    pub fn next(self: *Stream) !?Event {
        while (true) {
            if (self.ended) return null;
            if (self.response == null) return null;

            // Keep parser input bound to the current live response reader
            // (defends against `Stream` being moved by value after `connect()`).
            self.parser.input = self.response.?.reader();

            const maybe_ev = self.parser.next() catch |err| switch (err) {
                error.LineTooLong, error.EventTooLarge, error.OutOfMemory => return err,
                error.ReadFailed => {
                    const real_err = self.response.?.unwrapReadError() orelse error.ReadFailed;
                    if (real_err == error.Canceled or real_err == error.Timeout) return real_err;
                    if (!self.canReconnect()) return real_err;
                    try self.reconnect();
                    continue;
                },
            };

            if (maybe_ev) |ev| return ev;

            // Underlying HTTP body reached clean EOF.
            if (!self.canReconnect()) {
                self.closeCurrentResponse();
                self.ended = true;
                return null;
            }
            try self.reconnect();
        }
    }

    fn canReconnect(self: *const Stream) bool {
        if (!self.auto_reconnect or self.ended) return false;
        if (self.max_reconnects) |limit| {
            if (self.reconnects >= limit) return false;
        }
        return true;
    }

    fn closeCurrentResponse(self: *Stream) void {
        if (self.response) |*resp| {
            resp.deinit();
            self.response = null;
        }
    }

    fn reconnect(self: *Stream) !void {
        self.closeCurrentResponse();
        self.reconnects += 1;

        const delay_ms = @min(self.parser.retryMs(), self.max_retry_ms);
        if (delay_ms > 0) {
            try zio.sleep(.fromMilliseconds(delay_ms));
        }

        try self.openOnce();
    }

    fn openOnce(self: *Stream) !void {
        while (true) {
            var req_headers: std.ArrayList(http.Header) = .empty;
            defer req_headers.deinit(self.gpa);

            var has_accept = false;
            var has_cache_control = false;
            const last_id = self.parser.lastEventId();

            for (self.owned_headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "Accept")) has_accept = true;
                if (std.ascii.eqlIgnoreCase(h.name, "Cache-Control")) has_cache_control = true;
                // Replace any user-supplied Last-Event-ID when we have a live tracked id.
                if (last_id.len > 0 and std.ascii.eqlIgnoreCase(h.name, "Last-Event-ID")) continue;
                try req_headers.append(self.gpa, h);
            }

            if (!has_accept) {
                try req_headers.append(self.gpa, .{ .name = "Accept", .value = "text/event-stream" });
            }
            if (!has_cache_control) {
                try req_headers.append(self.gpa, .{ .name = "Cache-Control", .value = "no-cache" });
            }
            if (last_id.len > 0) {
                try req_headers.append(self.gpa, .{ .name = "Last-Event-ID", .value = last_id });
            }

            var pending = try self.client.open(.{
                .method = self.method,
                .url = self.url,
                .headers = req_headers.items,
                .body = if (self.owned_body) |b| .{ .bytes = b } else .none,
                .timeout = self.timeout,
                .connect_timeout = self.connect_timeout,
                .response_header_timeout = self.response_header_timeout,
                .read_idle_timeout = self.read_idle_timeout,
                .max_redirects = self.max_redirects,
                .check_redirect = self.check_redirect,
                .auto_decompress = self.auto_decompress,
            });
            defer pending.deinit();

            var resp = try pending.receiveHead();
            errdefer resp.deinit();

            self.last_status = resp.status();

            // WHATWG §9.2: `204 No Content` instructs the client to stop permanently (no reconnect).
            if (resp.status() == .no_content) {
                resp.deinit();
                self.response = null;
                self.ended = true;
                return;
            }

            if (resp.status() != .ok) {
                if (self.reconnect_on_transient_status and
                    isTransientSseStatus(resp.status()) and
                    self.canReconnect())
                {
                    const delay_ms = if (RetryTransport.parseRetryAfter(resp.headers().get("Retry-After"))) |ra|
                        @min(ra.toMilliseconds(), self.max_retry_ms)
                    else
                        @min(self.parser.retryMs(), self.max_retry_ms);
                    resp.deinit();
                    self.reconnects += 1;
                    if (delay_ms > 0) try zio.sleep(.fromMilliseconds(delay_ms));
                    continue;
                }
                if (self.rejected_status) |out_st| out_st.* = resp.status();
                return error.UnexpectedStatus;
            }

            if (self.validate_content_type) {
                const ct = resp.headers().get("Content-Type") orelse return error.InvalidContentType;
                if (!isEventStreamContentType(ct)) return error.InvalidContentType;
            }

            self.response = resp;
            self.parser.resetInput(self.response.?.reader());
            return;
        }
    }
};

fn isTransientSseStatus(status: http.Status) bool {
    return switch (status) {
        .too_many_requests, .bad_gateway, .service_unavailable, .gateway_timeout => true,
        else => false,
    };
}

/// Convenience helper equivalent to `sse.Stream.connect(client, opts)`.
pub fn connect(client: *Client, opts: Stream.ConnectOptions) !Stream {
    return Stream.connect(client, opts);
}

fn cloneHeaders(gpa: Allocator, src: []const http.Header) Allocator.Error![]http.Header {
    if (src.len == 0) return &.{};
    const out = try gpa.alloc(http.Header, src.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |h| {
            gpa.free(h.name);
            gpa.free(h.value);
        }
        gpa.free(out);
    }
    for (src, 0..) |h, i| {
        const name = try gpa.dupe(u8, h.name);
        errdefer gpa.free(name);
        const value = try gpa.dupe(u8, h.value);
        out[i] = .{ .name = name, .value = value };
        initialized = i + 1;
    }
    return out;
}

fn freeHeaders(gpa: Allocator, hdrs: []http.Header) void {
    if (hdrs.len == 0) return;
    for (hdrs) |h| {
        gpa.free(h.name);
        gpa.free(h.value);
    }
    gpa.free(hdrs);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockServer = @import("testing/MockServer.zig");

/// Deterministic 1-byte-at-a-time reader to verify split-boundary safety (BOM, CRLF).
const DripReader = struct {
    data: []const u8,
    pos: usize = 0,
    interface: IoReader,

    fn init(data: []const u8, buf: []u8) DripReader {
        return .{
            .data = data,
            .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = buf,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamImpl(r: *IoReader, w: *IoWriter, limit: std.Io.Limit) IoReader.StreamError!usize {
        const self: *DripReader = @fieldParentPtr("interface", r);
        if (self.pos >= self.data.len) return error.EndOfStream;
        const max_n = @min(@as(usize, 1), limit.minInt(1));
        if (max_n == 0) return 0;
        try w.writeAll(self.data[self.pos .. self.pos + 1]);
        self.pos += 1;
        return 1;
    }
};

test "sse.Reader handles UTF-8 BOM, 1-byte split CRLF/CR/LF, comments, and multi-line data" {
    const gpa = std.testing.allocator;
    const raw =
        "\xEF\xBB\xBF" ++
        ": heartbeat comment\r\n" ++
        "event: token\r\n" ++
        "id: 101\r" ++
        "retry: 2500\n" ++
        "data: hello\r\n" ++
        "data:  world\r" ++
        "\r\n" ++
        "event: orphan_no_data\n" ++
        "\n" ++
        "data:\n" ++
        "id: bad\x00nul\n" ++
        "retry: 12abc\n" ++
        "unknown: ignored\n" ++
        "\n" ++
        "data: trailing_without_blank_line";

    var buf: [1]u8 = undefined;
    var drip = DripReader.init(raw, &buf);
    var reader = try Reader.init(gpa, &drip.interface, .{});
    defer reader.deinit();

    // Event 1: BOM stripped, CRLF/CR/LF normalized, single leading space stripped.
    const ev1 = (try reader.next()).?;
    try std.testing.expectEqualStrings("token", ev1.event);
    try std.testing.expectEqualStrings("hello\n world", ev1.data);
    try std.testing.expectEqualStrings("101", ev1.id);
    try std.testing.expectEqual(@as(?u64, 2500), ev1.retry_ms);

    var owned = try ev1.dupe(gpa);
    defer owned.deinit();

    // Event 2: orphan event-only block dropped & event reset to "message";
    // empty `data:` dispatches empty string; NUL id & non-numeric retry ignored.
    const ev2 = (try reader.next()).?;
    try std.testing.expectEqualStrings("message", ev2.event);
    try std.testing.expectEqualStrings("", ev2.data);
    try std.testing.expectEqualStrings("101", ev2.id);
    try std.testing.expectEqual(@as(u64, 2500), reader.retryMs());

    // Owned copy from ev1 remains intact after ev2 overwrote buffers.
    try std.testing.expectEqualStrings("hello\n world", owned.data);

    // Trailing data without terminating blank line is discarded at EOF per WHATWG §9.2.6.
    try std.testing.expectEqual(@as(?Event, null), try reader.next());
}

test "sse.Reader enforces max_line_bytes and max_event_bytes caps" {
    const gpa = std.testing.allocator;

    {
        var fixed: IoReader = .fixed("data: 0123456789abcdef0123456789abcdef\n\n");
        var reader = try Reader.init(gpa, &fixed, .{ .max_line_bytes = 16 });
        defer reader.deinit();
        try std.testing.expectError(error.LineTooLong, reader.next());
    }

    {
        var fixed: IoReader = .fixed("data: 1234567890\ndata: 1234567890\n\n");
        var reader = try Reader.init(gpa, &fixed, .{ .max_event_bytes = 15 });
        defer reader.deinit();
        try std.testing.expectError(error.EventTooLarge, reader.next());
    }
}

fn readHttpRequestForTest(sr: *IoReader, out: []u8) ![]const u8 {
    var total: usize = 0;
    var header_end: ?usize = null;
    while (total < out.len) {
        const b = try sr.takeByte();
        out[total] = b;
        total += 1;
        if (total >= 4 and std.mem.eql(u8, out[total - 4 .. total], "\r\n\r\n")) {
            header_end = total;
            break;
        }
    }
    const hdr_end = header_end orelse return error.HeaderTooLarge;
    // Check for Content-Length and read exact body bytes if present.
    var content_len: usize = 0;
    var lines = std.mem.splitSequence(u8, out[0..hdr_end], "\r\n");
    while (lines.next()) |line| {
        if (std.mem.findScalar(u8, line, ':')) |colon| {
            const name = std.mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
                const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
                content_len = std.fmt.parseInt(usize, val, 10) catch 0;
            }
        }
    }
    var i: usize = 0;
    while (i < content_len and total < out.len) : (i += 1) {
        out[total] = try sr.takeByte();
        total += 1;
    }
    return out[0..total];
}

test "sse.Stream end-to-end POST streaming, Last-Event-ID reconnect, and 204 termination" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const State = struct {
        attempts: std.atomic.Value(u32) = .init(0),
        saw_post_body: std.atomic.Value(bool) = .init(false),
        saw_last_event_id: std.atomic.Value(bool) = .init(false),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [2048]u8 = undefined;
            var wbuf: [2048]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            var req_bytes: [2048]u8 = undefined;
            const req = readHttpRequestForTest(&sr.interface, &req_bytes) catch return;

            if (std.mem.find(u8, req, "{\"prompt\":\"hi\"}") != null) {
                self.saw_post_body.store(true, .release);
            }
            if (std.mem.find(u8, req, "Last-Event-ID: 42\r\n") != null) {
                self.saw_last_event_id.store(true, .release);
            }

            const attempt = self.attempts.fetchAdd(1, .acq_rel);
            switch (attempt) {
                0 => {
                    sw.interface.writeAll(
                        "HTTP/1.1 200 OK\r\n" ++
                            "Content-Type: text/event-stream; charset=utf-8\r\n" ++
                            "Transfer-Encoding: chunked\r\n" ++
                            "Connection: close\r\n\r\n" ++
                            "1e\r\n" ++
                            "id: 42\nretry: 10\ndata: part1\n\n" ++
                            "\r\n0\r\n\r\n",
                    ) catch return;
                    sw.interface.flush() catch return;
                },
                1 => {
                    sw.interface.writeAll(
                        "HTTP/1.1 200 OK\r\n" ++
                            "Content-Type: text/event-stream\r\n" ++
                            "Connection: close\r\n\r\n" ++
                            "event: delta\ndata: part2\n\n",
                    ) catch return;
                    sw.interface.flush() catch return;
                },
                else => {
                    sw.interface.writeAll(
                        "HTTP/1.1 204 No Content\r\n" ++
                            "Connection: close\r\n\r\n",
                    ) catch return;
                    sw.interface.flush() catch return;
                },
            }
        }
    };

    var state: State = .{};
    var srv: MockServer = undefined;
    try srv.start(&state, State.handle);
    defer srv.stop();

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    const url = try gpa.print("http://127.0.0.1:{d}/v1/chat/stream", .{srv.port()});
    defer gpa.free(url);

    var stream = try connect(&client, .{
        .method = .POST,
        .url = url,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = .{ .bytes = "{\"prompt\":\"hi\"}" },
        .auto_reconnect = true,
        .max_reconnects = 5,
    });
    defer stream.deinit();

    const e1 = (try stream.next()).?;
    try std.testing.expectEqualStrings("message", e1.event);
    try std.testing.expectEqualStrings("part1", e1.data);
    try std.testing.expectEqualStrings("42", e1.id);

    const e2 = (try stream.next()).?;
    try std.testing.expectEqualStrings("delta", e2.event);
    try std.testing.expectEqualStrings("part2", e2.data);
    try std.testing.expectEqualStrings("42", e2.id);

    // 3rd attempt returns 204 -> terminates cleanly with null.
    try std.testing.expectEqual(@as(?Event, null), try stream.next());
    try std.testing.expectEqual(http.Status.no_content, stream.status());
    try std.testing.expect(state.saw_post_body.load(.acquire));
    try std.testing.expect(state.saw_last_event_id.load(.acquire));
    try std.testing.expectEqual(@as(u32, 3), state.attempts.load(.acquire));
}

test "sse.Stream rejects non-200 status and non-event-stream Content-Type" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const Handler = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);
            var req_buf: [1024]u8 = undefined;
            const req = readHttpRequestForTest(&sr.interface, &req_buf) catch return;
            if (std.mem.find(u8, req, "GET /bad-ct") != null) {
                sw.interface.writeAll(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                ) catch return;
            } else {
                sw.interface.writeAll(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                ) catch return;
            }
            sw.interface.flush() catch return;
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, Handler.handle);
    defer srv.stop();

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    const bad_ct_url = try gpa.print("http://127.0.0.1:{d}/bad-ct", .{srv.port()});
    defer gpa.free(bad_ct_url);
    try std.testing.expectError(error.InvalidContentType, connect(&client, .{ .url = bad_ct_url }));

    const unauth_url = try gpa.print("http://127.0.0.1:{d}/auth", .{srv.port()});
    defer gpa.free(unauth_url);
    var rej: http.Status = .ok;
    try std.testing.expectError(error.UnexpectedStatus, connect(&client, .{
        .url = unauth_url,
        .auto_reconnect = true,
        .rejected_status = &rej,
    }));
    try std.testing.expectEqual(http.Status.unauthorized, rej);
}

test "sse.Stream retries transient 503 with Retry-After cap when auto_reconnect is enabled" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const FlakyState = struct {
        calls: std.atomic.Value(u32) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);
            var req_buf: [1024]u8 = undefined;
            _ = readHttpRequestForTest(&sr.interface, &req_buf) catch return;

            const c = self.calls.fetchAdd(1, .acq_rel);
            if (c == 0) {
                sw.interface.writeAll(
                    "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 999\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ) catch return;
            } else {
                sw.interface.writeAll(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n" ++
                        "data: recovered\n\n",
                ) catch return;
            }
            sw.interface.flush() catch return;
        }
    };

    var st: FlakyState = .{};
    var srv: MockServer = undefined;
    try srv.start(&st, FlakyState.handle);
    defer srv.stop();

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    const url = try gpa.print("http://127.0.0.1:{d}/stream", .{srv.port()});
    defer gpa.free(url);

    var stream = try connect(&client, .{
        .url = url,
        .auto_reconnect = true,
        .max_reconnects = 2,
        .max_retry_ms = 10,
    });
    defer stream.deinit();

    const ev = (try stream.next()).?;
    try std.testing.expectEqualStrings("recovered", ev.data);
    try std.testing.expectEqual(@as(u32, 2), st.calls.load(.acquire));
}
