//! HTTP/1.1 wire protocol engine (RFC 9112 & RFC 9110).
//!
//! Pure Sans-IO design: operates exclusively on `*std.Io.Reader` and
//! `*std.Io.Writer` with zero socket or runtime dependencies. Owns all
//! HTTP/1.1 framing knowledge: request serialization, 1xx skipping, header
//! parsing with memory limits, RFC 9112 §6.3 length resolution, anti-smuggling
//! checks, and chunked/fixed/close-delimited body state machines.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

const http = @import("http.zig");
const Method = http.Method;
const Status = http.Status;
const Origin = http.Origin;
const Header = http.Header;
const Headers = http.Headers;

pub const Version = enum {
    http1_0,
    http1_1,

    pub fn text(self: Version) []const u8 {
        return switch (self) {
            .http1_0 => "HTTP/1.0",
            .http1_1 => "HTTP/1.1",
        };
    }
};

pub const RequestFraming = union(enum) {
    none,
    content_length: u64,
    chunked,
};

pub const ResponseFraming = union(enum) {
    none,
    fixed: u64,
    chunked,
    close_delimited,
};

pub const RequestHead = struct {
    method: Method,
    origin: Origin,
    /// Origin-form request-target (e.g. "/items?limit=10"). Empty defaults to "/".
    target: []const u8 = "/",
    headers: []const Header = &.{},
    framing: RequestFraming = .none,
    close_connection: bool = false,
    /// When true, emits `Expect: 100-continue` (RFC 9110 §10.1.1).
    expect_continue: bool = false,
};

pub const RequestEncodeError = error{
    InvalidMethod,
    InvalidRequestTarget,
    ManagedHeaderConflict,
} || http.HeaderError || Writer.Error;

/// Serializes an HTTP/1.1 request-line, canonical Host/framing headers,
/// caller headers, and terminating CRLF to `w`.
///
/// Validates method, target, and all headers upfront before writing a single byte so
/// malformed input never leaks partial bytes onto a connection.
pub fn writeRequestHead(w: *Writer, req: RequestHead) RequestEncodeError!void {
    http.validateHeaderName(req.method.name()) catch return error.InvalidMethod;
    const target = if (req.target.len == 0) "/" else req.target;
    try validateRequestTarget(req.method, target);

    var has_host = false;
    var has_connection = false;
    var has_expect = false;
    for (req.headers) |h| {
        try http.validateHeaderName(h.name);
        try http.validateHeaderValue(h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "Host")) has_host = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Connection")) has_connection = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Expect")) has_expect = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Length") or
            std.ascii.eqlIgnoreCase(h.name, "Transfer-Encoding"))
        {
            return error.ManagedHeaderConflict;
        }
    }

    try w.print("{s} {s} HTTP/1.1\r\n", .{ req.method.name(), target });

    if (!has_host) {
        try w.writeAll("Host: ");
        try req.origin.writeHostHeader(w);
        try w.writeAll("\r\n");
    }

    switch (req.framing) {
        .none => {
            // Many HTTP/1.1 servers and proxies expect explicit Content-Length: 0
            // on body-bearing methods even when the payload is empty.
            if (req.method.expectsContentLengthZero()) {
                try w.writeAll("Content-Length: 0\r\n");
            }
        },
        .content_length => |len| {
            try w.print("Content-Length: {d}\r\n", .{len});
        },
        .chunked => {
            try w.writeAll("Transfer-Encoding: chunked\r\n");
        },
    }

    if (req.close_connection and !has_connection) {
        try w.writeAll("Connection: close\r\n");
    }

    if (req.expect_continue and !has_expect) {
        try w.writeAll("Expect: 100-continue\r\n");
    }

    for (req.headers) |h| {
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }

    try w.writeAll("\r\n");
}

fn validateRequestTarget(method: Method, target: []const u8) error{InvalidRequestTarget}!void {
    if (target.len == 0) return error.InvalidRequestTarget;
    if (std.mem.eql(u8, target, "*")) {
        if (!method.eql(.OPTIONS)) return error.InvalidRequestTarget;
        return;
    }
    // Allow origin-form ("/..."), absolute-form ("http://..." for HTTP proxies),
    // and authority-form ("host:port" for CONNECT tunnels).
    const valid_prefix = target[0] == '/' or
        std.mem.startsWith(u8, target, "http://") or
        method.eql(.CONNECT);
    if (!valid_prefix) return error.InvalidRequestTarget;
    for (target) |c| {
        // Disallow whitespace, CTLs, CR/LF, and '#' (URI fragments are never sent on the wire).
        if (c <= 0x20 or c >= 0x7F or c == '#') return error.InvalidRequestTarget;
    }
}

/// Framed HTTP/1.1 request body writer supporting none, fixed Content-Length,
/// and Transfer-Encoding: chunked.
///
/// Initialize in-place via `init()` so internal `std.Io.Writer` pointers stay valid.
pub const BodyWriter = struct {
    underlying: *Writer,
    framing: RequestFraming,
    bytes_written: u64 = 0,
    finished: bool = false,
    err: ?WriteError = null,
    interface: Writer,

    pub const WriteError = error{
        BodyNotAllowed,
        ContentLengthExceeded,
        ContentLengthMismatch,
        AlreadyFinished,
        EarlyResponse,
        WriteFailed,
    };

    pub fn init(self: *BodyWriter, underlying: *Writer, framing: RequestFraming, buffer: []u8) void {
        // Only chunked encoding benefits from a local coalescing buffer (combining
        // small writes into fewer chunks). Fixed-length and bodiless requests write
        // straight through to the already-buffered underlying writer so length
        // overflows or forbidden body writes are caught immediately on write().
        const effective_buf: []u8 = switch (framing) {
            .chunked => buffer,
            .none, .content_length => &.{},
        };
        self.* = .{
            .underlying = underlying,
            .framing = framing,
            .bytes_written = 0,
            .finished = false,
            .err = null,
            .interface = .{
                .vtable = &.{
                    .drain = drainImpl,
                },
                .buffer = effective_buf,
                .end = 0,
            },
        };
    }

    /// Initializes a writer that immediately rejects any write with `error.EarlyResponse`
    /// (used when a server short-circuits `Expect: 100-continue` with an early 4xx/5xx).
    pub fn initEarlyRejected(self: *BodyWriter, underlying: *Writer) void {
        self.* = .{
            .underlying = underlying,
            .framing = .none,
            .bytes_written = 0,
            .finished = false,
            .err = error.EarlyResponse,
            .interface = .{
                .vtable = &.{
                    .drain = drainImpl,
                },
                .buffer = &.{},
                .end = 0,
            },
        };
    }

    /// Flushes buffered body data and writes framing terminators (e.g. `0\r\n\r\n`
    /// for chunked) or verifies exact byte count (for fixed Content-Length).
    /// Idempotent once completed successfully.
    pub fn finish(self: *BodyWriter) WriteError!void {
        if (self.finished) return;
        if (self.err) |e| return e;

        self.interface.flush() catch {
            return self.err orelse error.WriteFailed;
        };

        switch (self.framing) {
            .none => {},
            .content_length => |expected| {
                if (self.bytes_written != expected) {
                    self.err = error.ContentLengthMismatch;
                    return error.ContentLengthMismatch;
                }
            },
            .chunked => {
                self.underlying.writeAll("0\r\n\r\n") catch {
                    self.err = error.WriteFailed;
                    return error.WriteFailed;
                };
            },
        }

        self.underlying.flush() catch {
            self.err = error.WriteFailed;
            return error.WriteFailed;
        };
        self.finished = true;
    }

    fn drainImpl(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *BodyWriter = @alignCast(@fieldParentPtr("interface", w));
        if (self.finished) {
            self.err = error.AlreadyFinished;
            return error.WriteFailed;
        }
        if (self.err != null) return error.WriteFailed;

        // Calculate total payload bytes to emit in this drain call.
        const buffered = w.buffer[0..w.end];
        var data_len: u64 = 0;
        if (data.len > 1) {
            for (data[0 .. data.len - 1]) |slice| data_len += slice.len;
        }
        const last = data[data.len - 1];
        data_len += @as(u64, last.len) * splat;
        const total = buffered.len + data_len;

        if (total == 0) return 0;

        switch (self.framing) {
            .none => {
                self.err = error.BodyNotAllowed;
                return error.WriteFailed;
            },
            .content_length => |expected| {
                if (total > expected - self.bytes_written) {
                    self.err = error.ContentLengthExceeded;
                    return error.WriteFailed;
                }
                try self.writeSegments(buffered, data, splat);
                self.bytes_written += total;
            },
            .chunked => {
                self.underlying.print("{x}\r\n", .{total}) catch {
                    self.err = error.WriteFailed;
                    return error.WriteFailed;
                };
                try self.writeSegments(buffered, data, splat);
                self.underlying.writeAll("\r\n") catch {
                    self.err = error.WriteFailed;
                    return error.WriteFailed;
                };
                self.bytes_written += total;
            },
        }

        w.end = 0;
        return @intCast(data_len);
    }

    fn writeSegments(self: *BodyWriter, buffered: []const u8, data: []const []const u8, splat: usize) Writer.Error!void {
        if (buffered.len > 0) {
            self.underlying.writeAll(buffered) catch {
                self.err = error.WriteFailed;
                return error.WriteFailed;
            };
        }
        if (data.len > 1) {
            for (data[0 .. data.len - 1]) |slice| {
                if (slice.len > 0) {
                    self.underlying.writeAll(slice) catch {
                        self.err = error.WriteFailed;
                        return error.WriteFailed;
                    };
                }
            }
        }
        const last = data[data.len - 1];
        if (last.len > 0 and splat > 0) {
            for (0..splat) |_| {
                self.underlying.writeAll(last) catch {
                    self.err = error.WriteFailed;
                    return error.WriteFailed;
                };
            }
        }
    }
};

pub const ParseOptions = struct {
    /// Total byte cap across all response head lines (including skipped 1xx heads).
    max_header_bytes: usize = 64 * 1024,
    /// Maximum number of header fields in a single response head.
    max_headers: usize = 128,
    /// Maximum number of 1xx informational responses skipped before failing.
    max_informational_responses: u8 = 8,
};

pub const ResponseHead = struct {
    version: Version,
    status: Status,
    reason: []const u8,
    headers: Headers,
    framing: ResponseFraming,
    /// True iff the protocol layer permits reusing the underlying connection
    /// once the response body has been fully consumed.
    keep_alive: bool,

    pub fn deinit(self: *ResponseHead, gpa: Allocator) void {
        gpa.free(self.reason);
        self.headers.deinit(gpa);
        self.* = undefined;
    }
};

pub const ParseHeadError = error{
    /// Peer closed cleanly before sending a single response byte (e.g. stale keep-alive socket).
    EndOfStream,
    /// Peer closed mid-headers after sending partial bytes.
    UnexpectedEof,
    ReadFailed,
    HeadersTooLarge,
    TooManyHeaders,
    TooManyInformationalResponses,
    InvalidStatusLine,
    InvalidStatusCode,
    InvalidHeaderLine,
    InvalidHeaderName,
    InvalidHeaderValue,
    ConflictingFraming,
    UnsupportedTransferEncoding,
    InvalidContentLength,
    ConflictingContentLength,
} || Allocator.Error;

pub const ContinueResult = union(enum) {
    /// Server replied `100 Continue`; client may now transmit the request body.
    @"continue",
    /// Server rejected or short-circuited the request with a final status (e.g. 401/413/417)
    /// before receiving the body.
    final_head: ResponseHead,
};

/// Reads either a `100 Continue` signal or an early final response head when
/// `Expect: 100-continue` was sent. Other 1xx responses (e.g. 103) are skipped.
pub fn readContinueOrFinalHead(
    gpa: Allocator,
    r: *Reader,
    request_method: Method,
    opts: ParseOptions,
) ParseHeadError!ContinueResult {
    return readResponseHeadInternal(gpa, r, request_method, opts, true);
}

/// Reads and validates an HTTP/1.1 response head from `r`.
///
/// Automatically skips non-101 `1xx` informational responses (such as
/// `100 Continue` and `103 Early Hints`), enforces memory limits, and resolves
/// exact body framing and keep-alive eligibility per RFC 9112 §6.3.
pub fn readResponseHead(
    gpa: Allocator,
    r: *Reader,
    request_method: Method,
    opts: ParseOptions,
) ParseHeadError!ResponseHead {
    return switch (try readResponseHeadInternal(gpa, r, request_method, opts, false)) {
        .final_head => |head| head,
        .@"continue" => unreachable,
    };
}

fn readResponseHeadInternal(
    gpa: Allocator,
    r: *Reader,
    request_method: Method,
    opts: ParseOptions,
    stop_on_100: bool,
) ParseHeadError!ContinueResult {
    var line_buf: std.ArrayList(u8) = .empty;
    defer line_buf.deinit(gpa);

    var total_bytes: usize = 0;
    var info_count: u8 = 0;

    while (true) {
        try readCrLfLine(gpa, r, &line_buf, &total_bytes, opts.max_header_bytes);
        const status_line = try parseStatusLine(line_buf.items);

        // Skip intermediate 1xx responses (e.g. 100 Continue, 103 Early Hints),
        // but return 101 Switching Protocols directly to the caller.
        if (status_line.status.isInformational() and status_line.status != .switching_protocols) {
            if (info_count >= opts.max_informational_responses) {
                return error.TooManyInformationalResponses;
            }
            info_count += 1;

            // Drain informational headers until the terminating empty line.
            var info_headers: usize = 0;
            while (true) {
                try readCrLfLine(gpa, r, &line_buf, &total_bytes, opts.max_header_bytes);
                if (line_buf.items.len == 0) break;
                if (info_headers >= opts.max_headers) return error.TooManyHeaders;
                info_headers += 1;
                try validateHeaderLineSyntax(line_buf.items);
            }
            if (stop_on_100 and status_line.status == .@"continue") {
                return .@"continue";
            }
            continue;
        }

        const owned_reason = try gpa.dupe(u8, status_line.reason);
        errdefer gpa.free(owned_reason);

        var headers: Headers = .empty;
        errdefer headers.deinit(gpa);

        while (true) {
            try readCrLfLine(gpa, r, &line_buf, &total_bytes, opts.max_header_bytes);
            if (line_buf.items.len == 0) break;
            if (headers.len() >= opts.max_headers) return error.TooManyHeaders;

            const parsed = try splitHeaderLine(line_buf.items);
            try headers.append(gpa, parsed.name, parsed.value);
        }

        const resolution = try resolveFramingAndKeepAlive(
            status_line.version,
            request_method,
            status_line.status,
            &headers,
        );

        return .{
            .final_head = .{
                .version = status_line.version,
                .status = status_line.status,
                .reason = owned_reason,
                .headers = headers,
                .framing = resolution.framing,
                .keep_alive = resolution.keep_alive,
            },
        };
    }
}

const ParsedStatusLine = struct {
    version: Version,
    status: Status,
    reason: []const u8,
};

fn parseStatusLine(line: []const u8) ParseHeadError!ParsedStatusLine {
    // Minimum valid status-line: "HTTP/1.1 200" (12 bytes).
    if (line.len < 12) return error.InvalidStatusLine;

    const version: Version = if (std.mem.eql(u8, line[0..9], "HTTP/1.1 "))
        .http1_1
    else if (std.mem.eql(u8, line[0..9], "HTTP/1.0 "))
        .http1_0
    else
        return error.InvalidStatusLine;

    const digits = line[9..12];
    for (digits) |d| {
        if (!std.ascii.isDigit(d)) return error.InvalidStatusLine;
    }
    const raw_code: u16 = (@as(u16, digits[0] - '0') * 100) +
        (@as(u16, digits[1] - '0') * 10) +
        @as(u16, digits[2] - '0');
    const status = try Status.fromInt(raw_code);

    const reason: []const u8 = if (line.len == 12)
        ""
    else if (line[12] == ' ')
        line[13..]
    else
        return error.InvalidStatusLine;

    // Validate reason-phrase contains no control characters (RFC 9112 §4).
    http.validateHeaderValue(reason) catch return error.InvalidStatusLine;

    return .{
        .version = version,
        .status = status,
        .reason = reason,
    };
}

fn validateHeaderLineSyntax(line: []const u8) ParseHeadError!void {
    const parsed = try splitHeaderLine(line);
    try http.validateHeaderName(parsed.name);
    try http.validateHeaderValue(parsed.value);
}

fn splitHeaderLine(line: []const u8) ParseHeadError!Header {
    // Reject obsolete line folding (obs-fold, RFC 9112 §5.2).
    if (line.len == 0 or line[0] == ' ' or line[0] == '\t') {
        return error.InvalidHeaderLine;
    }
    const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidHeaderLine;
    const raw_name = line[0..colon];
    const raw_value = trimOws(line[colon + 1 ..]);
    return .{
        .name = raw_name,
        .value = raw_value,
    };
}

fn trimOws(slice: []const u8) []const u8 {
    var start: usize = 0;
    while (start < slice.len and (slice[start] == ' ' or slice[start] == '\t')) : (start += 1) {}
    var end: usize = slice.len;
    while (end > start and (slice[end - 1] == ' ' or slice[end - 1] == '\t')) : (end -= 1) {}
    return slice[start..end];
}

/// Reads a single strict CRLF-terminated line into `out` (stripping `\r\n`).
/// Scans buffered chunks in bulk while rejecting bare CR and bare LF to prevent
/// line-splitting smuggling.
fn readCrLfLine(
    gpa: Allocator,
    r: *Reader,
    out: *std.ArrayList(u8),
    total_bytes: *usize,
    max_total_bytes: usize,
) ParseHeadError!void {
    out.clearRetainingCapacity();

    while (true) {
        const chunk = r.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return if (total_bytes.* == 0) error.EndOfStream else error.UnexpectedEof,
            error.ReadFailed => return error.ReadFailed,
        };

        if (std.mem.findAny(u8, chunk, "\r\n")) |idx| {
            const prefix = chunk[0..idx];
            const delim = chunk[idx];

            // Enforce byte cap before copying prefix + delimiter.
            if (prefix.len + 1 > max_total_bytes -| total_bytes.*) {
                return error.HeadersTooLarge;
            }
            if (prefix.len > 0) {
                try out.appendSlice(gpa, prefix);
            }
            r.toss(prefix.len + 1);
            total_bytes.* += prefix.len + 1;

            if (delim == '\n') {
                // Bare LF without CR is rejected.
                return error.InvalidHeaderLine;
            }

            // Saw '\r'; next byte MUST be '\n'.
            const next = r.takeByte() catch |err| switch (err) {
                error.EndOfStream => return error.UnexpectedEof,
                error.ReadFailed => return error.ReadFailed,
            };
            total_bytes.* += 1;
            if (total_bytes.* > max_total_bytes) return error.HeadersTooLarge;
            if (next != '\n') return error.InvalidHeaderLine;
            return;
        }

        // No CR/LF in current buffered chunk: append whole chunk in one memcpy.
        if (chunk.len > max_total_bytes -| total_bytes.*) {
            return error.HeadersTooLarge;
        }
        try out.appendSlice(gpa, chunk);
        r.toss(chunk.len);
        total_bytes.* += chunk.len;
    }
}

const FramingResolution = struct {
    framing: ResponseFraming,
    keep_alive: bool,
};

/// Determines response body framing and keep-alive eligibility strictly in
/// RFC 9112 §6.3 precedence order.
fn resolveFramingAndKeepAlive(
    version: Version,
    request_method: Method,
    status: Status,
    headers: *const Headers,
) ParseHeadError!FramingResolution {
    var conn_close = false;
    var conn_keep_alive = false;
    var conn_it = headers.valueIterator("Connection");
    while (conn_it.next()) |val| {
        var tok_it = std.mem.splitScalar(u8, val, ',');
        while (tok_it.next()) |raw_tok| {
            const tok = trimOws(raw_tok);
            if (std.ascii.eqlIgnoreCase(tok, "close")) conn_close = true;
            if (std.ascii.eqlIgnoreCase(tok, "keep-alive")) conn_keep_alive = true;
        }
    }

    var keep_alive = switch (version) {
        .http1_1 => !conn_close,
        .http1_0 => conn_keep_alive and !conn_close,
    };

    const has_te = headers.has("Transfer-Encoding");
    const has_cl = headers.has("Content-Length");

    // Priority 1: HEAD responses, 1xx / 204 / 304, and 2xx CONNECT tunnel responses
    // never carry a message body (RFC 9112 §6.3).
    if (request_method.forbidsResponseBody() or
        status.forbidsResponseBody() or
        (request_method.eql(.CONNECT) and status.isSuccess()))
    {
        if (status == .switching_protocols or request_method.eql(.CONNECT)) keep_alive = false;
        // Conservatively disable reuse if a bodyless status anomalously advertises TE.
        if (status.forbidsResponseBody() and has_te) keep_alive = false;
        return .{
            .framing = .none,
            .keep_alive = keep_alive,
        };
    }

    // Priority 2: Both Transfer-Encoding and Content-Length present => smuggling vector.
    if (has_te and has_cl) {
        return error.ConflictingFraming;
    }

    // Priority 3: Transfer-Encoding must terminate in a single `chunked` coding.
    if (has_te) {
        var coding_count: usize = 0;
        var te_it = headers.valueIterator("Transfer-Encoding");
        while (te_it.next()) |val| {
            var tok_it = std.mem.splitScalar(u8, val, ',');
            while (tok_it.next()) |raw_tok| {
                const tok = trimOws(raw_tok);
                if (tok.len == 0) continue;
                coding_count += 1;
                if (!std.ascii.eqlIgnoreCase(tok, "chunked")) {
                    return error.UnsupportedTransferEncoding;
                }
            }
        }
        // Reject empty TE or duplicate "chunked, chunked".
        if (coding_count != 1) return error.UnsupportedTransferEncoding;
        return .{
            .framing = .chunked,
            .keep_alive = keep_alive,
        };
    }

    // Priority 4: Content-Length (may appear multiple times / comma-separated if identical).
    if (has_cl) {
        var resolved_len: ?u64 = null;
        var cl_it = headers.valueIterator("Content-Length");
        while (cl_it.next()) |val| {
            var tok_it = std.mem.splitScalar(u8, val, ',');
            while (tok_it.next()) |raw_tok| {
                const tok = trimOws(raw_tok);
                const parsed = parseDecimalU64(tok) orelse return error.InvalidContentLength;
                if (resolved_len) |prev| {
                    if (prev != parsed) return error.ConflictingContentLength;
                } else {
                    resolved_len = parsed;
                }
            }
        }
        const len = resolved_len orelse return error.InvalidContentLength;
        return .{
            .framing = .{ .fixed = len },
            .keep_alive = keep_alive,
        };
    }

    // Priority 5: Close-delimited (read until EOF; connection cannot be reused).
    return .{
        .framing = .close_delimited,
        .keep_alive = false,
    };
}

fn parseDecimalU64(raw: []const u8) ?u64 {
    if (raw.len == 0) return null;
    var value: u64 = 0;
    for (raw) |c| {
        if (!std.ascii.isDigit(c)) return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, c - '0') catch return null;
    }
    return value;
}

/// Streaming HTTP/1.1 response body reader implementing `std.Io.Reader`.
///
/// Enforces exact wire framing boundaries so keep-alive connections stop at
/// byte 0 of the next response without over-reading a single byte.
///
/// Initialize in-place via `init()` so internal `std.Io.Reader` pointers stay valid.
pub const BodyReader = struct {
    underlying: *Reader,
    state: State,
    /// Remaining bytes in the current fixed body or current chunk payload.
    remaining: u64 = 0,
    /// Detailed error captured when `interface` returns `error.ReadFailed`.
    err: ?BodyReadError = null,
    interface: Reader,

    pub const max_chunk_line_bytes: usize = 4 * 1024;
    pub const max_trailer_bytes: usize = 16 * 1024;

    pub const BodyReadError = error{
        UnexpectedEof,
        InvalidChunkSize,
        ChunkTooLarge,
        MalformedChunk,
        TrailersTooLarge,
        ReadFailed,
    };

    const State = enum {
        done,
        fixed,
        chunk_size,
        chunk_data,
        chunk_crlf,
        trailers,
        close_delimited,
        failed,
    };

    pub fn init(self: *BodyReader, underlying: *Reader, framing: ResponseFraming, buffer: []u8) void {
        const initial_state: State, const initial_rem: u64 = switch (framing) {
            .none => .{ .done, 0 },
            .fixed => |n| if (n == 0) .{ .done, 0 } else .{ .fixed, n },
            .chunked => .{ .chunk_size, 0 },
            .close_delimited => .{ .close_delimited, 0 },
        };

        self.* = .{
            .underlying = underlying,
            .state = initial_state,
            .remaining = initial_rem,
            .err = null,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// True iff the underlying wire stream has been consumed cleanly to the
    /// exact boundary of this HTTP message (safe for keep-alive reuse if the
    /// response head also negotiated keep-alive).
    pub fn isComplete(self: *const BodyReader) bool {
        return self.state == .done and self.err == null;
    }

    fn fail(self: *BodyReader, e: BodyReadError) Reader.StreamError {
        self.state = .failed;
        self.err = e;
        return error.ReadFailed;
    }

    fn streamImpl(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const self: *BodyReader = @alignCast(@fieldParentPtr("interface", r));

        while (true) {
            switch (self.state) {
                .done => return error.EndOfStream,
                .failed => return error.ReadFailed,

                .fixed => {
                    if (self.remaining == 0) {
                        self.state = .done;
                        return error.EndOfStream;
                    }
                    const step_limit = limit.min(.limited64(self.remaining));
                    const n = self.underlying.stream(w, step_limit) catch |err| switch (err) {
                        error.EndOfStream => return self.fail(error.UnexpectedEof),
                        error.ReadFailed => return self.fail(error.ReadFailed),
                        error.WriteFailed => return error.WriteFailed,
                    };
                    self.remaining -= n;
                    if (self.remaining == 0) self.state = .done;
                    return n;
                },

                .chunk_size => {
                    const chunk_len = try self.readChunkSizeLine();
                    if (chunk_len == 0) {
                        self.state = .trailers;
                        continue;
                    }
                    self.remaining = chunk_len;
                    self.state = .chunk_data;
                    continue;
                },

                .chunk_data => {
                    const step_limit = limit.min(.limited64(self.remaining));
                    const n = self.underlying.stream(w, step_limit) catch |err| switch (err) {
                        error.EndOfStream => return self.fail(error.UnexpectedEof),
                        error.ReadFailed => return self.fail(error.ReadFailed),
                        error.WriteFailed => return error.WriteFailed,
                    };
                    self.remaining -= n;
                    if (self.remaining == 0) {
                        self.state = .chunk_crlf;
                    }
                    return n;
                },

                .chunk_crlf => {
                    try self.expectCrLf();
                    self.state = .chunk_size;
                    continue;
                },

                .trailers => {
                    try self.consumeTrailers();
                    self.state = .done;
                    return error.EndOfStream;
                },

                .close_delimited => {
                    const n = self.underlying.stream(w, limit) catch |err| switch (err) {
                        error.EndOfStream => {
                            self.state = .done;
                            return error.EndOfStream;
                        },
                        error.ReadFailed => return self.fail(error.ReadFailed),
                        error.WriteFailed => return error.WriteFailed,
                    };
                    return n;
                },
            }
        }
    }

    fn takeUnderlyingByte(self: *BodyReader) Reader.StreamError!u8 {
        return self.underlying.takeByte() catch |err| switch (err) {
            error.EndOfStream => return self.fail(error.UnexpectedEof),
            error.ReadFailed => return self.fail(error.ReadFailed),
        };
    }

    fn expectCrLf(self: *BodyReader) Reader.StreamError!void {
        const cr = try self.takeUnderlyingByte();
        if (cr != '\r') return self.fail(error.MalformedChunk);
        const lf = try self.takeUnderlyingByte();
        if (lf != '\n') return self.fail(error.MalformedChunk);
    }

    /// Parses RFC 9112 §7.1 `chunk-size [ chunk-ext ] CRLF` without heap allocation.
    fn readChunkSizeLine(self: *BodyReader) Reader.StreamError!u64 {
        var size: u64 = 0;
        var digit_count: usize = 0;
        var bytes_read: usize = 0;
        var in_bws_or_ext = false;
        var in_ext = false;

        while (true) {
            const b = try self.takeUnderlyingByte();
            bytes_read += 1;
            if (bytes_read > max_chunk_line_bytes) return self.fail(error.MalformedChunk);

            if (b == '\r') {
                const lf = try self.takeUnderlyingByte();
                bytes_read += 1;
                if (bytes_read > max_chunk_line_bytes or lf != '\n') {
                    return self.fail(error.MalformedChunk);
                }
                if (digit_count == 0) return self.fail(error.InvalidChunkSize);
                return size;
            }
            if (b == '\n') return self.fail(error.MalformedChunk);

            if (in_ext) {
                // Reject NUL/control bytes inside chunk-ext.
                if (b < 0x20 and b != '\t') return self.fail(error.MalformedChunk);
                continue;
            }

            if (in_bws_or_ext) {
                if (b == ';') {
                    in_ext = true;
                    continue;
                }
                if (b == ' ' or b == '\t') continue;
                return self.fail(error.InvalidChunkSize);
            }

            if (hexValue(b)) |digit| {
                digit_count += 1;
                size = std.math.mul(u64, size, 16) catch return self.fail(error.ChunkTooLarge);
                size = std.math.add(u64, size, digit) catch return self.fail(error.ChunkTooLarge);
                continue;
            }

            if (digit_count == 0) return self.fail(error.InvalidChunkSize);

            if (b == ';') {
                in_bws_or_ext = true;
                in_ext = true;
            } else if (b == ' ' or b == '\t') {
                in_bws_or_ext = true;
            } else {
                return self.fail(error.InvalidChunkSize);
            }
        }
    }

    /// Consumes optional trailer-section lines until the terminating empty CRLF line.
    fn consumeTrailers(self: *BodyReader) Reader.StreamError!void {
        var total_bytes: usize = 0;
        var line_len: usize = 0;

        while (true) {
            const b = try self.takeUnderlyingByte();
            total_bytes += 1;
            if (total_bytes > max_trailer_bytes) return self.fail(error.TrailersTooLarge);

            if (b == '\r') {
                const lf = try self.takeUnderlyingByte();
                total_bytes += 1;
                if (total_bytes > max_trailer_bytes) return self.fail(error.TrailersTooLarge);
                if (lf != '\n') return self.fail(error.MalformedChunk);
                if (line_len == 0) return; // Final empty line terminates chunked body.
                line_len = 0;
                continue;
            }
            if (b == '\n') return self.fail(error.MalformedChunk);
            line_len += 1;
        }
    }
};

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ===========================================================================
// Unit Tests (pure in-memory, deterministic, including 1-byte fragmentation)
// ===========================================================================

/// Test helper: feeds an in-memory byte slice 1 byte per underlying read call
/// to stress-test incremental parsing across worst-case TCP fragmentation.
const OneByteReader = struct {
    source: []const u8,
    pos: usize = 0,
    interface: Reader,

    fn init(self: *OneByteReader, source: []const u8, buf: []u8) void {
        self.* = .{
            .source = source,
            .pos = 0,
            .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = buf,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamImpl(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const self: *OneByteReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.pos >= self.source.len) return error.EndOfStream;
        const n = limit.minInt(1);
        if (n == 0) return 0;
        try w.writeByte(self.source[self.pos]);
        self.pos += 1;
        return 1;
    }
};

test "writeRequestHead formats Host, framing headers, and rejects conflicts" {
    var out_buf: [512]u8 = undefined;
    var w: Writer = .fixed(&out_buf);

    try writeRequestHead(&w, .{
        .method = .GET,
        .origin = .{ .scheme = .https, .host = "example.com", .port = 443 },
        .target = "/v1/items?a=1",
        .headers = &.{
            .{ .name = "Accept", .value = "application/json" },
        },
    });
    try std.testing.expectEqualStrings(
        "GET /v1/items?a=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Accept: application/json\r\n" ++
            "\r\n",
        w.buffered(),
    );

    // Empty POST auto-emits Content-Length: 0 and non-default port in Host
    w = .fixed(&out_buf);
    try writeRequestHead(&w, .{
        .method = .POST,
        .origin = .{ .scheme = .http, .host = "127.0.0.1", .port = 8080 },
        .target = "",
        .close_connection = true,
    });
    try std.testing.expectEqualStrings(
        "POST / HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:8080\r\n" ++
            "Content-Length: 0\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        w.buffered(),
    );

    // Rejects fragment '#' in target and caller-supplied Content-Length conflict
    w = .fixed(&out_buf);
    try std.testing.expectError(error.InvalidRequestTarget, writeRequestHead(&w, .{
        .method = .GET,
        .origin = .{ .scheme = .http, .host = "example.com", .port = 80 },
        .target = "/page#frag",
    }));
    try std.testing.expectError(error.ManagedHeaderConflict, writeRequestHead(&w, .{
        .method = .POST,
        .origin = .{ .scheme = .http, .host = "example.com", .port = 80 },
        .headers = &.{.{ .name = "Content-Length", .value = "5" }},
    }));
}

test "BodyWriter enforces Content-Length and encodes chunked framing" {
    // Fixed Content-Length happy path + mismatch/overflow checks
    var wire_buf: [256]u8 = undefined;
    var wire_w: Writer = .fixed(&wire_buf);
    var body_buf: [16]u8 = undefined;
    var bw: BodyWriter = undefined;
    bw.init(&wire_w, .{ .content_length = 5 }, &body_buf);

    try bw.interface.writeAll("he");
    try bw.interface.writeAll("llo");
    try bw.finish();
    try bw.finish(); // idempotent
    try std.testing.expectEqualStrings("hello", wire_w.buffered());

    // Short write detected on finish()
    wire_w = .fixed(&wire_buf);
    bw.init(&wire_w, .{ .content_length = 5 }, &body_buf);
    try bw.interface.writeAll("hi");
    try std.testing.expectError(error.ContentLengthMismatch, bw.finish());

    // Overflow write rejected before emitting excess bytes
    wire_w = .fixed(&wire_buf);
    bw.init(&wire_w, .{ .content_length = 3 }, &body_buf);
    try std.testing.expectError(error.WriteFailed, bw.interface.writeAll("1234"));
    try std.testing.expectEqual(@as(?BodyWriter.WriteError, error.ContentLengthExceeded), bw.err);

    // Bodiless framing rejects writes immediately
    wire_w = .fixed(&wire_buf);
    bw.init(&wire_w, .none, &body_buf);
    try std.testing.expectError(error.WriteFailed, bw.interface.writeAll("x"));
    try std.testing.expectEqual(@as(?BodyWriter.WriteError, error.BodyNotAllowed), bw.err);

    // Chunked encoding emits hex length + CRLF + payload + CRLF + 0\r\n\r\n
    wire_w = .fixed(&wire_buf);
    bw.init(&wire_w, .chunked, &body_buf);
    try bw.interface.writeAll("hello");
    try bw.interface.flush();
    try bw.interface.writeAll(" world!");
    try bw.finish();
    try std.testing.expectEqualStrings("5\r\nhello\r\n7\r\n world!\r\n0\r\n\r\n", wire_w.buffered());
}

test "readResponseHead handles 1xx skipping, OWS trimming, multi-value headers, and RFC 9112 §6.3" {
    const gpa = std.testing.allocator;

    const raw =
        "HTTP/1.1 100 Continue\r\n" ++
        "\r\n" ++
        "HTTP/1.1 103 Early Hints\r\n" ++
        "Link: </app.css>; rel=preload\r\n" ++
        "\r\n" ++
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type:  application/json \t\r\n" ++
        "Set-Cookie: a=1\r\n" ++
        "Set-Cookie: b=2\r\n" ++
        "Content-Length: 4, 4\r\n" ++
        "\r\n" ++
        "body";

    var r: Reader = .fixed(raw);
    var head = try readResponseHead(gpa, &r, .GET, .{});
    defer head.deinit(gpa);

    try std.testing.expectEqual(Version.http1_1, head.version);
    try std.testing.expectEqual(Status.ok, head.status);
    try std.testing.expectEqualStrings("OK", head.reason);
    try std.testing.expectEqual(ResponseFraming{ .fixed = 4 }, head.framing);
    try std.testing.expect(head.keep_alive);
    try std.testing.expectEqualStrings("application/json", head.headers.get("content-type").?);

    // HEAD ignores Content-Length for body framing and keeps connection reusable
    const head_raw = "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n";
    var hr: Reader = .fixed(head_raw);
    var head_res = try readResponseHead(gpa, &hr, .HEAD, .{});
    defer head_res.deinit(gpa);
    try std.testing.expectEqual(ResponseFraming.none, head_res.framing);
    try std.testing.expect(head_res.keep_alive);
}

test "readResponseHead rejects smuggling vectors, obs-fold, bare CR/LF, and oversize headers" {
    const gpa = std.testing.allocator;

    // Transfer-Encoding + Content-Length together => ConflictingFraming
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n");
        try std.testing.expectError(error.ConflictingFraming, readResponseHead(gpa, &r, .GET, .{}));
    }

    // Conflicting Content-Length values
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n");
        try std.testing.expectError(error.ConflictingContentLength, readResponseHead(gpa, &r, .GET, .{}));
    }

    // Duplicate chunked coding rejected
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n");
        try std.testing.expectError(error.UnsupportedTransferEncoding, readResponseHead(gpa, &r, .GET, .{}));
    }

    // Obsolete header folding rejected
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\r\nX-A: 1\r\n continued\r\n\r\n");
        try std.testing.expectError(error.InvalidHeaderLine, readResponseHead(gpa, &r, .GET, .{}));
    }

    // Bare LF rejected
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\nContent-Length: 0\n\n");
        try std.testing.expectError(error.InvalidHeaderLine, readResponseHead(gpa, &r, .GET, .{}));
    }

    // Header byte limit enforced
    {
        var r: Reader = .fixed("HTTP/1.1 200 OK\r\nX-Big: 12345678901234567890\r\n\r\n");
        try std.testing.expectError(
            error.HeadersTooLarge,
            readResponseHead(gpa, &r, .GET, .{ .max_header_bytes = 24 }),
        );
    }
}

test "1-byte fragmentation stress test: two back-to-back keep-alive responses (chunked+ext+trailer then fixed)" {
    const gpa = std.testing.allocator;

    const stream_bytes =
        // Response 1: 100 Continue + chunked with chunk-ext + trailer
        "HTTP/1.1 100 Continue\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5;ext=val\r\n" ++
        "hello\r\n" ++
        "6 ;foo=\"bar\"\r\n" ++
        " world\r\n" ++
        "0;last\r\n" ++
        "X-Checksum: abc123\r\n" ++
        "\r\n" ++
        // Response 2 immediately following on the same keep-alive stream
        "HTTP/1.1 201 Created\r\n" ++
        "Content-Length: 4\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "done";

    var one_byte_buf: [1]u8 = undefined;
    var source: OneByteReader = undefined;
    source.init(stream_bytes, &one_byte_buf);

    // Parse & consume Response 1 completely
    var head1 = try readResponseHead(gpa, &source.interface, .POST, .{});
    defer head1.deinit(gpa);
    try std.testing.expectEqual(Status.ok, head1.status);
    try std.testing.expectEqual(ResponseFraming.chunked, head1.framing);
    try std.testing.expect(head1.keep_alive);

    var body_buf1: [8]u8 = undefined;
    var body1: BodyReader = undefined;
    body1.init(&source.interface, head1.framing, &body_buf1);
    const payload1 = try body1.interface.allocRemaining(gpa, .limited(1024));
    defer gpa.free(payload1);
    try std.testing.expectEqualStrings("hello world", payload1);
    try std.testing.expect(body1.isComplete());

    // Stream MUST now sit at byte 0 of Response 2 with zero over-read
    var head2 = try readResponseHead(gpa, &source.interface, .GET, .{});
    defer head2.deinit(gpa);
    try std.testing.expectEqual(Status.created, head2.status);
    try std.testing.expectEqual(ResponseFraming{ .fixed = 4 }, head2.framing);
    try std.testing.expect(!head2.keep_alive);

    var body_buf2: [8]u8 = undefined;
    var body2: BodyReader = undefined;
    body2.init(&source.interface, head2.framing, &body_buf2);
    const payload2 = try body2.interface.allocRemaining(gpa, .limited(1024));
    defer gpa.free(payload2);
    try std.testing.expectEqualStrings("done", payload2);
    try std.testing.expect(body2.isComplete());
}

test "BodyReader detects truncated fixed/chunked bodies and malformed chunk syntax" {
    const gpa = std.testing.allocator;

    // Truncated Content-Length body must fail and report !isComplete()
    {
        var r: Reader = .fixed("abc");
        var buf: [8]u8 = undefined;
        var br: BodyReader = undefined;
        br.init(&r, .{ .fixed = 5 }, &buf);
        try std.testing.expectError(error.ReadFailed, br.interface.allocRemaining(gpa, .limited(16)));
        try std.testing.expectEqual(@as(?BodyReader.BodyReadError, error.UnexpectedEof), br.err);
        try std.testing.expect(!br.isComplete());
    }

    // Missing CRLF after chunk payload
    {
        var r: Reader = .fixed("3\r\nabcXX0\r\n\r\n");
        var buf: [8]u8 = undefined;
        var br: BodyReader = undefined;
        br.init(&r, .chunked, &buf);
        try std.testing.expectError(error.ReadFailed, br.interface.allocRemaining(gpa, .limited(32)));
        try std.testing.expectEqual(@as(?BodyReader.BodyReadError, error.MalformedChunk), br.err);
        try std.testing.expect(!br.isComplete());
    }

    // Chunk size hex overflow
    {
        var r: Reader = .fixed("ffffffffffffffff1\r\n");
        var buf: [8]u8 = undefined;
        var br: BodyReader = undefined;
        br.init(&r, .chunked, &buf);
        try std.testing.expectError(error.ReadFailed, br.interface.allocRemaining(gpa, .limited(32)));
        try std.testing.expectEqual(@as(?BodyReader.BodyReadError, error.ChunkTooLarge), br.err);
        try std.testing.expect(!br.isComplete());
    }

    // Close-delimited reads cleanly to EOF
    {
        var r: Reader = .fixed("until-eof");
        var buf: [8]u8 = undefined;
        var br: BodyReader = undefined;
        br.init(&r, .close_delimited, &buf);
        const payload = try br.interface.allocRemaining(gpa, .limited(32));
        defer gpa.free(payload);
        try std.testing.expectEqualStrings("until-eof", payload);
        try std.testing.expect(br.isComplete());
    }
}

test "fuzz h1.readResponseHead and BodyReader never panic or leak on arbitrary bytes" {
    const Fuzz = struct {
        fn run(_: void, smith: *std.testing.Smith) !void {
            var input_buf: [512]u8 = undefined;
            const n = smith.sliceWithHash(&input_buf, 0x11a1);
            const input = input_buf[0..n];

            const gpa = std.testing.allocator;
            var r: Reader = .fixed(input);
            var head = readResponseHead(gpa, &r, .GET, .{
                .max_header_bytes = 512,
                .max_headers = 32,
            }) catch return;
            defer head.deinit(gpa);

            var bbuf: [32]u8 = undefined;
            var br: BodyReader = undefined;
            br.init(&r, head.framing, &bbuf);
            const body = br.interface.allocRemaining(gpa, .limited(512)) catch return;
            gpa.free(body);
        }
    };

    try std.testing.fuzz({}, Fuzz.run, .{
        .corpus = &.{
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            "HTTP/1.0 404\r\n\r\nnot found",
            "GARBAGE\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n",
        },
    });
}
