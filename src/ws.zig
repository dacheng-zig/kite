//! Full-duplex RFC 6455 + RFC 7692 (`permessage-deflate`) WebSocket client built on
//! Kite's `Connection` and `h1` primitives.
//!
//! Architecture boundaries:
//! - Reuses `Connection` (DNS Happy Eyeballs, TLS 1.2/1.3, `CaStore`, HTTP/HTTPS/SOCKS5
//!   proxies, Unix domain sockets, SSRF `AddressFilter`, coroutine-stack-safe pinned buffers)
//!   and `h1` (`101 Switching Protocols` pass-through), plus optional `CookieJar`.
//! - Completely bypasses `Pool` and `Transport.Exchange`: once upgraded, `*Connection`
//!   transfers linearly to `ws.Conn` (preserving any pre-buffered leftover bytes received in
//!   the same TCP segment as the `101` response).
//! - Separates pure Sans-IO framing primitives (`ws.Frame`) from the coroutine-safe
//!   full-duplex `ws.Conn` (concurrent writers serialized via `zio.Mutex`).
//! - All large compression state (`std.compress.flate.Compress` ~224 KiB + 64 KiB windows)
//!   is lazily heap-allocated ONLY when `permessage-deflate` is negotiated, protecting
//!   `zio`'s 256 KiB default coroutine stacks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const IoReader = std.Io.Reader;
const IoWriter = std.Io.Writer;
const flate = std.compress.flate;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");
const Connection = @import("Connection.zig");
const CookieJar = @import("CookieJar.zig");
const Client = @import("Client.zig");

const ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// RFC 7692 §7.2.1 sync-flush trailer stripped on transmit / restored on inflate.
const deflate_tail = [4]u8{ 0x00, 0x00, 0xFF, 0xFF };
/// RFC 7692 §7.2.2 restore trailer (`00 00 FF FF`) followed by a 2-byte final empty
/// fixed-Huffman block (`BFINAL=1, BTYPE=01, EOB=0`) so `std.compress.flate.Decompress`
/// terminates cleanly on both BFINAL=0 (sync-flush) and BFINAL=1 peer streams.
const deflate_inflate_tail = [6]u8{ 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00 };
const read_chunk_step: usize = 64 * 1024;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn isControl(self: Opcode) bool {
        return (@backingInt(self) & 0x8) != 0;
    }

    pub fn isKnown(self: Opcode) bool {
        return switch (self) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            else => false,
        };
    }
};

pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    _,

    /// RFC 6455 §7.4 & IANA WebSocket Close Code Registry: returns true iff `code`
    /// is legal to transmit on the wire (forbids 1004, 1005, 1006, 1015, <1000, >=5000).
    pub fn isValidOnWire(code: u16) bool {
        return switch (code) {
            1000...1003, 1007...1014, 3000...4999 => true,
            else => false,
        };
    }
};

/// Read-only view of one complete WebSocket message returned by `Conn.readMessage()`.
///
/// `payload` borrows `Conn`'s internal reassembly buffer and stays valid until the
/// next `readMessage()` call or `deinit()`.
pub const Message = struct {
    pub const Kind = enum {
        text,
        binary,
        pong,
        close,
    };

    kind: Kind,
    /// For `.text`/`.binary`/`.pong`, the message payload; for `.close`, the UTF-8 reason string.
    payload: []const u8,
    /// Populated only for `.close` frames that carried a 2-byte status code.
    close_code: ?u16 = null,
};

/// Pure Sans-IO RFC 6455 wire framing and handshake key derivation primitives.
/// Zero socket and zero zio dependencies.
pub const Frame = struct {
    pub const Header = struct {
        fin: bool,
        rsv: u3,
        opcode: Opcode,
        masked: bool,
        payload_len: u64,
        mask_key: [4]u8,
    };

    pub const ReadError = error{
        EndOfStream,
        ReadFailed,
        ProtocolError,
    };

    /// Computes RFC 6455 §1.3 `Sec-WebSocket-Accept = Base64(SHA1(key || GUID))`.
    pub fn computeAcceptKey(client_key: []const u8) [28]u8 {
        var hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(client_key);
        hasher.update(ws_guid);
        var digest: [20]u8 = undefined;
        hasher.final(&digest);

        var encoded: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&encoded, &digest);
        return encoded;
    }

    /// XOR-masks or unmasks `data` in place starting at byte index `offset`.
    pub fn applyMask(data: []u8, key: [4]u8, offset: usize) void {
        for (data, 0..) |*b, i| {
            b.* ^= key[(offset + i) & 3];
        }
    }

    /// Reads and decodes one RFC 6455 frame header from `r`.
    pub fn readHeader(r: *IoReader) ReadError!Header {
        var b01: [2]u8 = undefined;
        r.readSliceAll(&b01) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };

        const fin = (b01[0] & 0x80) != 0;
        const rsv: u3 = @truncate((b01[0] >> 4) & 0x07);
        const opcode: Opcode = @fromBackingInt(@as(u4, @truncate(b01[0] & 0x0F)));
        const masked = (b01[1] & 0x80) != 0;
        const len7: u7 = @truncate(b01[1] & 0x7F);

        const payload_len: u64 = switch (len7) {
            0...125 => len7,
            126 => blk: {
                var ext: [2]u8 = undefined;
                r.readSliceAll(&ext) catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    error.ReadFailed => return error.ReadFailed,
                };
                break :blk std.mem.readInt(u16, &ext, .big);
            },
            127 => blk: {
                var ext: [8]u8 = undefined;
                r.readSliceAll(&ext) catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    error.ReadFailed => return error.ReadFailed,
                };
                const raw = std.mem.readInt(u64, &ext, .big);
                // RFC 6455 §5.2: the most significant bit of a 64-bit length MUST be 0.
                if ((raw & (@as(u64, 1) << 63)) != 0) return error.ProtocolError;
                break :blk raw;
            },
        };

        var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
        if (masked) {
            r.readSliceAll(&mask_key) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
            };
        }

        return .{
            .fin = fin,
            .rsv = rsv,
            .opcode = opcode,
            .masked = masked,
            .payload_len = payload_len,
            .mask_key = mask_key,
        };
    }

    /// Writes one RFC 6455 frame to `w` with `RSV=0`.
    pub fn writeFrame(
        w: *IoWriter,
        opcode: Opcode,
        fin: bool,
        payload: []const u8,
        mask_key: ?[4]u8,
    ) IoWriter.Error!void {
        return writeFrameRsv(w, opcode, fin, 0, payload, mask_key);
    }

    /// Writes one RFC 6455 frame with explicit 3-bit `rsv` flags (e.g. `0b100` for
    /// RFC 7692 `permessage-deflate` RSV1). Masks payload in fixed stack chunks with
    /// zero heap allocations.
    pub fn writeFrameRsv(
        w: *IoWriter,
        opcode: Opcode,
        fin: bool,
        rsv: u3,
        payload: []const u8,
        mask_key: ?[4]u8,
    ) IoWriter.Error!void {
        var hdr: [14]u8 = undefined;
        var hdr_len: usize = 2;

        hdr[0] = (if (fin) @as(u8, 0x80) else 0) | (@as(u8, rsv) << 4) | @as(u8, @backingInt(opcode));
        const mask_bit: u8 = if (mask_key != null) 0x80 else 0;

        if (payload.len <= 125) {
            hdr[1] = mask_bit | @as(u8, @intCast(payload.len));
        } else if (payload.len <= std.math.maxInt(u16)) {
            hdr[1] = mask_bit | 126;
            std.mem.writeInt(u16, hdr[2..4], @intCast(payload.len), .big);
            hdr_len = 4;
        } else {
            hdr[1] = mask_bit | 127;
            std.mem.writeInt(u64, hdr[2..10], @intCast(payload.len), .big);
            hdr_len = 10;
        }

        if (mask_key) |mk| {
            @memcpy(hdr[hdr_len..][0..4], &mk);
            hdr_len += 4;
        }

        try w.writeAll(hdr[0..hdr_len]);

        if (payload.len == 0) return;

        if (mask_key) |mk| {
            var chunk: [2048]u8 = undefined;
            var offset: usize = 0;
            while (offset < payload.len) {
                const take = @min(chunk.len, payload.len - offset);
                @memcpy(chunk[0..take], payload[offset..][0..take]);
                applyMask(chunk[0..take], mk, offset);
                try w.writeAll(chunk[0..take]);
                offset += take;
            }
        } else {
            try w.writeAll(payload);
        }
    }
};

/// Heap-allocated RFC 7692 `permessage-deflate` scratch workspace.
/// Keeps `flate.Compress` (~224 KiB) and 64 KiB inflate/deflate windows completely
/// off `zio`'s 256 KiB default coroutine stacks.
const DeflateWorkspace = struct {
    compressor: flate.Compress,
    compress_input_buf: [flate.max_window_len]u8,
    inflate_window: [flate.max_window_len]u8,

    fn create(gpa: Allocator) Allocator.Error!*DeflateWorkspace {
        const ws = try gpa.create(DeflateWorkspace);
        return ws;
    }

    fn destroy(self: *DeflateWorkspace, gpa: Allocator) void {
        gpa.destroy(self);
    }

    /// Compresses `plaintext` into `out` per RFC 7692 §7.2.1 (`client_no_context_takeover`):
    /// raw deflate followed by sync-flush empty stored block with trailing `00 00 FF FF` stripped.
    fn compressMessage(self: *DeflateWorkspace, gpa: Allocator, plaintext: []const u8, out: *std.ArrayList(u8)) !void {
        out.clearRetainingCapacity();

        var sink: IoWriter.Allocating = .init(gpa);
        defer sink.deinit();
        // `flate.Compress.init` asserts `output.buffer.len > 8`.
        try sink.ensureUnusedCapacity(@max(plaintext.len / 2 + 64, 64));

        self.compressor = try flate.Compress.init(
            &sink.writer,
            &self.compress_input_buf,
            .raw,
            .default,
        );
        try self.compressor.writer.writeAll(plaintext);
        try self.compressor.writer.flush();

        const raw = sink.written();
        if (raw.len >= 4 and std.mem.eql(u8, raw[raw.len - 4 ..], &deflate_tail)) {
            // `byteAlignBlocks()` emitted a stored empty block ending in `00 00 FF FF`: strip tail.
            try out.appendSlice(gpa, raw[0 .. raw.len - 4]);
        } else {
            // Byte-aligned without stored block tail: append 1-byte non-final empty stored header
            // (`0x00`); the trailing `00 00 FF FF` is elided per RFC 7692 §7.2.1.
            try out.ensureTotalCapacity(gpa, raw.len + 1);
            out.appendSliceAssumeCapacity(raw);
            out.appendAssumeCapacity(0x00);
        }
    }

    /// Decompresses RFC 7692 payload (already appended with `00 00 FF FF` tail) into `out`,
    /// strictly bounding expanded bytes to `max_bytes` to defeat Zip Bomb DoS attacks.
    fn decompressMessage(
        self: *DeflateWorkspace,
        gpa: Allocator,
        compressed_with_tail: []const u8,
        max_bytes: usize,
        out: *std.ArrayList(u8),
    ) !void {
        out.clearRetainingCapacity();

        var input_r: IoReader = .fixed(compressed_with_tail);
        var dec = flate.Decompress.init(&input_r, .raw, &self.inflate_window);

        var scratch: [4096]u8 = undefined;
        while (true) {
            const n = dec.reader.readSliceShort(&scratch) catch |err| switch (err) {
                error.ReadFailed => return dec.err orelse error.InvalidCompressedData,
            };
            if (n == 0) break;
            if (out.items.len + n > max_bytes) return error.MessageTooLarge;
            try out.appendSlice(gpa, scratch[0..n]);
        }
    }
};

pub const ConnectOptions = struct {
    /// Target URL (`ws://`, `wss://`, `ws+unix://`, or `http://` / `https://`).
    url: []const u8,
    /// Optional additional HTTP headers sent in the upgrade handshake.
    headers: []const http.Header = &.{},
    /// Optional `Sec-WebSocket-Protocol` subprotocol preference list.
    subprotocols: []const []const u8 = &.{},
    /// Optional `Origin` header value.
    origin: ?[]const u8 = null,
    /// Negotiate RFC 7692 `permessage-deflate` (`client_no_context_takeover; server_no_context_takeover`).
    enable_compression: bool = false,
    /// Minimum plaintext payload size (bytes) before outbound compression is applied.
    compression_min_bytes: usize = 64,
    /// Optional TLS configuration (`null` uses system root CAs or the parent `Client`'s config).
    tls: ?Connection.TlsConfig = null,
    /// Optional fallback proxy configuration (`http://`, `https://`, `socks5://`, `socks5h://`).
    proxy: ?Connection.ProxyConfig = null,
    /// Optional proxy specifically for `ws://` targets (overrides `proxy`).
    http_proxy: ?Connection.ProxyConfig = null,
    /// Optional proxy specifically for `wss://` targets (overrides `proxy`).
    https_proxy: ?Connection.ProxyConfig = null,
    /// Optional `no_proxy` bypass rules applied in addition to per-proxy `ProxyConfig.no_proxy`.
    no_proxy: []const []const u8 = &.{},
    /// Optional Unix domain socket path override.
    unix_socket_path: ?[]const u8 = null,
    /// Optional post-DNS IP address filter (SSRF protection).
    address_filter: ?Connection.AddressFilter = null,
    /// Optional cookie jar (sends matching cookies and stores `Set-Cookie` from handshake).
    cookie_jar: ?*CookieJar = null,
    /// Optional User-Agent header (`null` omits when not provided by `connectWithClient`).
    user_agent: ?[]const u8 = null,
    connect_timeout: zio.Timeout = .fromSeconds(10),
    handshake_timeout: zio.Timeout = .fromSeconds(10),
    /// Optional per-read idle timeout applied to the upgraded socket (detects dead/half-open peers).
    read_idle_timeout: zio.Timeout = .none,
    max_redirects: u8 = 5,
    max_frame_bytes: usize = 16 * 1024 * 1024,
    max_message_bytes: usize = 16 * 1024 * 1024,
    /// Automatically reply to incoming `Ping` frames with a matching `Pong` frame.
    auto_pong: bool = true,
    /// Surface incoming `Pong` frames from `readMessage()` (defaults to silent consume).
    return_pong: bool = false,
    /// Optional diagnostic sink populated with the HTTP status code when handshake
    /// fails with `error.UpgradeRejected` (e.g. `401`, `403`, `503`).
    rejected_status: ?*http.Status = null,
};

/// Active full-duplex WebSocket connection owning a pinned `*Connection`.
///
/// Safe for 1 reader coroutine calling `readMessage()` concurrently with N writer
/// coroutines calling `sendText()`/`sendBinary()`/`sendFragmented()`/`ping()`/`pong()`/`close()`.
/// Always `defer ws_conn.deinit()`.
pub const Conn = struct {
    gpa: Allocator,
    conn: *Connection,
    handshake_head: h1.ResponseHead,
    negotiated_subprotocol: ?[]u8 = null,

    write_mutex: zio.Mutex = .init,
    msg_buf: std.ArrayList(u8) = .empty,
    decomp_buf: std.ArrayList(u8) = .empty,
    comp_buf: std.ArrayList(u8) = .empty,
    ctrl_buf: [125]u8 = undefined,

    deflate_ws: ?*DeflateWorkspace = null,
    compression_enabled: bool = false,
    compression_min_bytes: usize = 64,

    max_frame_bytes: usize,
    max_message_bytes: usize,
    auto_pong: bool,
    return_pong: bool,

    close_sent: bool = false,
    close_received: bool = false,

    /// Connects directly to a WebSocket endpoint without needing a `kite.Client`.
    pub fn connect(gpa: Allocator, io: std.Io, opts: ConnectOptions) !Conn {
        var local_ca: Connection.CaStore = .init;
        defer local_ca.deinit(gpa);

        const tls_cfg = opts.tls orelse Connection.TlsConfig{ .system = &local_ca };
        return connectInternal(gpa, io, opts, tls_cfg);
    }

    /// Connects to a WebSocket endpoint while inheriting `client`'s TLS/CA store,
    /// proxy, Unix socket, address filter, cookie jar, and user-agent settings
    /// unless explicitly overridden in `opts`.
    pub fn connectWithClient(client: *Client, opts: ConnectOptions) !Conn {
        var effective = opts;
        const explicit_proxy_override = opts.proxy != null or opts.http_proxy != null or opts.https_proxy != null;
        if (!explicit_proxy_override) {
            effective.proxy = client.pool.config.proxy;
            effective.http_proxy = client.pool.config.http_proxy;
            effective.https_proxy = client.pool.config.https_proxy;
        }
        if (effective.no_proxy.len == 0) effective.no_proxy = client.pool.config.no_proxy;
        if (effective.unix_socket_path == null) effective.unix_socket_path = client.pool.config.unix_socket_path;
        if (effective.address_filter == null) effective.address_filter = client.pool.config.address_filter;
        if (effective.cookie_jar == null) effective.cookie_jar = client.config.cookie_jar;
        if (effective.user_agent == null) effective.user_agent = client.config.user_agent;

        const tls_cfg = effective.tls orelse client.pool.config.tls orelse Connection.TlsConfig{ .system = &client.pool.ca_store };
        return connectInternal(client.gpa, client.pool.io, effective, tls_cfg);
    }

    pub fn deinit(self: *Conn) void {
        if (self.deflate_ws) |ws| ws.destroy(self.gpa);
        if (self.negotiated_subprotocol) |sp| self.gpa.free(sp);
        self.msg_buf.deinit(self.gpa);
        self.decomp_buf.deinit(self.gpa);
        self.comp_buf.deinit(self.gpa);
        self.handshake_head.deinit(self.gpa);
        self.conn.destroy(self.gpa);
        self.* = undefined;
    }

    pub fn negotiatedSubprotocol(self: *const Conn) ?[]const u8 {
        return self.negotiated_subprotocol;
    }

    pub fn isCompressionEnabled(self: *const Conn) bool {
        return self.compression_enabled;
    }

    pub fn isClosed(self: *const Conn) bool {
        return self.close_sent or self.close_received;
    }

    pub fn handshakeHeaders(self: *const Conn) *const http.Headers {
        return &self.handshake_head.headers;
    }

    /// Sets or updates the per-read idle timeout on the underlying socket.
    pub fn setReadIdleTimeout(self: *Conn, timeout: zio.Timeout) void {
        self.conn.setReadIdleTimeout(timeout);
    }

    /// Reads the next complete WebSocket message (reassembling fragmented frames,
    /// decompressing RFC 7692 messages, and handling interleaved control frames).
    ///
    /// Returns `Message{ .kind = .close, ... }` upon receiving a peer Close frame
    /// (automatically echoing a Close reply if none was sent yet), and `null` on
    /// subsequent calls or clean EOF after a close handshake.
    pub fn readMessage(self: *Conn) !?Message {
        if (self.close_received) return null;

        self.msg_buf.clearRetainingCapacity();
        var active_kind: ?Message.Kind = null;
        var msg_compressed = false;

        while (true) {
            const hdr = Frame.readHeader(self.conn.reader()) catch |err| switch (err) {
                error.EndOfStream => {
                    if (self.close_sent) {
                        self.close_received = true;
                        return null;
                    }
                    return error.UnexpectedEof;
                },
                error.ReadFailed => return self.conn.unwrapReadError() orelse error.ReadFailed,
                error.ProtocolError => return error.ProtocolError,
            };

            // RFC 6455 §5.1: server-to-client frames MUST NOT be masked.
            if (hdr.masked) {
                self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                return error.MaskedServerFrame;
            }
            if (!hdr.opcode.isKnown()) {
                self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                return error.ProtocolError;
            }
            // RSV2 and RSV3 are never negotiated; RSV1 is legal ONLY on the initial
            // data frame when `permessage-deflate` was negotiated (RFC 7692 §6).
            if ((hdr.rsv & 0b011) != 0) {
                self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                return error.ProtocolError;
            }
            const has_rsv1 = (hdr.rsv & 0b100) != 0;

            if (hdr.opcode.isControl()) {
                // RFC 6455 §5.5 + RFC 7692 §6: control frames MUST NOT be fragmented,
                // compressed (RSV1=0), or exceed 125 bytes.
                if (!hdr.fin or has_rsv1 or hdr.payload_len > 125) {
                    self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                    return error.ProtocolError;
                }
                const clen: usize = @intCast(hdr.payload_len);
                if (clen > 0) {
                    try self.readPayloadExact(self.ctrl_buf[0..clen]);
                }
                const payload = self.ctrl_buf[0..clen];

                switch (hdr.opcode) {
                    .ping => {
                        if (self.auto_pong) {
                            try self.writeMaskedFrame(.pong, true, 0, payload);
                        }
                        continue;
                    },
                    .pong => {
                        if (self.return_pong and active_kind == null) {
                            return .{ .kind = .pong, .payload = payload };
                        }
                        continue;
                    },
                    .close => {
                        self.close_received = true;
                        if (clen == 1) {
                            self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                            return error.ProtocolError;
                        }
                        var code: ?u16 = null;
                        var reason: []const u8 = "";
                        if (clen >= 2) {
                            const raw_code = std.mem.readInt(u16, payload[0..2], .big);
                            if (!CloseCode.isValidOnWire(raw_code)) {
                                self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                                return error.ProtocolError;
                            }
                            code = raw_code;
                            reason = payload[2..];
                            if (!std.unicode.utf8ValidateSlice(reason)) {
                                self.sendBestEffortClose(@backingInt(CloseCode.invalid_payload));
                                return error.InvalidUtf8;
                            }
                        }
                        // Echo Close handshake back to peer if client did not initiate close.
                        if (!self.close_sent) {
                            self.sendBestEffortClose(code);
                        }
                        return .{
                            .kind = .close,
                            .payload = reason,
                            .close_code = code,
                        };
                    },
                    else => unreachable,
                }
            }

            // Data frame (`text`, `binary`, `continuation`)
            if (hdr.payload_len > self.max_frame_bytes) {
                self.sendBestEffortClose(@backingInt(CloseCode.message_too_big));
                return error.FrameTooLarge;
            }
            const flen: usize = @intCast(hdr.payload_len);

            switch (hdr.opcode) {
                .text, .binary => {
                    if (active_kind != null) {
                        self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                        return error.ProtocolError;
                    }
                    if (has_rsv1 and !self.compression_enabled) {
                        self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                        return error.ProtocolError;
                    }
                    active_kind = if (hdr.opcode == .text) .text else .binary;
                    msg_compressed = has_rsv1;
                },
                .continuation => {
                    if (active_kind == null or has_rsv1) {
                        self.sendBestEffortClose(@backingInt(CloseCode.protocol_error));
                        return error.ProtocolError;
                    }
                },
                else => unreachable,
            }

            if (self.msg_buf.items.len + flen > self.max_message_bytes) {
                self.sendBestEffortClose(@backingInt(CloseCode.message_too_big));
                return error.MessageTooLarge;
            }

            // Read payload incrementally in bounded steps (defeats memory-amplification DoS
            // where a malicious header declares 16 MiB before disconnecting immediately).
            var remaining: usize = flen;
            while (remaining > 0) {
                const take = @min(remaining, read_chunk_step);
                const start = self.msg_buf.items.len;
                try self.msg_buf.resize(self.gpa, start + take);
                self.readPayloadExact(self.msg_buf.items[start .. start + take]) catch |err| {
                    self.msg_buf.items.len = start;
                    return err;
                };
                remaining -= take;
            }

            if (hdr.fin) {
                const kind = active_kind.?;
                const final_payload: []const u8 = if (msg_compressed) blk: {
                    // RFC 7692 §7.2.2: append `00 00 FF FF` sync tail (+ final EOB for flate.Decompress)
                    // and inflate with strict Zip Bomb cap.
                    try self.msg_buf.appendSlice(self.gpa, &deflate_inflate_tail);
                    const ws = try self.ensureDeflateWorkspace();
                    ws.decompressMessage(self.gpa, self.msg_buf.items, self.max_message_bytes, &self.decomp_buf) catch |err| {
                        if (err == error.MessageTooLarge) {
                            self.sendBestEffortClose(@backingInt(CloseCode.message_too_big));
                        } else {
                            self.sendBestEffortClose(@backingInt(CloseCode.invalid_payload));
                        }
                        return err;
                    };
                    break :blk self.decomp_buf.items;
                } else self.msg_buf.items;

                if (kind == .text and !std.unicode.utf8ValidateSlice(final_payload)) {
                    self.sendBestEffortClose(@backingInt(CloseCode.invalid_payload));
                    return error.InvalidUtf8;
                }
                return .{
                    .kind = kind,
                    .payload = final_payload,
                };
            }
        }
    }

    pub fn sendText(self: *Conn, text: []const u8) !void {
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
        try self.sendDataMessage(.text, text);
    }

    pub fn sendBinary(self: *Conn, data: []const u8) !void {
        try self.sendDataMessage(.binary, data);
    }

    /// Sends a multi-fragment message (`text` or `binary` followed by `continuation` frames)
    /// atomically under `write_mutex` without concatenating chunks into a single buffer.
    pub fn sendFragmented(self: *Conn, kind: enum { text, binary }, chunks: []const []const u8) !void {
        const first_opcode: Opcode = if (kind == .text) .text else .binary;
        try self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.close_sent) return error.ConnectionClosed;

        if (chunks.len == 0) {
            try self.writeMaskedFrameLocked(first_opcode, true, 0, &.{});
            return;
        }
        for (chunks, 0..) |chunk, i| {
            const op: Opcode = if (i == 0) first_opcode else .continuation;
            const is_last = (i + 1 == chunks.len);
            try self.writeMaskedFrameLocked(op, is_last, 0, chunk);
        }
    }

    pub fn ping(self: *Conn, payload: []const u8) !void {
        if (payload.len > 125) return error.ControlPayloadTooLarge;
        try self.writeMaskedFrame(.ping, true, 0, payload);
    }

    pub fn pong(self: *Conn, payload: []const u8) !void {
        if (payload.len > 125) return error.ControlPayloadTooLarge;
        try self.writeMaskedFrame(.pong, true, 0, payload);
    }

    /// Sends a WebSocket Close frame (RFC 6455 §5.5.1). Calling `close()` more than
    /// once is a safe no-op.
    pub fn close(self: *Conn, code: ?u16, reason: []const u8) !void {
        if (code == null and reason.len > 0) return error.InvalidClosePayload;
        if (code) |c| {
            if (!CloseCode.isValidOnWire(c)) return error.InvalidCloseCode;
        }
        if (reason.len > 123) return error.ControlPayloadTooLarge;
        if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidUtf8;

        var buf: [125]u8 = undefined;
        var len: usize = 0;
        if (code) |c| {
            std.mem.writeInt(u16, buf[0..2], c, .big);
            @memcpy(buf[2..][0..reason.len], reason);
            len = 2 + reason.len;
        }

        try self.write_mutex.lock();
        defer self.write_mutex.unlock();

        if (self.close_sent) return;
        self.close_sent = true;
        try self.writeMaskedFrameLocked(.close, true, 0, buf[0..len]);
    }

    fn sendDataMessage(self: *Conn, opcode: Opcode, payload: []const u8) !void {
        try self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.close_sent) return error.ConnectionClosed;

        if (self.compression_enabled and payload.len >= self.compression_min_bytes) {
            const ws = try self.ensureDeflateWorkspace();
            try ws.compressMessage(self.gpa, payload, &self.comp_buf);
            // Only transmit compressed frame if compression actually saved bytes.
            if (self.comp_buf.items.len < payload.len) {
                try self.writeMaskedFrameLocked(opcode, true, 0b100, self.comp_buf.items);
                return;
            }
        }
        try self.writeMaskedFrameLocked(opcode, true, 0, payload);
    }

    fn ensureDeflateWorkspace(self: *Conn) Allocator.Error!*DeflateWorkspace {
        if (self.deflate_ws) |ws| return ws;
        const ws = try DeflateWorkspace.create(self.gpa);
        self.deflate_ws = ws;
        return ws;
    }

    fn sendBestEffortClose(self: *Conn, code: ?u16) void {
        self.write_mutex.lockUncancelable();
        defer self.write_mutex.unlock();
        if (self.close_sent) return;
        self.close_sent = true;
        var buf: [2]u8 = undefined;
        const payload: []const u8 = if (code) |c| blk: {
            std.mem.writeInt(u16, &buf, c, .big);
            break :blk &buf;
        } else &.{};
        self.writeMaskedFrameLocked(.close, true, 0, payload) catch {};
    }

    fn writeMaskedFrame(self: *Conn, opcode: Opcode, fin: bool, rsv: u3, payload: []const u8) !void {
        try self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.close_sent and opcode != .close) return error.ConnectionClosed;
        try self.writeMaskedFrameLocked(opcode, fin, rsv, payload);
    }

    fn writeMaskedFrameLocked(self: *Conn, opcode: Opcode, fin: bool, rsv: u3, payload: []const u8) !void {
        var mask_key: [4]u8 = undefined;
        try zio.randomSecure(&mask_key);
        Frame.writeFrameRsv(self.conn.writer(), opcode, fin, rsv, payload, mask_key) catch {
            return self.conn.unwrapWriteError() orelse error.WriteFailed;
        };
        try self.conn.flush();
    }

    fn readPayloadExact(self: *Conn, dest: []u8) !void {
        self.conn.reader().readSliceAll(dest) catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedEof,
            error.ReadFailed => return self.conn.unwrapReadError() orelse error.ReadFailed,
        };
    }
};

/// Convenience helper equivalent to `ws.Conn.connect(gpa, io, opts)`.
pub fn connect(gpa: Allocator, io: std.Io, opts: ConnectOptions) !Conn {
    return Conn.connect(gpa, io, opts);
}

/// Convenience helper equivalent to `ws.Conn.connectWithClient(client, opts)`.
pub fn connectWithClient(client: *Client, opts: ConnectOptions) !Conn {
    return Conn.connectWithClient(client, opts);
}

fn connectInternal(
    gpa: Allocator,
    io: std.Io,
    opts: ConnectOptions,
    tls_cfg: Connection.TlsConfig,
) !Conn {
    var current_url = try gpa.dupe(u8, opts.url);
    defer gpa.free(current_url);

    var extra_headers: http.Headers = .empty;
    defer extra_headers.deinit(gpa);
    for (opts.headers) |h| {
        try extra_headers.append(gpa, h.name, h.value);
    }

    var hops: u8 = 0;
    while (true) {
        const parsed = try parseWsUrl(current_url);
        var host_buf: [http.Origin.max_host_len]u8 = undefined;
        const origin = try parseWsOrigin(parsed.uri, &host_buf);
        const target = try extractTarget(current_url);

        const active_proxy = if (opts.unix_socket_path == null)
            Connection.ProxyConfig.resolve(origin, .{
                .proxy = opts.proxy,
                .http_proxy = opts.http_proxy,
                .https_proxy = opts.https_proxy,
                .no_proxy = opts.no_proxy,
            })
        else
            null;

        const conn = try zio.withTimeout(opts.connect_timeout, Connection.connect, .{
            gpa,
            origin,
            Connection.ConnectOptions{
                .io = io,
                .tls = tls_cfg,
                .proxy = active_proxy,
                .unix_socket_path = opts.unix_socket_path,
                .address_filter = opts.address_filter,
                .force_connect_tunnel = true,
            },
        });
        var conn_owned = true;
        errdefer if (conn_owned) conn.destroy(gpa);

        // Generate 16-byte random Sec-WebSocket-Key (Base64 = 24 chars).
        var key_raw: [16]u8 = undefined;
        try zio.randomSecure(&key_raw);
        var key_b64: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

        // Assemble upgrade request headers.
        var req_headers: std.ArrayList(http.Header) = .empty;
        defer req_headers.deinit(gpa);

        var subproto_joined: ?[]u8 = null;
        defer if (subproto_joined) |s| gpa.free(s);
        var jar_cookie: ?[]u8 = null;
        defer if (jar_cookie) |c| gpa.free(c);

        var has_cookie = false;
        var has_ua = false;
        for (extra_headers.items()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "Upgrade") or
                std.ascii.eqlIgnoreCase(h.name, "Connection") or
                std.ascii.eqlIgnoreCase(h.name, "Sec-WebSocket-Key") or
                std.ascii.eqlIgnoreCase(h.name, "Sec-WebSocket-Version") or
                (opts.enable_compression and std.ascii.eqlIgnoreCase(h.name, "Sec-WebSocket-Extensions")))
            {
                continue;
            }
            if (std.ascii.eqlIgnoreCase(h.name, "Cookie")) has_cookie = true;
            if (std.ascii.eqlIgnoreCase(h.name, "User-Agent")) has_ua = true;
            try req_headers.append(gpa, h);
        }

        try req_headers.append(gpa, .{ .name = "Upgrade", .value = "websocket" });
        try req_headers.append(gpa, .{ .name = "Connection", .value = "Upgrade" });
        try req_headers.append(gpa, .{ .name = "Sec-WebSocket-Key", .value = &key_b64 });
        try req_headers.append(gpa, .{ .name = "Sec-WebSocket-Version", .value = "13" });

        if (opts.enable_compression) {
            try req_headers.append(gpa, .{
                .name = "Sec-WebSocket-Extensions",
                .value = "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
            });
        }
        if (opts.origin) |orig_hdr| {
            try req_headers.append(gpa, .{ .name = "Origin", .value = orig_hdr });
        }
        if (opts.user_agent) |ua| {
            if (!has_ua) try req_headers.append(gpa, .{ .name = "User-Agent", .value = ua });
        }
        if (opts.subprotocols.len > 0) {
            subproto_joined = try joinSubprotocols(gpa, opts.subprotocols);
            try req_headers.append(gpa, .{ .name = "Sec-WebSocket-Protocol", .value = subproto_joined.? });
        }
        if (opts.cookie_jar) |jar| {
            if (!has_cookie) {
                jar_cookie = try jar.cookieHeaderAlloc(gpa, origin, target);
                if (jar_cookie) |cv| {
                    try req_headers.append(gpa, .{ .name = "Cookie", .value = cv });
                }
            }
        }

        // Send HTTP/1.1 Upgrade request and read response head under handshake_timeout.
        var head = try zio.withTimeout(opts.handshake_timeout, performHandshake, .{
            gpa,
            conn,
            origin,
            target,
            req_headers.items,
        });
        var head_owned = true;
        errdefer if (head_owned) head.deinit(gpa);

        if (opts.cookie_jar) |jar| {
            try jar.storeFromHeaders(origin, target, &head.headers);
        }

        // Follow 3xx redirects before upgrade if enabled.
        if (head.status.isRedirect()) {
            if (head.headers.get("Location")) |location| {
                if (hops >= opts.max_redirects) return error.TooManyRedirects;
                hops += 1;

                const next_url = try resolveWsRedirectUrl(gpa, parsed.uri, location);
                errdefer gpa.free(next_url);

                const next_parsed = try parseWsUrl(next_url);
                var next_host_buf: [http.Origin.max_host_len]u8 = undefined;
                const next_origin = try parseWsOrigin(next_parsed.uri, &next_host_buf);

                if (origin.scheme != .http_unix and next_origin.scheme == .http_unix) {
                    return error.UnixSocketRedirectBlocked;
                }
                if (!origin.eql(next_origin)) {
                    _ = extra_headers.removeAll(gpa, "Authorization");
                    _ = extra_headers.removeAll(gpa, "Cookie");
                    _ = extra_headers.removeAll(gpa, "Proxy-Authorization");
                }
                _ = extra_headers.removeAll(gpa, "Host");

                head.deinit(gpa);
                head_owned = false;
                conn.destroy(gpa);
                conn_owned = false;

                gpa.free(current_url);
                current_url = next_url;
                continue;
            }
        }

        if (head.status != .switching_protocols) {
            if (opts.rejected_status) |out_status| out_status.* = head.status;
            return error.UpgradeRejected;
        }

        // RFC 6455 §4.1 strict handshake response validation.
        const upgrade_hdr = head.headers.get("Upgrade") orelse return error.InvalidUpgradeResponse;
        if (!headerHasToken(upgrade_hdr, "websocket")) return error.InvalidUpgradeResponse;

        const conn_hdr = head.headers.get("Connection") orelse return error.InvalidUpgradeResponse;
        if (!headerHasToken(conn_hdr, "upgrade")) return error.InvalidUpgradeResponse;

        const accept_hdr = head.headers.get("Sec-WebSocket-Accept") orelse return error.InvalidAcceptKey;
        const expected_accept = Frame.computeAcceptKey(&key_b64);
        if (!std.mem.eql(u8, std.mem.trim(u8, accept_hdr, " \t"), &expected_accept)) {
            return error.InvalidAcceptKey;
        }

        // Subprotocol negotiation validation.
        var negotiated: ?[]u8 = null;
        errdefer if (negotiated) |sp| gpa.free(sp);
        if (head.headers.get("Sec-WebSocket-Protocol")) |resp_proto_raw| {
            const resp_proto = std.mem.trim(u8, resp_proto_raw, " \t");
            var matched = false;
            for (opts.subprotocols) |candidate| {
                if (std.mem.eql(u8, candidate, resp_proto)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return error.InvalidSubprotocol;
            negotiated = try gpa.dupe(u8, resp_proto);
        }

        // RFC 7692 extension negotiation validation.
        const compression_negotiated = if (opts.enable_compression)
            negotiatedPermessageDeflate(&head.headers)
        else
            false;

        if (opts.read_idle_timeout != .none) {
            conn.setReadIdleTimeout(opts.read_idle_timeout);
        }

        // Linearly transfer ownership of `conn` and `head` to `Conn`.
        conn_owned = false;
        head_owned = false;
        return .{
            .gpa = gpa,
            .conn = conn,
            .handshake_head = head,
            .negotiated_subprotocol = negotiated,
            .compression_enabled = compression_negotiated,
            .compression_min_bytes = opts.compression_min_bytes,
            .max_frame_bytes = opts.max_frame_bytes,
            .max_message_bytes = opts.max_message_bytes,
            .auto_pong = opts.auto_pong,
            .return_pong = opts.return_pong,
        };
    }
}

fn negotiatedPermessageDeflate(headers: *const http.Headers) bool {
    var it = headers.valueIterator("Sec-WebSocket-Extensions");
    while (it.next()) |raw| {
        var exts = std.mem.splitScalar(u8, raw, ',');
        while (exts.next()) |ext_raw| {
            const ext = std.mem.trim(u8, ext_raw, " \t");
            const semi = std.mem.findScalar(u8, ext, ';') orelse ext.len;
            const name = std.mem.trim(u8, ext[0..semi], " \t");
            if (std.ascii.eqlIgnoreCase(name, "permessage-deflate")) {
                return true;
            }
        }
    }
    return false;
}

fn performHandshake(
    gpa: Allocator,
    conn: *Connection,
    origin: http.Origin,
    target: []const u8,
    headers: []const http.Header,
) !h1.ResponseHead {
    h1.writeRequestHead(conn.writer(), .{
        .method = .GET,
        .origin = origin,
        .target = target,
        .headers = headers,
    }) catch |err| switch (err) {
        error.WriteFailed => return conn.unwrapWriteError() orelse error.WriteFailed,
        else => return err,
    };
    try conn.flush();

    return h1.readResponseHead(gpa, conn.reader(), .GET, .{}) catch |err| switch (err) {
        error.ReadFailed => return conn.unwrapReadError() orelse error.ReadFailed,
        else => return err,
    };
}

const ParsedWsUrl = struct {
    uri: std.Uri,
};

fn parseWsUrl(url: []const u8) !ParsedWsUrl {
    return .{ .uri = try std.Uri.parse(url) };
}

fn parseWsOrigin(uri: std.Uri, host_buf: *[http.Origin.max_host_len]u8) !http.Origin {
    const scheme: http.Scheme = if (std.ascii.eqlIgnoreCase(uri.scheme, "ws") or std.ascii.eqlIgnoreCase(uri.scheme, "http"))
        .http
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "wss") or std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        .https
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "ws+unix") or std.ascii.eqlIgnoreCase(uri.scheme, "http+unix"))
        .http_unix
    else
        return error.UnsupportedScheme;

    var normalized_uri = uri;
    normalized_uri.scheme = switch (scheme) {
        .http => "http",
        .https => "https",
        .http_unix => "http+unix",
    };
    return http.Origin.fromUri(normalized_uri, host_buf);
}

fn extractTarget(url: []const u8) ![]const u8 {
    const scheme_sep = std.mem.find(u8, url, "://") orelse return error.InvalidUrl;
    const after_scheme = scheme_sep + 3;
    const frag = std.mem.findScalarPos(u8, url, after_scheme, '#') orelse url.len;
    const no_frag = url[0..frag];

    const slash = std.mem.findScalarPos(u8, no_frag, after_scheme, '/');
    const qmark = std.mem.findScalarPos(u8, no_frag, after_scheme, '?');
    if (slash) |s| {
        if (qmark == null or s < qmark.?) return no_frag[s..];
    }
    return "/";
}

fn resolveWsRedirectUrl(gpa: Allocator, base: std.Uri, location: []const u8) ![]u8 {
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

    var out: IoWriter.Allocating = .init(gpa);
    errdefer out.deinit();

    try out.writer.print("{s}://", .{resolved.scheme});
    if (resolved.host) |h| {
        if (std.ascii.eqlIgnoreCase(resolved.scheme, "ws+unix") or std.ascii.eqlIgnoreCase(resolved.scheme, "http+unix")) {
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
    if (resolved.path.percent_encoded.len == 0) {
        try out.writer.writeByte('/');
    } else {
        try out.writer.writeAll(resolved.path.percent_encoded);
    }
    if (resolved.query) |q| {
        try out.writer.writeByte('?');
        try out.writer.writeAll(q.percent_encoded);
    }
    return out.toOwnedSlice();
}

fn joinSubprotocols(gpa: Allocator, list: []const []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (list, 0..) |sp, i| {
        if (i > 0) try out.appendSlice(gpa, ", ");
        try out.appendSlice(gpa, sp);
    }
    return out.toOwnedSlice(gpa);
}

fn headerHasToken(value: []const u8, needle: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const tok = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(tok, needle)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockServer = @import("testing/MockServer.zig");

test "ws.Frame RFC 6455 §1.3 Sec-WebSocket-Accept vector, mask roundtrip, and IANA close codes" {
    const accept = Frame.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);

    // Verify 7-bit, 16-bit, and masked frame encode/decode roundtrip.
    const gpa = std.testing.allocator;
    const big = try gpa.alloc(u8, 300);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i * 31 + 7);

    var wire: IoWriter.Allocating = .init(gpa);
    defer wire.deinit();

    const key = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    try Frame.writeFrame(&wire.writer, .binary, true, big, key);

    var r: IoReader = .fixed(wire.written());
    const hdr = try Frame.readHeader(&r);
    try std.testing.expect(hdr.fin);
    try std.testing.expectEqual(Opcode.binary, hdr.opcode);
    try std.testing.expect(hdr.masked);
    try std.testing.expectEqual(@as(u64, 300), hdr.payload_len);
    try std.testing.expectEqualSlices(u8, &key, &hdr.mask_key);

    const decoded = try gpa.alloc(u8, 300);
    defer gpa.free(decoded);
    try r.readSliceAll(decoded);
    Frame.applyMask(decoded, hdr.mask_key, 0);
    try std.testing.expectEqualSlices(u8, big, decoded);

    // Wire close-code validation (RFC 6455 §7.4 + IANA 1012/1013/1014)
    try std.testing.expect(CloseCode.isValidOnWire(1000));
    try std.testing.expect(CloseCode.isValidOnWire(1012));
    try std.testing.expect(CloseCode.isValidOnWire(1013));
    try std.testing.expect(CloseCode.isValidOnWire(1014));
    try std.testing.expect(CloseCode.isValidOnWire(3000));
    try std.testing.expect(!CloseCode.isValidOnWire(1005));
    try std.testing.expect(!CloseCode.isValidOnWire(1006));
    try std.testing.expect(!CloseCode.isValidOnWire(1015));
    try std.testing.expect(!CloseCode.isValidOnWire(999));
}

fn readUpgradeKeyForTest(sr: *IoReader, key_out: *[24]u8) !void {
    var got_key = false;
    while (true) {
        const line = try sr.takeDelimiterInclusive('\n');
        if (std.mem.eql(u8, line, "\r\n")) break;
        if (std.ascii.startsWithIgnoreCase(line, "sec-websocket-key:")) {
            const v = std.mem.trim(u8, line["sec-websocket-key:".len..], " \t\r\n");
            if (v.len == 24) {
                @memcpy(key_out, v);
                got_key = true;
            }
        }
    }
    if (!got_key) return error.MissingKey;
}

test "ws.Conn end-to-end: leftover piggybacked frame, split UTF-8 fragments + interleaved Ping, concurrent writes, fragmented send, and Close" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const WsServer = struct {
        saw_pong: std.atomic.Value(bool) = .init(false),
        echoed_count: std.atomic.Value(u32) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [4096]u8 = undefined;
            var wbuf: [4096]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            var client_key: [24]u8 = undefined;
            readUpgradeKeyForTest(&sr.interface, &client_key) catch return;
            const accept = Frame.computeAcceptKey(&client_key);

            // 1. Piggyback first WebSocket frame in the EXACT same write as `101` response (R2 leftover bytes test).
            sw.interface.print(
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: keep-alive, Upgrade\r\n" ++
                    "Sec-WebSocket-Accept: {s}\r\n" ++
                    "Sec-WebSocket-Protocol: chat.v1\r\n\r\n",
                .{accept},
            ) catch return;
            Frame.writeFrame(&sw.interface, .text, true, "instant", null) catch return;

            // 2. Fragmented 3-byte UTF-8 char "中" (0xE4 0xB8 0xAD) split across 2 frames
            //    with an interleaved Ping("hb") control frame in between!
            Frame.writeFrame(&sw.interface, .text, false, &.{ 0xE4, 0xB8 }, null) catch return;
            Frame.writeFrame(&sw.interface, .ping, true, "hb", null) catch return;
            Frame.writeFrame(&sw.interface, .continuation, true, &.{0xAD}, null) catch return;
            sw.interface.flush() catch return;

            // 3. Read masked frames from client: expect auto-Pong("hb"), reassemble/echo text frames, handle Close.
            var payload_buf: [256]u8 = undefined;
            var frag_buf: [256]u8 = undefined;
            var frag_len: usize = 0;
            while (true) {
                const hdr = Frame.readHeader(&sr.interface) catch return;
                if (!hdr.masked or hdr.payload_len > payload_buf.len) return;
                const plen: usize = @intCast(hdr.payload_len);
                if (plen > 0) sr.interface.readSliceAll(payload_buf[0..plen]) catch return;
                Frame.applyMask(payload_buf[0..plen], hdr.mask_key, 0);
                const data = payload_buf[0..plen];

                switch (hdr.opcode) {
                    .pong => {
                        if (std.mem.eql(u8, data, "hb")) {
                            self.saw_pong.store(true, .release);
                        }
                    },
                    .text, .continuation => {
                        if (frag_len + data.len > frag_buf.len) return;
                        @memcpy(frag_buf[frag_len..][0..data.len], data);
                        frag_len += data.len;
                        if (hdr.fin) {
                            _ = self.echoed_count.fetchAdd(1, .acq_rel);
                            Frame.writeFrame(&sw.interface, .text, true, frag_buf[0..frag_len], null) catch return;
                            sw.interface.flush() catch return;
                            frag_len = 0;
                        }
                    },
                    .close => {
                        Frame.writeFrame(&sw.interface, .close, true, data, null) catch return;
                        sw.interface.flush() catch return;
                        return;
                    },
                    else => {},
                }
            }
        }
    };

    var ws_srv: WsServer = .{};
    var srv: MockServer = undefined;
    try srv.start(&ws_srv, WsServer.handle);
    defer srv.stop();

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    const url = try gpa.print("ws://127.0.0.1:{d}/realtime", .{srv.port()});
    defer gpa.free(url);

    var conn = try connectWithClient(&client, .{
        .url = url,
        .subprotocols = &.{ "chat.v1", "chat.v2" },
    });
    defer conn.deinit();

    try std.testing.expectEqualStrings("chat.v1", conn.negotiatedSubprotocol().?);

    // Message 1: piggybacked directly after 101 headers (leftover bytes preserved!)
    const m1 = (try conn.readMessage()).?;
    try std.testing.expectEqual(Message.Kind.text, m1.kind);
    try std.testing.expectEqualStrings("instant", m1.payload);

    // Message 2: fragmented UTF-8 "中" with interleaved Ping (auto-Pong sent)
    const m2 = (try conn.readMessage()).?;
    try std.testing.expectEqual(Message.Kind.text, m2.kind);
    try std.testing.expectEqualStrings("中", m2.payload);

    // Concurrent writers test (I-WS-1 write_mutex serialization)
    const WriterTask = struct {
        fn send(c: *Conn, text: []const u8) !void {
            try c.sendText(text);
        }
    };
    var group: zio.Group = .init;
    try group.spawn(WriterTask.send, .{ &conn, "msg-a" });
    try group.spawn(WriterTask.send, .{ &conn, "msg-b" });
    try group.spawn(WriterTask.send, .{ &conn, "msg-c" });
    try group.wait();

    var received: u32 = 0;
    while (received < 3) : (received += 1) {
        const m = (try conn.readMessage()).?;
        try std.testing.expectEqual(Message.Kind.text, m.kind);
        try std.testing.expect(std.mem.startsWith(u8, m.payload, "msg-"));
    }

    // Fragmented outbound send test
    try conn.sendFragmented(.text, &.{ "part1-", "part2-", "part3" });
    const frag_echo = (try conn.readMessage()).?;
    try std.testing.expectEqualStrings("part1-part2-part3", frag_echo.payload);

    // Graceful Close handshake with IANA 1012 code
    try conn.close(@backingInt(CloseCode.service_restart), "restarting");
    const close_msg = (try conn.readMessage()).?;
    try std.testing.expectEqual(Message.Kind.close, close_msg.kind);
    try std.testing.expectEqual(@as(?u16, 1012), close_msg.close_code);
    try std.testing.expectEqualStrings("restarting", close_msg.payload);
    try std.testing.expectEqual(@as(?Message, null), try conn.readMessage());

    try std.testing.expect(ws_srv.saw_pong.load(.acquire));
    try std.testing.expectEqual(@as(u32, 4), ws_srv.echoed_count.load(.acquire));
}

test "ws.Conn RFC 7692 permessage-deflate bidirectional roundtrip and Zip Bomb protection" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const DeflateServer = struct {
        saw_client_rsv1: std.atomic.Value(bool) = .init(false),
        server_gpa: Allocator,

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [4096]u8 = undefined;
            var wbuf: [4096]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            var req_line: [128]u8 = undefined;
            var req_len: usize = 0;
            var key: [24]u8 = undefined;
            var first = true;
            while (true) {
                const line = sr.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
                if (first) {
                    first = false;
                    req_len = @min(line.len, req_line.len);
                    @memcpy(req_line[0..req_len], line[0..req_len]);
                } else if (std.ascii.startsWithIgnoreCase(line, "sec-websocket-key:")) {
                    const v = std.mem.trim(u8, line["sec-websocket-key:".len..], " \t\r\n");
                    if (v.len == 24) @memcpy(&key, v);
                }
            }

            const accept = Frame.computeAcceptKey(&key);
            sw.interface.print(
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Sec-WebSocket-Accept: {s}\r\n" ++
                    "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n",
                .{accept},
            ) catch return;

            const ws_work = DeflateWorkspace.create(self.server_gpa) catch return;
            defer ws_work.destroy(self.server_gpa);

            if (std.mem.find(u8, req_line[0..req_len], "GET /bomb") != null) {
                // Compress 4 KiB of 'A' into tiny wire frame -> client with max_message_bytes=512 MUST reject!
                const bomb_plain = self.server_gpa.alloc(u8, 4096) catch return;
                defer self.server_gpa.free(bomb_plain);
                @memset(bomb_plain, 'A');

                var comp: std.ArrayList(u8) = .empty;
                defer comp.deinit(self.server_gpa);
                ws_work.compressMessage(self.server_gpa, bomb_plain, &comp) catch return;

                Frame.writeFrameRsv(&sw.interface, .text, true, 0b100, comp.items, null) catch return;
                sw.interface.flush() catch return;
                return;
            }

            sw.interface.flush() catch return;

            // Echo loop: receive client's RSV1 compressed frame, decompress to verify integrity,
            // and send back compressed with RSV1=1.
            const hdr = Frame.readHeader(&sr.interface) catch return;
            if (!hdr.masked) return;
            if ((hdr.rsv & 0b100) != 0) {
                self.saw_client_rsv1.store(true, .release);
            }
            const plen: usize = @intCast(hdr.payload_len);
            var raw = self.server_gpa.alloc(u8, plen + deflate_inflate_tail.len) catch return;
            defer self.server_gpa.free(raw);
            sr.interface.readSliceAll(raw[0..plen]) catch return;
            Frame.applyMask(raw[0..plen], hdr.mask_key, 0);
            @memcpy(raw[plen .. plen + deflate_inflate_tail.len], &deflate_inflate_tail);

            var inflated: std.ArrayList(u8) = .empty;
            defer inflated.deinit(self.server_gpa);
            ws_work.decompressMessage(self.server_gpa, raw, 64 * 1024, &inflated) catch return;

            var recompressed: std.ArrayList(u8) = .empty;
            defer recompressed.deinit(self.server_gpa);
            ws_work.compressMessage(self.server_gpa, inflated.items, &recompressed) catch return;

            Frame.writeFrameRsv(&sw.interface, .text, true, 0b100, recompressed.items, null) catch return;
            sw.interface.flush() catch return;
        }
    };

    var ds: DeflateServer = .{ .server_gpa = gpa };
    var srv: MockServer = undefined;
    try srv.start(&ds, DeflateServer.handle);
    defer srv.stop();

    // 1. Bidirectional RFC 7692 permessage-deflate roundtrip
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/deflate", .{srv.port()});
        defer gpa.free(url);

        var c = try connect(gpa, rt.io(), .{
            .url = url,
            .enable_compression = true,
        });
        defer c.deinit();

        try std.testing.expect(c.isCompressionEnabled());

        var repeated_buf: [60 * 16]u8 = undefined;
        const unit = "Kite WebSocket permessage-deflate compression works cleanly!";
        for (0..16) |i| {
            @memcpy(repeated_buf[i * unit.len ..][0..unit.len], unit);
        }
        const repeated = repeated_buf[0 .. 16 * unit.len];
        try c.sendText(repeated);

        const echo = (try c.readMessage()).?;
        try std.testing.expectEqual(Message.Kind.text, echo.kind);
        try std.testing.expectEqualStrings(repeated, echo.payload);
        try std.testing.expect(ds.saw_client_rsv1.load(.acquire));
    }

    // 2. Zip Bomb defense: tiny compressed frame expanding > max_message_bytes MUST fail cleanly
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/bomb", .{srv.port()});
        defer gpa.free(url);

        var c = try connect(gpa, rt.io(), .{
            .url = url,
            .enable_compression = true,
            .max_message_bytes = 512,
        });
        defer c.deinit();

        try std.testing.expectError(error.MessageTooLarge, c.readMessage());
    }
}

test "ws.Conn diagnostics (rejected_status), read_idle_timeout, invalid Accept key, masked server frames, and 302 redirect" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const FaultyServer = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            var req_line: [128]u8 = undefined;
            var req_len: usize = 0;
            var key: [24]u8 = undefined;
            var first = true;
            while (true) {
                const line = sr.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
                if (first) {
                    first = false;
                    req_len = @min(line.len, req_line.len);
                    @memcpy(req_line[0..req_len], line[0..req_len]);
                } else if (std.ascii.startsWithIgnoreCase(line, "sec-websocket-key:")) {
                    const v = std.mem.trim(u8, line["sec-websocket-key:".len..], " \t\r\n");
                    if (v.len == 24) @memcpy(&key, v);
                }
            }
            const req = req_line[0..req_len];

            if (std.mem.find(u8, req, "GET /unauth") != null) {
                sw.interface.writeAll(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                ) catch return;
                sw.interface.flush() catch return;
            } else if (std.mem.find(u8, req, "GET /bad-accept") != null) {
                sw.interface.writeAll(
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                        "Upgrade: websocket\r\n" ++
                        "Connection: Upgrade\r\n" ++
                        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n",
                ) catch return;
                sw.interface.flush() catch return;
            } else if (std.mem.find(u8, req, "GET /masked-server") != null) {
                const accept = Frame.computeAcceptKey(&key);
                sw.interface.print(
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                        "Upgrade: websocket\r\n" ++
                        "Connection: Upgrade\r\n" ++
                        "Sec-WebSocket-Accept: {s}\r\n\r\n",
                    .{accept},
                ) catch return;
                Frame.writeFrame(&sw.interface, .text, true, "bad", .{ 1, 2, 3, 4 }) catch return;
                sw.interface.flush() catch return;
            } else if (std.mem.find(u8, req, "GET /silent") != null) {
                const accept = Frame.computeAcceptKey(&key);
                sw.interface.print(
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                        "Upgrade: websocket\r\n" ++
                        "Connection: Upgrade\r\n" ++
                        "Sec-WebSocket-Accept: {s}\r\n\r\n",
                    .{accept},
                ) catch return;
                sw.interface.flush() catch return;
                zio.sleep(.fromMilliseconds(200)) catch return;
            } else if (std.mem.find(u8, req, "GET /redir") != null) {
                sw.interface.writeAll(
                    "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n",
                ) catch return;
                sw.interface.flush() catch return;
            } else {
                const accept = Frame.computeAcceptKey(&key);
                sw.interface.print(
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                        "Upgrade: websocket\r\n" ++
                        "Connection: Upgrade\r\n" ++
                        "Sec-WebSocket-Accept: {s}\r\n\r\n",
                    .{accept},
                ) catch return;
                Frame.writeFrame(&sw.interface, .text, true, "redirected-ok", null) catch return;
                sw.interface.flush() catch return;
            }
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, FaultyServer.handle);
    defer srv.stop();

    // 1. Upgrade rejection surfaces exact HTTP status via rejected_status
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/unauth", .{srv.port()});
        defer gpa.free(url);
        var rej_status: http.Status = .ok;
        try std.testing.expectError(error.UpgradeRejected, connect(gpa, rt.io(), .{
            .url = url,
            .rejected_status = &rej_status,
        }));
        try std.testing.expectEqual(http.Status.unauthorized, rej_status);
    }

    // 2. Invalid Accept key rejected
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/bad-accept", .{srv.port()});
        defer gpa.free(url);
        try std.testing.expectError(error.InvalidAcceptKey, connect(gpa, rt.io(), .{ .url = url }));
    }

    // 3. Masked server frame rejected per RFC 6455 §5.1
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/masked-server", .{srv.port()});
        defer gpa.free(url);
        var c = try connect(gpa, rt.io(), .{ .url = url });
        defer c.deinit();
        try std.testing.expectError(error.MaskedServerFrame, c.readMessage());
    }

    // 4. read_idle_timeout surfaces error.Timeout on silent peer
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/silent", .{srv.port()});
        defer gpa.free(url);
        var c = try connect(gpa, rt.io(), .{
            .url = url,
            .read_idle_timeout = .fromMilliseconds(25),
        });
        defer c.deinit();
        try std.testing.expectError(error.Timeout, c.readMessage());
    }

    // 5. Handshake 302 redirect followed cleanly
    {
        const url = try gpa.print("ws://127.0.0.1:{d}/redir", .{srv.port()});
        defer gpa.free(url);
        var c = try connect(gpa, rt.io(), .{ .url = url });
        defer c.deinit();
        const msg = (try c.readMessage()).?;
        try std.testing.expectEqualStrings("redirected-ok", msg.payload);
    }
}

test "WebSocket connectWithClient inherits client.initDefaultProxies scheme routing and NO_PROXY" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const WsProxyStub = struct {
        connect_hits: std.atomic.Value(u32) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = stream.reader(&rbuf);
            var sw = stream.writer(&wbuf);

            const req_line = sr.interface.takeDelimiterInclusive('\n') catch return;
            while (true) {
                const line = sr.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            if (std.mem.startsWith(u8, req_line, "CONNECT ")) {
                _ = self.connect_hits.fetchAdd(1, .acq_rel);
                sw.interface.writeAll(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ) catch return;
                sw.interface.flush() catch return;
            }
        }
    };

    var http_proxy_st: WsProxyStub = .{};
    var https_proxy_st: WsProxyStub = .{};

    var http_proxy_srv: MockServer = undefined;
    try http_proxy_srv.start(&http_proxy_st, WsProxyStub.handle);
    defer http_proxy_srv.stop();

    var https_proxy_srv: MockServer = undefined;
    try https_proxy_srv.start(&https_proxy_st, WsProxyStub.handle);
    defer https_proxy_srv.stop();

    const http_proxy_url = try gpa.print("http://127.0.0.1:{d}", .{http_proxy_srv.port()});
    defer gpa.free(http_proxy_url);
    const https_proxy_url = try gpa.print("http://127.0.0.1:{d}", .{https_proxy_srv.port()});
    defer gpa.free(https_proxy_url);

    var env_map: std.process.Environ.Map = .init(gpa);
    defer env_map.deinit();
    try env_map.put("HTTP_PROXY", http_proxy_url);
    try env_map.put("HTTPS_PROXY", https_proxy_url);

    var client = Client.init(gpa, rt.io(), .{});
    defer client.deinit();
    try client.initDefaultProxies(&env_map);

    // ws:// routes to HTTP_PROXY
    try std.testing.expectError(
        error.ProxyAuthRequired,
        Conn.connectWithClient(&client, .{ .url = "ws://ws-target.example/chat" }),
    );
    // wss:// routes to HTTPS_PROXY
    try std.testing.expectError(
        error.ProxyAuthRequired,
        Conn.connectWithClient(&client, .{ .url = "wss://wss-target.example/chat" }),
    );

    try std.testing.expectEqual(@as(u32, 1), http_proxy_st.connect_hits.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), https_proxy_st.connect_hits.load(.acquire));
}
