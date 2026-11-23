//! Full-duplex RFC 6455 + RFC 7692 (`permessage-deflate`) WebSocket (`kite.ws`) example (offline).
//!
//! Spawns a local loopback WebSocket echo server, performs the HTTP/1.1 `101`
//! upgrade handshake with subprotocol & `permessage-deflate` negotiation, exchanges
//! messages (including `read_idle_timeout` & `sendFragmented`), and runs a graceful Close.
//!
//! Usage:
//!   zig build example-websocket

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

fn acceptLoop(srv: zio.net.Server, group: *zio.Group) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleWsConn, .{stream}) catch stream.close();
    }
}

fn handleWsConn(stream: zio.net.Stream) void {
    defer stream.close();
    var rbuf: [2048]u8 = undefined;
    var wbuf: [2048]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    var key: [24]u8 = undefined;
    var got_key = false;
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return;
        if (std.mem.eql(u8, line, "\r\n")) break;
        if (std.ascii.startsWithIgnoreCase(line, "sec-websocket-key:")) {
            const val = std.mem.trim(u8, line["sec-websocket-key:".len..], " \t\r\n");
            if (val.len == 24) {
                @memcpy(&key, val);
                got_key = true;
            }
        }
    }
    if (!got_key) return;

    const accept = kite.ws.Frame.computeAcceptKey(&key);
    w.interface.print(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "Sec-WebSocket-Protocol: echo.v1\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n",
        .{accept},
    ) catch return;
    w.interface.flush() catch return;

    var payload: [1024]u8 = undefined;
    var frag_buf: [1024]u8 = undefined;
    var frag_len: usize = 0;
    var frag_rsv: u3 = 0;
    while (true) {
        const hdr = kite.ws.Frame.readHeader(&r.interface) catch return;
        if (!hdr.masked or hdr.payload_len > payload.len) return;
        const len: usize = @intCast(hdr.payload_len);
        if (len > 0) r.interface.readSliceAll(payload[0..len]) catch return;
        kite.ws.Frame.applyMask(payload[0..len], hdr.mask_key, 0);

        switch (hdr.opcode) {
            .text, .continuation => {
                if (hdr.opcode == .text) frag_rsv = hdr.rsv;
                if (frag_len + len > frag_buf.len) return;
                @memcpy(frag_buf[frag_len..][0..len], payload[0..len]);
                frag_len += len;
                if (hdr.fin) {
                    // Echo back preserving RSV1 compression flag when compressed.
                    kite.ws.Frame.writeFrameRsv(&w.interface, .text, true, frag_rsv, frag_buf[0..frag_len], null) catch return;
                    w.interface.flush() catch return;
                    frag_len = 0;
                    frag_rsv = 0;
                }
            },
            .close => {
                kite.ws.Frame.writeFrame(&w.interface, .close, true, payload[0..len], null) catch return;
                w.interface.flush() catch return;
                return;
            },
            else => {},
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const srv = try addr.listen(.{});
    defer srv.close();

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(acceptLoop, .{ srv, &group });

    const url = try gpa.print("ws://127.0.0.1:{d}/echo", .{srv.socket.address.ip.getPort()});
    defer gpa.free(url);

    var conn = try kite.ws.connect(gpa, rt.io(), .{
        .url = url,
        .subprotocols = &.{"echo.v1"},
        .enable_compression = true,
        .read_idle_timeout = .fromSeconds(5),
    });
    defer conn.deinit();

    std.debug.print("Connected (subprotocol={s}, permessage-deflate={})\n", .{
        conn.negotiatedSubprotocol() orelse "<none>",
        conn.isCompressionEnabled(),
    });

    // 1. Compressed text message (exceeds default 64-byte compression threshold)
    const msg_text = "Hello WebSocket from Kite v0.2.0! " ++
        "RFC 7692 permessage-deflate compresses repeated payloads transparently.";
    try conn.sendText(msg_text);
    if (try conn.readMessage()) |msg| {
        std.debug.print("Echoed [{t}] ({d} bytes): {s}\n", .{ msg.kind, msg.payload.len, msg.payload });
    }

    // 2. Multi-fragment outbound message
    try conn.sendFragmented(.text, &.{ "frag-1 + ", "frag-2" });
    if (try conn.readMessage()) |msg| {
        std.debug.print("Fragmented echo [{t}]: {s}\n", .{ msg.kind, msg.payload });
    }

    try conn.close(@backingInt(kite.ws.CloseCode.normal), "done");
    if (try conn.readMessage()) |closed| {
        std.debug.print("Closed cleanly: code={?d} reason=\"{s}\"\n", .{ closed.close_code, closed.payload });
    }
}
