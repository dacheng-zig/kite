//! Server-Sent Events (`kite.sse`) streaming & Last-Event-ID reconnect example (offline).
//!
//! Spawns a local loopback SSE endpoint that sends two events across a reconnect
//! boundary and terminates cleanly with `204 No Content`.
//!
//! Usage:
//!   zig build example-sse

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

const ServerState = struct {
    attempts: std.atomic.Value(u32) = .init(0),
};

fn acceptLoop(srv: zio.net.Server, group: *zio.Group, state: *ServerState) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleConn, .{ stream, state }) catch stream.close();
    }
}

fn handleConn(stream: zio.net.Stream, state: *ServerState) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return;
        if (std.mem.eql(u8, line, "\r\n")) break;
        if (std.ascii.startsWithIgnoreCase(line, "Last-Event-ID:")) {
            std.debug.print("[server] received {s}", .{line});
        }
    }

    const n = state.attempts.fetchAdd(1, .acq_rel);
    switch (n) {
        0 => {
            w.interface.writeAll(
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: text/event-stream; charset=utf-8\r\n" ++
                    "Connection: close\r\n\r\n" ++
                    "id: 1\nretry: 20\nevent: token\ndata: Hello, \n\n",
            ) catch return;
        },
        1 => {
            w.interface.writeAll(
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Type: text/event-stream\r\n" ++
                    "Connection: close\r\n\r\n" ++
                    "id: 2\nevent: token\ndata: Kite SSE!\n\n",
            ) catch return;
        },
        else => {
            w.interface.writeAll("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n") catch return;
        },
    }
    w.interface.flush() catch return;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const srv = try addr.listen(.{});
    defer srv.close();

    var state: ServerState = .{};
    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(acceptLoop, .{ srv, &group, &state });

    var client = kite.Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    const url = try gpa.print("http://127.0.0.1:{d}/events", .{srv.socket.address.ip.getPort()});
    defer gpa.free(url);

    var stream = try kite.sse.connect(&client, .{
        .url = url,
        .auto_reconnect = true,
    });
    defer stream.deinit();

    while (try stream.next()) |ev| {
        std.debug.print("[sse] id={s} event={s} data=\"{s}\"\n", .{ ev.id, ev.event, ev.data });
    }
    std.debug.print("SSE stream terminated cleanly (status={d}).\n", .{stream.status().code()});
}
