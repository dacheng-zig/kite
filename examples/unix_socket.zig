//! Unix Domain Socket (`http+unix://` and `Pool.Config.unix_socket_path`) example (offline).
//!
//! Spawns a local POSIX Unix domain socket HTTP server (similar to Docker Engine API
//! `/var/run/docker.sock`) and demonstrates both calling modes:
//! 1. `http+unix://<percent-encoded-path>/...` URL routing (auto `Host: localhost`)
//! 2. Explicit `Pool.Config.unix_socket_path` preserving logical URL `Host` headers
//!
//! Usage:
//!   zig build example-uds

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

fn acceptLoop(srv: zio.net.Server, group: *zio.Group) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleConn, .{stream}) catch stream.close();
    }
}

fn handleConn(stream: zio.net.Stream) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    while (true) {
        const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
        const trimmed_req = std.mem.trimEnd(u8, req_line, "\r\n");

        var host_buf: [128]u8 = undefined;
        var host_len: usize = 0;
        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (std.ascii.startsWithIgnoreCase(line, "host:")) {
                const v = std.mem.trim(u8, line[5..], " \t\r\n");
                host_len = @min(v.len, host_buf.len);
                @memcpy(host_buf[0..host_len], v[0..host_len]);
            }
        }

        var body_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"request\":\"{s}\",\"host\":\"{s}\"}}", .{
            trimmed_req,
            host_buf[0..host_len],
        }) catch return;

        w.interface.print(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ body.len, body },
        ) catch return;
        w.interface.flush() catch return;
    }
}

pub fn main(init: std.process.Init) !void {
    if (!zio.net.has_unix_sockets) {
        std.debug.print("Unix domain sockets are not supported on this platform.\n", .{});
        return;
    }

    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var rnd: [6]u8 = undefined;
    try zio.randomSecure(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);
    var path_buf: [64]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&path_buf, "/tmp/kite-example-{s}.sock", .{hex});
    std.Io.Dir.cwd().deleteFile(rt.io(), sock_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(rt.io(), sock_path) catch {};

    const addr = try zio.net.UnixAddress.init(sock_path);
    const srv = try addr.listen(.{});
    defer srv.close();

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(acceptLoop, .{ srv, &group });

    // Mode 1: `http+unix://` URL routing (single Client can reach any UDS + regular HTTP)
    {
        var client = kite.Client.init(gpa, rt.io(), .{});
        defer client.deinit();

        const url = try gpa.print("http+unix://%2Ftmp%2Fkite-example-{s}.sock/v1.43/version", .{hex});
        defer gpa.free(url);

        var res = try client.get(url);
        defer res.deinit();
        std.debug.print("[http+unix://] {d} {s}\n", .{ res.status.code(), res.body });
    }

    // Mode 2: Explicit `Pool.Config.unix_socket_path` (like `curl --unix-socket`)
    {
        var client = kite.Client.init(gpa, rt.io(), .{
            .pool = .{ .unix_socket_path = sock_path },
        });
        defer client.deinit();

        var res = try client.get("http://docker.local/v1.43/containers/json");
        defer res.deinit();
        std.debug.print("[unix_socket_path] {d} {s}\n", .{ res.status.code(), res.body });
    }
}
