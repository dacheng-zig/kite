//! HTTP forward proxy (`ProxyConfig`) example.
//!
//! Runs a tiny local loopback HTTP proxy so you can see the exact absolute-form
//! request-line (`GET http://upstream.example/hello HTTP/1.1`) and
//! `Proxy-Authorization` header without needing an external proxy server.
//!
//! For HTTPS URLs, `kite` automatically issues `CONNECT host:port HTTP/1.1`
//! and upgrades the tunnel socket in-place with TLS.
//!
//! Usage:
//!   zig build example-proxy

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

fn acceptLoop(srv: zio.net.Server, group: *zio.Group) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleProxyConn, .{stream}) catch stream.close();
    }
}

fn handleProxyConn(stream: zio.net.Stream) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    while (true) {
        const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
        std.debug.print("[proxy received] {s}", .{req_line});
        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (std.ascii.startsWithIgnoreCase(line, "Host:") or
                std.ascii.startsWithIgnoreCase(line, "Proxy-Authorization:"))
            {
                std.debug.print("[proxy received] {s}", .{line});
            }
        }
        w.interface.writeAll(
            "HTTP/1.1 200 OK\r\n" ++
                "Content-Length: 18\r\n" ++
                "\r\n" ++
                "served-via-proxy!\n",
        ) catch return;
        w.interface.flush() catch return;
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const proxy_srv = try addr.listen(.{});
    defer proxy_srv.close();

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(acceptLoop, .{ proxy_srv, &group });

    const proxy_auth = try kite.Client.basicAuthValue(gpa, "proxy-user", "s3cr3t");
    defer gpa.free(proxy_auth);

    var client = kite.Client.init(gpa, rt.io(), .{
        .pool = .{
            .proxy = .{
                .host = "127.0.0.1",
                .port = proxy_srv.socket.address.ip.getPort(),
                .authorization = proxy_auth,
            },
        },
    });
    defer client.deinit();

    var res = try client.get("http://upstream.example:8080/hello?from=kite");
    defer res.deinit();

    std.debug.print("Client got: {d} {s} body=\"{s}\"\n", .{
        res.status.code(),
        res.reason,
        std.mem.trimEnd(u8, res.body, "\r\n"),
    });
}
