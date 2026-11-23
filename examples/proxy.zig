//! HTTP forward proxy and SOCKS5h (`ProxyConfig`) example (offline).
//!
//! Spawns two tiny local loopback mock proxies:
//! 1. HTTP forward proxy (`http://`): shows absolute-form request-line and `Proxy-Authorization`
//! 2. SOCKS5h proxy (`socks5h://`): shows RFC 1929 username/password auth and remote DNS
//!    (`ATYP=0x03`) forwarding without leaking `Proxy-Authorization` to the origin
//!
//! Usage:
//!   zig build example-proxy

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

fn acceptHttpProxy(srv: zio.net.Server, group: *zio.Group) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleHttpProxyConn, .{stream}) catch stream.close();
    }
}

fn handleHttpProxyConn(stream: zio.net.Stream) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    while (true) {
        const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
        std.debug.print("[http-proxy] {s}", .{req_line});
        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (std.ascii.startsWithIgnoreCase(line, "Host:") or
                std.ascii.startsWithIgnoreCase(line, "Proxy-Authorization:"))
            {
                std.debug.print("[http-proxy] {s}", .{line});
            }
        }
        w.interface.writeAll(
            "HTTP/1.1 200 OK\r\n" ++
                "Content-Length: 22\r\n" ++
                "\r\n" ++
                "served-via-http-proxy!",
        ) catch return;
        w.interface.flush() catch return;
    }
}

fn acceptSocks5Proxy(srv: zio.net.Server, group: *zio.Group) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleSocks5Conn, .{stream}) catch stream.close();
    }
}

fn handleSocks5Conn(stream: zio.net.Stream) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    // 1. Greeting + RFC 1929 username/password auth
    var hdr: [2]u8 = undefined;
    r.interface.readSliceAll(&hdr) catch return;
    var methods: [255]u8 = undefined;
    r.interface.readSliceAll(methods[0..hdr[1]]) catch return;
    w.interface.writeAll(&.{ 0x05, 0x02 }) catch return;
    w.interface.flush() catch return;

    var u_hdr: [2]u8 = undefined;
    r.interface.readSliceAll(&u_hdr) catch return;
    var user: [255]u8 = undefined;
    r.interface.readSliceAll(user[0..u_hdr[1]]) catch return;
    var p_len: [1]u8 = undefined;
    r.interface.readSliceAll(&p_len) catch return;
    var pass: [255]u8 = undefined;
    r.interface.readSliceAll(pass[0..p_len[0]]) catch return;
    std.debug.print("[socks5h-proxy] authenticated user={s}\n", .{user[0..u_hdr[1]]});
    w.interface.writeAll(&.{ 0x01, 0x00 }) catch return;
    w.interface.flush() catch return;

    // 2. CONNECT command with ATYP=0x03 (remote DNS domain)
    var req_hdr: [4]u8 = undefined;
    r.interface.readSliceAll(&req_hdr) catch return;
    var dlen: [1]u8 = undefined;
    r.interface.readSliceAll(&dlen) catch return;
    var domain: [255]u8 = undefined;
    r.interface.readSliceAll(domain[0..dlen[0]]) catch return;
    var port_bytes: [2]u8 = undefined;
    r.interface.readSliceAll(&port_bytes) catch return;
    const dst_port = std.mem.readInt(u16, &port_bytes, .big);
    std.debug.print("[socks5h-proxy] remote CONNECT target={s}:{d}\n", .{ domain[0..dlen[0]], dst_port });

    w.interface.writeAll(&.{ 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }) catch return;
    w.interface.flush() catch return;

    // 3. Handle tunneled HTTP/1.1 request
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return;
        if (std.mem.eql(u8, line, "\r\n")) break;
    }
    w.interface.writeAll(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 25\r\n" ++
            "Connection: close\r\n\r\n" ++
            "served-via-socks5h-proxy!",
    ) catch return;
    w.interface.flush() catch return;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const http_proxy_srv = try addr.listen(.{});
    defer http_proxy_srv.close();
    const socks5_srv = try addr.listen(.{});
    defer socks5_srv.close();

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(acceptHttpProxy, .{ http_proxy_srv, &group });
    try group.spawn(acceptSocks5Proxy, .{ socks5_srv, &group });

    // 1. HTTP forward proxy with Basic Proxy-Authorization
    {
        const proxy_auth = try kite.Client.basicAuthValue(gpa, "proxy-user", "s3cr3t");
        defer gpa.free(proxy_auth);

        var client = kite.Client.init(gpa, rt.io(), .{
            .pool = .{
                .proxy = .{
                    .scheme = .http,
                    .host = "127.0.0.1",
                    .port = http_proxy_srv.socket.address.ip.getPort(),
                    .authorization = proxy_auth,
                },
            },
        });
        defer client.deinit();

        var res = try client.get("http://upstream.example:8080/hello?from=kite");
        defer res.deinit();
        std.debug.print("HTTP proxy got: {d} body=\"{s}\"\n", .{ res.status.code(), res.body });
    }

    // 2. SOCKS5h proxy (RFC 1929 auth + remote DNS for unresolvable internal hostname)
    {
        var client = kite.Client.init(gpa, rt.io(), .{
            .pool = .{
                .proxy = .{
                    .scheme = .socks5h,
                    .host = "127.0.0.1",
                    .port = socks5_srv.socket.address.ip.getPort(),
                    .username = "alice",
                    .password = "wonderland",
                },
            },
        });
        defer client.deinit();

        var res = try client.get("http://internal-service.corp:9000/status");
        defer res.deinit();
        std.debug.print("SOCKS5h proxy got: {d} body=\"{s}\"\n", .{ res.status.code(), res.body });
    }
}
