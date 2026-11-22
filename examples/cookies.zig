//! RFC 6265 `CookieJar` session & login-redirect example.
//!
//! Runs a self-contained local auth flow:
//!   1. `POST /login` -> `303 See Other` + `Set-Cookie: sid=kite-42; Path=/` -> `/profile`
//!   2. Redirected `GET /profile` automatically sends `Cookie: sid=kite-42`
//!   3. `POST /logout` clears the cookie via `Max-Age=0`
//!
//! Usage:
//!   zig build example-cookies

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
        var has_valid_cookie = false;
        var content_len: usize = 0;

        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (std.ascii.startsWithIgnoreCase(line, "Cookie:") and
                std.mem.find(u8, line, "sid=kite-42") != null)
            {
                has_valid_cookie = true;
            }
            if (std.ascii.startsWithIgnoreCase(line, "Content-Length:")) {
                const v = std.mem.trim(u8, line["Content-Length:".len..], " \t\r\n");
                content_len = std.fmt.parseInt(usize, v, 10) catch 0;
            }
        }
        if (content_len > 0) {
            var discard: [128]u8 = undefined;
            var left = content_len;
            while (left > 0) {
                const step = @min(left, discard.len);
                r.interface.readSliceAll(discard[0..step]) catch return;
                left -= step;
            }
        }

        const resp = if (std.mem.startsWith(u8, req_line, "POST /login "))
            "HTTP/1.1 303 See Other\r\n" ++
                "Set-Cookie: sid=kite-42; Path=/; HttpOnly\r\n" ++
                "Location: /profile\r\n" ++
                "Content-Length: 0\r\n\r\n"
        else if (std.mem.startsWith(u8, req_line, "GET /profile "))
            if (has_valid_cookie)
                "HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\nauthenticated:alice"
            else
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nunauthorized"
        else if (std.mem.startsWith(u8, req_line, "POST /logout "))
            "HTTP/1.1 200 OK\r\n" ++
                "Set-Cookie: sid=; Path=/; Max-Age=0\r\n" ++
                "Content-Length: 10\r\n\r\nlogged-out"
        else
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

        w.interface.writeAll(resp) catch return;
        w.interface.flush() catch return;
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

    const port = srv.socket.address.ip.getPort();
    const login_url = try gpa.print("http://127.0.0.1:{d}/login", .{port});
    defer gpa.free(login_url);
    const profile_url = try gpa.print("http://127.0.0.1:{d}/profile", .{port});
    defer gpa.free(profile_url);
    const logout_url = try gpa.print("http://127.0.0.1:{d}/logout", .{port});
    defer gpa.free(logout_url);

    var jar = kite.CookieJar.init(gpa);
    defer jar.deinit();

    var client = kite.Client.init(gpa, rt.io(), .{
        .cookie_jar = &jar,
    });
    defer client.deinit();

    // 1. Login sets cookie and redirects 303 -> /profile with cookie automatically attached.
    {
        var res = try client.fetch(.{
            .method = .POST,
            .url = login_url,
            .body = .{ .bytes = "user=alice" },
        });
        defer res.deinit();
        std.debug.print("1. POST /login -> final={s} status={d} body=\"{s}\" (jar count={d})\n", .{
            res.final_url,
            res.status.code(),
            res.body,
            jar.count(),
        });
    }

    // 2. Logout clears the cookie via Max-Age=0.
    {
        var res = try client.fetch(.{ .method = .POST, .url = logout_url });
        defer res.deinit();
        std.debug.print("2. POST /logout -> status={d} body=\"{s}\" (jar count={d})\n", .{
            res.status.code(),
            res.body,
            jar.count(),
        });
    }

    // 3. Subsequent /profile request has no cookie and gets 401.
    {
        var res = try client.get(profile_url);
        defer res.deinit();
        std.debug.print("3. GET /profile after logout -> status={d} body=\"{s}\"\n", .{
            res.status.code(),
            res.body,
        });
    }
}
