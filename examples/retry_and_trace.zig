//! RetryTransport + built-in `Trace` observability example.
//!
//! Spins up a tiny local loopback server that replies 503 -> 429 (Retry-After)
//! -> 200 OK, then serves a second request over the reused keep-alive socket.
//! Watch `Trace` report connect time, TTFB, total duration, status, and pool reuse
//! for every physical attempt.
//!
//! Usage:
//!   zig build example-retry

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

const FlakyServer = struct {
    hits: std.atomic.Value(usize) = .init(0),

    fn acceptLoop(srv: zio.net.Server, self: *FlakyServer, group: *zio.Group) void {
        while (true) {
            const stream = srv.accept(.{}) catch break;
            group.spawn(handleConn, .{ self, stream }) catch stream.close();
        }
    }

    fn handleConn(self: *FlakyServer, stream: zio.net.Stream) void {
        defer stream.close();
        var rbuf: [512]u8 = undefined;
        var wbuf: [512]u8 = undefined;
        var r = stream.reader(&rbuf);
        var w = stream.writer(&wbuf);

        while (true) {
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            const n = self.hits.fetchAdd(1, .acq_rel) + 1;
            const resp = switch (n) {
                1 => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy",
                2 => "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 4\r\n\r\nwait",
                else => "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhealthy-ok",
            };
            w.interface.writeAll(resp) catch return;
            w.interface.flush() catch return;
        }
    }
};

fn onExchange(_: ?*anyopaque, m: kite.ExchangeMetrics) void {
    const code: u16 = if (m.status) |s| s.code() else 0;
    std.debug.print("[trace] {s} {s} -> {d} | reused={} | connect={d}us ttfb={d}us total={d}us\n", .{
        m.method.name(),
        m.target,
        code,
        m.reused_connection,
        m.connect_ns / 1000,
        m.ttfb_ns / 1000,
        m.total_ns / 1000,
    });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Start local flaky loopback server on an ephemeral port.
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const srv = try addr.listen(.{});
    defer srv.close();

    var flaky: FlakyServer = .{};
    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(FlakyServer.acceptLoop, .{ srv, &flaky, &group });

    // Attach built-in `Trace` to Pool, then wrap Pool in `RetryTransport`.
    var pool = kite.Pool.init(gpa, rt.io(), .{
        .trace = .{ .on_exchange = onExchange },
    });
    defer pool.deinit();

    var retry = kite.RetryTransport.init(pool.transport(), .{
        .max_retries = 3,
        .initial_backoff = .fromMilliseconds(20),
        .max_backoff = .fromMilliseconds(100),
    });

    var client = kite.Client.initWithTransport(gpa, rt.io(), retry.transport(), .{});
    defer client.deinit();

    const url = try gpa.print("http://127.0.0.1:{d}/health", .{srv.socket.address.ip.getPort()});
    defer gpa.free(url);

    std.debug.print("--- Request 1 (auto-recovers across 503 -> 429 -> 200) ---\n", .{});
    {
        var res = try client.get(url);
        defer res.deinit();
        std.debug.print("Final response: {d} {s} body=\"{s}\"\n\n", .{ res.status.code(), res.reason, res.body });
    }

    std.debug.print("--- Request 2 (reuses keep-alive socket from Pool) ---\n", .{});
    {
        var res = try client.get(url);
        defer res.deinit();
        std.debug.print("Final response: {d} {s} body=\"{s}\"\n", .{ res.status.code(), res.reason, res.body });
    }
}
