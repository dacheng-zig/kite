//! Composable Transport middlewares (`CacheTransport` + `CircuitBreakerTransport`
//! + `RetryTransport`) example (offline).
//!
//! Demonstrates stacking:
//!   `Client -> CacheTransport -> RetryTransport -> CircuitBreakerTransport -> Pool`
//! showing:
//! - RFC 9111 `max-age` caching (0 upstream calls on cache hit)
//! - Lock-free `CircuitBreakerTransport.StateChangeHook` transition logging
//! - Fail-fast `error.CircuitOpen` (RetryTransport does NOT amplify retries once open)
//!
//! Usage:
//!   zig build example-middleware

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

const ServerState = struct {
    hits: std.atomic.Value(u32) = .init(0),
};

fn acceptLoop(srv: zio.net.Server, group: *zio.Group, state: *ServerState) void {
    while (true) {
        const stream = srv.accept(.{}) catch break;
        group.spawn(handleHttp, .{ stream, state }) catch stream.close();
    }
}

fn handleHttp(stream: zio.net.Stream, state: *ServerState) void {
    defer stream.close();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = stream.reader(&rbuf);
    var w = stream.writer(&wbuf);

    while (true) {
        const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        const count = state.hits.fetchAdd(1, .acq_rel) + 1;
        if (std.mem.find(u8, req_line, "GET /fail") != null) {
            w.interface.writeAll(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\ndown",
            ) catch return;
        } else {
            var body_buf: [64]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "origin-hit-#{d}", .{count}) catch return;
            w.interface.print(
                "HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ body.len, body },
            ) catch return;
        }
        w.interface.flush() catch return;
    }
}

fn logStateChange(
    _: ?*anyopaque,
    origin: kite.Origin,
    from: kite.CircuitBreakerTransport.State,
    to: kite.CircuitBreakerTransport.State,
) void {
    std.debug.print("[circuit-breaker] {s}:{d} {t} -> {t}\n", .{ origin.host, origin.port, from, to });
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

    // Compose: Client -> CacheTransport -> RetryTransport -> CircuitBreakerTransport -> Pool
    var pool = kite.Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();

    var cb = kite.CircuitBreakerTransport.init(gpa, pool.transport(), .{
        .failure_threshold = 2,
        .open_duration = .fromSeconds(10),
        .on_state_change = .{ .on_change = logStateChange },
    });
    defer cb.deinit();

    var retry = kite.RetryTransport.init(cb.transport(), .{
        .max_retries = 3,
        .initial_backoff = .fromMilliseconds(5),
    });

    var cache = kite.CacheTransport.init(gpa, retry.transport(), .{});
    defer cache.deinit();

    var client = kite.Client.initWithTransport(gpa, rt.io(), cache.transport(), .{});
    defer client.deinit();

    const ok_url = try gpa.print("http://127.0.0.1:{d}/cached", .{srv.socket.address.ip.getPort()});
    defer gpa.free(ok_url);

    // 1. First GET populates cache; second GET is served from memory (0 upstream hits)
    var r1 = try client.get(ok_url);
    defer r1.deinit();
    var r2 = try client.get(ok_url);
    defer r2.deinit();
    std.debug.print("Cache demo: r1=\"{s}\" r2=\"{s}\" cache_hits={d} server_hits={d}\n", .{
        r1.body,
        r2.body,
        cache.stats().hits,
        state.hits.load(.acquire),
    });

    // 2. Two 503 responses trip the CircuitBreaker -> RetryTransport fails fast with CircuitOpen
    const fail_url = try gpa.print("http://127.0.0.1:{d}/fail", .{srv.socket.address.ip.getPort()});
    defer gpa.free(fail_url);

    if (client.get(fail_url)) |unexpected| {
        var u = unexpected;
        u.deinit();
    } else |err| {
        std.debug.print("Fail-fast after circuit trip: {s} (total upstream hits={d})\n", .{
            @errorName(err),
            state.hits.load(.acquire),
        });
    }
}
