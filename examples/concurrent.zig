//! Concurrent HTTPS requests sharing one `kite.Client` connection pool over `zio.Group`.
//!
//! Demonstrates per-origin concurrency capping and keep-alive reuse across tasks.
//!
//! Usage:
//!   zig build example-concurrent
//!   zig build example-concurrent -- https://example.com

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

const Worker = struct {
    fn run(client: *kite.Client, id: usize, url: []const u8) !void {
        var res = try client.get(url);
        defer res.deinit();
        std.debug.print("[task {d}] {d} {s} ({d} bytes)\n", .{
            id,
            res.status.code(),
            res.reason,
            res.body.len,
        });
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const url = if (args.len > 1) args[1] else "https://example.com";

    var client = kite.Client.init(gpa, rt.io(), .{
        .pool = .{
            .max_conns_per_origin = 2,
            .max_idle_conns_per_origin = 2,
        },
    });
    defer client.deinit();

    var group: zio.Group = .init;
    defer group.cancel();

    // Launch 4 concurrent tasks sharing at most 2 pooled connections to the same origin.
    for (0..4) |i| {
        try group.spawn(Worker.run, .{ &client, i + 1, url });
    }
    try group.wait();

    const stats = client.pool.stats();
    std.debug.print("Pool after burst: origins={d}, idle={d}, in_flight={d}\n", .{
        stats.origin_count,
        stats.total_idle,
        stats.total_in_flight,
    });
}
