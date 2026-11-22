//! Streaming response example using `kite.Client.open()` + `StreamResponse.reader()`.
//!
//! Reads arbitrarily large responses using a fixed 4 KiB buffer without
//! buffering the entire body in memory.
//!
//! Usage:
//!   zig build example-stream
//!   zig build example-stream -- https://example.com

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const url = if (args.len > 1) args[1] else "https://example.com";

    var client = kite.Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    var req = try client.open(.{
        .method = .GET,
        .url = url,
    });
    defer req.deinit();

    var stream = try req.receiveHead();
    defer stream.deinit();

    var buf: [4096]u8 = undefined;
    var total_bytes: usize = 0;
    var chunks: usize = 0;

    const r = stream.reader();
    while (true) {
        const n = r.readSliceShort(&buf) catch |err| switch (err) {
            error.ReadFailed => return stream.unwrapReadError() orelse error.ReadFailed,
        };
        if (n == 0) break;
        total_bytes += n;
        chunks += 1;
    }

    std.debug.print("Streamed {s}\n", .{stream.final_url});
    std.debug.print("Status: {d} {s}\n", .{ stream.status().code(), stream.reason() });
    std.debug.print("Read {d} bytes across {d} chunk(s)\n", .{ total_bytes, chunks });
}
