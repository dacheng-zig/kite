//! Classic minimal HTTPS GET example using `kite.Client.get()`.
//!
//! Usage:
//!   zig build example-get
//!   zig build example-get -- https://httpbin.org/get

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

    var res = try client.get(url);
    defer res.deinit();

    std.debug.print("GET {s}\n", .{res.final_url});
    std.debug.print("Status: {d} {s}\n", .{ res.status.code(), res.reason });
    if (res.headers.get("Content-Type")) |ct| {
        std.debug.print("Content-Type: {s}\n", .{ct});
    }
    if (res.decompressed) {
        std.debug.print("Compression: transparently decoded\n", .{});
    }
    std.debug.print("Body: {d} bytes\n", .{res.body.len});

    const preview_len = @min(res.body.len, 240);
    std.debug.print("--- preview ---\n{s}\n", .{res.body[0..preview_len]});
}
