//! Streaming chunked upload example using `kite.Client.open()` + `req.writer()`.
//!
//! Sends request body chunks incrementally without knowing the total length upfront;
//! `req.receiveHead()` automatically emits the terminating `0\r\n\r\n` chunk and flushes.
//!
//! Usage:
//!   zig build example-upload
//!   zig build example-upload -- https://postman-echo.com/post

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const url = if (args.len > 1) args[1] else "https://postman-echo.com/post";

    var client = kite.Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    var req = try client.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{
            .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
        },
        .body = .stream_chunked,
    });
    defer req.deinit();

    // Stream multiple chunks incrementally; write errors are recoverable via unwrapWriteError().
    const parts = [_][]const u8{
        "line 1: streamed over Transfer-Encoding: chunked\n",
        "line 2: powered by kite + zio\n",
        "line 3: done\n",
    };
    for (parts) |part| {
        req.writer().writeAll(part) catch {
            return req.unwrapWriteError() orelse error.WriteFailed;
        };
    }

    // No manual finish() call required: receiveHead() finalizes the chunked stream
    // and transfers connection lease ownership to `stream`.
    var stream = try req.receiveHead();
    defer stream.deinit();

    const body = try stream.readAll(gpa, 1024 * 1024);
    defer gpa.free(body);

    std.debug.print("Uploaded chunked POST to {s}\n", .{stream.final_url});
    std.debug.print("Status: {d} {s}\n", .{ stream.status().code(), stream.reason() });
    const preview_len = @min(body.len, 240);
    std.debug.print("--- response preview ---\n{s}\n", .{body[0..preview_len]});
}
