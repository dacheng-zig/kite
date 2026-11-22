//! RFC 7578 `multipart/form-data` upload example (text fields + binary file).
//!
//! Usage:
//!   zig build example-multipart
//!   zig build example-multipart -- https://postman-echo.com/post

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

    var builder = try kite.multipart.Builder.init(gpa);
    defer builder.deinit();

    try builder.addField("project", "kite");
    try builder.addField("description", "Zig 0.17 async HTTP client");
    try builder.addFile(
        "attachment",
        "hello.txt",
        "text/plain; charset=utf-8",
        "Hello from kite multipart/form-data!\n",
    );

    var form = try builder.finish();
    defer form.deinit(gpa);

    var client = kite.Client.init(gpa, rt.io(), .{});
    defer client.deinit();

    var res = try client.fetch(.{
        .method = .POST,
        .url = url,
        .headers = &.{form.contentTypeHeader()},
        .body = .{ .bytes = form.body },
    });
    defer res.deinit();

    std.debug.print("POST {s}\n", .{res.final_url});
    std.debug.print("Content-Type sent: {s}\n", .{form.content_type});
    std.debug.print("Status: {d} {s} ({d} bytes)\n", .{ res.status.code(), res.reason, res.body.len });

    const preview_len = @min(res.body.len, 280);
    std.debug.print("--- response preview ---\n{s}\n", .{res.body[0..preview_len]});
}
