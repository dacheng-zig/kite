//! JSON REST API example: Bearer auth, custom headers, form/query encoding,
//! `client.postJson()`, per-request timeout, and `Response.json()` decoding.
//!
//! Usage:
//!   zig build example-json
//!   zig build example-json -- https://postman-echo.com/post

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

const CreateItem = struct {
    name: []const u8,
    version: []const u8,
    async_io: bool,
};

const EchoReply = struct {
    url: []const u8,
    json: CreateItem,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const base_url = if (args.len > 1) args[1] else "https://postman-echo.com/post";

    // Encode query parameters safely per RFC 3986.
    const query = try kite.Client.encodeForm(gpa, &.{
        .{ .name = "source", .value = "kite example" },
        .{ .name = "lang", .value = "zig" },
    });
    defer gpa.free(query);

    const url = try gpa.print("{s}?{s}", .{ base_url, query });
    defer gpa.free(url);

    // Build an Authorization: Bearer header value.
    const auth = try kite.Client.bearerAuthValue(gpa, "demo-token-123");
    defer gpa.free(auth);

    var client = kite.Client.init(gpa, rt.io(), .{
        .default_timeout = .fromSeconds(15),
    });
    defer client.deinit();

    var res = try client.postJson(
        url,
        CreateItem{ .name = "kite", .version = kite.version, .async_io = true },
        &.{
            .{ .name = "Authorization", .value = auth },
            .{ .name = "X-Request-Id", .value = "req-001" },
        },
    );
    defer res.deinit();

    std.debug.print("POST {s}\n", .{res.final_url});
    std.debug.print("Status: {d} {s} ({d} bytes)\n", .{ res.status.code(), res.reason, res.body.len });

    const parsed = try res.json(EchoReply, gpa, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    std.debug.print("Server echoed JSON: name={s}, version={s}, async_io={}\n", .{
        parsed.value.json.name,
        parsed.value.json.version,
        parsed.value.json.async_io,
    });
}
