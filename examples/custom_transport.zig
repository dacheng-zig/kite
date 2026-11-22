//! Custom `Transport` decorator & redirect/timeout control example.
//!
//! Shows how to wrap `kite.Pool` with a lightweight `LoggingTransport` that
//! observes every physical HTTP hop (including redirect hops) without modifying
//! `kite.Client`, plus how to inspect redirects with `.max_redirects = 0` and
//! catch per-request `error.Timeout`.
//!
//! Usage:
//!   zig build example-transport
//!   zig build example-transport -- http://example.com

const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub const std_options_debug_io = zio.debug_io;

/// Thin `kite.Transport` wrapper that logs every physical HTTP exchange.
const LoggingTransport = struct {
    inner: kite.Transport,

    fn transport(self: *LoggingTransport) kite.Transport {
        return .{
            .ptr = self,
            .vtable = &.{
                .openExchange = openExchangeImpl,
            },
        };
    }

    fn openExchangeImpl(ptr: *anyopaque, req: kite.Transport.ExchangeRequest) anyerror!kite.Transport.Exchange {
        const self: *LoggingTransport = @ptrCast(@alignCast(ptr));
        const t0 = zio.Timestamp.now(.awake);
        const ex = try self.inner.openExchange(req);
        const elapsed_ms = (zio.Timestamp.now(.awake).toNanoseconds() -| t0.toNanoseconds()) / zio.time.ns_per_ms;

        std.debug.print("[transport] {s} {s}://{s}:{d}{s} (open+send {d}ms)\n", .{
            req.method.name(),
            @tagName(req.origin.scheme),
            req.origin.host,
            req.origin.port,
            req.target,
            elapsed_ms,
        });
        return ex;
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const url = if (args.len > 1) args[1] else "http://github.com";

    // Build a standalone Pool, wrap it in LoggingTransport, and inject via initWithTransport().
    var pool = kite.Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();

    var logging: LoggingTransport = .{ .inner = pool.transport() };

    var client = kite.Client.initWithTransport(gpa, rt.io(), logging.transport(), .{});
    defer client.deinit();

    // 1. Disable redirects (.max_redirects = 0) to inspect the raw 301/302 Location header.
    std.debug.print("--- 1. Inspect redirect without following ---\n", .{});
    {
        var res = try client.fetch(.{
            .url = url,
            .max_redirects = 0,
            .timeout = .fromSeconds(10),
        });
        defer res.deinit();
        std.debug.print("Status: {d} {s}, Location: {s}\n\n", .{
            res.status.code(),
            res.reason,
            res.headers.get("Location") orelse "<none>",
        });
    }

    // 2. Follow redirects automatically and watch LoggingTransport trace every hop.
    std.debug.print("--- 2. Follow redirects automatically ---\n", .{});
    {
        var res = try client.fetch(.{
            .url = url,
            .max_redirects = 5,
            .timeout = .fromSeconds(15),
        });
        defer res.deinit();
        std.debug.print("Final URL: {s} -> {d} {s} ({d} bytes)\n\n", .{
            res.final_url,
            res.status.code(),
            res.reason,
            res.body.len,
        });
    }

    // 3. Demonstrate catching a tight per-request timeout cleanly.
    std.debug.print("--- 3. Tight per-request timeout handling ---\n", .{});
    if (client.fetch(.{
        .url = url,
        .timeout = .fromMilliseconds(1),
    })) |res_val| {
        var res = res_val;
        defer res.deinit();
        std.debug.print("Completed within 1ms! Status: {d}\n", .{res.status.code()});
    } else |err| switch (err) {
        error.Timeout => std.debug.print("Caught expected error.Timeout cleanly!\n", .{}),
        else => return err,
    }
}
