//! Scriptable local loopback TCP server built on zio for offline tests.
//!
//! Binds to `127.0.0.1:0` so concurrent test runs never collide on ports.

const std = @import("std");
const zio = @import("zio");
const http = @import("../http.zig");

const MockServer = @This();

server: zio.net.Server,
group: zio.Group,
stopped: std.atomic.Value(bool),

pub const HandlerFn = *const fn (ctx: ?*anyopaque, stream: zio.net.Stream) void;

/// Initializes and starts accepting connections in a background task owned by `self.group`.
/// Caller must keep `self` pinned in memory (never move by value) until `stop()` returns.
pub fn start(self: *MockServer, ctx: ?*anyopaque, handler: HandlerFn) !void {
    const bind_addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const server = try bind_addr.listen(.{});
    errdefer server.close();

    self.* = .{
        .server = server,
        .group = .init,
        .stopped = .init(false),
    };

    try self.group.spawn(acceptLoop, .{ self, ctx, handler });
}

/// Stops accepting new connections, cancels active server tasks, and closes the listener.
pub fn stop(self: *MockServer) void {
    self.stopped.store(true, .release);
    self.group.cancel();
    self.server.close();
}

pub fn port(self: *const MockServer) u16 {
    return self.server.socket.address.ip.getPort();
}

pub fn origin(self: *const MockServer) http.Origin {
    return .{
        .scheme = .http,
        .host = "127.0.0.1",
        .port = self.port(),
    };
}

fn acceptLoop(self: *MockServer, ctx: ?*anyopaque, handler: HandlerFn) void {
    while (!self.stopped.load(.acquire)) {
        const stream = self.server.accept(.{}) catch break;
        self.group.spawn(runHandler, .{ handler, ctx, stream }) catch {
            stream.close();
        };
    }
}

fn runHandler(handler: HandlerFn, ctx: ?*anyopaque, stream: zio.net.Stream) void {
    defer stream.close();
    handler(ctx, stream);
}
