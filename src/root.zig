//! Kite — an async HTTP/1.1 client library for Zig 0.17 powered by zio.

const std = @import("std");
const zio = @import("zio");

pub const version = "0.0.1";

// ---------------------------------------------------------------------------
// Phase 0 Spike Tests: verify foundational zio 0.20.1 + Zig 0.17.1 guarantees
// before building protocol, connection, and pool modules.
// ---------------------------------------------------------------------------

test "phase0 spike: loopback TCP roundtrip over zio + std.Io Reader/Writer" {
    const gpa = std.testing.allocator;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Port 0 asks the OS for an ephemeral free port, making tests collision-free.
    const bind_addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const server = try bind_addr.listen(.{});
    defer server.close();

    const ServerTask = struct {
        fn run(srv: zio.net.Server) !void {
            const conn = try srv.accept(.{});
            defer conn.close();

            var rbuf: [256]u8 = undefined;
            var wbuf: [256]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&wbuf);

            const line = r.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
                error.ReadFailed => return r.err orelse error.ReadFailed,
                else => return err,
            };
            try w.interface.writeAll(line);
            w.interface.flush() catch |err| switch (err) {
                error.WriteFailed => return w.err orelse error.WriteFailed,
            };
        }
    };

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(ServerTask.run, .{server});

    const client = try server.socket.address.connect(.{});
    defer client.close();

    var rbuf: [256]u8 = undefined;
    var wbuf: [256]u8 = undefined;
    var r = client.reader(&rbuf);
    var w = client.writer(&wbuf);

    try w.interface.writeAll("PING kite\n");
    w.interface.flush() catch |err| switch (err) {
        error.WriteFailed => return w.err orelse error.WriteFailed,
    };

    const reply = r.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err orelse error.ReadFailed,
        else => return err,
    };
    try std.testing.expectEqualStrings("PING kite\n", reply);

    try group.wait();
}

test "phase0 spike: zio.withTimeout unwraps reader.err into error.Timeout" {
    const gpa = std.testing.allocator;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const bind_addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    const server = try bind_addr.listen(.{});
    defer server.close();

    // Server accepts the socket and deliberately sends nothing until canceled.
    const SilentServer = struct {
        fn run(srv: zio.net.Server) !void {
            const conn = try srv.accept(.{});
            defer conn.close();
            try zio.sleep(.fromSeconds(5));
        }
    };

    var group: zio.Group = .init;
    defer group.cancel();
    try group.spawn(SilentServer.run, .{server});

    const client = try server.socket.address.connect(.{});
    defer client.close();

    const ReadOp = struct {
        fn readLine(stream: zio.net.Stream) ![]const u8 {
            var rbuf: [128]u8 = undefined;
            var r = stream.reader(&rbuf);
            return r.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
                // Critical invariant: std.Io.Reader erases the underlying error into
                // error.ReadFailed. We MUST unwrap r.err so zio.withTimeout sees
                // error.Canceled and translates it into error.Timeout.
                error.ReadFailed => return r.err orelse error.ReadFailed,
                else => return err,
            };
        }
    };

    const result = zio.withTimeout(.fromMilliseconds(30), ReadOp.readLine, .{client});
    try std.testing.expectError(error.Timeout, result);
}

test "phase0 spike: lockUncancelable succeeds during canceled cleanup path" {
    const gpa = std.testing.allocator;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const CleanupState = struct {
        mutex: zio.Mutex = .init,
        cleaned_up: bool = false,
        saw_cancel: bool = false,

        fn worker(state: *@This()) void {
            defer {
                // Even when this task is canceled, cleanup MUST acquire the mutex
                // without returning error.Canceled (invariant I5 for Pool.release/discard).
                state.mutex.lockUncancelable();
                defer state.mutex.unlock();
                state.cleaned_up = true;
            }

            zio.sleep(.fromSeconds(5)) catch |err| {
                if (err == error.Canceled) state.saw_cancel = true;
            };
        }
    };

    var state: CleanupState = .{};
    var handle = try zio.spawn(CleanupState.worker, .{&state});
    try zio.sleep(.fromMilliseconds(10));
    handle.cancel();

    try std.testing.expect(state.saw_cancel);
    try std.testing.expect(state.cleaned_up);
}

test "phase0 spike: rt.io() bridges zio Runtime to Zig 0.17 std.Io" {
    const gpa = std.testing.allocator;

    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const io: std.Io = rt.io();
    // Verify std.Io clock/sleep works through zio's std.Io implementation.
    const t0 = std.Io.Clock.awake.now(io);
    try io.sleep(.fromMilliseconds(5), .awake);
    const t1 = std.Io.Clock.awake.now(io);
    try std.testing.expect(t1.nanoseconds >= t0.nanoseconds);
}
