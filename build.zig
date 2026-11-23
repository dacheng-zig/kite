const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zio_dep = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
    });
    const zio_mod = zio_dep.module("zio");

    const kite_build_options = b.addOptions();
    kite_build_options.addOption([]const u8, "name", @tagName(zon.name));
    kite_build_options.addOption([]const u8, "version", zon.version);

    const kite_mod = b.addModule("kite", .{
        .root_source_file = b.path("src/kite.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zio", .module = zio_mod },
            .{ .name = "kite_build_options", .module = kite_build_options.createModule() },
        },
    });

    const lib_tests = b.addTest(.{ .root_module = kite_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_lib_tests.step);

    const examples = [_]struct { name: []const u8, path: []const u8, desc: []const u8 }{
        .{ .name = "example-get", .path = "examples/get.zig", .desc = "Run minimal HTTPS GET example" },
        .{ .name = "example-json", .path = "examples/json_api.zig", .desc = "Run JSON REST API + Auth + Form example" },
        .{ .name = "example-stream", .path = "examples/stream.zig", .desc = "Run streaming download example" },
        .{ .name = "example-upload", .path = "examples/upload.zig", .desc = "Run streaming chunked upload example" },
        .{ .name = "example-multipart", .path = "examples/multipart.zig", .desc = "Run multipart/form-data file upload example" },
        .{ .name = "example-concurrent", .path = "examples/concurrent.zig", .desc = "Run concurrent pooled requests example" },
        .{ .name = "example-transport", .path = "examples/custom_transport.zig", .desc = "Run custom Transport decorator + redirect/timeout example" },
        .{ .name = "example-retry", .path = "examples/retry_and_trace.zig", .desc = "Run RetryTransport + Trace observability example" },
        .{ .name = "example-cookies", .path = "examples/cookies.zig", .desc = "Run RFC 6265 CookieJar session & redirect example" },
        .{ .name = "example-proxy", .path = "examples/proxy.zig", .desc = "Run HTTP forward proxy + SOCKS5h proxy example" },
        .{ .name = "example-sse", .path = "examples/sse.zig", .desc = "Run Server-Sent Events (SSE) streaming & reconnect example" },
        .{ .name = "example-websocket", .path = "examples/websocket.zig", .desc = "Run full-duplex RFC 6455/7692 WebSocket example" },
        .{ .name = "example-middleware", .path = "examples/middleware.zig", .desc = "Run CacheTransport + RetryTransport + CircuitBreakerTransport example" },
        .{ .name = "example-uds", .path = "examples/unix_socket.zig", .desc = "Run Unix Domain Socket (http+unix:// & unix_socket_path) example" },
    };

    const examples_step = b.step("examples", "Build all examples");
    for (examples) |ex| {
        const ex_exe = b.addExecutable(.{
            .name = ex.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(ex.path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "kite", .module = kite_mod },
                    .{ .name = "zio", .module = zio_mod },
                },
            }),
        });
        examples_step.dependOn(&ex_exe.step);

        const ex_run = b.addRunArtifact(ex_exe);
        ex_run.addPassthruArgs();
        b.step(ex.name, ex.desc).dependOn(&ex_run.step);
    }
}
