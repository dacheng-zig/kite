//! Deterministic in-memory `Transport` for testing `Client` policies
//! (redirects, cross-origin stripping, decompression, body limits, timeouts)
//! without opening sockets.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const zio = @import("zio");
const http = @import("../http.zig");
const h1 = @import("../h1.zig");
const Transport = @import("../Transport.zig");

const MockTransport = @This();

pub const ScriptedResponse = struct {
    status: http.Status = .ok,
    reason: []const u8 = "OK",
    headers: []const http.Header = &.{},
    body: []const u8 = "",
    /// Optional delay before returning response head (useful for timeout tests).
    delay: ?zio.Duration = null,
};

pub const RecordedRequest = struct {
    method: http.Method,
    origin: http.Origin,
    target: []const u8,
    headers: http.Headers,
    body: []const u8,

    pub fn deinit(self: *RecordedRequest, gpa: Allocator) void {
        self.origin.deinitOwned(gpa);
        gpa.free(self.target);
        self.headers.deinit(gpa);
        gpa.free(self.body);
        self.* = undefined;
    }
};

gpa: Allocator,
scripted: std.ArrayList(ScriptedResponse) = .empty,
next_idx: usize = 0,
recorded: std.ArrayList(RecordedRequest) = .empty,

pub fn init(gpa: Allocator) MockTransport {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *MockTransport) void {
    for (self.recorded.items) |*rec| rec.deinit(self.gpa);
    self.recorded.deinit(self.gpa);
    self.scripted.deinit(self.gpa);
    self.* = undefined;
}

pub fn pushResponse(self: *MockTransport, resp: ScriptedResponse) Allocator.Error!void {
    try self.scripted.append(self.gpa, resp);
}

pub fn requests(self: *const MockTransport) []const RecordedRequest {
    return self.recorded.items;
}

pub fn transport(self: *MockTransport) Transport {
    return .{
        .ptr = self,
        .vtable = &.{
            .openExchange = openExchangeImpl,
        },
    };
}

fn openExchangeImpl(ptr: *anyopaque, req: Transport.ExchangeRequest) anyerror!Transport.Exchange {
    const self: *MockTransport = @ptrCast(@alignCast(ptr));
    if (self.next_idx >= self.scripted.items.len) return error.MockNoMoreResponses;

    const spec = self.scripted.items[self.next_idx];
    self.next_idx += 1;

    const ex = try MockExchange.create(self, req, spec);
    return ex.handle();
}

const MockExchange = struct {
    mock: *MockTransport,
    req_index: usize,
    method: http.Method,
    spec: ScriptedResponse,
    response_header_timeout: zio.Timeout,
    body_capture: Writer.Allocating,
    head_received: bool = false,
    head_taken: bool = false,
    response_head: h1.ResponseHead = undefined,
    body_reader: Reader = undefined,
    read_err: ?anyerror = null,

    const vtable: Transport.Exchange.VTable = .{
        .writer = writerImpl,
        .unwrapWriteError = unwrapWriteErrorImpl,
        .receiveHead = receiveHeadImpl,
        .takeHead = takeHeadImpl,
        .reader = readerImpl,
        .unwrapReadError = unwrapReadErrorImpl,
        .deinit = deinitImpl,
    };

    fn handle(self: *MockExchange) Transport.Exchange {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn create(mock: *MockTransport, req: Transport.ExchangeRequest, spec: ScriptedResponse) !*MockExchange {
        const gpa = mock.gpa;

        var origin_copy = try req.origin.dupeOwned(gpa);
        errdefer origin_copy.deinitOwned(gpa);

        const target_copy = try gpa.dupe(u8, req.target);
        errdefer gpa.free(target_copy);

        var headers_copy: http.Headers = .empty;
        errdefer headers_copy.deinit(gpa);
        for (req.headers) |h| {
            try headers_copy.append(gpa, h.name, h.value);
        }

        const initial_body: []const u8 = switch (req.body) {
            .bytes => |b| try gpa.dupe(u8, b),
            else => try gpa.dupe(u8, ""),
        };
        errdefer gpa.free(initial_body);

        const req_index = mock.recorded.items.len;
        try mock.recorded.append(gpa, .{
            .method = req.method,
            .origin = origin_copy,
            .target = target_copy,
            .headers = headers_copy,
            .body = initial_body,
        });

        const ex = try gpa.create(MockExchange);
        ex.* = .{
            .mock = mock,
            .req_index = req_index,
            .method = req.method,
            .spec = spec,
            .response_header_timeout = req.response_header_timeout,
            .body_capture = .init(gpa),
        };
        return ex;
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *MockExchange = @ptrCast(@alignCast(ptr));
        return &self.body_capture.writer;
    }

    fn unwrapWriteErrorImpl(_: *const anyopaque) ?anyerror {
        return null;
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *MockExchange = @ptrCast(@alignCast(ptr));
        if (self.head_received) return &self.response_head;

        const gpa = self.mock.gpa;

        // If the caller streamed body bytes via writer(), save them onto the recorded request.
        if (self.body_capture.written().len > 0) {
            const streamed = try self.body_capture.toOwnedSlice();
            gpa.free(self.mock.recorded.items[self.req_index].body);
            self.mock.recorded.items[self.req_index].body = streamed;
        }

        if (self.spec.delay) |d| {
            const SleepOp = struct {
                fn run(dur: zio.Duration) zio.Cancelable!void {
                    try zio.sleep(dur);
                }
            };
            try zio.withTimeout(self.response_header_timeout, SleepOp.run, .{d});
        }

        const reason_copy = try gpa.dupe(u8, self.spec.reason);
        errdefer gpa.free(reason_copy);

        var headers: http.Headers = .empty;
        errdefer headers.deinit(gpa);
        for (self.spec.headers) |h| {
            try headers.append(gpa, h.name, h.value);
        }

        const body_forbidden = self.method.forbidsResponseBody() or self.spec.status.forbidsResponseBody();
        const framing: h1.ResponseFraming = if (body_forbidden)
            .none
        else
            .{ .fixed = self.spec.body.len };

        self.response_head = .{
            .version = .http1_1,
            .status = self.spec.status,
            .reason = reason_copy,
            .headers = headers,
            .framing = framing,
            .keep_alive = true,
        };
        self.body_reader = .fixed(if (body_forbidden) "" else self.spec.body);
        self.head_received = true;
        return &self.response_head;
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *MockExchange = @ptrCast(@alignCast(ptr));
        if (!self.head_received or self.head_taken) return null;
        self.head_taken = true;
        return self.response_head;
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *MockExchange = @ptrCast(@alignCast(ptr));
        return &self.body_reader;
    }

    fn unwrapReadErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const MockExchange = @ptrCast(@alignCast(ptr));
        return self.read_err;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *MockExchange = @ptrCast(@alignCast(ptr));
        const gpa = self.mock.gpa;
        self.body_capture.deinit();
        if (self.head_received and !self.head_taken) {
            self.response_head.deinit(gpa);
        }
        gpa.destroy(self);
    }
};
