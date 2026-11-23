//! Per-origin 3-state circuit breaker decorator implementing `kite.Transport`.
//!
//! Protects downstream services and caller coroutines from cascading failures:
//! - `closed`: normal traffic flows through; consecutive failures reaching
//!   `failure_threshold` trip the breaker to `open`.
//! - `open`: fast-fails immediately with `error.CircuitOpen` without dialing
//!   or consuming pool slots until `open_duration` elapses.
//! - `half_open`: permits at most `half_open_max_probes` concurrent probe
//!   requests; `success_threshold` consecutive successes restore `closed`,
//!   while any probe failure immediately re-opens the circuit.
//!
//! Invariants:
//! - `error.Canceled` (caller cancellation) is NEVER counted as an upstream failure.
//! - Half-open probe slots are ALWAYS released via `lockUncancelable` in `deinit()`
//!   even if the probe is canceled or dropped before `receiveHead()`.
//! - Bounded `max_origins` LRU eviction prevents unbounded memory growth.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");
const Transport = @import("Transport.zig");

const CircuitBreakerTransport = @This();

pub const State = enum {
    closed,
    open,
    half_open,
};

/// Optional observability callback invoked OUTSIDE the internal mutex whenever
/// an origin's circuit state transitions (e.g. `closed -> open`, `open -> half_open`,
/// `half_open -> closed`). Safe to query `cb.stateFor()` or emit metrics/logs inside.
pub const StateChangeHook = struct {
    ctx: ?*anyopaque = null,
    on_change: *const fn (ctx: ?*anyopaque, origin: http.Origin, from: State, to: State) void,
};

pub const Config = struct {
    /// Consecutive failures required in `closed` state to trip the breaker open.
    failure_threshold: u32 = 5,
    /// Consecutive probe successes required in `half_open` state to return to `closed`.
    success_threshold: u32 = 1,
    /// Cooldown duration before an `open` circuit transitions to `half_open`.
    open_duration: zio.Duration = .fromSeconds(30),
    /// Maximum concurrent probe requests permitted while in `half_open` state.
    half_open_max_probes: u32 = 1,
    /// Treat `5xx` HTTP responses as upstream failures (in addition to transport errors).
    trip_on_5xx: bool = true,
    /// Treat `429 Too Many Requests` as an upstream failure.
    trip_on_429: bool = false,
    /// Hard cap on tracked Origin buckets (LRU eviction prevents OOM on unbounded domains).
    max_origins: usize = 1024,
    /// Optional state-transition observability callback.
    on_state_change: ?StateChangeHook = null,
};

const OriginContext = struct {
    pub fn hash(_: OriginContext, key: http.Origin) u64 {
        return key.hash();
    }

    pub fn eql(_: OriginContext, a: http.Origin, b: http.Origin) bool {
        return a.eql(b);
    }
};

const Bucket = struct {
    origin: http.Origin,
    state: State = .closed,
    consecutive_failures: u32 = 0,
    half_open_successes: u32 = 0,
    in_flight_probes: u32 = 0,
    opened_at: zio.Timestamp = .{ .value = 0 },
    lru_node: std.DoublyLinkedList.Node = .{},
};

gpa: Allocator,
inner: Transport,
config: Config,
mutex: zio.Mutex = .init,
buckets: std.HashMapUnmanaged(http.Origin, *Bucket, OriginContext, std.hash_map.default_max_load_percentage) = .empty,
lru: std.DoublyLinkedList = .{},

pub fn init(gpa: Allocator, inner: Transport, config: Config) CircuitBreakerTransport {
    return .{
        .gpa = gpa,
        .inner = inner,
        .config = config,
    };
}

pub fn deinit(self: *CircuitBreakerTransport) void {
    self.mutex.lockUncancelable();
    var it = self.buckets.valueIterator();
    while (it.next()) |bp| {
        const b = bp.*;
        var owned = b.origin;
        owned.deinitOwned(self.gpa);
        self.gpa.destroy(b);
    }
    self.buckets.deinit(self.gpa);
    self.lru = .{};
    self.mutex.unlock();
}

pub fn transport(self: *CircuitBreakerTransport) Transport {
    return .{
        .ptr = self,
        .vtable = &.{
            .openExchange = openExchangeImpl,
        },
    };
}

/// Returns the current circuit state for `origin` (defaults to `.closed` if unseen).
pub fn stateFor(self: *CircuitBreakerTransport, origin: http.Origin) State {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    const b = self.buckets.get(origin) orelse return .closed;
    if (b.state == .open) {
        const now = zio.Timestamp.now(.awake);
        if (now.value -| b.opened_at.value >= self.config.open_duration.value) {
            return .half_open;
        }
    }
    return b.state;
}

/// Manually resets an origin's circuit back to `.closed`.
pub fn reset(self: *CircuitBreakerTransport, origin: http.Origin) void {
    var prev_state: ?State = null;
    {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();
        if (self.buckets.get(origin)) |b| {
            if (b.state != .closed) prev_state = b.state;
            b.state = .closed;
            b.consecutive_failures = 0;
            b.half_open_successes = 0;
            b.in_flight_probes = 0;
        }
    }
    if (prev_state) |from| self.notifyTransition(origin, from, .closed);
}

fn notifyTransition(self: *const CircuitBreakerTransport, origin: http.Origin, from: State, to: State) void {
    if (from == to) return;
    if (self.config.on_state_change) |hook| {
        hook.on_change(hook.ctx, origin, from, to);
    }
}

fn openExchangeImpl(ptr: *anyopaque, req: Transport.ExchangeRequest) anyerror!Transport.Exchange {
    const self: *CircuitBreakerTransport = @ptrCast(@alignCast(ptr));

    const is_probe = try self.beforeRequest(req.origin);

    const inner_ex = self.inner.openExchange(req) catch |err| {
        if (err == error.Canceled) {
            self.releaseProbeOnly(req.origin, is_probe);
        } else {
            self.recordFailure(req.origin, is_probe);
        }
        return err;
    };

    const wrap = self.gpa.create(WrappedExchange) catch |err| {
        var ex_copy = inner_ex;
        ex_copy.deinit();
        self.releaseProbeOnly(req.origin, is_probe);
        return err;
    };
    const origin_copy = req.origin.dupeOwned(self.gpa) catch |err| {
        var ex_copy = inner_ex;
        ex_copy.deinit();
        self.gpa.destroy(wrap);
        self.releaseProbeOnly(req.origin, is_probe);
        return err;
    };

    wrap.* = .{
        .cb = self,
        .origin = origin_copy,
        .inner = inner_ex,
        .is_probe = is_probe,
        .outcome_recorded = false,
    };
    return wrap.handle();
}

fn beforeRequest(self: *CircuitBreakerTransport, origin: http.Origin) !bool {
    var transitioned_to_half_open = false;
    const is_probe: bool = blk: {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();

        const now = zio.Timestamp.now(.awake);
        const b = try self.getOrCreateBucketLocked(origin);

        switch (b.state) {
            .closed => break :blk false,
            .open => {
                if (now.value -| b.opened_at.value < self.config.open_duration.value) {
                    return error.CircuitOpen;
                }
                // Cooldown elapsed: transition to half_open and claim 1 probe slot.
                b.state = .half_open;
                b.half_open_successes = 0;
                b.in_flight_probes = 1;
                transitioned_to_half_open = true;
                break :blk true;
            },
            .half_open => {
                if (b.in_flight_probes >= self.config.half_open_max_probes) {
                    return error.CircuitOpen;
                }
                b.in_flight_probes += 1;
                break :blk true;
            },
        }
    };
    if (transitioned_to_half_open) {
        self.notifyTransition(origin, .open, .half_open);
    }
    return is_probe;
}

fn recordSuccess(self: *CircuitBreakerTransport, origin: http.Origin, is_probe: bool) void {
    var closed_from_half_open = false;
    {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();

        const b = self.buckets.get(origin) orelse return;
        if (is_probe and b.in_flight_probes > 0) b.in_flight_probes -= 1;

        switch (b.state) {
            .closed => {
                b.consecutive_failures = 0;
            },
            .half_open => {
                if (is_probe) {
                    b.half_open_successes += 1;
                    if (b.half_open_successes >= self.config.success_threshold) {
                        b.state = .closed;
                        b.consecutive_failures = 0;
                        b.half_open_successes = 0;
                        closed_from_half_open = true;
                    }
                }
            },
            .open => {},
        }
    }
    if (closed_from_half_open) {
        self.notifyTransition(origin, .half_open, .closed);
    }
}

fn recordFailure(self: *CircuitBreakerTransport, origin: http.Origin, is_probe: bool) void {
    var opened_from: ?State = null;
    {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();

        const b = self.buckets.get(origin) orelse return;
        if (is_probe and b.in_flight_probes > 0) b.in_flight_probes -= 1;

        const now = zio.Timestamp.now(.awake);
        switch (b.state) {
            .closed => {
                b.consecutive_failures +|= 1;
                if (self.config.failure_threshold > 0 and b.consecutive_failures >= self.config.failure_threshold) {
                    b.state = .open;
                    b.opened_at = now;
                    b.half_open_successes = 0;
                    opened_from = .closed;
                }
            },
            .half_open => {
                if (is_probe) {
                    b.state = .open;
                    b.opened_at = now;
                    b.half_open_successes = 0;
                    opened_from = .half_open;
                }
            },
            .open => {},
        }
    }
    if (opened_from) |from| {
        self.notifyTransition(origin, from, .open);
    }
}

fn releaseProbeOnly(self: *CircuitBreakerTransport, origin: http.Origin, is_probe: bool) void {
    if (!is_probe) return;
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    if (self.buckets.get(origin)) |b| {
        if (b.in_flight_probes > 0) b.in_flight_probes -= 1;
    }
}

fn isFailureStatus(self: *const CircuitBreakerTransport, status: http.Status) bool {
    const code = status.code();
    if (self.config.trip_on_5xx and code >= 500 and code <= 599) return true;
    if (self.config.trip_on_429 and code == 429) return true;
    return false;
}

fn getOrCreateBucketLocked(self: *CircuitBreakerTransport, origin: http.Origin) Allocator.Error!*Bucket {
    if (self.buckets.get(origin)) |existing| {
        self.lru.remove(&existing.lru_node);
        self.lru.append(&existing.lru_node);
        return existing;
    }

    // Evict oldest idle/non-probing bucket if at capacity.
    if (self.config.max_origins > 0 and self.buckets.count() >= self.config.max_origins) {
        var cursor = self.lru.first;
        while (cursor) |node| {
            const candidate: *Bucket = @fieldParentPtr("lru_node", node);
            const next_node = node.next;
            if (candidate.in_flight_probes == 0) {
                self.lru.remove(node);
                _ = self.buckets.remove(candidate.origin);
                var owned = candidate.origin;
                owned.deinitOwned(self.gpa);
                self.gpa.destroy(candidate);
                break;
            }
            cursor = next_node;
        }
    }

    const owned_origin = try origin.dupeOwned(self.gpa);
    errdefer {
        var o = owned_origin;
        o.deinitOwned(self.gpa);
    }

    const b = try self.gpa.create(Bucket);
    errdefer self.gpa.destroy(b);
    b.* = .{ .origin = owned_origin };

    try self.buckets.put(self.gpa, b.origin, b);
    self.lru.append(&b.lru_node);
    return b;
}

const WrappedExchange = struct {
    cb: *CircuitBreakerTransport,
    origin: http.Origin,
    inner: Transport.Exchange,
    is_probe: bool,
    outcome_recorded: bool,

    fn handle(self: *WrappedExchange) Transport.Exchange {
        return .{
            .ptr = self,
            .vtable = &.{
                .writer = writerImpl,
                .unwrapWriteError = unwrapWriteErrorImpl,
                .receiveHead = receiveHeadImpl,
                .takeHead = takeHeadImpl,
                .reader = readerImpl,
                .unwrapReadError = unwrapReadErrorImpl,
                .deinit = deinitImpl,
            },
        };
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *WrappedExchange = @ptrCast(@alignCast(ptr));
        return self.inner.writer();
    }

    fn unwrapWriteErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const WrappedExchange = @ptrCast(@alignCast(ptr));
        return self.inner.unwrapWriteError();
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *WrappedExchange = @ptrCast(@alignCast(ptr));
        const head = self.inner.receiveHead() catch |err| {
            if (!self.outcome_recorded) {
                self.outcome_recorded = true;
                if (err == error.Canceled) {
                    self.cb.releaseProbeOnly(self.origin, self.is_probe);
                } else {
                    self.cb.recordFailure(self.origin, self.is_probe);
                }
            }
            return err;
        };

        if (!self.outcome_recorded) {
            self.outcome_recorded = true;
            if (self.cb.isFailureStatus(head.status)) {
                self.cb.recordFailure(self.origin, self.is_probe);
            } else {
                self.cb.recordSuccess(self.origin, self.is_probe);
            }
        }
        return head;
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *WrappedExchange = @ptrCast(@alignCast(ptr));
        return self.inner.takeHead();
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *WrappedExchange = @ptrCast(@alignCast(ptr));
        return self.inner.reader();
    }

    fn unwrapReadErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const WrappedExchange = @ptrCast(@alignCast(ptr));
        return self.inner.unwrapReadError();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *WrappedExchange = @ptrCast(@alignCast(ptr));
        if (!self.outcome_recorded) {
            self.outcome_recorded = true;
            // Dropped before receiveHead() (e.g. caller abort/cancel): release probe slot safely.
            self.cb.releaseProbeOnly(self.origin, self.is_probe);
        }
        self.inner.deinit();
        var o = self.origin;
        o.deinitOwned(self.cb.gpa);
        self.cb.gpa.destroy(self);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockTransport = @import("testing/MockTransport.zig");
const RetryTransport = @import("RetryTransport.zig");
const Client = @import("Client.zig");

test "CircuitBreakerTransport transitions Closed -> Open -> HalfOpen -> Closed with Origin isolation" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();

    // 2 consecutive 503 failures trip Origin A; Origin B succeeds; probe recovers Origin A.
    try mock.pushResponse(.{ .status = .service_unavailable, .body = "down1" });
    try mock.pushResponse(.{ .status = .service_unavailable, .body = "down2" });
    try mock.pushResponse(.{ .status = .ok, .body = "b-ok" });
    try mock.pushResponse(.{ .status = .ok, .body = "a-recovered" });
    try mock.pushResponse(.{ .status = .ok, .body = "a-normal" });

    var cb = CircuitBreakerTransport.init(gpa, mock.transport(), .{
        .failure_threshold = 2,
        .success_threshold = 1,
        .open_duration = .fromMilliseconds(25),
        .half_open_max_probes = 1,
    });
    defer cb.deinit();

    var client = Client.initWithTransport(gpa, rt.io(), cb.transport(), .{});
    defer client.deinit();

    const origin_a: http.Origin = .{ .scheme = .http, .host = "a.example", .port = 80 };
    const origin_b: http.Origin = .{ .scheme = .http, .host = "b.example", .port = 80 };

    // 2 failures on Origin A -> Open
    {
        var r1 = try client.get("http://a.example/1");
        defer r1.deinit();
        try std.testing.expectEqual(http.Status.service_unavailable, r1.status);
        try std.testing.expectEqual(State.closed, cb.stateFor(origin_a));

        var r2 = try client.get("http://a.example/2");
        defer r2.deinit();
        try std.testing.expectEqual(http.Status.service_unavailable, r2.status);
        try std.testing.expectEqual(State.open, cb.stateFor(origin_a));
    }

    // Immediate call to Origin A fast-fails WITHOUT calling inner transport
    try std.testing.expectError(error.CircuitOpen, client.get("http://a.example/3"));
    try std.testing.expectEqual(@as(usize, 2), mock.requests().len);

    // Origin B is completely isolated and unaffected
    {
        var rb = try client.get("http://b.example/ok");
        defer rb.deinit();
        try std.testing.expectEqualStrings("b-ok", rb.body);
        try std.testing.expectEqual(State.closed, cb.stateFor(origin_b));
    }

    // After open_duration, state becomes half_open; probe succeeds -> closed
    try zio.sleep(.fromMilliseconds(30));
    try std.testing.expectEqual(State.half_open, cb.stateFor(origin_a));

    {
        var r3 = try client.get("http://a.example/probe");
        defer r3.deinit();
        try std.testing.expectEqualStrings("a-recovered", r3.body);
        try std.testing.expectEqual(State.closed, cb.stateFor(origin_a));

        var r4 = try client.get("http://a.example/after");
        defer r4.deinit();
        try std.testing.expectEqualStrings("a-normal", r4.body);
    }
}

test "CircuitBreakerTransport half_open caps concurrent probes and releases slot on early deinit" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();

    try mock.pushResponse(.{ .status = .bad_gateway });
    try mock.pushResponse(.{ .status = .ok, .body = "aborted-probe" });
    try mock.pushResponse(.{ .status = .ok, .body = "second-probe-ok" });

    var cb = CircuitBreakerTransport.init(gpa, mock.transport(), .{
        .failure_threshold = 1,
        .open_duration = .fromMilliseconds(15),
        .half_open_max_probes = 1,
    });
    defer cb.deinit();

    const origin: http.Origin = .{ .scheme = .http, .host = "svc.local", .port = 80 };
    const t = cb.transport();

    // Trip open
    {
        var ex = try t.openExchange(.{ .method = .GET, .origin = origin, .target = "/" });
        defer ex.deinit();
        _ = try ex.receiveHead();
        try std.testing.expectEqual(State.open, cb.stateFor(origin));
    }

    try zio.sleep(.fromMilliseconds(20));

    // Claim the single half_open probe slot; second concurrent call must get CircuitOpen
    {
        var probe = try t.openExchange(.{ .method = .GET, .origin = origin, .target = "/p1" });
        defer probe.deinit(); // Dropped BEFORE receiveHead() -> must release probe slot!

        try std.testing.expectError(
            error.CircuitOpen,
            t.openExchange(.{ .method = .GET, .origin = origin, .target = "/p2" }),
        );
    }

    // Slot was cleanly released on deinit: next probe succeeds and closes the circuit
    {
        var probe2 = try t.openExchange(.{ .method = .GET, .origin = origin, .target = "/p3" });
        defer probe2.deinit();
        const head = try probe2.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);
        try std.testing.expectEqual(State.closed, cb.stateFor(origin));
    }
}

test "CircuitBreakerTransport StateChangeHook fires lock-free and RetryTransport does not retry CircuitOpen" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var mock: MockTransport = .init(gpa);
    defer mock.deinit();
    try mock.pushResponse(.{ .status = .service_unavailable });
    try mock.pushResponse(.{ .status = .ok, .body = "ok" });

    const Recorder = struct {
        cb: ?*CircuitBreakerTransport = null,
        transitions: [8]struct { from: State, to: State } = undefined,
        count: usize = 0,

        fn onChange(ctx: ?*anyopaque, origin: http.Origin, from: State, to: State) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            // Prove callback runs outside mutex (re-entrant `stateFor` must not deadlock!)
            _ = self.cb.?.stateFor(origin);
            if (self.count < self.transitions.len) {
                self.transitions[self.count] = .{ .from = from, .to = to };
                self.count += 1;
            }
        }
    };

    var rec: Recorder = .{};
    var cb = CircuitBreakerTransport.init(gpa, mock.transport(), .{
        .failure_threshold = 1,
        .open_duration = .fromMilliseconds(15),
        .on_state_change = .{ .ctx = &rec, .on_change = Recorder.onChange },
    });
    defer cb.deinit();
    rec.cb = &cb;

    // Stack RetryTransport outside CircuitBreakerTransport: once open, Retry MUST fail fast!
    var retry = RetryTransport.init(cb.transport(), .{
        .max_retries = 3,
        .initial_backoff = .fromMilliseconds(1),
    });

    var client = Client.initWithTransport(gpa, rt.io(), retry.transport(), .{});
    defer client.deinit();

    // First call hits 503 -> trips circuit open -> Retry's 1st retry immediately gets CircuitOpen and stops!
    try std.testing.expectError(error.CircuitOpen, client.get("http://flaky.local/api"));
    // Exactly 1 upstream call reached mock (no storm retry amplification!)
    try std.testing.expectEqual(@as(usize, 1), mock.requests().len);

    // Wait cooldown -> probe succeeds -> transitions recorded cleanly
    try zio.sleep(.fromMilliseconds(20));
    var ok_res = try client.get("http://flaky.local/api");
    defer ok_res.deinit();
    try std.testing.expectEqualStrings("ok", ok_res.body);

    try std.testing.expectEqual(@as(usize, 3), rec.count);
    try std.testing.expectEqual(State.closed, rec.transitions[0].from);
    try std.testing.expectEqual(State.open, rec.transitions[0].to);
    try std.testing.expectEqual(State.open, rec.transitions[1].from);
    try std.testing.expectEqual(State.half_open, rec.transitions[1].to);
    try std.testing.expectEqual(State.half_open, rec.transitions[2].from);
    try std.testing.expectEqual(State.closed, rec.transitions[2].to);
}
