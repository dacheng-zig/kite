//! Configurable retry decorator implementing `kite.Transport`.
//!
//! Wraps any `Transport` (such as `Pool.transport()` or `MockTransport.transport()`)
//! without modifying `Client`. Enforces strict idempotency and rewindable-body
//! guards by default, respects `Retry-After` (RFC 9110 §10.2.3), applies bounded
//! exponential backoff with jitter, and releases connections BEFORE sleeping so
//! pool slots are never held idle during backoff.

const std = @import("std");
const Allocator = std.mem.Allocator;

const zio = @import("zio");
const http = @import("http.zig");
const Transport = @import("Transport.zig");

const RetryTransport = @This();

const drain_limit: usize = 4 * 1024;

pub const default_retry_statuses = [_]http.Status{
    .request_timeout, // 408
    .too_many_requests, // 429
    .bad_gateway, // 502
    .service_unavailable, // 503
    .gateway_timeout, // 504
};

/// Coroutine-safe token-bucket retry budget that prevents retry storms during
/// downstream outages (inspired by Envoy/Linkerd retry budgets).
///
/// Every primary request deposits `deposit_per_request` tokens (and time refills
/// `min_retries_per_sec * withdraw_per_retry` tokens/sec for low-QPS traffic).
/// Every retry consumes `withdraw_per_retry` tokens; once the bucket drops below
/// `withdraw_per_retry`, retries are shed immediately instead of amplifying load.
///
/// With defaults (`deposit = 2`, `withdraw = 10`), sustained retries are bounded
/// to 20% of primary traffic plus a `min_retries_per_sec` floor.
pub const RetryBudget = struct {
    pub const Options = struct {
        capacity: u64 = 1000,
        deposit_per_request: u64 = 2,
        withdraw_per_retry: u64 = 10,
        min_retries_per_sec: u64 = 10,
    };

    mutex: zio.Mutex = .init,
    opts: Options,
    tokens: u64,
    last_refill: zio.Timestamp,

    pub fn init(opts: Options) RetryBudget {
        return .{
            .opts = opts,
            .tokens = opts.capacity,
            .last_refill = zio.Timestamp.now(.awake),
        };
    }

    /// Deposits tokens for a primary (non-retry) request attempt.
    pub fn recordRequest(self: *RetryBudget) void {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();
        self.refillLocked();
        self.tokens = @min(self.opts.capacity, self.tokens +| self.opts.deposit_per_request);
    }

    /// Attempts to withdraw tokens for a retry; returns `false` if budget is exhausted.
    pub fn tryConsumeRetry(self: *RetryBudget) bool {
        self.mutex.lockUncancelable();
        defer self.mutex.unlock();
        self.refillLocked();
        if (self.tokens < self.opts.withdraw_per_retry) return false;
        self.tokens -= self.opts.withdraw_per_retry;
        return true;
    }

    fn refillLocked(self: *RetryBudget) void {
        if (self.opts.min_retries_per_sec == 0) return;
        const now = zio.Timestamp.now(.awake);
        const elapsed_ns = now.toNanoseconds() -| self.last_refill.toNanoseconds();
        const tokens_per_sec = self.opts.min_retries_per_sec *| self.opts.withdraw_per_retry;
        const added = (@as(u128, elapsed_ns) * tokens_per_sec) / std.time.ns_per_s;
        if (added > 0) {
            self.last_refill = now;
            const added_u64: u64 = @intCast(@min(added, std.math.maxInt(u64)));
            self.tokens = @min(self.opts.capacity, self.tokens +| added_u64);
        }
    }
};

pub const Config = struct {
    /// Maximum retry attempts after the initial attempt (0 disables retries).
    max_retries: u8 = 3,
    /// Initial backoff duration for attempt 0 (doubles each attempt).
    initial_backoff: zio.Duration = .fromMilliseconds(100),
    /// Hard ceiling for both exponential backoff and server-supplied `Retry-After`.
    max_backoff: zio.Duration = .fromSeconds(10),
    /// When true, only idempotent methods (GET/HEAD/OPTIONS/TRACE/PUT/DELETE) are retried.
    /// Non-rewindable streaming bodies are never retried regardless of this flag.
    only_idempotent: bool = true,
    /// Honor server `Retry-After` headers (delay-seconds or IMF-fixdate HTTP-date).
    respect_retry_after: bool = true,
    /// HTTP status codes eligible for retry.
    retry_statuses: []const http.Status = &default_retry_statuses,
    /// Optional shared retry budget to shed retries during backend outages.
    budget: ?*RetryBudget = null,
};

inner: Transport,
config: Config,

pub fn init(inner: Transport, config: Config) RetryTransport {
    return .{
        .inner = inner,
        .config = config,
    };
}

pub fn transport(self: *RetryTransport) Transport {
    return .{
        .ptr = self,
        .vtable = &.{
            .openExchange = openExchangeImpl,
        },
    };
}

fn openExchangeImpl(ptr: *anyopaque, req: Transport.ExchangeRequest) anyerror!Transport.Exchange {
    const self: *RetryTransport = @ptrCast(@alignCast(ptr));

    const eligible = self.config.max_retries > 0 and
        req.body.isRewindable() and
        (!self.config.only_idempotent or req.method.isIdempotent());

    if (!eligible) {
        return self.inner.openExchange(req);
    }

    if (self.config.budget) |b| b.recordRequest();

    var attempt: u8 = 0;
    while (true) {
        var ex = self.inner.openExchange(req) catch |err| {
            if (attempt < self.config.max_retries and isRetryableError(err) and self.allowRetry()) {
                try zio.sleep(self.computeBackoff(attempt, null));
                attempt += 1;
                continue;
            }
            return err;
        };

        const head = ex.receiveHead() catch |err| {
            ex.deinit();
            if (attempt < self.config.max_retries and isRetryableError(err) and self.allowRetry()) {
                try zio.sleep(self.computeBackoff(attempt, null));
                attempt += 1;
                continue;
            }
            return err;
        };

        if (attempt < self.config.max_retries and self.isRetryableStatus(head.status) and self.allowRetry()) {
            const retry_after: ?zio.Duration = if (self.config.respect_retry_after)
                parseRetryAfter(head.headers.get("Retry-After"))
            else
                null;

            // Drain small error body and release the connection BEFORE sleeping so
            // backoff wait never pins a connection slot in the pool.
            drainSmallBody(&ex);
            ex.deinit();

            const delay = self.computeBackoff(attempt, retry_after);
            try zio.sleep(delay);
            attempt += 1;
            continue;
        }

        // `receiveHead()` on the underlying Exchange is idempotent, so we return
        // it directly without allocating a wrapper Exchange.
        return ex;
    }
}

fn allowRetry(self: *const RetryTransport) bool {
    if (self.config.budget) |b| return b.tryConsumeRetry();
    return true;
}

fn isRetryableStatus(self: *const RetryTransport, status: http.Status) bool {
    for (self.config.retry_statuses) |s| {
        if (s == status) return true;
    }
    return false;
}

fn isRetryableError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.EndOfStream,
        error.UnexpectedEof,
        error.Timeout,
        error.TemporaryNameServerFailure,
        => true,
        // Explicit user cancellation (`error.Canceled`), TLS certificate failures,
        // and invalid inputs must NEVER be retried.
        else => false,
    };
}

fn computeBackoff(self: *const RetryTransport, attempt: u8, retry_after: ?zio.Duration) zio.Duration {
    const cap_ns = self.config.max_backoff.toNanoseconds();
    if (retry_after) |ra| {
        return .fromNanoseconds(@min(ra.toNanoseconds(), cap_ns));
    }

    const shift: u6 = @intCast(@min(attempt, 30));
    const base_ns = @min(self.config.initial_backoff.toNanoseconds() *| (@as(u64, 1) << shift), cap_ns);
    if (base_ns <= 1) return .fromNanoseconds(base_ns);

    // Equal jitter: random value in [base/2, base] reduces thundering herds while
    // preserving a guaranteed minimum backoff floor.
    const half = base_ns / 2;
    var rnd_bytes: [8]u8 = undefined;
    zio.random(&rnd_bytes);
    const rnd = std.mem.readInt(u64, &rnd_bytes, .little);
    const jitter = rnd % (base_ns - half + 1);
    return .fromNanoseconds(half + jitter);
}

fn drainSmallBody(ex: *Transport.Exchange) void {
    const r = ex.reader();
    var buf: [512]u8 = undefined;
    var drained: usize = 0;
    while (drained < drain_limit) {
        const n = r.readSliceShort(&buf) catch return;
        if (n == 0) return;
        drained += n;
    }
}

/// Parses an RFC 9110 §10.2.3 `Retry-After` header value:
/// - Non-negative integer delay-seconds (e.g. `"2"`)
/// - HTTP-date (IMF-fixdate / RFC 850 / asctime)
pub fn parseRetryAfter(raw_opt: ?[]const u8) ?zio.Duration {
    const raw = raw_opt orelse return null;
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return null;

    if (std.fmt.parseInt(u64, trimmed, 10)) |secs| {
        return .fromSeconds(secs);
    } else |_| {}

    const target_epoch = http.parseHttpDate(trimmed) orelse return null;
    const now_epoch: i64 = @intCast(zio.Timestamp.now(.real).toSeconds());
    if (target_epoch <= now_epoch) return .zero;
    return .fromSeconds(@intCast(target_epoch - now_epoch));
}

/// Re-exported alias for RFC 9110 §5.6.7 IMF-fixdate parsing.
pub const parseImfFixdate = http.parseImfFixdate;

// ===========================================================================
// Unit Tests
// ===========================================================================

const Client = @import("Client.zig");
const MockTransport = @import("testing/MockTransport.zig");

test "RetryTransport retries 503 and 429 for GET, honors Retry-After cap, and never retries POST" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // 1. GET encounters 503 -> 429 (with huge Retry-After capped to 5ms) -> 200 OK
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        try mock.pushResponse(.{ .status = .service_unavailable, .body = "busy" });
        try mock.pushResponse(.{
            .status = .too_many_requests,
            .headers = &.{.{ .name = "Retry-After", .value = "99999" }},
            .body = "slow down",
        });
        try mock.pushResponse(.{ .status = .ok, .body = "recovered" });

        var retry = RetryTransport.init(mock.transport(), .{
            .max_retries = 3,
            .initial_backoff = .fromMilliseconds(2),
            .max_backoff = .fromMilliseconds(5),
        });

        var client = Client.initWithTransport(gpa, rt.io(), retry.transport(), .{});
        defer client.deinit();

        var res = try client.get("https://api.example.com/data");
        defer res.deinit();

        try std.testing.expectEqual(http.Status.ok, res.status);
        try std.testing.expectEqualStrings("recovered", res.body);
        try std.testing.expectEqual(@as(usize, 3), mock.requests().len);
    }

    // 2. Non-idempotent POST receiving 503 MUST NOT retry under default config
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();

        try mock.pushResponse(.{ .status = .service_unavailable, .body = "down" });
        try mock.pushResponse(.{ .status = .ok, .body = "should-not-run" });

        var retry = RetryTransport.init(mock.transport(), .{
            .max_retries = 3,
            .initial_backoff = .fromMilliseconds(1),
            .max_backoff = .fromMilliseconds(5),
        });

        var client = Client.initWithTransport(gpa, rt.io(), retry.transport(), .{});
        defer client.deinit();

        var res = try client.fetch(.{
            .method = .POST,
            .url = "https://api.example.com/orders",
            .body = .{ .bytes = "amount=50" },
        });
        defer res.deinit();

        try std.testing.expectEqual(http.Status.service_unavailable, res.status);
        try std.testing.expectEqual(@as(usize, 1), mock.requests().len);
    }

    // 3. Exhausting max_retries returns the last response cleanly
    {
        var mock = MockTransport.init(gpa);
        defer mock.deinit();
        for (0..3) |_| {
            try mock.pushResponse(.{ .status = .bad_gateway, .body = "bad gw" });
        }

        var retry = RetryTransport.init(mock.transport(), .{
            .max_retries = 2,
            .initial_backoff = .fromMilliseconds(1),
            .max_backoff = .fromMilliseconds(2),
        });

        var client = Client.initWithTransport(gpa, rt.io(), retry.transport(), .{});
        defer client.deinit();

        var res = try client.get("https://api.example.com/fail");
        defer res.deinit();
        try std.testing.expectEqual(http.Status.bad_gateway, res.status);
        try std.testing.expectEqual(@as(usize, 3), mock.requests().len);
    }
}

test "parseRetryAfter and parseImfFixdate handle delay-seconds, HTTP-date, and invalid values" {
    try std.testing.expectEqual(@as(?u64, 120), parseRetryAfter(" 120 ").?.toSeconds());
    try std.testing.expectEqual(@as(?u64, 0), parseRetryAfter("0").?.toSeconds());
    try std.testing.expectEqual(@as(?zio.Duration, null), parseRetryAfter(""));
    try std.testing.expectEqual(@as(?zio.Duration, null), parseRetryAfter("-5"));
    try std.testing.expectEqual(@as(?zio.Duration, null), parseRetryAfter("not-a-date"));

    // RFC 9110 §5.6.7 canonical example: Sun, 06 Nov 1994 08:49:37 GMT == 784111777
    try std.testing.expectEqual(@as(?i64, 784111777), parseImfFixdate("Sun, 06 Nov 1994 08:49:37 GMT"));
    // Invalid date (Feb 30) rejected
    try std.testing.expectEqual(@as(?i64, null), parseImfFixdate("Sun, 30 Feb 2025 08:49:37 GMT"));
    // Past HTTP-date resolves to Duration.zero
    try std.testing.expectEqual(@as(?u64, 0), parseRetryAfter("Sun, 06 Nov 1994 08:49:37 GMT").?.toSeconds());
}

test "RetryBudget sheds retries when exhausted and TemporaryNameServerFailure is retryable" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Verify transient DNS failure is classified as retryable.
    try std.testing.expect(isRetryableError(error.TemporaryNameServerFailure));
    try std.testing.expect(!isRetryableError(error.UnknownHostName));

    var mock = MockTransport.init(gpa);
    defer mock.deinit();

    // Budget starts with only 1 retry worth of tokens (capacity=10, withdraw=10, deposit=0, refill=0).
    var budget = RetryBudget.init(.{
        .capacity = 10,
        .deposit_per_request = 0,
        .withdraw_per_retry = 10,
        .min_retries_per_sec = 0,
    });

    // Server returns 503 three times in a row.
    try mock.pushResponse(.{ .status = .service_unavailable, .body = "busy 1" });
    try mock.pushResponse(.{ .status = .service_unavailable, .body = "busy 2" });
    try mock.pushResponse(.{ .status = .ok, .body = "should not reach" });

    var retry_tr = RetryTransport.init(mock.transport(), .{
        .max_retries = 3,
        .initial_backoff = .fromMilliseconds(1),
        .budget = &budget,
    });
    var client = Client.initWithTransport(gpa, rt.io(), retry_tr.transport(), .{});
    defer client.deinit();

    // Primary attempt + 1 budgeted retry = 2 total attempts (second retry shed by budget!).
    var res = try client.get("http://api.example.com/data");
    defer res.deinit();

    try std.testing.expectEqual(http.Status.service_unavailable, res.status);
    try std.testing.expectEqualStrings("busy 2", res.body);
    try std.testing.expectEqual(@as(usize, 2), mock.requests().len);
}
