//! Concurrent HTTP/1.1 connection pool and single-exchange executor (`Transport`).
//!
//! Governance model:
//! - Buckets connections by normalized `http.Origin` (`scheme`, lowercase `host`, `port`).
//! - Acquires idle connections LIFO (most recently used first, least likely to be
//!   stale) and evicts excess idle connections LRU (oldest first) in O(1) via two
//!   intrusive doubly-linked lists on `Connection`.
//! - Enforces `max_conns_per_origin` backpressure via cooperative `zio.Condition`
//!   waiting (fully cancelable by `zio.withTimeout` or task cancellation).
//! - Enforces lazy `max_idle_time` and `max_conn_lifetime` expiration (no hidden
//!   background tasks) plus an explicit `pruneExpired()` method.
//! - Uses `zio.Mutex.lockUncancelable()` on all release/discard/deinit paths and
//!   closes sockets outside the lock so cancellation never deadlocks or leaks.
//! - Transparently retries once on a fresh connection when a reused idle socket
//!   is closed by the peer before sending any response byte, strictly limited to
//!   idempotent methods with rewindable request bodies.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const assert = std.debug.assert;

const zio = @import("zio");
const http = @import("http.zig");
const h1 = @import("h1.zig");
const Connection = @import("Connection.zig");
const Transport = @import("Transport.zig");

const Pool = @This();

pub const Config = struct {
    /// Maximum concurrent in-flight connections per Origin (0 = unlimited).
    max_conns_per_origin: usize = 16,
    /// Maximum idle connections retained across all Origins (0 = disable pooling).
    max_idle_conns: usize = 64,
    /// Maximum idle connections retained for any single Origin.
    max_idle_conns_per_origin: usize = 8,
    /// Maximum time an idle connection may sit unused before eviction (`null` = no limit).
    max_idle_time: ?zio.Duration = .fromSeconds(60),
    /// Maximum total age of a connection since creation (`null` = no limit).
    /// Bounds exposure to stale DNS / load-balancer rotations.
    max_conn_lifetime: ?zio.Duration = .fromSeconds(300),
    /// Optional TLS override; when `null`, verifies against the Pool's lazily loaded system CA store.
    tls: ?Connection.TlsConfig = null,
    /// Optional HTTP / HTTPS forward proxy configuration.
    proxy: ?Connection.ProxyConfig = null,
    /// Optional post-DNS IP address filter (e.g. `Connection.blockPrivateAddresses()`).
    address_filter: ?Connection.AddressFilter = null,
    /// Optional per-exchange observability hook (DNS/TCP/TLS connect time, TTFB, Total, reuse).
    trace: ?Transport.Trace = null,
    read_buffer_size: usize = Connection.default_read_buffer_size,
    write_buffer_size: usize = Connection.default_write_buffer_size,
};

/// Handle to an optional periodic background reaper created by `Pool.startReaper()`.
/// Always call `reaper.stop()` before calling `Pool.deinit()`.
pub const Reaper = struct {
    handle: zio.JoinHandle(void),

    pub fn stop(self: *Reaper) void {
        self.handle.cancel();
    }
};

pub const Stats = struct {
    total_idle: usize,
    total_in_flight: usize,
    origin_count: usize,
};

const OriginContext = struct {
    pub fn hash(_: OriginContext, key: http.Origin) u64 {
        return key.hash();
    }

    pub fn eql(_: OriginContext, a: http.Origin, b: http.Origin) bool {
        return a.eql(b);
    }
};

const OriginBucket = struct {
    origin: http.Origin,
    /// Per-origin idle connections: push tail (`append`), pop tail (`popLast`, LIFO),
    /// evict head (`popFirst`, LRU).
    idle: std.DoublyLinkedList = .{},
    idle_count: usize = 0,
    /// Currently checked-out or dialing connections for this Origin.
    in_flight: usize = 0,
    /// Coroutines currently parked on `cond` waiting for a slot in this bucket.
    waiters: usize = 0,
    cond: zio.Condition = .init,
};

gpa: Allocator,
io: std.Io,
config: Config,
ca_store: Connection.CaStore = .init,
mutex: zio.Mutex = .init,
buckets: std.HashMapUnmanaged(http.Origin, *OriginBucket, OriginContext, std.hash_map.default_max_load_percentage) = .empty,
/// Global idle connections ordered oldest-first (`first`) to newest-last (`last`).
global_idle: std.DoublyLinkedList = .{},
total_idle: usize = 0,
total_waiters: usize = 0,
closed: bool = false,
closed_cond: zio.Condition = .init,

pub fn init(gpa: Allocator, io: std.Io, config: Config) Pool {
    return .{
        .gpa = gpa,
        .io = io,
        .config = config,
    };
}

/// Spawns a cooperative background task that calls `pruneExpired()` every `interval`.
/// `self` must remain pinned in memory; always call `reaper.stop()` before `Pool.deinit()`.
pub fn startReaper(self: *Pool, interval: zio.Duration) !Reaper {
    return .{
        .handle = try zio.spawn(reaperLoop, .{ self, interval }),
    };
}

fn reaperLoop(pool: *Pool, interval: zio.Duration) void {
    while (true) {
        zio.sleep(interval) catch return;
        _ = pool.pruneExpired();
    }
}

/// Transitions the pool into the closed state without freeing metadata:
/// closes all idle connections immediately and wakes every parked waiter with
/// `error.PoolClosed`. Safe to call while active exchanges are still finishing
/// (call `deinit()` once all active exchanges have been released).
pub fn close(self: *Pool) void {
    var to_destroy: std.DoublyLinkedList = .{};
    defer destroyList(self.gpa, &to_destroy);

    self.mutex.lockUncancelable();
    self.closed = true;

    while (self.global_idle.popFirst()) |node| {
        const conn = connFromGlobalNode(node);
        if (self.buckets.get(conn.origin())) |bucket| {
            bucket.idle.remove(&conn.origin_node);
            bucket.idle_count -= 1;
        }
        self.total_idle -= 1;
        to_destroy.append(&conn.global_idle_node);
    }

    var wake_it = self.buckets.valueIterator();
    while (wake_it.next()) |bucket_ptr| {
        bucket_ptr.*.cond.broadcast();
    }
    self.mutex.unlock();
}

/// Closes all idle connections, wakes any parked waiters with `error.PoolClosed`,
/// waits for woken waiters to release bucket references, and frees pool metadata.
/// Callers must `deinit()` all active `Exchange`s before calling `Pool.deinit()`.
pub fn deinit(self: *Pool) void {
    var to_destroy: std.DoublyLinkedList = .{};
    defer destroyList(self.gpa, &to_destroy);

    self.mutex.lockUncancelable();
    self.closed = true;

    // Wake every parked waiter and wait until all of them exit `bucket.cond.wait`
    // before freeing any `OriginBucket` (prevents use-after-free on bucket pointers).
    {
        var wake_it = self.buckets.valueIterator();
        while (wake_it.next()) |bucket_ptr| {
            bucket_ptr.*.cond.broadcast();
        }
    }
    while (self.total_waiters > 0) {
        self.closed_cond.waitUncancelable(&self.mutex);
    }

    while (self.global_idle.popFirst()) |node| {
        const conn = connFromGlobalNode(node);
        if (self.buckets.get(conn.origin())) |bucket| {
            bucket.idle.remove(&conn.origin_node);
            bucket.idle_count -= 1;
        }
        self.total_idle -= 1;
        to_destroy.append(&conn.global_idle_node);
    }

    var it = self.buckets.valueIterator();
    while (it.next()) |bucket_ptr| {
        const bucket = bucket_ptr.*;
        assert(bucket.in_flight == 0);
        assert(bucket.waiters == 0);
        bucket.origin.deinitOwned(self.gpa);
        self.gpa.destroy(bucket);
    }
    self.buckets.deinit(self.gpa);
    self.mutex.unlock();

    self.ca_store.deinit(self.gpa);
}

/// Returns a `Transport` fat-pointer backed by this `Pool`.
/// `self` must remain pinned in memory for as long as the returned `Transport` is used.
pub fn transport(self: *Pool) Transport {
    return .{
        .ptr = self,
        .vtable = &.{
            .openExchange = openExchangeImpl,
        },
    };
}

/// Explicitly scans and closes all idle connections that have exceeded
/// `max_idle_time` or `max_conn_lifetime`. Returns the number of connections closed.
pub fn pruneExpired(self: *Pool) usize {
    var to_destroy: std.DoublyLinkedList = .{};
    defer destroyList(self.gpa, &to_destroy);

    const now = zio.Timestamp.now(.awake);
    var pruned: usize = 0;

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var cursor = self.global_idle.first;
    while (cursor) |node| {
        cursor = node.next;
        const conn = connFromGlobalNode(node);
        if (conn.isExpired(now, self.config.max_idle_time, self.config.max_conn_lifetime)) {
            const bucket = self.buckets.get(conn.origin());
            self.unlinkIdleLocked(conn);
            to_destroy.append(&conn.global_idle_node);
            if (bucket) |b| self.maybeReclaimBucketLocked(b);
            pruned += 1;
        }
    }
    return pruned;
}

/// Returns a point-in-time snapshot of pool counts (useful for diagnostics and tests).
pub fn stats(self: *Pool) Stats {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    var in_flight: usize = 0;
    var it = self.buckets.valueIterator();
    while (it.next()) |bucket_ptr| {
        in_flight += bucket_ptr.*.in_flight;
    }
    return .{
        .total_idle = self.total_idle,
        .total_in_flight = in_flight,
        .origin_count = self.buckets.count(),
    };
}

fn connectOptions(self: *Pool) Connection.ConnectOptions {
    return .{
        .io = self.io,
        .tls = self.config.tls orelse .{ .system = &self.ca_store },
        .proxy = self.config.proxy,
        .address_filter = self.config.address_filter,
        .read_buffer_size = self.config.read_buffer_size,
        .write_buffer_size = self.config.write_buffer_size,
    };
}

fn bucketOriginFor(self: *const Pool, target_origin: http.Origin) http.Origin {
    if (target_origin.scheme == .http) {
        if (self.config.proxy) |p| {
            if (!p.bypasses(target_origin)) {
                return .{
                    .scheme = .http,
                    .host = p.host,
                    .port = p.port,
                };
            }
        }
    }
    return target_origin;
}

fn openExchangeImpl(ptr: *anyopaque, req: Transport.ExchangeRequest) anyerror!Transport.Exchange {
    const self: *Pool = @ptrCast(@alignCast(ptr));
    const ex = try PoolExchange.create(self, req);
    return ex.handle();
}

fn acquireConnection(
    self: *Pool,
    target_origin: http.Origin,
    connect_timeout: zio.Timeout,
    skip_idle: bool,
) !*Connection {
    return zio.withTimeout(connect_timeout, acquireConnectionInner, .{ self, target_origin, skip_idle });
}

fn acquireConnectionInner(self: *Pool, target_origin: http.Origin, skip_idle: bool) !*Connection {
    var expired: std.DoublyLinkedList = .{};
    defer destroyList(self.gpa, &expired);

    const bucket_origin = self.bucketOriginFor(target_origin);

    try self.mutex.lock();
    var mutex_held = true;
    defer if (mutex_held) self.mutex.unlock();

    if (self.closed) return error.PoolClosed;

    const bucket = try self.getOrCreateBucketLocked(bucket_origin);

    while (self.config.max_conns_per_origin > 0 and bucket.in_flight >= self.config.max_conns_per_origin) {
        if (self.closed) {
            self.maybeReclaimBucketLocked(bucket);
            return error.PoolClosed;
        }
        bucket.waiters += 1;
        self.total_waiters += 1;
        const wait_res = bucket.cond.wait(&self.mutex);
        bucket.waiters -= 1;
        self.total_waiters -= 1;
        if (self.closed) {
            if (self.total_waiters == 0) self.closed_cond.broadcast();
            return error.PoolClosed;
        }
        wait_res catch |err| {
            self.maybeReclaimBucketLocked(bucket);
            return err;
        };
    }
    if (self.closed) {
        return error.PoolClosed;
    }

    // Reserve the concurrency slot before releasing the mutex.
    bucket.in_flight += 1;

    if (!skip_idle) {
        const now = zio.Timestamp.now(.awake);
        while (bucket.idle.popLast()) |origin_node| {
            const conn = connFromOriginNode(origin_node);
            self.global_idle.remove(&conn.global_idle_node);
            bucket.idle_count -= 1;
            self.total_idle -= 1;

            if (conn.isExpired(now, self.config.max_idle_time, self.config.max_conn_lifetime)) {
                expired.append(&conn.global_idle_node);
                continue;
            }

            conn.reused = true;
            mutex_held = false;
            self.mutex.unlock();
            return conn;
        }
    }

    // No reusable idle connection available: unlock and dial outside the mutex.
    mutex_held = false;
    self.mutex.unlock();

    // Close any expired connections before dialing so fds are freed promptly.
    destroyList(self.gpa, &expired);

    const conn = Connection.connect(self.gpa, target_origin, self.connectOptions()) catch |err| {
        self.releaseSlotUncancelable(bucket);
        return err;
    };
    return conn;
}

/// Returns a connection to the pool if eligible, or destroys it otherwise.
/// Always uses `lockUncancelable()` and closes sockets after unlocking.
fn releaseConnection(self: *Pool, conn: *Connection, reusable: bool) void {
    var to_destroy: std.DoublyLinkedList = .{};
    defer destroyList(self.gpa, &to_destroy);

    const now = zio.Timestamp.now(.awake);

    self.mutex.lockUncancelable();
    defer self.mutex.unlock();

    // Always clear any per-request read idle timeout before returning or closing.
    conn.setReadIdleTimeout(.none);

    const bucket = self.buckets.get(conn.origin()).?;
    assert(bucket.in_flight > 0);
    bucket.in_flight -= 1;
    bucket.cond.signal();

    const can_pool = reusable and
        !self.closed and
        !conn.closing and
        self.config.max_idle_conns > 0 and
        self.config.max_idle_conns_per_origin > 0 and
        !conn.isExpired(now, null, self.config.max_conn_lifetime);

    if (!can_pool) {
        to_destroy.append(&conn.global_idle_node);
        self.maybeReclaimBucketLocked(bucket);
        return;
    }

    conn.markUsed(now);

    while (bucket.idle_count >= self.config.max_idle_conns_per_origin) {
        const oldest_node = bucket.idle.popFirst().?;
        const oldest = connFromOriginNode(oldest_node);
        self.global_idle.remove(&oldest.global_idle_node);
        bucket.idle_count -= 1;
        self.total_idle -= 1;
        to_destroy.append(&oldest.global_idle_node);
    }

    while (self.total_idle >= self.config.max_idle_conns) {
        const oldest_global = self.global_idle.popFirst().?;
        const oldest = connFromGlobalNode(oldest_global);
        const oldest_bucket = self.buckets.get(oldest.origin()).?;
        oldest_bucket.idle.remove(&oldest.origin_node);
        oldest_bucket.idle_count -= 1;
        self.total_idle -= 1;
        to_destroy.append(&oldest.global_idle_node);
        if (oldest_bucket != bucket) {
            self.maybeReclaimBucketLocked(oldest_bucket);
        }
    }

    bucket.idle.append(&conn.origin_node);
    self.global_idle.append(&conn.global_idle_node);
    bucket.idle_count += 1;
    self.total_idle += 1;
}

fn releaseSlotUncancelable(self: *Pool, bucket: *OriginBucket) void {
    self.mutex.lockUncancelable();
    defer self.mutex.unlock();
    assert(bucket.in_flight > 0);
    bucket.in_flight -= 1;
    bucket.cond.signal();
    self.maybeReclaimBucketLocked(bucket);
}

/// Reclaims an `OriginBucket` as soon as it has zero active connections, zero
/// idle connections, and zero waiting coroutines — bounding bucket map memory
/// for long-lived clients that contact many distinct origins.
fn maybeReclaimBucketLocked(self: *Pool, bucket: *OriginBucket) void {
    if (bucket.in_flight != 0 or bucket.idle_count != 0 or bucket.waiters != 0) return;
    _ = self.buckets.remove(bucket.origin);
    bucket.origin.deinitOwned(self.gpa);
    self.gpa.destroy(bucket);
}

fn getOrCreateBucketLocked(self: *Pool, origin: http.Origin) Allocator.Error!*OriginBucket {
    if (self.buckets.get(origin)) |existing| return existing;

    var owned_origin = try origin.dupeOwned(self.gpa);
    errdefer owned_origin.deinitOwned(self.gpa);

    const bucket = try self.gpa.create(OriginBucket);
    errdefer self.gpa.destroy(bucket);
    bucket.* = .{ .origin = owned_origin };

    try self.buckets.put(self.gpa, bucket.origin, bucket);
    return bucket;
}

fn unlinkIdleLocked(self: *Pool, conn: *Connection) void {
    self.global_idle.remove(&conn.global_idle_node);
    if (self.buckets.get(conn.origin())) |bucket| {
        bucket.idle.remove(&conn.origin_node);
        bucket.idle_count -= 1;
    }
    self.total_idle -= 1;
}

fn connFromOriginNode(node: *std.DoublyLinkedList.Node) *Connection {
    return @alignCast(@fieldParentPtr("origin_node", node));
}

fn connFromGlobalNode(node: *std.DoublyLinkedList.Node) *Connection {
    return @alignCast(@fieldParentPtr("global_idle_node", node));
}

fn destroyList(gpa: Allocator, list: *std.DoublyLinkedList) void {
    while (list.popFirst()) |node| {
        const conn = connFromGlobalNode(node);
        conn.destroy(gpa);
    }
}

/// Heap-pinned single HTTP/1.1 exchange managed by `Pool`.
const PoolExchange = struct {
    pool: *Pool,
    conn: ?*Connection = null,
    method: http.Method,
    origin_owned: ?http.Origin = null,
    close_connection: bool,
    parse_options: h1.ParseOptions,
    connect_timeout: zio.Timeout,
    response_header_timeout: zio.Timeout,
    read_idle_timeout: zio.Timeout,

    request_sent: bool = false,
    head_received: bool = false,
    head_taken: bool = false,
    head_keep_alive: bool = false,
    head_status: ?http.Status = null,
    errored: bool = false,
    last_err: ?anyerror = null,

    /// Observability fields populated when `pool.config.trace != null`.
    started_at: zio.Timestamp = .zero,
    request_sent_at: zio.Timestamp = .zero,
    dns_ns: u64 = 0,
    tcp_ns: u64 = 0,
    tls_ns: u64 = 0,
    connect_ns: u64 = 0,
    ttfb_ns: u64 = 0,
    reused_conn: bool = false,
    proxied_conn: bool = false,
    trace_origin: ?http.Origin = null,
    trace_target: ?[]u8 = null,

    /// Saved serialized request bytes strictly when a reused connection may
    /// require a single transparent stale-connection retry on an idempotent request.
    replay_head: ?[]u8 = null,
    replay_body: ?[]u8 = null,

    chunk_write_buf: [2048]u8 = undefined,
    body_writer: h1.BodyWriter = undefined,
    has_body_writer: bool = false,

    response_head: h1.ResponseHead = undefined,
    body_read_buf: [4096]u8 = undefined,
    body_reader: h1.BodyReader = undefined,

    const vtable: Transport.Exchange.VTable = .{
        .writer = writerImpl,
        .unwrapWriteError = unwrapWriteErrorImpl,
        .receiveHead = receiveHeadImpl,
        .takeHead = takeHeadImpl,
        .reader = readerImpl,
        .unwrapReadError = unwrapReadErrorImpl,
        .deinit = deinitImpl,
    };

    fn handle(self: *PoolExchange) Transport.Exchange {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    fn create(pool: *Pool, req: Transport.ExchangeRequest) !*PoolExchange {
        const gpa = pool.gpa;
        const t_start = zio.Timestamp.now(.awake);

        const ex = try gpa.create(PoolExchange);
        ex.* = .{
            .pool = pool,
            .method = req.method,
            .close_connection = req.close_connection,
            .parse_options = req.parse_options,
            .connect_timeout = req.connect_timeout,
            .response_header_timeout = req.response_header_timeout,
            .read_idle_timeout = req.read_idle_timeout,
            .started_at = t_start,
        };
        errdefer ex.destroy();

        if (pool.config.trace != null) {
            ex.trace_origin = try req.origin.dupeOwned(gpa);
            ex.trace_target = try gpa.dupe(u8, req.target);
        }

        const framing = req.body.toRequestFraming();
        const active_proxy: ?Connection.ProxyConfig = if (pool.config.proxy) |p|
            if (p.bypasses(req.origin)) null else p
        else
            null;
        const use_plain_proxy = active_proxy != null and req.origin.scheme == .http;

        var abs_target_owned: ?[]u8 = null;
        defer if (abs_target_owned) |t| gpa.free(t);

        const wire_target: []const u8 = if (use_plain_proxy) blk: {
            abs_target_owned = try formatAbsoluteHttpTarget(gpa, req.origin, req.target);
            break :blk abs_target_owned.?;
        } else req.target;

        var proxy_headers: std.ArrayList(http.Header) = .empty;
        defer proxy_headers.deinit(gpa);
        const wire_headers: []const http.Header = if (use_plain_proxy and active_proxy.?.authorization != null) blk: {
            try proxy_headers.ensureTotalCapacity(gpa, req.headers.len + 1);
            var has_proxy_auth = false;
            for (req.headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "Proxy-Authorization")) has_proxy_auth = true;
                proxy_headers.appendAssumeCapacity(h);
            }
            if (!has_proxy_auth) {
                proxy_headers.appendAssumeCapacity(.{
                    .name = "Proxy-Authorization",
                    .value = active_proxy.?.authorization.?,
                });
            }
            break :blk proxy_headers.items;
        } else req.headers;

        const has_request_body = switch (req.body) {
            .none => false,
            .bytes => |b| b.len > 0,
            .stream_fixed => |len| len > 0,
            .stream_chunked => true,
        };
        const use_expect_continue = has_request_body and req.expect_continue_timeout != null;

        const head_spec: h1.RequestHead = .{
            .method = req.method,
            .origin = req.origin,
            .target = wire_target,
            .headers = wire_headers,
            .framing = framing,
            .close_connection = req.close_connection,
            .expect_continue = use_expect_continue,
        };

        // Pre-serialize the request head once. This validates target and headers
        // BEFORE acquiring a connection slot and also gives us exact replay bytes
        // if a reused idle connection turns out to be stale.
        var head_buf: Writer.Allocating = .init(gpa);
        defer head_buf.deinit();
        h1.writeRequestHead(&head_buf.writer, head_spec) catch |err| {
            ex.errored = true;
            ex.last_err = err;
            return err;
        };

        const can_retry = req.method.isIdempotent() and req.body.isRewindable();

        var conn = pool.acquireConnection(req.origin, req.connect_timeout, false) catch |err| {
            ex.errored = true;
            ex.last_err = err;
            return err;
        };
        ex.conn = conn;
        ex.connect_ns = zio.Timestamp.now(.awake).toNanoseconds() -| t_start.toNanoseconds();
        ex.recordConnTimings(conn);

        switch (req.body) {
            .none, .bytes => {
                const payload: []const u8 = switch (req.body) {
                    .bytes => |b| b,
                    else => "",
                };

                if (use_expect_continue) {
                    const cont_res = try sendHeadAndWaitContinue(
                        ex,
                        pool,
                        &conn,
                        req,
                        head_buf.written(),
                        can_retry,
                    );
                    switch (cont_res) {
                        .@"continue" => {
                            sendSerialized(conn, "", payload) catch |err| {
                                ex.errored = true;
                                ex.last_err = err;
                                return err;
                            };
                            ex.request_sent = true;
                            ex.request_sent_at = zio.Timestamp.now(.awake);
                        },
                        .final_head => |early_head| {
                            // Server rejected before body: skip sending body, mark non-reusable
                            // (conservative per RFC 9110 §10.1.1) and return early head directly.
                            var h = early_head;
                            h.keep_alive = false;
                            ex.request_sent = true;
                            ex.installHead(conn, h);
                            return ex;
                        },
                    }
                    return ex;
                }

                sendSerialized(conn, head_buf.written(), payload) catch |err| {
                    if (conn.reused and can_retry and isStaleConnectionError(err)) {
                        ex.conn = null;
                        pool.releaseConnection(conn, false);

                        conn = pool.acquireConnection(req.origin, req.connect_timeout, true) catch |dial_err| {
                            ex.errored = true;
                            ex.last_err = dial_err;
                            return dial_err;
                        };
                        ex.conn = conn;
                        ex.recordConnTimings(conn);
                        sendSerialized(conn, head_buf.written(), payload) catch |send_err| {
                            ex.errored = true;
                            ex.last_err = send_err;
                            return send_err;
                        };
                    } else {
                        ex.errored = true;
                        ex.last_err = err;
                        return err;
                    }
                };
                ex.request_sent = true;
                ex.request_sent_at = zio.Timestamp.now(.awake);

                // If we wrote to a reused connection, TCP send may have succeeded
                // locally into the kernel buffer even after the peer sent FIN.
                // Keep replay bytes until receiveHead() reads the first response byte.
                if (conn.reused and can_retry) {
                    ex.replay_head = try head_buf.toOwnedSlice();
                    if (payload.len > 0) {
                        ex.replay_body = try gpa.dupe(u8, payload);
                    }
                    ex.origin_owned = try req.origin.dupeOwned(gpa);
                }
            },
            .stream_fixed, .stream_chunked => {
                if (use_expect_continue) {
                    const cont_res = try sendHeadAndWaitContinue(
                        ex,
                        pool,
                        &conn,
                        req,
                        head_buf.written(),
                        false,
                    );
                    switch (cont_res) {
                        .@"continue" => {
                            ex.body_writer.init(conn.writer(), framing, &ex.chunk_write_buf);
                            ex.has_body_writer = true;
                        },
                        .final_head => |early_head| {
                            // Server short-circuited streaming upload (e.g. 401/413):
                            // install early head immediately and arm an early-rejected writer
                            // so any subsequent write fails fast with `error.EarlyResponse`.
                            var h = early_head;
                            h.keep_alive = false;
                            ex.request_sent = true;
                            ex.body_writer.initEarlyRejected(conn.writer());
                            ex.has_body_writer = true;
                            ex.installHead(conn, h);
                        },
                    }
                } else {
                    sendSerialized(conn, head_buf.written(), "") catch |err| {
                        ex.errored = true;
                        ex.last_err = err;
                        return err;
                    };
                    ex.body_writer.init(conn.writer(), framing, &ex.chunk_write_buf);
                    ex.has_body_writer = true;
                }
            },
        }

        return ex;
    }

    fn recordConnTimings(self: *PoolExchange, conn: *const Connection) void {
        self.reused_conn = conn.reused;
        self.proxied_conn = conn.proxied;
        if (conn.reused) {
            self.dns_ns = 0;
            self.tcp_ns = 0;
            self.tls_ns = 0;
        } else {
            self.dns_ns = conn.connect_timings.dns_ns;
            self.tcp_ns = conn.connect_timings.tcp_ns;
            self.tls_ns = conn.connect_timings.tls_ns;
        }
    }

    fn sendHeadAndWaitContinue(
        ex: *PoolExchange,
        pool: *Pool,
        conn_ptr: **Connection,
        req: Transport.ExchangeRequest,
        head_bytes: []const u8,
        can_retry: bool,
    ) !h1.ContinueResult {
        var conn = conn_ptr.*;
        var retried = false;

        while (true) {
            const send_res = sendSerialized(conn, head_bytes, "");
            if (send_res) |_| {
                ex.request_sent_at = zio.Timestamp.now(.awake);
                const cont = waitForContinue(
                    pool.gpa,
                    conn,
                    req.method,
                    req.parse_options,
                    req.expect_continue_timeout.?,
                ) catch |err| switch (err) {
                    // Legacy servers that ignore Expect: 100-continue -> proceed to send body.
                    error.Timeout => return .@"continue",
                    else => {
                        if (!retried and conn.reused and can_retry and isStaleConnectionError(err)) {
                            retried = true;
                            ex.conn = null;
                            pool.releaseConnection(conn, false);
                            conn = pool.acquireConnection(req.origin, req.connect_timeout, true) catch |dial_err| {
                                ex.errored = true;
                                ex.last_err = dial_err;
                                return dial_err;
                            };
                            conn_ptr.* = conn;
                            ex.conn = conn;
                            ex.recordConnTimings(conn);
                            continue;
                        }
                        ex.errored = true;
                        ex.last_err = err;
                        return err;
                    },
                };
                return cont;
            } else |err| {
                if (!retried and conn.reused and can_retry and isStaleConnectionError(err)) {
                    retried = true;
                    ex.conn = null;
                    pool.releaseConnection(conn, false);
                    conn = pool.acquireConnection(req.origin, req.connect_timeout, true) catch |dial_err| {
                        ex.errored = true;
                        ex.last_err = dial_err;
                        return dial_err;
                    };
                    conn_ptr.* = conn;
                    ex.conn = conn;
                    ex.recordConnTimings(conn);
                    continue;
                }
                ex.errored = true;
                ex.last_err = err;
                return err;
            }
        }
    }

    fn clearReplayState(self: *PoolExchange) void {
        const gpa = self.pool.gpa;
        if (self.replay_head) |b| {
            gpa.free(b);
            self.replay_head = null;
        }
        if (self.replay_body) |b| {
            gpa.free(b);
            self.replay_body = null;
        }
        if (self.origin_owned) |*o| {
            o.deinitOwned(gpa);
            self.origin_owned = null;
        }
    }

    fn destroy(self: *PoolExchange) void {
        const gpa = self.pool.gpa;

        if (self.pool.config.trace) |trace| {
            if (self.trace_origin) |orig| {
                const total_ns = zio.Timestamp.now(.awake).toNanoseconds() -| self.started_at.toNanoseconds();
                const final_err: ?anyerror = self.last_err orelse
                    if (self.head_received and self.body_reader.err != null)
                        self.body_reader.err
                    else
                        null;
                trace.record(.{
                    .method = self.method,
                    .origin = orig,
                    .target = self.trace_target orelse "/",
                    .reused_connection = self.reused_conn,
                    .proxied = self.proxied_conn,
                    .dns_ns = self.dns_ns,
                    .tcp_ns = self.tcp_ns,
                    .tls_ns = self.tls_ns,
                    .connect_ns = self.connect_ns,
                    .ttfb_ns = self.ttfb_ns,
                    .total_ns = total_ns,
                    .status = self.head_status,
                    .err = final_err,
                });
            }
        }

        if (self.trace_origin) |*orig| {
            orig.deinitOwned(gpa);
            self.trace_origin = null;
        }
        if (self.trace_target) |t| {
            gpa.free(t);
            self.trace_target = null;
        }

        self.clearReplayState();

        if (self.head_received) {
            const reusable = !self.errored and
                !self.close_connection and
                self.head_keep_alive and
                self.body_reader.isComplete();
            if (!self.head_taken) {
                self.response_head.deinit(gpa);
            }
            self.head_received = false;

            if (self.conn) |conn| {
                self.conn = null;
                self.pool.releaseConnection(conn, reusable);
            }
        } else if (self.conn) |conn| {
            self.conn = null;
            self.pool.releaseConnection(conn, false);
        }

        gpa.destroy(self);
    }

    fn installHead(self: *PoolExchange, conn: *Connection, head: h1.ResponseHead) void {
        self.ttfb_ns = zio.Timestamp.now(.awake).toNanoseconds() -| self.request_sent_at.toNanoseconds();
        self.clearReplayState();
        self.head_keep_alive = head.keep_alive;
        self.head_status = head.status;
        self.response_head = head;
        self.body_reader.init(conn.reader(), head.framing, &self.body_read_buf);
        // Apply per-read idle timeout for body streaming (cleared automatically on release).
        conn.setReadIdleTimeout(self.read_idle_timeout);
        self.head_received = true;
    }

    fn writerImpl(ptr: *anyopaque) *Writer {
        const self: *PoolExchange = @ptrCast(@alignCast(ptr));
        assert(self.has_body_writer);
        return &self.body_writer.interface;
    }

    fn unwrapWriteErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const PoolExchange = @ptrCast(@alignCast(ptr));
        if (self.has_body_writer) {
            if (self.body_writer.err) |bw_err| {
                if (bw_err != error.WriteFailed) return bw_err;
            }
        }
        if (self.conn) |conn| return conn.unwrapWriteError();
        return null;
    }

    fn receiveHeadImpl(ptr: *anyopaque) anyerror!*const h1.ResponseHead {
        const self: *PoolExchange = @ptrCast(@alignCast(ptr));
        if (self.head_received) return &self.response_head;

        var conn = self.conn orelse return error.ConnectionClosed;

        if (!self.request_sent) {
            assert(self.has_body_writer);
            self.body_writer.finish() catch |err| {
                self.errored = true;
                const unwrapped = if (err == error.WriteFailed)
                    conn.unwrapWriteError() orelse error.WriteFailed
                else
                    err;
                self.last_err = unwrapped;
                return unwrapped;
            };
            conn.flush() catch |err| {
                self.errored = true;
                self.last_err = err;
                return err;
            };
            self.request_sent = true;
            self.request_sent_at = zio.Timestamp.now(.awake);
        }

        const head = readHeadTimed(self.pool.gpa, conn, self.method, self.parse_options, self.response_header_timeout) catch |err| blk: {
            if (self.replay_head != null and isStaleConnectionError(err)) {
                const replay_head = self.replay_head.?;
                const replay_body = self.replay_body orelse "";
                const retry_origin = self.origin_owned.?;

                self.conn = null;
                self.pool.releaseConnection(conn, false);

                conn = self.pool.acquireConnection(retry_origin, self.connect_timeout, true) catch |dial_err| {
                    self.errored = true;
                    self.last_err = dial_err;
                    return dial_err;
                };
                self.conn = conn;
                self.recordConnTimings(conn);

                sendSerialized(conn, replay_head, replay_body) catch |send_err| {
                    self.errored = true;
                    self.last_err = send_err;
                    return send_err;
                };
                self.request_sent_at = zio.Timestamp.now(.awake);
                self.clearReplayState();

                break :blk readHeadTimed(self.pool.gpa, conn, self.method, self.parse_options, self.response_header_timeout) catch |retry_err| {
                    self.errored = true;
                    self.last_err = retry_err;
                    return retry_err;
                };
            }
            self.errored = true;
            self.last_err = err;
            return err;
        };

        self.installHead(conn, head);
        return &self.response_head;
    }

    fn takeHeadImpl(ptr: *anyopaque) ?h1.ResponseHead {
        const self: *PoolExchange = @ptrCast(@alignCast(ptr));
        if (!self.head_received or self.head_taken) return null;
        self.head_taken = true;
        return self.response_head;
    }

    fn readerImpl(ptr: *anyopaque) *Reader {
        const self: *PoolExchange = @ptrCast(@alignCast(ptr));
        assert(self.head_received);
        return &self.body_reader.interface;
    }

    fn unwrapReadErrorImpl(ptr: *const anyopaque) ?anyerror {
        const self: *const PoolExchange = @ptrCast(@alignCast(ptr));
        if (self.head_received) {
            if (self.body_reader.err) |br_err| {
                if (br_err != error.ReadFailed) return br_err;
            }
        }
        if (self.conn) |conn| return conn.unwrapReadError();
        return null;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *PoolExchange = @ptrCast(@alignCast(ptr));
        self.destroy();
    }
};

fn sendSerialized(conn: *Connection, head_bytes: []const u8, body_bytes: []const u8) !void {
    const w = conn.writer();
    w.writeAll(head_bytes) catch {
        return conn.unwrapWriteError() orelse error.WriteFailed;
    };
    if (body_bytes.len > 0) {
        w.writeAll(body_bytes) catch {
            return conn.unwrapWriteError() orelse error.WriteFailed;
        };
    }
    try conn.flush();
}

fn waitForContinue(
    gpa: Allocator,
    conn: *Connection,
    method: http.Method,
    opts: h1.ParseOptions,
    timeout: zio.Timeout,
) !h1.ContinueResult {
    const Op = struct {
        fn run(alloc: Allocator, c: *Connection, m: http.Method, o: h1.ParseOptions) !h1.ContinueResult {
            return h1.readContinueOrFinalHead(alloc, c.reader(), m, o) catch |err| switch (err) {
                error.ReadFailed => return c.unwrapReadError() orelse error.ReadFailed,
                else => return err,
            };
        }
    };
    return zio.withTimeout(timeout, Op.run, .{ gpa, conn, method, opts });
}

fn readHeadTimed(
    gpa: Allocator,
    conn: *Connection,
    method: http.Method,
    opts: h1.ParseOptions,
    timeout: zio.Timeout,
) !h1.ResponseHead {
    const Op = struct {
        fn run(alloc: Allocator, c: *Connection, m: http.Method, o: h1.ParseOptions) !h1.ResponseHead {
            return h1.readResponseHead(alloc, c.reader(), m, o) catch |err| switch (err) {
                error.ReadFailed => return c.unwrapReadError() orelse error.ReadFailed,
                else => return err,
            };
        }
    };
    return zio.withTimeout(timeout, Op.run, .{ gpa, conn, method, opts });
}

fn formatAbsoluteHttpTarget(gpa: Allocator, origin: http.Origin, target: []const u8) ![]u8 {
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();

    const path = if (target.len == 0) "/" else target;
    try out.writer.writeAll("http://");
    try origin.writeHostHeader(&out.writer);
    try out.writer.writeAll(path);
    return out.toOwnedSlice();
}

fn isStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.EndOfStream,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        => true,
        else => false,
    };
}

// ===========================================================================
// Concurrency, Backpressure, Stale-Retry & Fault-Injection Tests
// ===========================================================================

const MockServer = @import("testing/MockServer.zig");

test "Pool reuses keep-alive connections and enforces max_conns_per_origin backpressure" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const Counter = struct {
        accepted: std.atomic.Value(usize) = .init(0),
        active: std.atomic.Value(usize) = .init(0),
        peak_active: std.atomic.Value(usize) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = self.accepted.fetchAdd(1, .monotonic);

            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }

                const cur = self.active.fetchAdd(1, .acq_rel) + 1;
                var prev = self.peak_active.load(.acquire);
                while (cur > prev) {
                    prev = self.peak_active.cmpxchgWeak(prev, cur, .acq_rel, .acquire) orelse break;
                }

                zio.sleep(.fromMilliseconds(15)) catch {
                    _ = self.active.fetchSub(1, .acq_rel);
                    return;
                };
                _ = self.active.fetchSub(1, .acq_rel);

                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var counter: Counter = .{};
    var srv: MockServer = undefined;
    try srv.start(&counter, Counter.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{
        .max_conns_per_origin = 3,
        .max_idle_conns = 8,
        .max_idle_conns_per_origin = 3,
    });
    defer pool.deinit();

    const Worker = struct {
        fn run(p: *Pool, origin: http.Origin, alloc: Allocator) !void {
            const tr = p.transport();
            var ex = try tr.openExchange(.{
                .method = .GET,
                .origin = origin,
                .target = "/ping",
            });
            defer ex.deinit();

            const head = try ex.receiveHead();
            try std.testing.expectEqual(http.Status.ok, head.status);

            const body = try ex.reader().allocRemaining(alloc, .limited(64));
            defer alloc.free(body);
            try std.testing.expectEqualStrings("ok", body);
        }
    };

    var group: zio.Group = .init;
    defer group.cancel();

    // Launch 12 concurrent coroutines through a pool capped at 3 conns per origin.
    for (0..12) |_| {
        try group.spawn(Worker.run, .{ &pool, srv.origin(), gpa });
    }
    try group.wait();

    // Peak concurrent requests at the server MUST NEVER exceed max_conns_per_origin (3),
    // and total TCP connections accepted MUST be <= 3 thanks to keep-alive reuse.
    try std.testing.expect(counter.peak_active.load(.acquire) <= 3);
    try std.testing.expect(counter.accepted.load(.acquire) <= 3);

    const s = pool.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total_in_flight);
    try std.testing.expect(s.total_idle >= 1 and s.total_idle <= 3);
}

test "Pool retries stale reused connection once for GET, but NEVER retries POST" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Server serves 1 response on connection #1 and then immediately closes the socket
    // (simulating server idle timeout closing a keep-alive connection while pooled).
    const StaleServer = struct {
        conn_count: std.atomic.Value(usize) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const num = self.conn_count.fetchAdd(1, .acq_rel) + 1;

            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            // Serve exactly one request, claiming keep-alive, then close the TCP socket!
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            var resp_buf: [128]u8 = undefined;
            const resp = std.fmt.bufPrint(
                &resp_buf,
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{d}",
                .{num},
            ) catch return;
            w.interface.writeAll(resp) catch return;
            w.interface.flush() catch return;
            // Closing here makes the pooled client socket stale on its next reuse.
        }
    };

    var st: StaleServer = .{};
    var srv: MockServer = undefined;
    try srv.start(&st, StaleServer.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();
    const tr = pool.transport();

    // 1. First GET populates the pool with connection #1.
    {
        var ex = try tr.openExchange(.{ .method = .GET, .origin = srv.origin(), .target = "/a" });
        defer ex.deinit();
        _ = try ex.receiveHead();
        const body = try ex.reader().allocRemaining(gpa, .limited(16));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("1", body);
    }

    // Give the server coroutine a moment to close connection #1.
    try zio.sleep(.fromMilliseconds(20));

    // 2. Second GET picks stale connection #1, sees EOF, transparently retries on connection #2!
    {
        var ex = try tr.openExchange(.{ .method = .GET, .origin = srv.origin(), .target = "/b" });
        defer ex.deinit();
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(16));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("2", body);
    }

    try zio.sleep(.fromMilliseconds(20));

    // 3. POST picks stale connection #2 -> MUST NOT auto-retry (non-idempotent)!
    {
        var ex = try tr.openExchange(.{
            .method = .POST,
            .origin = srv.origin(),
            .target = "/orders",
            .body = .{ .bytes = "pay=100" },
        });
        defer ex.deinit();
        const res = ex.receiveHead();
        try std.testing.expect(std.meta.isError(res));
    }

    // Server must only have accepted 2 connections total (no 3rd connection dialed for POST).
    try std.testing.expectEqual(@as(usize, 2), st.conn_count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_in_flight);
}

test "Pool discards tainted connection when body is unread or response_header_timeout fires" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const FaultHandler = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [256]u8 = undefined;
            var wbuf: [256]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }

            if (std.mem.startsWith(u8, req_line, "GET /slow ")) {
                zio.sleep(.fromSeconds(5)) catch {};
                return;
            }

            w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789") catch return;
            w.interface.flush() catch return;
            zio.sleep(.fromMilliseconds(100)) catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, FaultHandler.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();
    const tr = pool.transport();

    // Case A: Caller drops Exchange without draining the 10-byte body -> MUST discard, NOT pool.
    {
        var ex = try tr.openExchange(.{ .method = .GET, .origin = srv.origin(), .target = "/unread" });
        defer ex.deinit();
        _ = try ex.receiveHead();
        // Deliberately do NOT read the body!
    }
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_idle);
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_in_flight);

    // Case B: response_header_timeout fires -> returns error.Timeout and discards connection cleanly.
    {
        var ex = try tr.openExchange(.{
            .method = .GET,
            .origin = srv.origin(),
            .target = "/slow",
            .response_header_timeout = .fromMilliseconds(30),
        });
        defer ex.deinit();
        try std.testing.expectError(error.Timeout, ex.receiveHead());
    }
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_idle);
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_in_flight);
}

test "Pool streaming chunked upload auto-finishes in receiveHead and prunes expired idle connections" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const EchoChunkedHandler = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            // Drain request headers
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            // Read chunked request body using our own h1.BodyReader!
            var bbuf: [64]u8 = undefined;
            var br: h1.BodyReader = undefined;
            br.init(&r.interface, .chunked, &bbuf);

            var out: [64]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const n = br.interface.readSliceShort(out[total..]) catch break;
                if (n == 0) break;
                total += n;
            }

            w.interface.print(
                "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ total, out[0..total] },
            ) catch return;
            w.interface.flush() catch return;
            zio.sleep(.fromMilliseconds(200)) catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, EchoChunkedHandler.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{
        .max_idle_time = .fromMilliseconds(25),
    });
    defer pool.deinit();

    {
        var ex = try pool.transport().openExchange(.{
            .method = .POST,
            .origin = srv.origin(),
            .target = "/upload",
            .body = .stream_chunked,
        });
        defer ex.deinit();
        try ex.writer().writeAll("part1-");
        try ex.writer().writeAll("part2");
        // No manual finish() required — receiveHead() auto-finishes the chunked stream!
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);

        const body = try ex.reader().allocRemaining(gpa, .limited(64));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("part1-part2", body);
    }

    try std.testing.expectEqual(@as(usize, 1), pool.stats().total_idle);

    // After exceeding max_idle_time, explicit pruneExpired() reaps the idle socket.
    try zio.sleep(.fromMilliseconds(35));
    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired());
    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_idle);
}

test "Pool routes plain HTTP through forward proxy using absolute-form target, Proxy-Authorization, and keep-alive" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const ProxyState = struct {
        accepted: std.atomic.Value(usize) = .init(0),
        saw_abs_target: std.atomic.Value(bool) = .init(false),
        saw_proxy_auth: std.atomic.Value(bool) = .init(false),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = self.accepted.fetchAdd(1, .acq_rel);

            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, req_line, "GET http://upstream.example.test:8080/hello?x=1 HTTP/1.1\r\n")) {
                    self.saw_abs_target.store(true, .release);
                }
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                    if (std.mem.eql(u8, line, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")) {
                        self.saw_proxy_auth.store(true, .release);
                    }
                }
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvia-proxy") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var st: ProxyState = .{};
    var proxy_srv: MockServer = undefined;
    try proxy_srv.start(&st, ProxyState.handle);
    defer proxy_srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{
        .proxy = .{
            .host = "127.0.0.1",
            .port = proxy_srv.port(),
            .authorization = "Basic dXNlcjpwYXNz",
        },
    });
    defer pool.deinit();

    const upstream: http.Origin = .{ .scheme = .http, .host = "upstream.example.test", .port = 8080 };

    // Send 2 requests through the proxy; both should share 1 keep-alive proxy connection.
    for (0..2) |_| {
        var ex = try pool.transport().openExchange(.{
            .method = .GET,
            .origin = upstream,
            .target = "/hello?x=1",
        });
        defer ex.deinit();
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(64));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("via-proxy", body);
    }

    try std.testing.expect(st.saw_abs_target.load(.acquire));
    try std.testing.expect(st.saw_proxy_auth.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), st.accepted.load(.acquire));
}

test "Pool establishes HTTPS CONNECT tunnel (407 rejection and 200 -> in-place TLS ClientHello upgrade)" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    // Case A: Proxy rejects CONNECT with 407 Proxy Authentication Required.
    {
        const Reject407 = struct {
            saw_connect: std.atomic.Value(bool) = .init(false),
            fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                var rbuf: [512]u8 = undefined;
                var wbuf: [512]u8 = undefined;
                var r = stream.reader(&rbuf);
                var w = stream.writer(&wbuf);

                const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, req_line, "CONNECT secret.example.test:8443 HTTP/1.1\r\n")) {
                    self.saw_connect.store(true, .release);
                }
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                w.interface.writeAll("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n") catch return;
                w.interface.flush() catch return;
            }
        };

        var st: Reject407 = .{};
        var srv: MockServer = undefined;
        try srv.start(&st, Reject407.handle);
        defer srv.stop();

        var pool = Pool.init(gpa, rt.io(), .{
            .tls = .no_verification,
            .proxy = .{ .host = "127.0.0.1", .port = srv.port() },
        });
        defer pool.deinit();

        const target: http.Origin = .{ .scheme = .https, .host = "secret.example.test", .port = 8443 };
        try std.testing.expectError(
            error.ProxyAuthRequired,
            pool.transport().openExchange(.{ .method = .GET, .origin = target }),
        );
        try std.testing.expect(st.saw_connect.load(.acquire));
    }

    // Case B: Proxy replies 200 Connection Established and verifies client immediately
    // begins a TLS handshake record (0x16 = Handshake) on the exact same TCP socket.
    {
        const TunnelVerifier = struct {
            saw_connect: std.atomic.Value(bool) = .init(false),
            saw_tls_client_hello: std.atomic.Value(bool) = .init(false),

            fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                var rbuf: [512]u8 = undefined;
                var wbuf: [512]u8 = undefined;
                var r = stream.reader(&rbuf);
                var w = stream.writer(&wbuf);

                const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, req_line, "CONNECT secret.example.test:443 HTTP/1.1\r\n")) {
                    self.saw_connect.store(true, .release);
                }
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                w.interface.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n") catch return;
                w.interface.flush() catch return;

                // First byte after 200 MUST be TLS Record Type 0x16 (Handshake / ClientHello).
                const first_tls_byte = r.interface.takeByte() catch return;
                if (first_tls_byte == 0x16) {
                    self.saw_tls_client_hello.store(true, .release);
                }
            }
        };

        var st: TunnelVerifier = .{};
        var srv: MockServer = undefined;
        try srv.start(&st, TunnelVerifier.handle);
        defer srv.stop();

        var pool = Pool.init(gpa, rt.io(), .{
            .tls = .no_verification,
            .proxy = .{ .host = "127.0.0.1", .port = srv.port() },
        });
        defer pool.deinit();

        const target: http.Origin = .{ .scheme = .https, .host = "secret.example.test", .port = 443 };
        // Proxy closes right after verifying the TLS ClientHello byte -> clean error, 0 leaks.
        const res = pool.transport().openExchange(.{ .method = .GET, .origin = target });
        try std.testing.expect(std.meta.isError(res));
        try std.testing.expect(st.saw_connect.load(.acquire));
        try std.testing.expect(st.saw_tls_client_hello.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), pool.stats().total_in_flight);
    }
}

test "Pool Trace emits per-exchange timing and connection reuse metrics" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const FastServer = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);
            while (true) {
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, FastServer.handle);
    defer srv.stop();

    const Recorder = struct {
        count: usize = 0,
        reused: [2]bool = .{ false, false },
        statuses: [2]?http.Status = .{ null, null },

        fn onExchange(ctx: ?*anyopaque, m: Transport.ExchangeMetrics) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (self.count < 2) {
                self.reused[self.count] = m.reused_connection;
                self.statuses[self.count] = m.status;
                std.debug.assert(m.err == null);
                std.debug.assert(m.total_ns >= m.ttfb_ns);
                if (m.reused_connection) {
                    std.debug.assert(m.dns_ns == 0 and m.tcp_ns == 0 and m.tls_ns == 0);
                } else {
                    std.debug.assert(m.connect_ns >= m.tcp_ns);
                }
            }
            self.count += 1;
        }
    };

    var rec: Recorder = .{};
    var pool = Pool.init(gpa, rt.io(), .{
        .trace = .{
            .ctx = &rec,
            .on_exchange = Recorder.onExchange,
        },
    });
    defer pool.deinit();

    for (0..2) |_| {
        var ex = try pool.transport().openExchange(.{
            .method = .GET,
            .origin = srv.origin(),
            .target = "/trace",
        });
        defer ex.deinit();
        _ = try ex.receiveHead();
        const body = try ex.reader().allocRemaining(gpa, .limited(32));
        defer gpa.free(body);
    }

    try std.testing.expectEqual(@as(usize, 2), rec.count);
    try std.testing.expect(!rec.reused[0]); // 1st request dialed fresh TCP
    try std.testing.expect(rec.reused[1]); // 2nd request reused keep-alive connection
    try std.testing.expectEqual(@as(?http.Status, .ok), rec.statuses[0]);
    try std.testing.expectEqual(@as(?http.Status, .ok), rec.statuses[1]);
}

test "Pool reclaims empty OriginBuckets on LRU eviction and pruneExpired" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const ProxyOk = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);
            while (true) {
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var srv1: MockServer = undefined;
    var srv2: MockServer = undefined;
    var srv3: MockServer = undefined;
    try srv1.start(null, ProxyOk.handle);
    defer srv1.stop();
    try srv2.start(null, ProxyOk.handle);
    defer srv2.stop();
    try srv3.start(null, ProxyOk.handle);
    defer srv3.stop();

    var pool = Pool.init(gpa, rt.io(), .{
        .max_idle_conns = 2,
        .max_idle_time = .fromMilliseconds(20),
    });
    defer pool.deinit();

    // Contact 3 distinct direct Origins; global LRU cap = 2 MUST evict srv1 and reclaim its empty bucket.
    const origins = [_]http.Origin{ srv1.origin(), srv2.origin(), srv3.origin() };
    for (origins) |orig| {
        var ex = try pool.transport().openExchange(.{
            .method = .GET,
            .origin = orig,
            .target = "/",
        });
        defer ex.deinit();
        _ = try ex.receiveHead();
        const body = try ex.reader().allocRemaining(gpa, .limited(16));
        defer gpa.free(body);
    }

    const s1 = pool.stats();
    try std.testing.expectEqual(@as(usize, 2), s1.total_idle);
    try std.testing.expectEqual(@as(usize, 2), s1.origin_count);

    try zio.sleep(.fromMilliseconds(30));
    try std.testing.expectEqual(@as(usize, 2), pool.pruneExpired());
    try std.testing.expectEqual(@as(usize, 0), pool.stats().origin_count);
}

test "Pool Expect: 100-continue approves body send and short-circuits early 413 rejection" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const ExpectServer = struct {
        saw_body_on_reject: std.atomic.Value(bool) = .init(false),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
            var cl: usize = 0;
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
                if (std.ascii.startsWithIgnoreCase(line, "Content-Length:")) {
                    const v = std.mem.trim(u8, line["Content-Length:".len..], " \t\r\n");
                    cl = std.fmt.parseInt(usize, v, 10) catch 0;
                }
            }

            if (std.mem.startsWith(u8, req_line, "POST /reject ")) {
                w.interface.writeAll("HTTP/1.1 413 Content Too Large\r\nContent-Length: 8\r\n\r\ntoo-big!") catch return;
                w.interface.flush() catch return;
                // Client must NOT send the body after 413.
                r.timeout = .fromMilliseconds(20);
                var probe: [1]u8 = undefined;
                if ((r.interface.readSliceShort(&probe) catch 0) > 0) {
                    self.saw_body_on_reject.store(true, .release);
                }
                return;
            }

            // Approve upload with 100 Continue, then read full body and echo length.
            w.interface.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
            w.interface.flush() catch return;

            var body_buf: [64]u8 = undefined;
            r.interface.readSliceAll(body_buf[0..cl]) catch return;
            w.interface.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ cl, body_buf[0..cl] }) catch return;
            w.interface.flush() catch return;
        }
    };

    var st: ExpectServer = .{};
    var srv: MockServer = undefined;
    try srv.start(&st, ExpectServer.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();

    // Case 1: 100 Continue approves upload
    {
        var ex = try pool.transport().openExchange(.{
            .method = .POST,
            .origin = srv.origin(),
            .target = "/ok",
            .body = .{ .bytes = "upload-payload" },
            .expect_continue_timeout = .fromSeconds(1),
        });
        defer ex.deinit();
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(64));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("upload-payload", body);
    }

    // Case 2: Early 413 rejects before client sends body
    {
        var ex = try pool.transport().openExchange(.{
            .method = .POST,
            .origin = srv.origin(),
            .target = "/reject",
            .body = .{ .bytes = "huge-unwanted-body" },
            .expect_continue_timeout = .fromSeconds(1),
        });
        defer ex.deinit();
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.content_too_large, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(64));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("too-big!", body);
    }
    try std.testing.expect(!st.saw_body_on_reject.load(.acquire));
}

test "Pool enforces per-read idle timeout against mid-body Slowloris stall" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const SlowBodyServer = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [256]u8 = undefined;
            var wbuf: [256]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            // Send valid headers + first 3 bytes of a 10-byte body, then stall!
            w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc") catch return;
            w.interface.flush() catch return;
            zio.sleep(.fromSeconds(5)) catch {};
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, SlowBodyServer.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();

    var ex = try pool.transport().openExchange(.{
        .method = .GET,
        .origin = srv.origin(),
        .target = "/drip",
        .read_idle_timeout = .fromMilliseconds(25),
    });
    defer ex.deinit();

    _ = try ex.receiveHead();
    var buf: [16]u8 = undefined;
    // First read gets the initial 3 available bytes cleanly
    const n1 = try ex.reader().readSliceShort(buf[0..3]);
    try std.testing.expectEqual(@as(usize, 3), n1);
    try std.testing.expectEqualStrings("abc", buf[0..3]);
    // Next read stalls and triggers per-read idle timeout -> error.Timeout!
    try std.testing.expectError(error.ReadFailed, ex.reader().readSliceShort(&buf));
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), ex.unwrapReadError());
}

test "Pool 48-coroutine concurrency stress with mixed fast, slow, and canceled requests" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const StressServer = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                if (std.mem.startsWith(u8, req_line, "GET /slow ")) {
                    zio.sleep(.fromMilliseconds(60)) catch return;
                }
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, StressServer.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{
        .max_conns_per_origin = 6,
        .max_idle_conns = 6,
        .max_idle_conns_per_origin = 6,
    });
    defer pool.deinit();

    const Worker = struct {
        fn run(p: *Pool, origin: http.Origin, alloc: Allocator, idx: usize) !void {
            const is_slow = (idx % 4 == 0);
            var ex = p.transport().openExchange(.{
                .method = .GET,
                .origin = origin,
                .target = if (is_slow) "/slow" else "/fast",
                .connect_timeout = .fromMilliseconds(200),
                .response_header_timeout = if (is_slow) .fromMilliseconds(15) else .fromMilliseconds(200),
            }) catch |err| switch (err) {
                error.Timeout => return,
                else => return err,
            };
            defer ex.deinit();

            _ = ex.receiveHead() catch |err| switch (err) {
                error.Timeout => return,
                else => return err,
            };
            const body = try ex.reader().allocRemaining(alloc, .limited(32));
            defer alloc.free(body);
            try std.testing.expectEqualStrings("ok", body);
        }
    };

    var group: zio.Group = .init;
    defer group.cancel();
    for (0..48) |i| {
        try group.spawn(Worker.run, .{ &pool, srv.origin(), gpa, i });
    }
    try group.wait();

    try std.testing.expectEqual(@as(usize, 0), pool.stats().total_in_flight);
}

test "Pool waiter cancel reclaims empty bucket, deinit drains waiters safely, and Reaper prunes idle conns" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const HoldServer = struct {
        accepted: std.atomic.Value(usize) = .init(0),

        fn handle(ctx: ?*anyopaque, stream: zio.net.Stream) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = self.accepted.fetchAdd(1, .acq_rel);

            var rbuf: [512]u8 = undefined;
            var wbuf: [512]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            while (true) {
                while (true) {
                    const line = r.interface.takeDelimiterInclusive('\n') catch return;
                    if (std.mem.eql(u8, line, "\r\n")) break;
                }
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch return;
                w.interface.flush() catch return;
            }
        }
    };

    var st: HoldServer = .{};
    var srv: MockServer = undefined;
    try srv.start(&st, HoldServer.handle);
    defer srv.stop();

    // 1. Plain HTTP proxy shares ONE keep-alive TCP connection across distinct target hosts!
    {
        var proxy_pool = Pool.init(gpa, rt.io(), .{
            .proxy = .{ .host = "127.0.0.1", .port = srv.port() },
        });
        defer proxy_pool.deinit();

        for ([_][]const u8{ "alpha.example.test", "beta.example.test", "gamma.example.test" }) |host| {
            var ex = try proxy_pool.transport().openExchange(.{
                .method = .GET,
                .origin = .{ .scheme = .http, .host = host, .port = 80 },
                .target = "/ping",
            });
            defer ex.deinit();
            _ = try ex.receiveHead();
            const body = try ex.reader().allocRemaining(gpa, .limited(16));
            defer gpa.free(body);
            try std.testing.expectEqualStrings("ok", body);
        }
        try std.testing.expectEqual(@as(usize, 1), st.accepted.load(.acquire));
        try std.testing.expectEqual(@as(usize, 1), proxy_pool.stats().origin_count);
    }

    // 2. Canceled waiter reclaims empty bucket + Reaper automatically prunes expired idle conns
    {
        var pool = Pool.init(gpa, rt.io(), .{
            .max_conns_per_origin = 1,
            .max_idle_conns = 1,
            .max_idle_time = .fromMilliseconds(20),
        });
        defer pool.deinit();

        var reaper = try pool.startReaper(.fromMilliseconds(10));
        defer reaper.stop();

        // Hold the sole slot with close_connection=true so releasing does not pool it.
        var ex1 = try pool.transport().openExchange(.{
            .method = .GET,
            .origin = srv.origin(),
            .target = "/",
            .close_connection = true,
        });

        // Spawn a second request that parks on bucket.cond and times out after 15ms.
        const Waiter = struct {
            err: ?anyerror = null,
            fn run(self: *@This(), p: *Pool, orig: http.Origin) void {
                var ex2 = p.transport().openExchange(.{
                    .method = .GET,
                    .origin = orig,
                    .target = "/",
                    .connect_timeout = .fromMilliseconds(15),
                }) catch |err| {
                    self.err = err;
                    return;
                };
                ex2.deinit();
            }
        };
        var w_state: Waiter = .{};
        var h = try zio.spawn(Waiter.run, .{ &w_state, &pool, srv.origin() });
        try zio.sleep(.fromMilliseconds(5));
        // Release ex1 BEFORE waiter wakes from timeout so waiter cancel is last owner check:
        // Wait until waiter times out while ex1 is held, then drop ex1 -> bucket MUST be reclaimed!
        h.join();
        try std.testing.expectEqual(@as(?anyerror, error.Timeout), w_state.err);
        ex1.deinit();
        try std.testing.expectEqual(@as(usize, 0), pool.stats().origin_count);

        // Now open a keep-alive request and let background Reaper auto-prune it!
        {
            var ex3 = try pool.transport().openExchange(.{
                .method = .GET,
                .origin = srv.origin(),
                .target = "/",
            });
            defer ex3.deinit();
            _ = try ex3.receiveHead();
            const body = try ex3.reader().allocRemaining(gpa, .limited(16));
            defer gpa.free(body);
        }
        try std.testing.expectEqual(@as(usize, 1), pool.stats().total_idle);
        try zio.sleep(.fromMilliseconds(50));
        try std.testing.expectEqual(@as(usize, 0), pool.stats().total_idle);
        try std.testing.expectEqual(@as(usize, 0), pool.stats().origin_count);
    }

    // 3. Pool.close() + Pool.deinit() safely wakes parked waiters with error.PoolClosed (zero UAF)
    {
        var pool = Pool.init(gpa, rt.io(), .{
            .max_conns_per_origin = 1,
            .max_idle_conns = 0,
        });

        var ex_hold = try pool.transport().openExchange(.{
            .method = .GET,
            .origin = srv.origin(),
            .target = "/",
            .close_connection = true,
        });

        const Parked = struct {
            err: ?anyerror = null,
            fn run(self: *@This(), p: *Pool, orig: http.Origin) void {
                var ex = p.transport().openExchange(.{
                    .method = .GET,
                    .origin = orig,
                    .target = "/",
                }) catch |err| {
                    self.err = err;
                    return;
                };
                ex.deinit();
            }
        };
        var parked: Parked = .{};
        var h = try zio.spawn(Parked.run, .{ &parked, &pool, srv.origin() });
        try zio.sleep(.fromMilliseconds(10));

        // Close pool while parked waiter is blocked on bucket.cond -> wakes with error.PoolClosed!
        pool.close();
        h.join();
        try std.testing.expectEqual(@as(?anyerror, error.PoolClosed), parked.err);

        ex_hold.deinit();
        pool.deinit();
    }
}

test "Pool Expect: 100-continue works for streaming chunked uploads (100 approve & 413 early reject)" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    const StreamExpectServer = struct {
        fn handle(_: ?*anyopaque, stream: zio.net.Stream) void {
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = stream.reader(&rbuf);
            var w = stream.writer(&wbuf);

            const req_line = r.interface.takeDelimiterInclusive('\n') catch return;
            while (true) {
                const line = r.interface.takeDelimiterInclusive('\n') catch return;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }

            if (std.mem.startsWith(u8, req_line, "PUT /deny ")) {
                w.interface.writeAll(
                    "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndeny",
                ) catch return;
                w.interface.flush() catch return;
                return;
            }

            // Approve streaming upload with 100 Continue, read chunked body until 0\r\n\r\n
            w.interface.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
            w.interface.flush() catch return;

            var br: h1.BodyReader = undefined;
            var bbuf: [512]u8 = undefined;
            br.init(&r.interface, .chunked, &bbuf);
            var total: usize = 0;
            var tmp: [256]u8 = undefined;
            while (true) {
                const n = br.interface.readSliceShort(&tmp) catch return;
                if (n == 0) break;
                total += n;
            }

            w.interface.print(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{d}",
                .{total},
            ) catch return;
            w.interface.flush() catch return;
        }
    };

    var srv: MockServer = undefined;
    try srv.start(null, StreamExpectServer.handle);
    defer srv.stop();

    var pool = Pool.init(gpa, rt.io(), .{});
    defer pool.deinit();

    // Case 1: Server approves with 100 Continue -> stream chunked upload succeeds
    {
        var ex = try pool.transport().openExchange(.{
            .method = .PUT,
            .origin = srv.origin(),
            .target = "/allow",
            .body = .stream_chunked,
            .expect_continue_timeout = .fromMilliseconds(500),
        });
        defer ex.deinit();

        try ex.writer().writeAll("hello ");
        try ex.writer().writeAll("world!"); // 12 bytes total
        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.ok, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(32));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("12", body);
    }

    // Case 2: Server rejects early with 413 -> writer() fails fast with error.EarlyResponse,
    // and receiveHead() returns the 413 response cleanly!
    {
        var ex = try pool.transport().openExchange(.{
            .method = .PUT,
            .origin = srv.origin(),
            .target = "/deny",
            .body = .stream_chunked,
            .expect_continue_timeout = .fromMilliseconds(500),
        });
        defer ex.deinit();

        try std.testing.expectError(error.WriteFailed, ex.writer().writeAll("should not send"));
        try std.testing.expectEqual(@as(?anyerror, error.EarlyResponse), ex.unwrapWriteError());

        const head = try ex.receiveHead();
        try std.testing.expectEqual(http.Status.content_too_large, head.status);
        const body = try ex.reader().allocRemaining(gpa, .limited(32));
        defer gpa.free(body);
        try std.testing.expectEqualStrings("deny", body);
    }
}
