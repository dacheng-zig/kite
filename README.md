# Kite — Async HTTP/1.1 Client for Zig 0.17

> Powered by [`zio`](https://github.com/lalinsky/zio) (`v0.20.1`) · MIT License

## Why Kite

Compared to using `std.http.Client` directly in Zig 0.17, Kite focuses on **production connection governance, coroutine safety, and clean DX**:

- **Ergonomic 3-line common path**: `client.get(url)` / `client.postJson(...)` handles redirects, transparent decompression, body size caps, and zero-copy response ownership — no manual 64 KiB `decompress_buffer` or `redirect_buffer` boilerplate.
- **Coroutine-stack safe by design**: `Connection` packs all socket & TLS buffers into a single heap-pinned allocation and allocates decompression windows on the heap only when needed, protecting `zio`'s 256 KiB default coroutine stacks.
- **Production pool governance**: per-origin concurrency capping with cancelable async queuing, LIFO reuse / LRU eviction, automatic empty-bucket reclamation (prevents OOM across unbounded domains), `max_idle_time` + `max_conn_lifetime` (handles DNS rotations), and transparent 1-time stale-connection retry strictly for idempotent requests.
- **Clean `Transport` extension seam**: swap `Pool` for offline `MockTransport` in tests or wrap it with `RetryTransport` / custom decorators without touching `Client`.

## Features

- **Spec-compliant HTTP/1.1** (RFC 9110 / RFC 9112): standard + custom extension `Method` (`.custom("PURGE")`), fixed `Content-Length`, `Transfer-Encoding: chunked` (extensions & trailers), `1xx` skipping, `Expect: 100-continue` (for both buffered and streaming uploads, with early rejection short-circuit), CRLF injection & response-smuggling protection.
- **HTTPS & Networking**: TLS 1.2 / 1.3 via `std.crypto.tls.Client` with SNI, lazily loaded system root CAs (`reloadSystem()`), custom PEM CA loading (`addCertsFromPem` / `addCertsFromFile`), RFC 8305 **Happy Eyeballs** dual-stack racing, and post-DNS `AddressFilter` (`Connection.blockPrivateAddresses()` for SSRF protection).
- **Timeouts, Pool & Cancellation**: scoped `connect_timeout`, `response_header_timeout`, `default_timeout` (honored by `fetch()` and `open()`/`receiveHead()`), per-read `read_idle_timeout` (Slowloris protection), graceful `Pool.close()`, optional background `Pool.startReaper()`, and cancel-safe `lockUncancelable` cleanup.
- **High-Level Semantics**: dual `fetch()` / streaming `open()` API, automatic redirects (`301`/`302`/`303`/`307`/`308`, RFC 3986 resolution, cross-origin credential stripping, `CheckRedirect` hook), transparent `gzip` / lazy-probed `deflate` (zlib + raw) / checksum-verified `zstd` decompression (`Response.decompressed` + header cleanup + keep-alive chunk-terminator draining), JSON / Form / Basic & Bearer Auth helpers.
- **Composable Extensions**:
  - `RetryTransport`: idempotent retry (`408`/`429`/`502`/`503`/`504` + transient socket/DNS errors), `Retry-After` (delay-seconds & HTTP-date), jittered exponential backoff, and optional `RetryBudget` storm guard.
  - `CookieJar`: coroutine-safe, domain-indexed RFC 6265 cookies (`O(labels)` lookup) with host-only isolation, `Secure` gating, `Max-Age` precedence, capacity limits, public-suffix blocking + `is_public_suffix` hook, inspect/remove API, and JSON persistence (`exportJsonAlloc` / `importJson`).
  - `multipart`: in-memory `Builder` and constant-memory `StreamWriter` (RFC 7578) for multi-GB uploads.
  - **Proxy & Observability**: HTTP plain forward proxy (pooled by proxy origin) + HTTPS `CONNECT` tunnel + `NO_PROXY` rules + `ProxyConfig.fromEnv()`, plus zero-allocation `Trace` timing hooks (`dns_ns` / `tcp_ns` / `tls_ns` / `connect_ns` / `ttfb_ns` / `total_ns` / `reused_connection`).

## Quick Start

```zig
const std = @import("std");
const zio = @import("zio");
const kite = @import("kite");

pub fn main(init: std.process.Init) !void {
    const rt = try zio.Runtime.init(init.gpa, .{});
    defer rt.deinit();

    var client = kite.Client.init(init.gpa, rt.io(), .{});
    defer client.deinit();

    var res = try client.get("https://example.com");
    defer res.deinit();

    std.debug.print("{d} {s} ({d} bytes)\n", .{ res.status.code(), res.reason, res.body.len });
}
```

## Examples

Run `zig build test` for the full offline test suite (51 tests incl. `std.testing.fuzz` & 48-coroutine concurrency stress, 0 memory leaks), `zig build examples` to compile all examples, or run any example directly:

| Example | Command | Highlights |
| --- | --- | --- |
| [examples/get.zig](examples/get.zig) | `zig build example-get -- [url]` | Minimal HTTPS GET, TLS verification, transparent gzip decode |
| [examples/json_api.zig](examples/json_api.zig) | `zig build example-json -- [url]` | `postJson`, `Response.json`, Bearer auth, RFC 3986 form/query encoding |
| [examples/stream.zig](examples/stream.zig) | `zig build example-stream -- [url]` | Streaming download (`open` + fixed 4 KiB buffer) |
| [examples/upload.zig](examples/upload.zig) | `zig build example-upload -- [url]` | Streaming chunked upload (`stream_chunked` + auto-finish `receiveHead`) |
| [examples/multipart.zig](examples/multipart.zig) | `zig build example-multipart -- [url]` | RFC 7578 `multipart/form-data` text fields + binary file upload |
| [examples/concurrent.zig](examples/concurrent.zig) | `zig build example-concurrent -- [url]` | `zio.Group` concurrency, per-origin cap, Keep-Alive pool stats |
| [examples/custom_transport.zig](examples/custom_transport.zig) | `zig build example-transport -- [url]` | Custom `Transport` decorator, redirect inspection, per-request timeout |
| [examples/retry_and_trace.zig](examples/retry_and_trace.zig) | `zig build example-retry` | `RetryTransport` (`503`/`429` + `Retry-After`) + `Trace` timing metrics (offline) |
| [examples/cookies.zig](examples/cookies.zig) | `zig build example-cookies` | RFC 6265 `CookieJar` login-redirect session & `Max-Age=0` logout (offline) |
| [examples/proxy.zig](examples/proxy.zig) | `zig build example-proxy` | HTTP forward proxy (`ProxyConfig` + `Proxy-Authorization`, offline) |

## Known Limitations & Non-Goals

- **HTTP/1.1 only**: HTTP/2 (RFC 9113) and HTTP/3 / QUIC are not implemented. In particular, Zig `0.17.1`'s `std.crypto.tls.Client` does not yet expose TLS ALPN negotiation required for `h2`.
- **TLS capabilities (upstream Zig `std.crypto.tls.Client` limits)**: mTLS client certificates and TLS session resumption (0-RTT) are not supported by Zig `0.17.1`'s standard TLS client.
- **No Brotli (`br`) decoding**: Zig `0.17.1` `std.compress` does not include a Brotli decoder, so Kite advertises `Accept-Encoding: gzip, deflate, zstd`.
- **Proxy protocols**: supports HTTP forward proxies (`http://`) and HTTPS `CONNECT` tunneling with `NO_PROXY`; TLS-to-proxy (`https://` proxy servers) and SOCKS5 are not yet supported.
- **Cookie Public Suffix List**: `CookieJar` blocks single-label TLDs and a built-in table of common multi-label public suffixes (`co.uk`, `com.cn`, `github.io`, etc.); applications needing the full Mozilla PSL should supply `CookieJar.Limits.is_public_suffix`.
