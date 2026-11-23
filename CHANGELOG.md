# Changelog

All notable changes to Kite are documented in this file.

## [0.2.0] - 2026-11-23

### Added
- **Server-Sent Events (`kite.sse`)**:
  - Sans-IO WHATWG §9.2 `text/event-stream` incremental `sse.Reader` with SIMD slice scanning, stream-start UTF-8 BOM stripping, split CRLF/CR/LF handling, and `max_line_bytes` / `max_event_bytes` OOM caps.
  - High-level `sse.Stream` supporting GET and POST+body (LLM token streams & MCP Streamable HTTP), `Content-Type` validation, `204 No Content` clean termination, `Last-Event-ID` + `retry:` auto-reconnect, transient `429`/`502`/`503`/`504` `Retry-After` recovery, and `rejected_status` diagnostics.
- **Full-Duplex WebSocket Client (`kite.ws`)**:
  - RFC 6455 client supporting `ws://`, `wss://`, and `ws+unix://` via `ws.connect` and `ws.connectWithClient` (inheriting CA store, proxy, UDS, SSRF `AddressFilter`, and `CookieJar`).
  - Zero-loss HTTP/1.1 `101 Switching Protocols` handoff preserving piggybacked leftover bytes, handshake redirects, subprotocol validation, `rejected_status` diagnostics, `read_idle_timeout`, `sendFragmented`, concurrent write mutex, fragmented UTF-8 reassembly, interleaved Ping/auto-Pong, and IANA `1012`/`1013`/`1014` close codes.
  - RFC 7692 `permessage-deflate` bidirectional compression (`client_no_context_takeover; server_no_context_takeover`) with lazily heap-allocated workspace (protects `zio`'s 256 KiB coroutine stacks), Zip Bomb decompression cap, and 64 KiB incremental frame reads against memory-amplification DoS.
- **Unix Domain Socket Support**:
  - `http+unix://<percent-encoded-path>/...` URL routing with case-sensitive path pooling and default `Host: localhost`.
  - Explicit `Pool.Config.unix_socket_path` / `Connection.ConnectOptions.unix_socket_path` preserving logical URL `Host` headers and Keep-Alive reuse.
  - Security guard blocking network `http://`/`https://` 3xx redirects to `http+unix://` (`error.UnixSocketRedirectBlocked`).
- **Proxy Extensions (SOCKS5 / SOCKS5h & HTTPS TLS-to-Proxy)**:
  - `ProxyConfig.Scheme` supporting `.http`, `.https`, `.socks5`, and `.socks5h` with full `ProxyConfig.fromEnv()` parsing.
  - RFC 1928 + RFC 1929 SOCKS5/SOCKS5h handshakes (remote DNS via `ATYP=0x03`, local DNS with `AddressFilter`, zero `Proxy-Authorization` header leakage).
  - HTTPS TLS-to-Proxy support for plain HTTP targets (single outer TLS), `ws://` CONNECT tunnels over outer TLS, and HTTPS targets via single-allocation heap-pinned double-TLS `TunnelTls`.
- **Composable `Transport` Middlewares**:
  - `CacheTransport`: RFC 9111 private in-memory HTTP cache (`Cache-Control` `max-age`/`no-store`/`no-cache`/`only-if-cached`, `Expires`/`Date`/`Age`, multi-variant `Vary` buckets with empty-bucket reclamation, `ETag`/`Last-Modified` `304` revalidation, unsafe-method + `Location`/`Content-Location` invalidation, LRU caps, EOF-only commit).
  - `CircuitBreakerTransport`: per-origin 3-state circuit breaker (`closed` / `open` / `half_open`) with concurrent probe limits, cancel-safe slot release, LRU origin bounds, lock-free `StateChangeHook`, and fail-fast synergy with `RetryTransport`.
- **Examples**:
  - New offline runnable examples (`example-sse`, `example-websocket`, `example-middleware`, `example-uds`, plus expanded SOCKS5h coverage in `example-proxy`).

## [0.1.0] - 2026-11-23

### Added
- Initial production-hardened async HTTP/1.1 client for Zig `0.17.1` + `zio` `v0.20.1`:
  - Core modules: `http`, `h1`, `Transport`, `Connection`, `Pool`, `Client`.
  - Extensions: `RetryTransport` (+ `RetryBudget`), `CookieJar` (RFC 6265), `multipart` (`Builder` + `StreamWriter`), HTTP forward / `CONNECT` proxy (`NO_PROXY` + `fromEnv`), `Trace` timing hooks, Happy Eyeballs, SSRF `AddressFilter`, and 10 runnable examples.
