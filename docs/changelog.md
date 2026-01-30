# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-29

### Added

- **BoringSSL TLS NIF**: Non-blocking TLS transport using BoringSSL via Memory BIOs and `enif_select`
  - Bypasses OTP ssl's rejection of Tailscale DERP certificates (CommonName > 64 chars)
  - Dirty NIF scheduling: handshake on dirty CPU, I/O operations on dirty IO schedulers
  - NIF resource lifecycle with automatic cleanup (SSL_free, close fd)
  - `derp_tls` high-level API: connect, accept, send, recv, activate, close
  - `derp_tls_nif` low-level NIF wrapper with 20 functions
  - Windows portability via `#ifdef _WIN32` for Winsock API
- **Native TLS server API**: `derp_tls:listen/2` and `derp_tls:accept_connection/3,4`
  - NIF owns entire socket lifecycle (listen → accept → close)
  - Eliminates fd handoff between gen_tcp and NIF
  - Fixes OTP 27 compatibility issues with enif_select
  - Old `accept/2,3` API deprecated but still works
- **TLS backend selection**: `tls_backend => boringssl | otp` option for client and server
  - BoringSSL is the default; OTP ssl available as fallback
  - Transport abstraction: `derp_tls` alongside `ssl` and `gen_tcp` in gen_statem
- **Automatic HTTP upgrade**: TLS connections always perform HTTP upgrade to DERP protocol
  - Sends `GET /derp HTTP/1.1` with `Upgrade: DERP` header
  - Parses HTTP 101 response and transitions to DERP handshake
  - Handles buffered data after HTTP upgrade via internal gen_statem event
  - Upgrade path configurable via `http_path` option (default: `/derp`)
- **Integration tests**: 8 tests against `derp1.tailscale.com` via BoringSSL
- **TLS unit tests**: 22 NIF smoke tests + loopback TLS tests
- **Event callbacks**: `set_event_callback/2` for server events (health, restarting, peer_gone, peer_present)
- **CI**: Multi-platform testing (Ubuntu, macOS ARM64, FreeBSD)

### Fixed

- **TLS large payload data loss**: `flush_wbio()` now buffers unsent data when socket returns EAGAIN
  - Added `pending_write` buffer to preserve data consumed from BIO but not yet sent
  - Added `flush/1` NIF to continue flushing after `want_write`
- **OTP 27 compatibility**: Native listen/accept eliminates enif_select conflicts with BEAM socket handling

### Dependencies

- BoringSSL (built from source in `c_src/boringssl/`, not committed)

## [0.1.0] - 2026-01-28

### Added

- **DERP Server**: Full implementation of Tailscale's DERP relay server
  - TLS transport with configurable certificates
  - WebSocket support via Cowboy for HTTP proxy traversal
  - Token bucket rate limiting per client
  - O(1) client lookup via ETS registry
  - Graceful handling of client disconnects
  - Peer gone notifications

- **DERP Client**: Erlang client library for connecting to DERP servers
  - Automatic reconnection with configurable backoff
  - Synchronous and asynchronous receive modes
  - Keep-alive management
  - TLS with configurable options
  - Callback-based message handling

- **Protocol Implementation**: Complete DERP frame protocol
  - Frame-based binary protocol: `[1B type][4B length][payload]`
  - Magic header: `DERP🔑` (8 bytes)
  - All standard frame types (ServerKey, ClientInfo, ServerInfo, SendPacket, RecvPacket, KeepAlive, Ping, Pong, PeerGone, etc.)
  - Maximum packet size: 65,536 bytes
  - Keep-alive interval: 60 seconds

- **Cryptography**: NaCl box encryption via libsodium NIF
  - Curve25519 keypair generation
  - XSalsa20-Poly1305 authenticated encryption
  - Cryptographically secure random bytes
  - Custom minimal NIF for only required operations

- **Docker Support**
  - Multi-platform Docker image (linux/amd64, linux/arm64)
  - Docker Compose configuration for easy deployment
  - Two-client simulation for testing relay functionality
  - Escript-based test client for interactive testing

- **Testing**
  - Comprehensive EUnit tests
  - Common Test integration tests
  - Dialyzer type checking
  - Xref cross-reference analysis

### Dependencies

- Erlang/OTP 26+ (27 recommended)
- Cowboy 2.12.0 (HTTP/WebSocket server)
- JSX 3.1.0 (JSON encoding/decoding)
- libsodium (NaCl cryptographic operations)

[0.2.0]: https://github.com/benoitc/erlang-derp/releases/tag/v0.2.0
[0.1.0]: https://github.com/benoitc/erlang-derp/releases/tag/v0.1.0
