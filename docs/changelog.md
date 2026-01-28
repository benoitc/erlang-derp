# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/benoitc/erlang-derp/releases/tag/v0.1.0
