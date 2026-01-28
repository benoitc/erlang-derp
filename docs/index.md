# DERP - Designated Encrypted Relay for Packets

An Erlang implementation of Tailscale's DERP relay protocol, providing secure packet relay when direct WireGuard connections aren't possible.

## Overview

DERP (Designated Encrypted Relay for Packets) is a relay protocol used by Tailscale to route encrypted WireGuard packets when direct peer-to-peer connections cannot be established due to NAT, firewalls, or other network restrictions.

This implementation provides:

- **DERP Server**: TLS-based relay server with WebSocket support
- **DERP Client**: Erlang client library for connecting to DERP servers
- **BoringSSL TLS**: NIF-based TLS transport that handles Tailscale's non-conforming certificates
- **Full Protocol Support**: Complete implementation of the DERP frame protocol

## Features

### Protocol Implementation

- Frame-based binary protocol: `[1B type][4B length][payload]`
- Magic header: `DERP🔑` (8 bytes)
- NaCl box encryption: Curve25519 + XSalsa20 + Poly1305
- Maximum packet size: 65,536 bytes
- Keep-alive interval: 60 seconds

### Server Features

- TLS transport with configurable certificates
- WebSocket support for HTTP proxy traversal
- Token bucket rate limiting per client
- O(1) client lookup via ETS registry
- Graceful handling of client disconnects
- Peer gone notifications

### Client Features

- Automatic reconnection with configurable backoff
- Both synchronous and asynchronous receive modes
- Keep-alive management
- BoringSSL TLS backend (default) with OTP ssl fallback

### TLS Transport

- BoringSSL NIF with Memory BIOs and `enif_select` for non-blocking I/O
- Handles Tailscale's self-signed certificates with long CommonNames
- Crypto-heavy operations run on dirty schedulers (CPU and IO)
- Transparent transport abstraction alongside OTP ssl and gen_tcp

### Security

- NaCl box encryption for handshake (via libsodium NIF)
- BoringSSL for transport encryption (via TLS NIF)
- Client authentication during handshake
- Rate limiting to prevent abuse
- No packet inspection (end-to-end encrypted)

## Platform Support

| Platform | Architectures |
|----------|---------------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| FreeBSD | amd64, arm64 |

**Requirements:**

- Erlang/OTP 26+ (27 recommended)
- libsodium
- CMake 3.14+, Ninja, C++ compiler, Perl (for BoringSSL build)

## Quick Links

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Server Configuration](guide/server.md)
- [Client Usage](guide/client.md)
- [TLS with BoringSSL](guide/tls.md)
- [Protocol Reference](reference/protocol.md)

## License

MIT License - See [LICENSE](https://github.com/benoitc/erlang-derp/blob/main/LICENSE) file for details.

## Credits

Based on Tailscale's DERP protocol specification.
