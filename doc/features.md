# DERP - Designated Encrypted Relay for Packets

An Erlang implementation of Tailscale's DERP relay protocol, providing secure packet relay when direct WireGuard connections aren't possible.

## Overview

DERP (Designated Encrypted Relay for Packets) is a relay protocol used by Tailscale to route encrypted WireGuard packets when direct peer-to-peer connections cannot be established due to NAT, firewalls, or other network restrictions.

This implementation provides:
- **DERP Server**: TLS-based relay server with WebSocket support
- **DERP Client**: Erlang client library for connecting to DERP servers
- **Full Protocol Support**: Complete implementation of the DERP frame protocol

## Features

### Protocol Implementation

- **Frame-based binary protocol**: `[1B type][4B length][payload]`
- **Magic header**: `DERP🔑` (8 bytes)
- **NaCl box encryption**: Curve25519 + XSalsa20 + Poly1305
- **Maximum packet size**: 65,536 bytes
- **Keep-alive interval**: 60 seconds

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
- TLS with configurable options

### Security

- NaCl box encryption for handshake (via libsodium NIF)
- Client authentication during handshake
- Rate limiting to prevent abuse
- No packet inspection (end-to-end encrypted)

## Architecture

```
src/
├── derp.app.src / derp_app.erl / derp_sup.erl   # Application skeleton
├── derp.hrl                                      # Protocol constants
├── derp_frame.erl                                # Frame encode/decode
├── derp_sodium.erl                               # NIF wrapper for libsodium
├── derp_crypto.erl                               # High-level crypto API
├── derp_registry.erl                             # ETS client registry
├── derp_rate_limiter.erl                         # Token bucket rate limiter
├── derp_conn.erl                                 # Server connection handler
├── derp_server.erl / derp_server_sup.erl         # TLS listener
├── derp_client.erl / derp_client_sup.erl         # Client state machine
└── derp_ws_handler.erl                           # WebSocket handler
```

## Usage

### Starting the Server

```erlang
%% Start with default options
{ok, _} = application:ensure_all_started(derp).

%% Or start manually with custom options
{ok, Pid} = derp_server:start_link(#{
    port => 443,
    certfile => "path/to/cert.pem",
    keyfile => "path/to/key.pem"
}).

%% Get server's public key
PubKey = derp_server:get_public_key().
```

### Using the Client

```erlang
%% Connect to a DERP server
{ok, Client} = derp_client:start_link(#{
    host => "derp.example.com",
    port => 443,
    reconnect => true
}).

%% Send a packet to a peer
ok = derp_client:send(Client, PeerPublicKey, <<"encrypted data">>).

%% Receive a packet (synchronous)
{ok, SrcKey, Data} = derp_client:recv(Client, 5000).

%% Or use async callback
derp_client:set_callback(Client, fun(SrcKey, Data) ->
    io:format("Received from ~p: ~p~n", [SrcKey, Data])
end).
```

### Frame Types

| Type | Name | Description |
|------|------|-------------|
| 0x01 | ServerKey | Server's public key (sent on connect) |
| 0x02 | ClientInfo | Client's encrypted info |
| 0x03 | ServerInfo | Server's encrypted response |
| 0x04 | SendPacket | Send packet to peer |
| 0x05 | RecvPacket | Receive packet from peer |
| 0x06 | KeepAlive | Keep connection alive |
| 0x07 | NotePreferred | Mark preferred connection |
| 0x08 | PeerGone | Peer disconnected |
| 0x09 | PeerPresent | Peer connected (mesh) |
| 0x0C | Ping | Ping request |
| 0x0D | Pong | Pong response |

## Configuration

### Application Environment

```erlang
{derp, [
    {port, 443},                          %% TLS listen port
    {ws_port, 80},                        %% WebSocket listen port
    {max_packet_size, 65536},             %% Max packet size
    {keepalive_interval, 60000},          %% Keep-alive interval (ms)
    {rate_limit_bytes_per_sec, 1048576},  %% Rate limit (1 MB/s)
    {rate_limit_burst, 2097152}           %% Rate limit burst (2 MB)
]}
```

### Release Configuration

See `config/sys.config` and `config/vm.args` for production settings.

## Building

### Prerequisites

- Erlang/OTP 26+
- rebar3
- libsodium (development headers)
- CMake 3.14+
- C compiler (GCC or Clang)

### Build Commands

```bash
# Compile
rebar3 compile

# Run tests
rebar3 eunit
rebar3 ct

# Dialyzer
rebar3 dialyzer

# Build release
rebar3 release
```

### Docker

```bash
# Build image
docker build -t derp -f docker/Dockerfile .

# Run with docker-compose
cd docker
./certs/generate.sh  # Generate test certificates
docker-compose up
```

## Platform Support

- **Operating Systems**: Linux, macOS, FreeBSD
- **Architectures**: amd64 (x86_64), arm64 (aarch64)
- **Erlang/OTP**: 26+

## Testing

### Unit Tests

```bash
rebar3 eunit
```

### Property-Based Tests

```bash
rebar3 as test eunit
```

### Integration Tests

```bash
rebar3 ct
```

### Docker-Based Integration Tests

```bash
cd docker
./certs/generate.sh
docker-compose up --build
```

## Protocol Flow

### Connection Handshake

1. Client connects via TLS/WebSocket
2. Server sends `FrameServerKey` with magic + public key
3. Client sends `FrameClientInfo` with encrypted info
4. Server validates, registers client, sends `FrameServerInfo`
5. Connection enters authenticated state

### Packet Relay

1. Client A sends `FrameSendPacket` with destination key + data
2. Server looks up destination in registry
3. If found: forward as `FrameRecvPacket` to Client B
4. If not found: send `FramePeerGone` to Client A

### Keep-Alive

- Clients must send `FrameKeepAlive` or other traffic every 60 seconds
- Server disconnects clients that go silent for 2× keep-alive interval

## License

MIT License - See LICENSE file for details.

## Credits

Based on Tailscale's DERP protocol specification.
