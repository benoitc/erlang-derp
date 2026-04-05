# erlang-derp

An Erlang implementation of [Tailscale's DERP](https://tailscale.com/kb/1232/derp-servers) (Designated Encrypted Relay for Packets) protocol.

DERP provides secure packet relay when direct WireGuard peer-to-peer connections cannot be established due to NAT, firewalls, or network restrictions.

## Features

- **DERP Server**: TLS-based relay with WebSocket support
- **DERP Client**: Erlang client library with auto-reconnect
- **BoringSSL TLS**: NIF-based TLS for Tailscale certificate compatibility
- **Full Protocol**: Complete DERP frame protocol implementation

## Quick Start

```erlang
%% Start the application
application:ensure_all_started(derp).

%% Connect to a DERP server
{ok, Client} = derp_client:start_link(#{
    host => "your-derp-server.example.com",
    port => 443
}).

%% Send a packet to another peer
ok = derp_client:send(Client, DestinationPublicKey, <<"Hello!">>).

%% Receive packets
{ok, SrcKey, Data} = derp_client:recv(Client, 5000).
```

## Requirements

- Erlang/OTP 26+ (27 recommended)
- libsodium
- CMake 3.14+, Ninja, C++ compiler, Perl (for BoringSSL)

## Installation

Add to your `rebar.config`:

```erlang
{deps, [
    {derp, {git, "https://github.com/benoitc/erlang-derp.git", {tag, "v0.3.0"}}}
]}.
```

## Platform Support

| Platform | Architectures |
|----------|---------------|
| Linux    | amd64, arm64  |
| macOS    | amd64, arm64  |
| FreeBSD  | amd64, arm64  |

## Documentation

API documentation available at: https://hexdocs.pm/derp/

## License

MIT License - See [LICENSE](LICENSE) for details.

## Credits

Based on [Tailscale's DERP protocol](https://tailscale.com/blog/how-tailscale-works/).
