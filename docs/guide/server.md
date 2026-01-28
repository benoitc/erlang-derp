# Server Configuration

This guide covers configuring and running the DERP server for production use.

## Configuration Options

### Application Environment

Configure the server in `config/sys.config`:

```erlang
{derp, [
    %% TLS listen port
    {port, 443},

    %% WebSocket listen port (for HTTP proxy traversal)
    {ws_port, 80},

    %% TLS certificate file
    {certfile, "/etc/derp/certs/server.crt"},

    %% TLS private key file
    {keyfile, "/etc/derp/certs/server.key"},

    %% Maximum packet size (bytes)
    {max_packet_size, 65536},

    %% Keep-alive interval (milliseconds)
    {keepalive_interval, 60000},

    %% Rate limiting: bytes per second per client
    {rate_limit_bytes_per_sec, 1048576},  % 1 MB/s

    %% Rate limiting: burst allowance
    {rate_limit_burst, 2097152}  % 2 MB
]}
```

### Environment Variables

When using releases with `RELX_REPLACE_OS_VARS=true`, you can use environment variables:

```erlang
{derp, [
    {port, "${DERP_PORT}"},
    {ws_port, "${DERP_WS_PORT}"},
    {certfile, "${DERP_CERTFILE}"},
    {keyfile, "${DERP_KEYFILE}"}
]}
```

Then set at runtime:

```bash
export DERP_PORT=443
export DERP_WS_PORT=80
export DERP_CERTFILE=/etc/derp/certs/server.crt
export DERP_KEYFILE=/etc/derp/certs/server.key
_build/prod/rel/derp/bin/derp foreground
```

## TLS Certificates

### Development (Self-Signed)

Generate test certificates using the provided script:

```bash
cd docker/certs
./generate.sh
```

This creates:

- `ca.key`, `ca.crt` - Certificate Authority
- `server.key`, `server.crt` - Server certificate

### Production

For production, use certificates from a trusted CA (Let's Encrypt, etc.):

```bash
# Example with certbot
certbot certonly --standalone -d derp.example.com

# Update sys.config
{certfile, "/etc/letsencrypt/live/derp.example.com/fullchain.pem"},
{keyfile, "/etc/letsencrypt/live/derp.example.com/privkey.pem"}
```

## Starting the Server

### Manual Start

```erlang
%% Start with default configuration
{ok, _} = application:ensure_all_started(derp).

%% Or start with custom options
{ok, Pid} = derp_server:start_link(#{
    port => 8443,
    certfile => "/path/to/cert.pem",
    keyfile => "/path/to/key.pem"
}).
```

### Release

```bash
# Development release
rebar3 release
_build/default/rel/derp/bin/derp foreground

# Production release
rebar3 as prod release
_build/prod/rel/derp/bin/derp foreground

# Background (daemon)
_build/prod/rel/derp/bin/derp start
_build/prod/rel/derp/bin/derp stop
```

## Rate Limiting

The server implements token bucket rate limiting per client:

- **Bytes per second**: Maximum sustained throughput
- **Burst**: Maximum bytes in a single burst

When a client exceeds the rate limit, packets are rejected with an error.

```erlang
%% Configure rate limits
{rate_limit_bytes_per_sec, 1048576},  % 1 MB/s sustained
{rate_limit_burst, 2097152}           % 2 MB burst
```

## Monitoring

### Server Public Key

```erlang
%% Get the server's public key
PubKey = derp_server:get_public_key().
io:format("Server public key: ~s~n", [base64:encode(PubKey)]).
```

### Connected Clients

```erlang
%% List registered clients (internal API)
ets:tab2list(derp_registry).
```

### Metrics

The server logs important events:

- Client connections/disconnections
- Authentication failures
- Rate limit violations
- Protocol errors

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    derp_sup                              │
│                  (supervisor)                            │
├─────────────┬─────────────┬─────────────┬───────────────┤
│ derp_server │ derp_reg    │ derp_rate   │ derp_server   │
│ (TLS)       │ (ETS)       │ (limiter)   │ _sup (conns)  │
└─────────────┴─────────────┴─────────────┴───────────────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              │                 │                 │
                         derp_conn         derp_conn         derp_conn
                         (client A)        (client B)        (client C)
```

## Supervision

The server uses OTP supervision for fault tolerance:

- `derp_sup` - Top-level supervisor (one_for_one)
- `derp_server_sup` - Connection supervisor (simple_one_for_one)
- `derp_conn` - Individual connection handlers (gen_statem)

If a connection handler crashes, only that connection is affected. The server continues running.

## WebSocket Support

The server supports WebSocket transport for clients behind HTTP proxies:

- Endpoint: `wss://server:ws_port/derp`
- Binary frames wrap DERP protocol frames
- Same authentication and protocol as TLS

```erlang
%% Client connecting via WebSocket
{ok, Client} = derp_client:start_link(#{
    host => "derp.example.com",
    port => 80,
    transport => websocket
}).
```

## Security Considerations

1. **Always use TLS** in production
2. **Use proper certificates** from a trusted CA
3. **Configure rate limits** to prevent abuse
4. **Monitor logs** for authentication failures
5. **Firewall rules** - only expose necessary ports
6. **Regular updates** - keep dependencies updated
