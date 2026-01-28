# API Reference

This document provides a complete API reference for the DERP Erlang library.

## derp_client

Client for connecting to DERP servers.

### start_link/1

Start a client connection.

```erlang
-spec start_link(Options) -> {ok, pid()} | {error, Reason}
    when Options :: #{
        host := string(),
        port => pos_integer(),
        use_tls => boolean(),
        tls_opts => [ssl:tls_client_option()],
        reconnect => boolean(),
        reconnect_delay => pos_integer(),
        reconnect_max_delay => pos_integer(),
        keypair => {PubKey :: binary(), SecKey :: binary()}
    }.
```

**Options:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | string | required | Server hostname or IP |
| `port` | integer | 443 | Server port |
| `use_tls` | boolean | true | Enable TLS |
| `tls_opts` | list | [] | SSL options |
| `reconnect` | boolean | false | Auto-reconnect on disconnect |
| `reconnect_delay` | integer | 1000 | Initial reconnect delay (ms) |
| `reconnect_max_delay` | integer | 30000 | Max reconnect delay (ms) |
| `keypair` | tuple | generated | Use specific keypair |

**Example:**

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "derp.example.com",
    port => 443,
    use_tls => true,
    reconnect => true
}).
```

### send/3

Send data to a peer.

```erlang
-spec send(Client, DstKey, Data) -> ok | {error, Reason}
    when Client :: pid(),
         DstKey :: binary(),  % 32-byte public key
         Data :: binary().
```

**Errors:**

- `not_connected` - Client not connected to server
- `peer_gone` - Destination peer not available

**Example:**

```erlang
ok = derp_client:send(Client, DstPubKey, <<"Hello!">>).
```

### recv/2

Receive data synchronously.

```erlang
-spec recv(Client, Timeout) -> {ok, SrcKey, Data} | {error, Reason}
    when Client :: pid(),
         Timeout :: timeout(),
         SrcKey :: binary(),  % 32-byte public key
         Data :: binary().
```

**Example:**

```erlang
{ok, SrcKey, Data} = derp_client:recv(Client, 5000).
```

### set_callback/2

Set callback for asynchronous receive.

```erlang
-spec set_callback(Client, Callback) -> ok
    when Client :: pid(),
         Callback :: fun((SrcKey :: binary(), Data :: binary()) -> any())
                   | undefined.
```

**Example:**

```erlang
derp_client:set_callback(Client, fun(SrcKey, Data) ->
    io:format("Received from ~p: ~p~n", [SrcKey, Data])
end).
```

### get_keypair/1

Get the client's keypair.

```erlang
-spec get_keypair(Client) -> {ok, {PubKey, SecKey}} | {error, Reason}
    when Client :: pid(),
         PubKey :: binary(),  % 32 bytes
         SecKey :: binary().  % 32 bytes
```

### get_server_pubkey/1

Get the server's public key.

```erlang
-spec get_server_pubkey(Client) -> {ok, PubKey} | {error, not_connected}
    when Client :: pid(),
         PubKey :: binary().  % 32 bytes
```

### close/1

Close the connection.

```erlang
-spec close(Client) -> ok
    when Client :: pid().
```

---

## derp_server

DERP server management.

### start_link/1

Start the server listener.

```erlang
-spec start_link(Options) -> {ok, pid()} | {error, Reason}
    when Options :: #{
        port => pos_integer(),
        certfile => file:filename(),
        keyfile => file:filename()
    }.
```

### get_public_key/0

Get the server's public key.

```erlang
-spec get_public_key() -> binary().  % 32 bytes
```

---

## derp_frame

Frame encoding and decoding.

### encode/2

Encode a frame.

```erlang
-spec encode(Type, Payload) -> iodata()
    when Type :: frame_type(),
         Payload :: binary().
```

### decode/1

Decode a frame from binary.

```erlang
-spec decode(Binary) -> {ok, Type, Payload, Rest} | {more, N} | {error, Reason}
    when Binary :: binary(),
         Type :: frame_type(),
         Payload :: binary(),
         Rest :: binary(),
         N :: pos_integer().
```

### Frame Type Constants

```erlang
-define(FRAME_SERVER_KEY, 16#01).
-define(FRAME_CLIENT_INFO, 16#02).
-define(FRAME_SERVER_INFO, 16#03).
-define(FRAME_SEND_PACKET, 16#04).
-define(FRAME_RECV_PACKET, 16#05).
-define(FRAME_KEEP_ALIVE, 16#06).
-define(FRAME_NOTE_PREFERRED, 16#07).
-define(FRAME_PEER_GONE, 16#08).
-define(FRAME_PEER_PRESENT, 16#09).
-define(FRAME_WATCH_CONNS, 16#0A).
-define(FRAME_CLOSE_PEER, 16#0B).
-define(FRAME_PING, 16#0C).
-define(FRAME_PONG, 16#0D).
-define(FRAME_HEALTH, 16#0E).
-define(FRAME_RESTARTING, 16#0F).
-define(FRAME_FORWARD_PACKET, 16#10).
```

---

## derp_crypto

High-level cryptographic operations.

### generate_keypair/0

Generate a new Curve25519 keypair.

```erlang
-spec generate_keypair() -> {PubKey, SecKey}
    when PubKey :: binary(),  % 32 bytes
         SecKey :: binary().  % 32 bytes
```

### box_seal/4

Encrypt and authenticate a message.

```erlang
-spec box_seal(Message, Nonce, TheirPub, MySec) -> Ciphertext
    when Message :: binary(),
         Nonce :: binary(),     % 24 bytes
         TheirPub :: binary(),  % 32 bytes
         MySec :: binary(),     % 32 bytes
         Ciphertext :: binary().
```

### box_open/4

Decrypt and verify a message.

```erlang
-spec box_open(Ciphertext, Nonce, TheirPub, MySec) -> {ok, Message} | {error, failed}
    when Ciphertext :: binary(),
         Nonce :: binary(),     % 24 bytes
         TheirPub :: binary(),  % 32 bytes
         MySec :: binary(),     % 32 bytes
         Message :: binary().
```

### random_nonce/0

Generate a random 24-byte nonce.

```erlang
-spec random_nonce() -> binary().  % 24 bytes
```

---

## derp_sodium

Low-level NIF wrapper for libsodium.

### box_keypair/0

Generate a Curve25519 keypair.

```erlang
-spec box_keypair() -> {PubKey, SecKey}
    when PubKey :: binary(),  % 32 bytes
         SecKey :: binary().  % 32 bytes
```

### box/4

NaCl box encryption.

```erlang
-spec box(Message, Nonce, TheirPub, MySec) -> Ciphertext
    when Message :: binary(),
         Nonce :: binary(),     % 24 bytes
         TheirPub :: binary(),  % 32 bytes
         MySec :: binary(),     % 32 bytes
         Ciphertext :: binary().
```

### box_open/4

NaCl box decryption.

```erlang
-spec box_open(Ciphertext, Nonce, TheirPub, MySec) -> {ok, Message} | error
    when Ciphertext :: binary(),
         Nonce :: binary(),     % 24 bytes
         TheirPub :: binary(),  % 32 bytes
         MySec :: binary(),     % 32 bytes
         Message :: binary().
```

### randombytes/1

Generate cryptographically secure random bytes.

```erlang
-spec randombytes(N) -> binary()
    when N :: non_neg_integer().  % max 65536
```

---

## derp_registry

Client registry (internal API).

### register_client/2

Register a client by public key.

```erlang
-spec register_client(PubKey, Pid) -> ok | {error, already_registered}
    when PubKey :: binary(),
         Pid :: pid().
```

### unregister_client/1

Unregister a client.

```erlang
-spec unregister_client(PubKey) -> ok
    when PubKey :: binary().
```

### lookup_client/1

Look up a client by public key.

```erlang
-spec lookup_client(PubKey) -> {ok, Pid} | {error, not_found}
    when PubKey :: binary(),
         Pid :: pid().
```

---

## derp_rate_limiter

Rate limiting (internal API).

### check/2

Check if an operation is within rate limits.

```erlang
-spec check(ClientKey, ByteCount) -> ok | {error, rate_limited}
    when ClientKey :: binary(),
         ByteCount :: non_neg_integer().
```

### reset/1

Reset rate limit for a client.

```erlang
-spec reset(ClientKey) -> ok
    when ClientKey :: binary().
```

---

## Application Environment

Configuration options in `sys.config`:

```erlang
{derp, [
    {port, 443},                          % TLS port
    {ws_port, 80},                        % WebSocket port
    {certfile, "path/to/cert.pem"},       % TLS certificate
    {keyfile, "path/to/key.pem"},         % TLS private key
    {max_packet_size, 65536},             % Max packet size
    {keepalive_interval, 60000},          % Keep-alive (ms)
    {rate_limit_bytes_per_sec, 1048576},  % Rate limit
    {rate_limit_burst, 2097152}           % Rate limit burst
]}
```
