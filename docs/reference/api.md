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
| `tls_backend` | atom | boringssl | TLS backend: `boringssl` or `otp` |
| `tls_opts` | list | [] | OTP SSL options (only with `tls_backend => otp`) |
| `http_path` | binary | `<<"/derp">>` | Path for HTTP upgrade |
| `reconnect` | boolean | false | Auto-reconnect on disconnect |
| `reconnect_delay` | integer | 1000 | Initial reconnect delay (ms) |
| `max_reconnect_delay` | integer | 30000 | Max reconnect delay (ms) |
| `keypair` | tuple | generated | Use specific keypair |
| `event_callback` | function | undefined | Fun/1 for server events |

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

### note_preferred/2

Tell the server this is the preferred DERP connection.

```erlang
-spec note_preferred(Client, Preferred) -> ok | {error, Reason}
    when Client :: pid(),
         Preferred :: boolean().
```

### get_health/1

Get the current server health status.

```erlang
-spec get_health(Client) -> {ok, Health}
    when Client :: pid(),
         Health :: binary().  % empty = healthy, or description string
```

### set_event_callback/2

Set a callback for server events.

```erlang
-spec set_event_callback(Client, Callback) -> ok
    when Client :: pid(),
         Callback :: fun((Event) -> any()) | undefined.
```

Events:

- `{health, Message :: binary()}` -- Server health change
- `{restarting, ReconnectMs :: non_neg_integer() | undefined}` -- Server restarting
- `{peer_gone, PeerKey :: binary(), Reason :: non_neg_integer()}` -- Peer disconnected
- `{peer_present, PeerKey :: binary()}` -- Peer connected

---

## derp_tls

High-level TLS API using BoringSSL NIF. No gen_server -- the owning process calls these functions directly and receives `{select, ConnRef, _, ready_input}` messages.

### connect/3, connect/4

Connect to a TLS server.

```erlang
-spec connect(Host, Port, Opts) -> {ok, ConnRef} | {error, Reason}
    when Host :: string(),
         Port :: inet:port_number(),
         Opts :: #{verify => boolean()}.

-spec connect(Host, Port, Opts, Timeout) -> {ok, ConnRef} | {error, Reason}
    when Host :: string(),
         Port :: inet:port_number(),
         Opts :: #{verify => boolean()},
         Timeout :: timeout().
```

Creates a TCP socket, performs async connect, completes the TLS handshake, and arms `enif_select` for the first read. Default timeout is 15 seconds.

**Example:**

```erlang
{ok, Conn} = derp_tls:connect("derp1.tailscale.com", 443, #{verify => false}).
```

### accept/2, accept/3

Accept and TLS-wrap an existing TCP socket for server mode.

```erlang
-spec accept(Fd, Opts) -> {ok, ConnRef} | {error, Reason}
    when Fd :: integer(),
         Opts :: #{certfile := string(), keyfile := string()}.

-spec accept(Fd, Opts, Timeout) -> {ok, ConnRef} | {error, Reason}.
```

**Example:**

```erlang
{ok, Sock} = gen_tcp:accept(LSock),
{ok, Fd} = inet:getfd(Sock),
{ok, Conn} = derp_tls:accept(Fd, #{
    certfile => "server.pem", keyfile => "server-key.pem"
}).
```

### send/2

Encrypt and send data.

```erlang
-spec send(ConnRef, Data) -> ok | {error, Reason}
    when ConnRef :: reference(),
         Data :: iodata().
```

Handles `want_write` internally by waiting for socket writability.

### recv/1

Read decrypted data from the connection.

```erlang
-spec recv(ConnRef) -> {ok, Data} | {error, Reason}
    when ConnRef :: reference(),
         Data :: binary().
```

Call after receiving `{select, ConnRef, _, ready_input}`. Returns `{error, want_read}` when no complete TLS record is available yet (not a fatal error -- re-arm with `activate/1`).

### activate/1

Arm the connection for the next read notification.

```erlang
-spec activate(ConnRef) -> ok | {error, Reason}
    when ConnRef :: reference().
```

After processing data from `recv/1`, call this to receive the next `{select, ConnRef, _, ready_input}` message.

### close/1

Perform TLS shutdown and close the socket.

```erlang
-spec close(ConnRef) -> ok
    when ConnRef :: reference().
```

### peername/1, sockname/1

Get remote or local address.

```erlang
-spec peername(ConnRef) -> {ok, {Address, Port}} | {error, Reason}.
-spec sockname(ConnRef) -> {ok, {Address, Port}} | {error, Reason}.
```

### controlling_process/2

Change the owner process that receives select messages.

```erlang
-spec controlling_process(ConnRef, NewOwner) -> ok
    when ConnRef :: reference(),
         NewOwner :: pid().
```

---

## derp_tls_nif

Low-level NIF wrapper for BoringSSL TLS operations. Crypto-heavy and I/O functions run on dirty schedulers. See [TLS with BoringSSL](../guide/tls.md) for architecture details.

### Context functions

```erlang
-spec ctx_new(client | server) -> {ok, reference()} | {error, term()}.
-spec ctx_set_verify(Ctx, Verify :: boolean()) -> ok | {error, term()}.
-spec ctx_set_cert(Ctx, CertFile :: string(), KeyFile :: string()) -> ok | {error, term()}.
```

### Connection functions

```erlang
-spec conn_new(Ctx, client | server, OwnerPid :: pid()) -> {ok, reference()} | {error, term()}.
-spec conn_set_hostname(Conn, Hostname :: string()) -> ok.
-spec conn_connect(Conn, Host :: string(), Port :: integer()) ->
    ok | {ok, einprogress} | {error, term()}.
-spec conn_set_fd(Conn, Fd :: integer()) -> ok | {error, term()}.
```

### I/O functions (dirty schedulers)

```erlang
-spec handshake(Conn) -> ok | want_read | want_write | {error, term()}.
-spec recv(Conn) -> {ok, binary()} | want_read | {error, term()}.
-spec send(Conn, Data :: binary()) -> ok | want_write | want_read | {error, term()}.
-spec select_read(Conn) -> ok | {error, term()}.
-spec select_write(Conn) -> ok | {error, term()}.
-spec shutdown(Conn) -> ok.
```

### Utility functions

```erlang
-spec peername(Conn) -> {ok, {string(), integer()}} | {error, term()}.
-spec sockname(Conn) -> {ok, {string(), integer()}} | {error, term()}.
-spec controlling_process(Conn, pid()) -> ok.
-spec get_fd(Conn) -> {ok, integer()} | {error, term()}.
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
