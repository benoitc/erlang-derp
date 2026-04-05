# Client Usage

This guide covers advanced usage of the DERP client library.

## Connection Options

```erlang
{ok, Client} = derp_client:start_link(#{
    %% Required
    host => "derp.example.com",  % Server hostname

    %% Optional
    port => 443,                 % Server port (default: 443)
    use_tls => true,             % Use TLS (default: true)
    tls_backend => boringssl,    % TLS backend: boringssl (default) or otp
    reconnect => true,           % Auto-reconnect on disconnect
    http_path => <<"/derp">>,    % HTTP upgrade path (default: "/derp")

    %% TLS options (only used when tls_backend => otp)
    tls_opts => [
        {verify, verify_peer},
        {cacertfile, "/path/to/ca.crt"}
    ],

    %% Custom keypair (optional - generates new if not provided)
    keypair => {PubKey, SecKey}
}).
```

## TLS Backend

The client supports two TLS backends:

### BoringSSL (default)

BoringSSL handles TLS via a C NIF with non-blocking I/O. This is the default backend and the only one that works with Tailscale's DERP servers (whose certificates exceed OTP's X.520 CommonName limit).

```erlang
%% Connect to Tailscale DERP
{ok, Client} = derp_client:start_link(#{
    host => "derp1.tailscale.com",
    port => 443,
    tls_backend => boringssl
}).
```

### OTP ssl

Falls back to OTP's `ssl` module. Use this when connecting to servers with standard certificates. Cannot connect to Tailscale DERP infrastructure.

```erlang
%% Connect to your own DERP server with standard certs
{ok, Client} = derp_client:start_link(#{
    host => "my-derp.example.com",
    port => 443,
    tls_backend => otp,
    tls_opts => [{verify, verify_none}]
}).
```

For more details on the TLS implementation, see the [TLS with BoringSSL](tls.md) guide.

## Sending Messages

### Basic Send

```erlang
%% Send raw binary data
ok = derp_client:send(Client, DestPubKey, <<"Hello!">>).

%% Send with error handling
case derp_client:send(Client, DestPubKey, Data) of
    ok -> io:format("Sent successfully~n");
    {error, not_connected} -> io:format("Not connected~n");
    {error, peer_gone} -> io:format("Peer not available~n");
    {error, Reason} -> io:format("Error: ~p~n", [Reason])
end.
```

### Message Format

The data you send is opaque to DERP. In practice, this is usually encrypted WireGuard packets or application-level messages.

```erlang
%% Example: Send JSON
Json = jsx:encode(#{type => <<"chat">>, message => <<"Hello!">>}),
derp_client:send(Client, DestKey, Json).

%% Example: Send term (not recommended for interop)
Data = term_to_binary({my_message, "Hello", 123}),
derp_client:send(Client, DestKey, Data).
```

## Receiving Messages

### Synchronous Receive

Block until a message arrives or timeout:

```erlang
%% Wait up to 5 seconds
case derp_client:recv(Client, 5000) of
    {ok, SrcKey, Data} ->
        handle_message(SrcKey, Data);
    {error, timeout} ->
        io:format("No message received~n")
end.

%% Infinite wait
{ok, SrcKey, Data} = derp_client:recv(Client, infinity).
```

### Asynchronous Receive (Callback)

Set a callback function to handle messages as they arrive:

```erlang
%% Simple callback
derp_client:set_callback(Client, fun(SrcKey, Data) ->
    io:format("From ~s: ~p~n", [base64:encode(SrcKey), Data])
end).

%% Callback with state (use a gen_server)
-module(my_handler).
-behaviour(gen_server).

init([Client]) ->
    derp_client:set_callback(Client, fun(Src, Data) ->
        gen_server:cast(self(), {derp_message, Src, Data})
    end),
    {ok, #state{}}.

handle_cast({derp_message, SrcKey, Data}, State) ->
    %% Process message
    {noreply, State}.
```

### Clearing Callback

```erlang
%% Remove the callback
derp_client:set_callback(Client, undefined).
```

## Connection State

### Check Connection

```erlang
%% Get server public key (only available when connected)
case derp_client:get_server_pubkey(Client) of
    {ok, ServerPubKey} ->
        io:format("Connected to server: ~s~n",
                  [base64:encode(ServerPubKey)]);
    {error, not_connected} ->
        io:format("Not connected~n")
end.
```

### Get Keypair

```erlang
%% Get this client's keypair
{ok, {MyPubKey, MySecKey}} = derp_client:get_keypair(Client).
io:format("My public key: ~s~n", [base64:encode(MyPubKey)]).
```

## Reconnection

When `reconnect => true`, the client automatically reconnects on disconnect:

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "derp.example.com",
    port => 443,
    reconnect => true,
    reconnect_delay => 1000,      % Initial delay (ms)
    reconnect_max_delay => 30000  % Maximum delay (ms)
}).
```

The client uses exponential backoff between reconnection attempts.

### Manual Reconnect

```erlang
%% Force reconnection
derp_client:reconnect(Client).
```

## Closing Connection

```erlang
%% Graceful close
derp_client:close(Client).

%% Or stop the process
gen_statem:stop(Client).
```

## Error Handling

### Common Errors

| Error | Meaning |
|-------|---------|
| `not_connected` | Client not connected to server |
| `peer_gone` | Destination peer not connected |
| `rate_limited` | Rate limit exceeded |
| `timeout` | Operation timed out |
| `closed` | Connection closed |

### Handling Disconnection

```erlang
%% Monitor the client process
Ref = monitor(process, Client),
receive
    {'DOWN', Ref, process, Client, Reason} ->
        io:format("Client died: ~p~n", [Reason])
end.
```

## Multiple Clients

You can run multiple clients in the same application:

```erlang
%% Connect to multiple servers
{ok, Client1} = derp_client:start_link(#{host => "derp1.example.com"}),
{ok, Client2} = derp_client:start_link(#{host => "derp2.example.com"}).

%% Or multiple connections to same server (different keys)
{ok, ClientA} = derp_client:start_link(#{host => "derp.example.com"}),
{ok, ClientB} = derp_client:start_link(#{host => "derp.example.com"}).
```

## Using with Supervisor

```erlang
-module(my_sup).
-behaviour(supervisor).

init([]) ->
    Children = [
        #{
            id => derp_client,
            start => {derp_client, start_link, [#{
                host => "derp.example.com",
                port => 443,
                reconnect => true
            }]},
            restart => permanent,
            type => worker
        }
    ],
    {ok, {#{strategy => one_for_one}, Children}}.
```

## Performance Tips

1. **Use BoringSSL** - The default TLS backend avoids OTP ssl limitations
2. **Use async receive** - Callbacks are more efficient than polling
3. **Batch messages** - Combine small messages when possible
4. **Monitor rate limits** - Respect server rate limits
5. **Handle reconnects** - Design for intermittent connectivity
6. **Buffer messages** - Queue messages during disconnection
