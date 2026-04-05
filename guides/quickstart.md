# Quick Start

This guide will get you up and running with DERP in a few minutes.

## Starting the Server

### Option 1: Using rebar3 shell

```bash
# Start the shell with the application loaded
rebar3 shell

# In the Erlang shell
1> application:ensure_all_started(derp).
{ok,[jsx,cowlib,ranch,cowboy,derp]}
```

### Option 2: Using a Release

```bash
# Build and start the release
rebar3 release
_build/default/rel/derp/bin/derp foreground
```

### Option 3: Docker

```bash
cd docker
./certs/generate.sh
docker-compose up
```

## Connecting a Client

Once the server is running, connect a client:

```erlang
%% Connect to the server (uses BoringSSL TLS by default)
{ok, Client} = derp_client:start_link(#{
    host => "localhost",
    port => 443,
    use_tls => true,
    reconnect => true
}).

%% Get your public key
{ok, {MyPubKey, _SecKey}} = derp_client:get_keypair(Client).
io:format("My public key: ~s~n", [base64:encode(MyPubKey)]).
```

To connect to Tailscale's public DERP infrastructure:

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "derp1.tailscale.com",
    port => 443,
    use_tls => true,
    tls_backend => boringssl       %% required for Tailscale (default)
}).
```

## Sending Messages

To send a message to another client, you need their public key:

```erlang
%% Destination public key (base64 decoded)
DstKey = base64:decode(<<"other_client_pubkey_base64">>).

%% Send a message
ok = derp_client:send(Client, DstKey, <<"Hello from DERP!">>).
```

## Receiving Messages

### Synchronous Receive

```erlang
%% Wait for a message (with 5 second timeout)
case derp_client:recv(Client, 5000) of
    {ok, SrcKey, Data} ->
        io:format("Received from ~s: ~s~n",
                  [base64:encode(SrcKey), Data]);
    {error, timeout} ->
        io:format("No message received~n")
end.
```

### Asynchronous Receive (Callback)

```erlang
%% Set up a callback for incoming messages
derp_client:set_callback(Client, fun(SrcKey, Data) ->
    io:format("Received from ~s: ~s~n",
              [base64:encode(SrcKey), Data])
end).

%% Messages will now be delivered asynchronously
```

## Two-Client Example

Here's a complete example with two clients communicating:

### Terminal 1 - Start Server

```bash
rebar3 shell
```

```erlang
application:ensure_all_started(derp).
```

### Terminal 2 - Client A (Receiver)

```bash
rebar3 shell --name a@localhost
```

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "localhost", port => 443,
    use_tls => true
}).

%% Print public key for Client B
{ok, {PubKey, _}} = derp_client:get_keypair(Client).
io:format("Client A public key: ~s~n", [base64:encode(PubKey)]).

%% Set up receiver
derp_client:set_callback(Client, fun(Src, Data) ->
    io:format("Received: ~s~n", [Data])
end).
```

### Terminal 3 - Client B (Sender)

```bash
rebar3 shell --name b@localhost
```

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "localhost", port => 443,
    use_tls => true
}).

%% Use Client A's public key from above
DstKey = base64:decode(<<"CLIENT_A_PUBKEY_HERE">>).

%% Send a message
derp_client:send(Client, DstKey, <<"Hello from Client B!">>).
```

Client A should print: `Received: Hello from Client B!`

## Using the Test Client

For quick testing, use the included escript:

```bash
# Build the test client
rebar3 escriptize

# Terminal 1: Start receiver
./_build/default/bin/derp_test_client receiver localhost 443

# Terminal 2: Start sender (use the public key printed by receiver)
./_build/default/bin/derp_test_client sender localhost 443 <RECEIVER_PUBKEY>
```

## Docker Simulation

Run a complete two-client simulation in Docker:

```bash
cd docker
./run_simulation.sh
```

This starts a server and two clients (Alice and Bob) that exchange messages.

## Next Steps

- [Server Configuration](server.md) - Configure the server for production
- [Client Usage](client.md) - Advanced client features
- [TLS with BoringSSL](tls.md) - TLS architecture and configuration
- [Docker Deployment](docker.md) - Deploy with Docker
- [Protocol Reference](protocol.md) - Understand the protocol
