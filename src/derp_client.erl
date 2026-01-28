%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP client connection.
%%%
%%% Manages a client connection to a DERP server using gen_statem.
%%% Handles connection establishment, handshake, packet sending/receiving,
%%% and automatic reconnection.
%%%
%%% States:
%%% - connecting: Establishing TCP/TLS connection
%%% - handshaking: Performing DERP handshake
%%% - connected: Ready to send/receive packets
%%% - reconnecting: Waiting to reconnect after disconnect
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_client).

-behaviour(gen_statem).

-include("derp.hrl").

%% API
-export([
    start_link/1,
    send/3,
    recv/1,
    recv/2,
    set_callback/2,
    get_server_pubkey/1,
    get_keypair/1,
    close/1
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3
]).

%% State functions
-export([
    connecting/3,
    handshaking/3,
    connected/3,
    reconnecting/3
]).

-record(data, {
    host :: inet:hostname() | inet:ip_address(),
    port :: inet:port_number(),
    keypair :: {binary(), binary()},
    server_pubkey :: binary() | undefined,
    socket :: ssl:sslsocket() | gen_tcp:socket() | undefined,
    transport :: ssl | gen_tcp,
    buffer :: binary(),
    recv_queue :: queue:queue(),
    callback :: fun((binary(), binary()) -> any()) | undefined,
    reconnect :: boolean(),
    reconnect_delay :: pos_integer(),
    keepalive_timer :: reference() | undefined,
    use_tls :: boolean(),
    tls_opts :: list()
}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start a DERP client connection.
%%
%% Options:
%% - host: Server hostname or IP (required)
%% - port: Server port (default: 443)
%% - keypair: {PubKey, SecKey} tuple (generated if not provided)
%% - reconnect: Auto-reconnect on disconnect (default: true)
%% - reconnect_delay: Delay between reconnect attempts in ms (default: 1000)
%% - use_tls: Use TLS connection (default: true)
%% - tls_opts: Additional TLS options (default: [])
%%
%% @param Opts Client options map
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_statem:start_link(?MODULE, Opts, []).

%% @doc Send a packet to a peer.
%%
%% @param Pid Client pid
%% @param DstKey Destination peer's public key (32 bytes)
%% @param Data Packet data
-spec send(pid(), binary(), binary()) -> ok | {error, term()}.
send(Pid, DstKey, Data) when byte_size(DstKey) =:= 32 ->
    gen_statem:call(Pid, {send, DstKey, Data}).

%% @doc Receive a packet synchronously.
%%
%% Blocks until a packet is received or timeout.
%%
%% @param Pid Client pid
%% @returns {ok, SrcKey, Data} | {error, timeout}
-spec recv(pid()) -> {ok, binary(), binary()} | {error, term()}.
recv(Pid) ->
    recv(Pid, 5000).

%% @doc Receive a packet with custom timeout.
%%
%% @param Pid Client pid
%% @param Timeout Timeout in milliseconds
%% @returns {ok, SrcKey, Data} | {error, timeout}
-spec recv(pid(), timeout()) -> {ok, binary(), binary()} | {error, term()}.
recv(Pid, Timeout) ->
    gen_statem:call(Pid, recv, Timeout).

%% @doc Set a callback function for received packets.
%%
%% The callback receives (SrcKey, Data) for each incoming packet.
%% Setting a callback disables synchronous recv.
%%
%% @param Pid Client pid
%% @param Fun Callback function or undefined to clear
-spec set_callback(pid(), fun() | undefined) -> ok.
set_callback(Pid, Fun) ->
    gen_statem:cast(Pid, {set_callback, Fun}).

%% @doc Get the server's public key.
%%
%% @param Pid Client pid
%% @returns {ok, PubKey} | {error, not_connected}
-spec get_server_pubkey(pid()) -> {ok, binary()} | {error, term()}.
get_server_pubkey(Pid) ->
    gen_statem:call(Pid, get_server_pubkey).

%% @doc Get the client's keypair.
%%
%% @param Pid Client pid
%% @returns {ok, {PubKey, SecKey}}
-spec get_keypair(pid()) -> {ok, {binary(), binary()}}.
get_keypair(Pid) ->
    gen_statem:call(Pid, get_keypair).

%% @doc Close the client connection.
%%
%% @param Pid Client pid
-spec close(pid()) -> ok.
close(Pid) ->
    gen_statem:stop(Pid).

%%--------------------------------------------------------------------
%% gen_statem callbacks
%%--------------------------------------------------------------------

callback_mode() ->
    state_functions.

init(Opts) ->
    Host = maps:get(host, Opts),
    Port = maps:get(port, Opts, 443),
    Keypair = maps:get(keypair, Opts, derp_crypto:generate_keypair()),
    Reconnect = maps:get(reconnect, Opts, true),
    ReconnectDelay = maps:get(reconnect_delay, Opts, 1000),
    UseTls = maps:get(use_tls, Opts, true),
    TlsOpts = maps:get(tls_opts, Opts, []),

    Transport = case UseTls of
        true -> ssl;
        false -> gen_tcp
    end,

    Data = #data{
        host = Host,
        port = Port,
        keypair = Keypair,
        transport = Transport,
        buffer = <<>>,
        recv_queue = queue:new(),
        reconnect = Reconnect,
        reconnect_delay = ReconnectDelay,
        use_tls = UseTls,
        tls_opts = TlsOpts
    },

    %% Start connecting
    {ok, ?CLIENT_STATE_CONNECTING, Data, [{next_event, internal, connect}]}.

terminate(_Reason, _State, #data{socket = Socket, transport = Transport}) ->
    _ = case Socket of
        undefined -> ok;
        _ -> close_socket(Transport, Socket)
    end,
    ok.

%%--------------------------------------------------------------------
%% State: connecting
%%--------------------------------------------------------------------

connecting(internal, connect, Data) ->
    #data{host = Host, port = Port, transport = Transport,
          use_tls = UseTls, tls_opts = TlsOpts} = Data,

    ConnectOpts = [
        {mode, binary},
        {packet, raw},
        {active, false},
        {nodelay, true}
    ],

    Result = case UseTls of
        true ->
            SslOpts = ConnectOpts ++ TlsOpts ++ [
                {verify, verify_none}  % TODO: Add proper cert verification
            ],
            ssl:connect(Host, Port, SslOpts, 10000);
        false ->
            gen_tcp:connect(Host, Port, ConnectOpts, 10000)
    end,

    case Result of
        {ok, Socket} ->
            ok = set_active(Transport, Socket, once),
            {next_state, ?CLIENT_STATE_HANDSHAKING, Data#data{socket = Socket}};
        {error, Reason} ->
            logger:warning("DERP connect failed: ~p", [Reason]),
            maybe_reconnect(Data)
    end;

connecting({call, From}, {send, _, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, recv, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, get_server_pubkey, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

connecting(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}}.

%%--------------------------------------------------------------------
%% State: handshaking
%%--------------------------------------------------------------------

handshaking(info, {ssl, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_handshake_data(Bin, Data);

handshaking(info, {tcp, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_handshake_data(Bin, Data);

handshaking(info, {ssl_closed, _}, Data) ->
    logger:warning("DERP connection closed during handshake"),
    maybe_reconnect(Data#data{socket = undefined});

handshaking(info, {tcp_closed, _}, Data) ->
    logger:warning("DERP connection closed during handshake"),
    maybe_reconnect(Data#data{socket = undefined});

handshaking(info, {ssl_error, _, Reason}, Data) ->
    logger:warning("DERP SSL error during handshake: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined});

handshaking(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("DERP TCP error during handshake: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined});

handshaking({call, From}, {send, _, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

handshaking({call, From}, recv, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

handshaking({call, From}, get_server_pubkey, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

handshaking({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

handshaking(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}}.

%%--------------------------------------------------------------------
%% State: connected
%%--------------------------------------------------------------------

connected(info, {ssl, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_connected_data(Bin, Data);

connected(info, {tcp, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_connected_data(Bin, Data);

connected(info, {ssl_closed, _}, Data) ->
    logger:info("DERP connection closed"),
    maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined});

connected(info, {tcp_closed, _}, Data) ->
    logger:info("DERP connection closed"),
    maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined});

connected(info, {ssl_error, _, Reason}, Data) ->
    logger:warning("DERP SSL error: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined});

connected(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("DERP TCP error: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined});

connected(info, send_keepalive, Data) ->
    #data{socket = Socket, transport = Transport} = Data,
    Frame = derp_frame:keep_alive(),
    ok = send_data(Transport, Socket, Frame),
    TimerRef = erlang:send_after(?KEEPALIVE_INTERVAL, self(), send_keepalive),
    {keep_state, Data#data{keepalive_timer = TimerRef}};

connected({call, From}, {send, DstKey, PacketData}, Data) ->
    #data{socket = Socket, transport = Transport} = Data,
    Frame = derp_frame:send_packet(DstKey, PacketData),
    case send_data(Transport, Socket, Frame) of
        ok -> {keep_state_and_data, [{reply, From, ok}]};
        {error, Reason} -> {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, recv, #data{recv_queue = Queue} = Data) ->
    case queue:out(Queue) of
        {{value, {SrcKey, PacketData}}, NewQueue} ->
            {keep_state, Data#data{recv_queue = NewQueue},
             [{reply, From, {ok, SrcKey, PacketData}}]};
        {empty, _} ->
            %% No packet available, caller will timeout
            {keep_state_and_data, [{reply, From, {error, timeout}}]}
    end;

connected({call, From}, get_server_pubkey, #data{server_pubkey = PubKey}) ->
    {keep_state_and_data, [{reply, From, {ok, PubKey}}]};

connected({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

connected(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}}.

%%--------------------------------------------------------------------
%% State: reconnecting
%%--------------------------------------------------------------------

reconnecting(state_timeout, reconnect, Data) ->
    {next_state, ?CLIENT_STATE_CONNECTING, Data, [{next_event, internal, connect}]};

reconnecting({call, From}, {send, _, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

reconnecting({call, From}, recv, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

reconnecting({call, From}, get_server_pubkey, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

reconnecting({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

reconnecting(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}}.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

handle_handshake_data(Bin, #data{buffer = Buffer} = Data) ->
    NewBuffer = <<Buffer/binary, Bin/binary>>,
    process_handshake(Data#data{buffer = NewBuffer}).

process_handshake(#data{buffer = Buffer} = Data) ->
    case derp_frame:decode(Buffer) of
        {ok, ?FRAME_SERVER_KEY, Payload, Rest} ->
            handle_server_key(Payload, Data#data{buffer = Rest});
        {ok, ?FRAME_SERVER_INFO, Payload, Rest} ->
            handle_server_info(Payload, Data#data{buffer = Rest});
        {more, _} ->
            ok = set_active(Data#data.transport, Data#data.socket, once),
            {keep_state, Data};
        {error, Reason} ->
            logger:error("DERP frame error: ~p", [Reason]),
            maybe_reconnect(Data)
    end.

handle_server_key(Payload, Data) ->
    case Payload of
        <<Magic:8/binary, ServerPubKey:32/binary>> when Magic =:= ?DERP_MAGIC ->
            %% Send client info
            send_client_info(ServerPubKey, Data),
            process_handshake(Data#data{server_pubkey = ServerPubKey});
        _ ->
            logger:error("Invalid server key frame"),
            maybe_reconnect(Data)
    end.

send_client_info(ServerPubKey, #data{keypair = {ClientPubKey, ClientSecKey},
                                      socket = Socket, transport = Transport}) ->
    Info = #{<<"version">> => 1},
    {Nonce, EncInfo} = derp_crypto:encrypt_client_info(Info, ServerPubKey, ClientSecKey),
    Frame = derp_frame:client_info(ClientPubKey, Nonce, EncInfo),
    ok = send_data(Transport, Socket, Frame).

handle_server_info(Payload, #data{keypair = {_ClientPubKey, ClientSecKey},
                                   server_pubkey = ServerPubKey} = Data) ->
    case Payload of
        <<Nonce:24/binary, EncInfo/binary>> ->
            case derp_crypto:decrypt_server_info(EncInfo, Nonce, ServerPubKey, ClientSecKey) of
                {ok, _Info} ->
                    %% Handshake complete, start keepalive timer
                    TimerRef = erlang:send_after(?KEEPALIVE_INTERVAL, self(), send_keepalive),
                    ok = set_active(Data#data.transport, Data#data.socket, once),
                    {next_state, ?CLIENT_STATE_CONNECTED,
                     Data#data{keepalive_timer = TimerRef, buffer = <<>>}};
                {error, Reason} ->
                    logger:error("Failed to decrypt server info: ~p", [Reason]),
                    maybe_reconnect(Data)
            end;
        _ ->
            logger:error("Invalid server info frame"),
            maybe_reconnect(Data)
    end.

handle_connected_data(Bin, #data{buffer = Buffer} = Data) ->
    NewBuffer = <<Buffer/binary, Bin/binary>>,
    process_connected_frames(Data#data{buffer = NewBuffer}).

process_connected_frames(#data{buffer = Buffer} = Data) ->
    case derp_frame:decode(Buffer) of
        {ok, Type, Payload, Rest} ->
            NewData = handle_frame(Type, Payload, Data#data{buffer = Rest}),
            process_connected_frames(NewData);
        {more, _} ->
            ok = set_active(Data#data.transport, Data#data.socket, once),
            {keep_state, Data};
        {error, Reason} ->
            logger:error("DERP frame error: ~p", [Reason]),
            maybe_reconnect(Data)
    end.

handle_frame(?FRAME_RECV_PACKET, Payload, Data) ->
    case Payload of
        <<SrcKey:32/binary, PacketData/binary>> ->
            case Data#data.callback of
                undefined ->
                    %% Queue for synchronous recv
                    Queue = queue:in({SrcKey, PacketData}, Data#data.recv_queue),
                    Data#data{recv_queue = Queue};
                Fun when is_function(Fun, 2) ->
                    %% Call async callback
                    try
                        Fun(SrcKey, PacketData)
                    catch
                        _:Err ->
                            logger:warning("DERP callback error: ~p", [Err])
                    end,
                    Data
            end;
        _ ->
            Data
    end;

handle_frame(?FRAME_PEER_GONE, Payload, Data) ->
    case Payload of
        <<PeerKey:32/binary, Reason:8>> ->
            logger:debug("Peer gone: ~p (reason: ~p)",
                        [base64:encode(PeerKey), Reason]);
        _ ->
            ok
    end,
    Data;

handle_frame(?FRAME_PING, Payload, #data{socket = Socket, transport = Transport} = Data)
  when byte_size(Payload) =:= 8 ->
    Frame = derp_frame:pong(Payload),
    ok = send_data(Transport, Socket, Frame),
    Data;

handle_frame(?FRAME_PONG, _Payload, Data) ->
    Data;

handle_frame(?FRAME_KEEP_ALIVE, _Payload, Data) ->
    Data;

handle_frame(?FRAME_RESTARTING, _Payload, Data) ->
    logger:info("DERP server is restarting"),
    Data;

handle_frame(Type, _Payload, Data) ->
    logger:debug("Unknown DERP frame type: ~p", [Type]),
    Data.

maybe_reconnect(#data{reconnect = false} = Data) ->
    {stop, normal, Data};
maybe_reconnect(#data{reconnect = true, reconnect_delay = Delay} = Data) ->
    %% Cancel keepalive timer if running
    _ = case Data#data.keepalive_timer of
        undefined -> ok;
        Timer -> erlang:cancel_timer(Timer)
    end,
    NewData = Data#data{
        socket = undefined,
        server_pubkey = undefined,
        buffer = <<>>,
        keepalive_timer = undefined
    },
    {next_state, ?CLIENT_STATE_RECONNECTING, NewData,
     [{state_timeout, Delay, reconnect}]}.

send_data(ssl, Socket, Frame) ->
    ssl:send(Socket, Frame);
send_data(gen_tcp, Socket, Frame) ->
    gen_tcp:send(Socket, Frame).

set_active(ssl, Socket, Mode) ->
    ssl:setopts(Socket, [{active, Mode}]);
set_active(gen_tcp, Socket, Mode) ->
    inet:setopts(Socket, [{active, Mode}]).

close_socket(ssl, Socket) ->
    ssl:close(Socket);
close_socket(gen_tcp, Socket) ->
    gen_tcp:close(Socket).
