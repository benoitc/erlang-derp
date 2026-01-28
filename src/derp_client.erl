%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP client connection.
%%%
%%% Manages a client connection to a DERP server using gen_statem.
%%% Handles connection establishment, handshake, packet sending/receiving,
%%% and automatic reconnection with exponential backoff.
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
    close/1,
    note_preferred/2,
    get_health/1,
    set_event_callback/2
]).

%% Exported for testing
-export([
    calculate_reconnect_delay/3
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
    http_upgrading/3,
    handshaking/3,
    connected/3,
    reconnecting/3
]).

-record(data, {
    host :: inet:hostname() | inet:ip_address(),
    port :: inet:port_number(),
    keypair :: {binary(), binary()},
    server_pubkey :: binary() | undefined,
    socket :: ssl:sslsocket() | gen_tcp:socket() | reference() | undefined,
    transport :: ssl | gen_tcp | derp_tls,
    buffer :: binary(),
    recv_queue :: queue:queue(),
    callback :: fun((binary(), binary()) -> any()) | undefined,
    reconnect :: boolean(),
    reconnect_delay :: pos_integer(),
    reconnect_attempts = 0 :: non_neg_integer(),
    max_reconnect_delay :: pos_integer(),
    keepalive_timer :: reference() | undefined,
    use_tls :: boolean(),
    tls_opts :: list(),
    tls_backend :: boringssl | otp,
    use_http_upgrade :: boolean(),
    http_path :: binary(),
    health = <<>> :: binary(),
    event_callback :: fun((term()) -> any()) | undefined
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
%% - reconnect_delay: Base delay between reconnect attempts in ms (default: 1000)
%% - max_reconnect_delay: Maximum reconnect delay in ms (default: 30000)
%% - use_tls: Use TLS connection (default: true)
%% - tls_opts: Additional TLS options (default: [])
%% - use_http_upgrade: Use HTTP upgrade to DERP protocol (default: false)
%% - http_path: Path for HTTP upgrade (default: "/derp")
%% - event_callback: Fun/1 for server events (default: undefined)
%%
%% @param Opts Client options map
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_statem:start_link(?MODULE, Opts, []).

%% @doc Send a packet to a peer.
-spec send(pid(), binary(), binary()) -> ok | {error, term()}.
send(Pid, DstKey, Data) when byte_size(DstKey) =:= 32 ->
    gen_statem:call(Pid, {send, DstKey, Data}).

%% @doc Receive a packet synchronously.
-spec recv(pid()) -> {ok, binary(), binary()} | {error, term()}.
recv(Pid) ->
    recv(Pid, 5000).

%% @doc Receive a packet with custom timeout.
-spec recv(pid(), timeout()) -> {ok, binary(), binary()} | {error, term()}.
recv(Pid, Timeout) ->
    gen_statem:call(Pid, recv, Timeout).

%% @doc Set a callback function for received packets.
%% The callback receives (SrcKey, Data) for each incoming packet.
-spec set_callback(pid(), fun() | undefined) -> ok.
set_callback(Pid, Fun) ->
    gen_statem:cast(Pid, {set_callback, Fun}).

%% @doc Get the server's public key.
-spec get_server_pubkey(pid()) -> {ok, binary()} | {error, term()}.
get_server_pubkey(Pid) ->
    gen_statem:call(Pid, get_server_pubkey).

%% @doc Get the client's keypair.
-spec get_keypair(pid()) -> {ok, {binary(), binary()}}.
get_keypair(Pid) ->
    gen_statem:call(Pid, get_keypair).

%% @doc Close the client connection.
-spec close(pid()) -> ok.
close(Pid) ->
    gen_statem:stop(Pid).

%% @doc Send NotePreferred frame to tell the server this is the preferred connection.
%% When a client has multiple DERP connections, it marks one as preferred.
-spec note_preferred(pid(), boolean()) -> ok | {error, term()}.
note_preferred(Pid, Preferred) when is_boolean(Preferred) ->
    gen_statem:call(Pid, {note_preferred, Preferred}).

%% @doc Get the current server health status.
%% Returns empty binary when healthy, or a message string describing the issue.
-spec get_health(pid()) -> {ok, binary()}.
get_health(Pid) ->
    gen_statem:call(Pid, get_health).

%% @doc Set an event callback for server events.
%% The callback receives events like:
%% - {health, Message :: binary()} - Server health change
%% - {restarting, ReconnectMs :: non_neg_integer() | undefined} - Server restarting
%% - {peer_gone, PeerKey :: binary(), Reason :: non_neg_integer()} - Peer left
%% - {peer_present, PeerKey :: binary()} - Peer joined
-spec set_event_callback(pid(), fun((term()) -> any()) | undefined) -> ok.
set_event_callback(Pid, Fun) ->
    gen_statem:cast(Pid, {set_event_callback, Fun}).

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
    MaxReconnectDelay = maps:get(max_reconnect_delay, Opts, 30000),
    UseTls = maps:get(use_tls, Opts, true),
    TlsOpts = maps:get(tls_opts, Opts, []),
    TlsBackend = maps:get(tls_backend, Opts, boringssl),
    UseHttpUpgrade = maps:get(use_http_upgrade, Opts, false),
    HttpPath = maps:get(http_path, Opts, <<"/derp">>),
    EventCallback = maps:get(event_callback, Opts, undefined),

    Transport = case UseTls of
        true ->
            case TlsBackend of
                boringssl -> derp_tls;
                otp -> ssl
            end;
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
        max_reconnect_delay = MaxReconnectDelay,
        use_tls = UseTls,
        tls_opts = TlsOpts,
        tls_backend = TlsBackend,
        use_http_upgrade = UseHttpUpgrade,
        http_path = HttpPath,
        event_callback = EventCallback
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
          use_tls = UseTls, tls_opts = TlsOpts,
          use_http_upgrade = UseHttpUpgrade} = Data,

    case Transport of
        derp_tls ->
            %% BoringSSL path: connect handles TCP + TLS handshake
            HostStr = if is_list(Host) -> Host;
                         is_binary(Host) -> binary_to_list(Host);
                         is_tuple(Host) -> inet:ntoa(Host)
                      end,
            case derp_tls:connect(HostStr, Port, #{verify => false}, 15000) of
                {ok, TlsRef} ->
                    case UseHttpUpgrade of
                        true ->
                            send_http_upgrade(Data#data{socket = TlsRef});
                        false ->
                            %% Already armed for read by derp_tls:connect
                            {next_state, ?CLIENT_STATE_HANDSHAKING,
                             Data#data{socket = TlsRef}}
                    end;
                {error, Reason} ->
                    logger:warning("DERP BoringSSL connect failed: ~p", [Reason]),
                    maybe_reconnect(Data)
            end;
        _ ->
            %% OTP ssl / gen_tcp path
            ConnectOpts = [
                {mode, binary},
                {packet, raw},
                {active, false},
                {nodelay, true}
            ],

            Result = case UseTls of
                true ->
                    SslOpts = ConnectOpts ++ TlsOpts ++ [
                        {verify, verify_none}
                    ],
                    ssl:connect(Host, Port, SslOpts, 10000);
                false ->
                    gen_tcp:connect(Host, Port, ConnectOpts, 10000)
            end,

            case Result of
                {ok, Socket} ->
                    case UseHttpUpgrade of
                        true ->
                            send_http_upgrade(Data#data{socket = Socket});
                        false ->
                            ok = set_active(Transport, Socket, once),
                            {next_state, ?CLIENT_STATE_HANDSHAKING,
                             Data#data{socket = Socket}}
                    end;
                {error, Reason} ->
                    logger:warning("DERP connect failed: ~p", [Reason]),
                    maybe_reconnect(Data)
            end
    end;

connecting({call, From}, {send, _, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, recv, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, get_server_pubkey, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

connecting({call, From}, {note_preferred, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

connecting({call, From}, get_health, #data{health = Health}) ->
    {keep_state_and_data, [{reply, From, {ok, Health}}]};

connecting(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}};

connecting(cast, {set_event_callback, Fun}, Data) ->
    {keep_state, Data#data{event_callback = Fun}}.

%%--------------------------------------------------------------------
%% State: http_upgrading
%%--------------------------------------------------------------------

http_upgrading(info, {select, TlsRef, _, ready_input},
               #data{socket = TlsRef, transport = derp_tls} = Data) ->
    case derp_tls:recv(TlsRef) of
        {ok, Bin} ->
            derp_tls:activate(TlsRef),
            handle_http_upgrade_response(Bin, Data);
        {error, want_read} ->
            %% Incomplete TLS record, re-arm and wait
            derp_tls:activate(TlsRef),
            {keep_state, Data};
        {error, closed} ->
            logger:warning("DERP connection closed during HTTP upgrade"),
            maybe_reconnect(Data#data{socket = undefined});
        {error, _Reason} ->
            logger:warning("DERP TLS recv error during HTTP upgrade"),
            maybe_reconnect(Data#data{socket = undefined})
    end;

http_upgrading(info, {ssl, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_http_upgrade_response(Bin, Data);

http_upgrading(info, {tcp, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_http_upgrade_response(Bin, Data);

http_upgrading(info, {ssl_closed, _}, Data) ->
    logger:warning("DERP connection closed during HTTP upgrade"),
    maybe_reconnect(Data#data{socket = undefined});

http_upgrading(info, {tcp_closed, _}, Data) ->
    logger:warning("DERP connection closed during HTTP upgrade"),
    maybe_reconnect(Data#data{socket = undefined});

http_upgrading(info, {ssl_error, _, Reason}, Data) ->
    logger:warning("DERP SSL error during HTTP upgrade: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined});

http_upgrading(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("DERP TCP error during HTTP upgrade: ~p", [Reason]),
    maybe_reconnect(Data#data{socket = undefined});

http_upgrading({call, From}, {send, _, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

http_upgrading({call, From}, recv, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

http_upgrading({call, From}, get_server_pubkey, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

http_upgrading({call, From}, get_keypair, #data{keypair = Keypair}) ->
    {keep_state_and_data, [{reply, From, {ok, Keypair}}]};

http_upgrading({call, From}, {note_preferred, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

http_upgrading({call, From}, get_health, #data{health = Health}) ->
    {keep_state_and_data, [{reply, From, {ok, Health}}]};

http_upgrading(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}};

http_upgrading(cast, {set_event_callback, Fun}, Data) ->
    {keep_state, Data#data{event_callback = Fun}}.

%%--------------------------------------------------------------------
%% State: handshaking
%%--------------------------------------------------------------------

handshaking(internal, process_buffer, Data) ->
    process_handshake(Data);

handshaking(info, {select, TlsRef, _, ready_input},
            #data{socket = TlsRef, transport = derp_tls} = Data) ->
    case derp_tls:recv(TlsRef) of
        {ok, Bin} ->
            derp_tls:activate(TlsRef),
            handle_handshake_data(Bin, Data);
        {error, want_read} ->
            %% Incomplete TLS record, re-arm and wait
            derp_tls:activate(TlsRef),
            {keep_state, Data};
        {error, closed} ->
            logger:warning("DERP connection closed during handshake"),
            maybe_reconnect(Data#data{socket = undefined});
        {error, _Reason} ->
            logger:warning("DERP TLS error during handshake"),
            maybe_reconnect(Data#data{socket = undefined})
    end;

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

handshaking({call, From}, {note_preferred, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

handshaking({call, From}, get_health, #data{health = Health}) ->
    {keep_state_and_data, [{reply, From, {ok, Health}}]};

handshaking(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}};

handshaking(cast, {set_event_callback, Fun}, Data) ->
    {keep_state, Data#data{event_callback = Fun}}.

%%--------------------------------------------------------------------
%% State: connected
%%--------------------------------------------------------------------

connected(info, {select, TlsRef, _, ready_input},
          #data{socket = TlsRef, transport = derp_tls} = Data) ->
    case derp_tls:recv(TlsRef) of
        {ok, Bin} ->
            derp_tls:activate(TlsRef),
            handle_connected_data(Bin, Data);
        {error, closed} ->
            logger:info("DERP connection closed"),
            maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined});
        {error, want_read} ->
            %% Incomplete TLS record, re-arm and wait
            derp_tls:activate(TlsRef),
            {keep_state, Data};
        {error, _Reason} ->
            logger:warning("DERP TLS error"),
            maybe_reconnect(Data#data{socket = undefined, server_pubkey = undefined})
    end;

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

connected({call, From}, {note_preferred, Preferred}, Data) ->
    #data{socket = Socket, transport = Transport} = Data,
    Frame = derp_frame:note_preferred(Preferred),
    case send_data(Transport, Socket, Frame) of
        ok -> {keep_state_and_data, [{reply, From, ok}]};
        {error, Reason} -> {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, get_health, #data{health = Health}) ->
    {keep_state_and_data, [{reply, From, {ok, Health}}]};

connected(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}};

connected(cast, {set_event_callback, Fun}, Data) ->
    {keep_state, Data#data{event_callback = Fun}}.

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

reconnecting({call, From}, {note_preferred, _}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};

reconnecting({call, From}, get_health, #data{health = Health}) ->
    {keep_state_and_data, [{reply, From, {ok, Health}}]};

reconnecting(cast, {set_callback, Fun}, Data) ->
    {keep_state, Data#data{callback = Fun}};

reconnecting(cast, {set_event_callback, Fun}, Data) ->
    {keep_state, Data#data{event_callback = Fun}}.

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
    Info = #{<<"version">> => ?PROTOCOL_VERSION},
    {Nonce, EncInfo} = derp_crypto:encrypt_client_info(Info, ServerPubKey, ClientSecKey),
    Frame = derp_frame:client_info(ClientPubKey, Nonce, EncInfo),
    ok = send_data(Transport, Socket, Frame).

handle_server_info(Payload, #data{keypair = {_ClientPubKey, ClientSecKey},
                                   server_pubkey = ServerPubKey} = Data) ->
    case Payload of
        <<Nonce:24/binary, EncInfo/binary>> ->
            case derp_crypto:decrypt_server_info(EncInfo, Nonce, ServerPubKey, ClientSecKey) of
                {ok, _Info} ->
                    %% Handshake complete, start keepalive timer, reset backoff
                    TimerRef = erlang:send_after(?KEEPALIVE_INTERVAL, self(), send_keepalive),
                    ok = set_active(Data#data.transport, Data#data.socket, once),
                    {next_state, ?CLIENT_STATE_CONNECTED,
                     Data#data{keepalive_timer = TimerRef, buffer = <<>>,
                               reconnect_attempts = 0}};
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
            case handle_frame(Type, Payload, Data#data{buffer = Rest}) of
                {reconnect, ReconnectMs, NewData} ->
                    %% Server is restarting, close and reconnect
                    _ = close_socket(NewData#data.transport, NewData#data.socket),
                    maybe_reconnect(
                        NewData#data{socket = undefined, server_pubkey = undefined},
                        ReconnectMs);
                NewData ->
                    process_connected_frames(NewData)
            end;
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
                        [base64:encode(PeerKey), Reason]),
            notify_event({peer_gone, PeerKey, Reason}, Data);
        <<PeerKey:32/binary>> ->
            %% Old format without reason byte
            logger:debug("Peer gone: ~p", [base64:encode(PeerKey)]),
            notify_event({peer_gone, PeerKey, ?PEER_GONE_DISCONNECTED}, Data);
        _ ->
            ok
    end,
    Data;

handle_frame(?FRAME_PEER_PRESENT, Payload, Data) ->
    case Payload of
        <<PeerKey:32/binary>> ->
            logger:debug("Peer present: ~p", [base64:encode(PeerKey)]),
            notify_event({peer_present, PeerKey}, Data);
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

handle_frame(?FRAME_HEALTH, Payload, Data) ->
    case Payload of
        <<>> ->
            logger:debug("Server health: OK"),
            notify_event({health, <<>>}, Data),
            Data#data{health = <<>>};
        Message when is_binary(Message) ->
            logger:info("Server health issue: ~s", [Message]),
            notify_event({health, Message}, Data),
            Data#data{health = Message}
    end;

handle_frame(?FRAME_RESTARTING, Payload, Data) ->
    ReconnectMs = case Payload of
        <<Ms:32/big-unsigned>> -> Ms;
        _ -> undefined
    end,
    logger:info("DERP server is restarting~s",
                [case ReconnectMs of
                     undefined -> "";
                     Ms2 -> io_lib:format(", reconnect in ~B ms", [Ms2])
                 end]),
    notify_event({restarting, ReconnectMs}, Data),
    {reconnect, ReconnectMs, Data};

handle_frame(Type, _Payload, Data) ->
    logger:debug("Unknown DERP frame type: ~p", [Type]),
    Data.

%%--------------------------------------------------------------------
%% HTTP Upgrade Functions
%%--------------------------------------------------------------------

send_http_upgrade(#data{host = Host, port = Port, transport = Transport,
                        socket = Socket, http_path = Path} = Data) ->
    %% Build HTTP upgrade request
    HostHeader = case Host of
        H when is_list(H) -> list_to_binary(H);
        H when is_binary(H) -> H;
        {A, B, C, D} -> iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D]))
    end,
    HostWithPort = case Port of
        80 -> HostHeader;
        443 -> HostHeader;
        P -> <<HostHeader/binary, ":", (integer_to_binary(P))/binary>>
    end,

    Request = [
        <<"GET ">>, Path, <<" HTTP/1.1\r\n">>,
        <<"Host: ">>, HostWithPort, <<"\r\n">>,
        <<"Upgrade: DERP\r\n">>,
        <<"Connection: Upgrade\r\n">>,
        <<"\r\n">>
    ],

    case send_data(Transport, Socket, Request) of
        ok ->
            ok = set_active(Transport, Socket, once),
            {next_state, ?CLIENT_STATE_HTTP_UPGRADING, Data};
        {error, Reason} ->
            logger:warning("Failed to send HTTP upgrade request: ~p", [Reason]),
            maybe_reconnect(Data)
    end.

handle_http_upgrade_response(Bin, #data{buffer = Buffer, transport = Transport,
                                         socket = Socket} = Data) ->
    NewBuffer = <<Buffer/binary, Bin/binary>>,

    %% Look for end of HTTP headers
    case binary:match(NewBuffer, <<"\r\n\r\n">>) of
        {Pos, 4} ->
            %% Found end of headers
            HeadersBin = binary:part(NewBuffer, 0, Pos),
            Rest = binary:part(NewBuffer, Pos + 4, byte_size(NewBuffer) - Pos - 4),

            case parse_http_upgrade_response(HeadersBin) of
                ok ->
                    %% HTTP upgrade successful, switch to DERP handshaking
                    NewData = Data#data{buffer = Rest},
                    case Rest of
                        <<>> ->
                            %% No buffered data, wait for next read
                            ok = set_active(Transport, Socket, once),
                            {next_state, ?CLIENT_STATE_HANDSHAKING, NewData};
                        _ ->
                            %% Buffer already has DERP data, process immediately
                            {next_state, ?CLIENT_STATE_HANDSHAKING, NewData,
                             [{next_event, internal, process_buffer}]}
                    end;
                {error, Reason} ->
                    logger:warning("HTTP upgrade failed: ~p", [Reason]),
                    maybe_reconnect(Data#data{socket = undefined})
            end;
        nomatch ->
            %% Need more data
            ok = set_active(Transport, Socket, once),
            {keep_state, Data#data{buffer = NewBuffer}}
    end.

parse_http_upgrade_response(HeadersBin) ->
    Lines = binary:split(HeadersBin, <<"\r\n">>, [global]),
    case Lines of
        [StatusLine | HeaderLines] ->
            case parse_status_line(StatusLine) of
                {ok, 101} ->
                    %% Check for Upgrade: DERP header
                    Headers = parse_headers(HeaderLines),
                    Upgrade = string:lowercase(maps:get(<<"upgrade">>, Headers, <<>>)),
                    case Upgrade of
                        <<"derp">> -> ok;
                        _ -> {error, {missing_upgrade_header, Upgrade}}
                    end;
                {ok, Status} ->
                    {error, {unexpected_status, Status}};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, invalid_response}
    end.

parse_status_line(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [<<"HTTP/1.1">>, StatusBin | _] ->
            try
                Status = binary_to_integer(StatusBin),
                {ok, Status}
            catch
                _:_ -> {error, invalid_status}
            end;
        [<<"HTTP/1.0">>, StatusBin | _] ->
            try
                Status = binary_to_integer(StatusBin),
                {ok, Status}
            catch
                _:_ -> {error, invalid_status}
            end;
        _ ->
            {error, invalid_status_line}
    end.

parse_headers(Lines) ->
    lists:foldl(fun(Line, Acc) ->
        case binary:split(Line, <<": ">>) of
            [Name, Value] ->
                maps:put(string:lowercase(Name), Value, Acc);
            _ ->
                Acc
        end
    end, #{}, Lines).

%%--------------------------------------------------------------------
%% Reconnection with Exponential Backoff
%%--------------------------------------------------------------------

%% @private Reconnect using exponential backoff delay.
maybe_reconnect(Data) ->
    maybe_reconnect(Data, undefined).

%% @private Reconnect with optional explicit delay (e.g. from FrameRestarting).
%% When Delay is undefined, exponential backoff is used.
maybe_reconnect(#data{reconnect = false} = Data, _Delay) ->
    {stop, normal, Data};
maybe_reconnect(Data, Delay) ->
    %% Cancel keepalive timer if running
    _ = case Data#data.keepalive_timer of
        undefined -> ok;
        Timer -> erlang:cancel_timer(Timer)
    end,
    ActualDelay = case Delay of
        undefined ->
            #data{reconnect_delay = BaseDelay, reconnect_attempts = Attempts,
                  max_reconnect_delay = MaxDelay} = Data,
            calculate_reconnect_delay(BaseDelay, Attempts, MaxDelay);
        D ->
            D
    end,
    NewData = Data#data{
        socket = undefined,
        server_pubkey = undefined,
        buffer = <<>>,
        keepalive_timer = undefined,
        reconnect_attempts = Data#data.reconnect_attempts + 1
    },
    {next_state, ?CLIENT_STATE_RECONNECTING, NewData,
     [{state_timeout, ActualDelay, reconnect}]}.

%% @doc Calculate reconnect delay with exponential backoff.
%% Returns BaseDelay * 2^Attempts, capped at MaxDelay.
-spec calculate_reconnect_delay(pos_integer(), non_neg_integer(), pos_integer()) ->
    pos_integer().
calculate_reconnect_delay(BaseDelay, Attempts, MaxDelay) ->
    Delay = BaseDelay * (1 bsl min(Attempts, 16)),
    min(Delay, MaxDelay).

%%--------------------------------------------------------------------
%% Helper Functions
%%--------------------------------------------------------------------

%% @private Notify event callback if set.
notify_event(_Event, #data{event_callback = undefined}) ->
    ok;
notify_event(Event, #data{event_callback = Fun}) when is_function(Fun, 1) ->
    try
        Fun(Event)
    catch
        _:_ -> ok
    end.

send_data(derp_tls, TlsRef, Frame) ->
    derp_tls:send(TlsRef, iolist_to_binary(Frame));
send_data(ssl, Socket, Frame) ->
    ssl:send(Socket, Frame);
send_data(gen_tcp, Socket, Frame) ->
    gen_tcp:send(Socket, Frame).

set_active(derp_tls, TlsRef, _Mode) ->
    derp_tls:activate(TlsRef);
set_active(ssl, Socket, Mode) ->
    ssl:setopts(Socket, [{active, Mode}]);
set_active(gen_tcp, Socket, Mode) ->
    inet:setopts(Socket, [{active, Mode}]).

close_socket(derp_tls, TlsRef) ->
    derp_tls:close(TlsRef);
close_socket(ssl, Socket) ->
    ssl:close(Socket);
close_socket(gen_tcp, Socket) ->
    gen_tcp:close(Socket).
