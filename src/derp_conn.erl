%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP server connection handler.
%%%
%%% Manages a single client connection using gen_statem. Handles the
%%% DERP handshake, packet forwarding, and connection lifecycle.
%%%
%%% States:
%%% - awaiting_client_info: Waiting for client's encrypted info
%%% - authenticated: Client authenticated, relaying packets
%%% - closed: Connection closing/closed
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_conn).

-behaviour(gen_statem).

-include("derp.hrl").

%% API
-export([
    start_link/2,
    start_link/3,
    send_packet/3,
    send_peer_gone/3,
    send_peer_present/2,
    send_forward_packet/4,
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
    deferred_init/3,
    awaiting_client_info/3,
    authenticated/3,
    closed/3
]).

-record(data, {
    socket :: ssl:sslsocket() | gen_tcp:socket() | reference(),
    transport :: ssl | gen_tcp | derp_tls,
    server_keypair :: {binary(), binary()},
    server_mesh_key :: binary() | undefined,
    client_pubkey :: binary() | undefined,
    client_mesh_key :: binary() | undefined,
    is_mesh_client :: boolean(),
    buffer :: binary(),
    keepalive_timer :: reference() | undefined,
    preferred :: boolean()
}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start a connection handler for a new client.
%%
%% @param Socket The accepted TLS/TCP socket
%% @param ServerKeypair The server's {PublicKey, SecretKey} tuple
%% @param Opts Optional map with mesh_key for mesh authentication
-spec start_link(Socket, ServerKeypair) -> {ok, pid()} | {error, term()}
    when Socket :: ssl:sslsocket() | gen_tcp:socket(),
         ServerKeypair :: {binary(), binary()}.
start_link(Socket, ServerKeypair) ->
    start_link(Socket, ServerKeypair, #{}).

-spec start_link(Socket, ServerKeypair, Opts) -> {ok, pid()} | {error, term()}
    when Socket :: ssl:sslsocket() | gen_tcp:socket(),
         ServerKeypair :: {binary(), binary()},
         Opts :: map().
start_link(Socket, ServerKeypair, Opts) ->
    gen_statem:start_link(?MODULE, {Socket, ServerKeypair, Opts}, []).

%% @doc Send a packet to this client from another peer.
%%
%% @param Pid The connection handler pid
%% @param SrcKey Source client's public key
%% @param Data Packet data
-spec send_packet(pid(), binary(), binary()) -> ok.
send_packet(Pid, SrcKey, Data) ->
    gen_statem:cast(Pid, {send_packet, SrcKey, Data}).

%% @doc Notify this client that a peer has gone.
%%
%% @param Pid The connection handler pid
%% @param PeerKey The disconnected peer's public key
%% @param Reason Disconnect reason
-spec send_peer_gone(pid(), binary(), non_neg_integer()) -> ok.
send_peer_gone(Pid, PeerKey, Reason) ->
    gen_statem:cast(Pid, {peer_gone, PeerKey, Reason}).

%% @doc Notify this client that a peer is present (for mesh watchers).
%%
%% @param Pid The connection handler pid
%% @param PeerKey The present peer's public key
-spec send_peer_present(pid(), binary()) -> ok.
send_peer_present(Pid, PeerKey) ->
    gen_statem:cast(Pid, {peer_present, PeerKey}).

%% @doc Forward a packet through this mesh client to the destination.
%%
%% @param Pid The connection handler pid (mesh forwarder)
%% @param SrcKey Source client's public key
%% @param DstKey Destination client's public key
%% @param Data Packet data
-spec send_forward_packet(pid(), binary(), binary(), binary()) -> ok.
send_forward_packet(Pid, SrcKey, DstKey, Data) ->
    gen_statem:cast(Pid, {forward_packet, SrcKey, DstKey, Data}).

%% @doc Close the connection.
-spec close(pid()) -> ok.
close(Pid) ->
    gen_statem:cast(Pid, close).

%%--------------------------------------------------------------------
%% gen_statem callbacks
%%--------------------------------------------------------------------

callback_mode() ->
    state_functions.

init({Socket, ServerKeypair}) ->
    init({Socket, ServerKeypair, #{}});
init({Socket, ServerKeypair, Opts}) ->
    %% Determine transport type
    Transport = case maps:get(transport, Opts, auto) of
        derp_tls -> derp_tls;
        auto ->
            %% Detect socket type - ssl:peername throws function_clause on TCP sockets
            case catch ssl:peername(Socket) of
                {ok, _} -> ssl;
                _ -> gen_tcp
            end
    end,

    %% Get optional mesh key for mesh authentication
    MeshKey = maps:get(mesh_key, Opts, undefined),

    Data = #data{
        socket = Socket,
        transport = Transport,
        server_keypair = ServerKeypair,
        server_mesh_key = MeshKey,
        is_mesh_client = false,
        buffer = <<>>,
        preferred = false
    },

    %% Check if we should defer initialization (for HTTP upgrade)
    case maps:get(deferred_init, Opts, false) of
        true ->
            logger:info("derp_conn ~p: starting in deferred_init mode for socket ~p",
                       [self(), Socket]),
            %% Wait for takeover_complete message before using the socket
            {ok, deferred_init, Data,
             [{state_timeout, ?HANDSHAKE_TIMEOUT, handshake_timeout}]};
        false ->
            logger:info("derp_conn ~p: starting in normal mode for socket ~p",
                       [self(), Socket]),
            %% Normal initialization - send server key immediately
            complete_init(Data)
    end.

%% Complete initialization - send server key and start handshake
complete_init(#data{server_keypair = {ServerPubKey, _}} = Data) ->
    %% Send server key frame (magic + server pubkey)
    ServerKeyFrame = derp_frame:server_key(ServerPubKey),
    ok = send_data(Data#data.transport, Data#data.socket, ServerKeyFrame),

    %% Set socket to active mode for receiving
    ok = set_active(Data#data.transport, Data#data.socket, once),

    %% Start handshake timeout
    {ok, ?STATE_AWAITING_CLIENT_INFO, Data,
     [{state_timeout, ?HANDSHAKE_TIMEOUT, handshake_timeout}]}.

terminate(_Reason, _State, #data{client_pubkey = ClientPubKey} = Data) ->
    %% Unregister from registry if authenticated
    _ = case ClientPubKey of
        undefined -> ok;
        _ -> derp_registry:unregister_client(ClientPubKey)
    end,

    %% Close socket
    _ = close_socket(Data),
    ok.

%%--------------------------------------------------------------------
%% State: deferred_init (waiting for socket ownership transfer)
%%--------------------------------------------------------------------

deferred_init(state_timeout, handshake_timeout, Data) ->
    %% Never received takeover_complete
    {stop, handshake_timeout, Data};

deferred_init(info, {takeover_complete, Buffer}, Data) ->
    %% Socket ownership transferred, now complete initialization
    #data{server_keypair = {ServerPubKey, _}, socket = Socket} = Data,

    logger:info("derp_conn ~p: takeover complete for socket ~p, buffer=~p bytes",
                [self(), Socket, byte_size(Buffer)]),

    %% Send server key frame (magic + server pubkey)
    ServerKeyFrame = derp_frame:server_key(ServerPubKey),
    ok = send_data(Data#data.transport, Data#data.socket, ServerKeyFrame),

    %% Process any buffered data from HTTP upgrade
    NewData = case Buffer of
        <<>> -> Data;
        _ -> Data#data{buffer = Buffer}
    end,

    %% Set socket to active mode for receiving
    ok = set_active(NewData#data.transport, NewData#data.socket, once),

    %% Transition to awaiting_client_info, processing any buffered data
    case NewData#data.buffer of
        <<>> ->
            {next_state, ?STATE_AWAITING_CLIENT_INFO, NewData,
             [{state_timeout, ?HANDSHAKE_TIMEOUT, handshake_timeout}]};
        Buf ->
            %% Process buffered data immediately
            handle_data(<<>>, ?STATE_AWAITING_CLIENT_INFO, NewData#data{buffer = Buf})
    end;

deferred_init(cast, close, Data) ->
    {stop, normal, Data}.

%%--------------------------------------------------------------------
%% State: awaiting_client_info
%%--------------------------------------------------------------------

awaiting_client_info(state_timeout, handshake_timeout, Data) ->
    %% Client didn't complete handshake in time
    {stop, handshake_timeout, Data};

awaiting_client_info(info, {select, TlsRef, _, ready_input},
                     #data{socket = TlsRef, transport = derp_tls} = Data) ->
    case derp_tls:recv(TlsRef) of
        {ok, Bin} ->
            _ = derp_tls:activate(TlsRef),
            handle_data(Bin, ?STATE_AWAITING_CLIENT_INFO, Data);
        {error, want_read} ->
            %% Incomplete TLS record, re-arm and wait
            _ = derp_tls:activate(TlsRef),
            {keep_state, Data};
        {error, closed} ->
            {stop, normal, Data};
        {error, _} ->
            {stop, tls_error, Data}
    end;

awaiting_client_info(info, {ssl, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_data(Bin, ?STATE_AWAITING_CLIENT_INFO, Data);

awaiting_client_info(info, {tcp, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_data(Bin, ?STATE_AWAITING_CLIENT_INFO, Data);

awaiting_client_info(info, {ssl_closed, Socket}, #data{socket = Socket} = Data) ->
    {stop, normal, Data};

awaiting_client_info(info, {tcp_closed, Socket}, #data{socket = Socket} = Data) ->
    {stop, normal, Data};

awaiting_client_info(info, {ssl_error, Socket, Reason}, #data{socket = Socket} = Data) ->
    {stop, {ssl_error, Reason}, Data};

awaiting_client_info(info, {tcp_error, Socket, Reason}, #data{socket = Socket} = Data) ->
    {stop, {tcp_error, Reason}, Data};

awaiting_client_info(cast, close, Data) ->
    {stop, normal, Data}.

%%--------------------------------------------------------------------
%% State: authenticated
%%--------------------------------------------------------------------

authenticated(info, {select, TlsRef, _, ready_input},
              #data{socket = TlsRef, transport = derp_tls} = Data) ->
    case derp_tls:recv(TlsRef) of
        {ok, Bin} ->
            _ = derp_tls:activate(TlsRef),
            handle_data(Bin, ?STATE_AUTHENTICATED, Data);
        {error, want_read} ->
            %% Incomplete TLS record, re-arm and wait
            _ = derp_tls:activate(TlsRef),
            {keep_state, Data};
        {error, closed} ->
            {stop, normal, Data};
        {error, _} ->
            {stop, tls_error, Data}
    end;

authenticated(info, {ssl, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_data(Bin, ?STATE_AUTHENTICATED, Data);

authenticated(info, {tcp, Socket, Bin}, #data{socket = Socket} = Data) ->
    handle_data(Bin, ?STATE_AUTHENTICATED, Data);

authenticated(info, {ssl_closed, Socket}, #data{socket = Socket} = Data) ->
    {stop, normal, Data};

authenticated(info, {tcp_closed, Socket}, #data{socket = Socket} = Data) ->
    {stop, normal, Data};

authenticated(info, {ssl_error, Socket, Reason}, #data{socket = Socket} = Data) ->
    {stop, {ssl_error, Reason}, Data};

authenticated(info, {tcp_error, Socket, Reason}, #data{socket = Socket} = Data) ->
    {stop, {tcp_error, Reason}, Data};

authenticated(info, keepalive_timeout, Data) ->
    %% Client didn't send keepalive in time
    {stop, keepalive_timeout, Data};

authenticated(cast, {send_packet, SrcKey, PacketData}, Data) ->
    %% Forward packet from another peer
    Frame = derp_frame:recv_packet(SrcKey, PacketData),
    ok = send_data(Data#data.transport, Data#data.socket, Frame),
    {keep_state, Data};

authenticated(cast, {peer_gone, PeerKey, Reason}, Data) ->
    %% Notify client that a peer disconnected
    Frame = derp_frame:peer_gone(PeerKey, Reason),
    ok = send_data(Data#data.transport, Data#data.socket, Frame),
    {keep_state, Data};

authenticated(cast, {peer_present, PeerKey}, Data) ->
    %% Notify watcher that a peer connected
    Frame = derp_frame:peer_present(PeerKey),
    ok = send_data(Data#data.transport, Data#data.socket, Frame),
    {keep_state, Data};

authenticated(cast, {forward_packet, SrcKey, DstKey, PacketData}, Data) ->
    %% Forward packet to mesh destination (used by mesh forwarders)
    Frame = derp_frame:forward_packet(SrcKey, DstKey, PacketData),
    ok = send_data(Data#data.transport, Data#data.socket, Frame),
    {keep_state, Data};

authenticated(cast, close, Data) ->
    {stop, normal, Data}.

%%--------------------------------------------------------------------
%% State: closed
%%--------------------------------------------------------------------

closed(_, _, Data) ->
    {stop, normal, Data}.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

handle_data(Bin, State, #data{buffer = Buffer} = Data) ->
    NewBuffer = <<Buffer/binary, Bin/binary>>,
    process_frames(State, Data#data{buffer = NewBuffer}).

process_frames(State, Data) ->
    %% StartState tracks the original state we entered with
    %% FinalState tracks the state after processing all frames
    process_frames_loop(State, State, Data).

%% process_frames_loop/3 tracks state transitions
%% StartState: the state when we started (for comparison)
%% CurrentState: the state used for frame processing (updated on next_state)
process_frames_loop(StartState, CurrentState, #data{buffer = Buffer} = Data) ->
    case derp_frame:decode(Buffer) of
        {ok, Type, Payload, Rest} ->
            case handle_frame(CurrentState, Type, Payload, Data#data{buffer = Rest}) of
                {next_state, NewState, NewData} ->
                    %% State transition - continue with new state
                    process_frames_loop(StartState, NewState, NewData);
                {keep_state, NewData} ->
                    process_frames_loop(StartState, CurrentState, NewData);
                {stop, Reason, NewData} ->
                    {stop, Reason, NewData}
            end;
        {more, _Needed} ->
            %% Need more data, continue receiving
            ok = set_active(Data#data.transport, Data#data.socket, once),
            %% Return appropriate response based on whether state changed
            case StartState =:= CurrentState of
                true -> {keep_state, Data};
                false -> {next_state, CurrentState, Data}
            end;
        {error, Reason} ->
            {stop, {frame_error, Reason}, Data}
    end.

handle_frame(?STATE_AWAITING_CLIENT_INFO, ?FRAME_CLIENT_INFO, Payload, Data) ->
    handle_client_info(Payload, Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_SEND_PACKET, Payload, Data) ->
    handle_send_packet(Payload, Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_KEEP_ALIVE, _Payload, Data) ->
    handle_keepalive(Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_PING, Payload, Data) ->
    handle_ping(Payload, Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_NOTE_PREFERRED, Payload, Data) ->
    handle_note_preferred(Payload, Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_WATCH_CONNS, _Payload, Data) ->
    handle_watch_conns(Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_FORWARD_PACKET, Payload, Data) ->
    handle_forward_packet(Payload, Data);

handle_frame(?STATE_AUTHENTICATED, ?FRAME_CLOSE_PEER, Payload, Data) ->
    handle_close_peer(Payload, Data);

handle_frame(State, Type, _Payload, Data) ->
    %% Unknown or unexpected frame type
    logger:warning("Unexpected frame type ~p in state ~p", [Type, State]),
    {keep_state, Data}.

handle_client_info(Payload, Data) ->
    {_ServerPubKey, ServerSecKey} = Data#data.server_keypair,

    %% Parse client info frame
    case Payload of
        <<ClientPubKey:32/binary, Nonce:24/binary, EncInfo/binary>> ->
            %% Decrypt client info
            case derp_crypto:decrypt_client_info(EncInfo, Nonce, ClientPubKey, ServerSecKey) of
                {ok, Info} ->
                    %% Extract mesh_key if present
                    ClientMeshKey = case Info of
                        #{<<"meshKey">> := MK} when is_binary(MK), byte_size(MK) > 0 -> MK;
                        _ -> undefined
                    end,

                    %% Determine if this is a valid mesh client
                    IsMesh = is_valid_mesh_client(ClientMeshKey, Data#data.server_mesh_key),

                    %% Register client
                    case derp_registry:register_client(ClientPubKey, self()) of
                        ok ->
                            logger:info("derp_conn ~p: client authenticated, transitioning to authenticated state",
                                       [self()]),

                            %% Send server info
                            send_server_info(ClientPubKey, Data),

                            %% Start keepalive timer
                            TimerRef = erlang:send_after(
                                ?KEEPALIVE_INTERVAL * 2, self(), keepalive_timeout),

                            NewData = Data#data{
                                client_pubkey = ClientPubKey,
                                client_mesh_key = ClientMeshKey,
                                is_mesh_client = IsMesh,
                                keepalive_timer = TimerRef
                            },
                            {next_state, ?STATE_AUTHENTICATED, NewData};

                        {error, already_registered} ->
                            logger:warning("Client already registered: ~p",
                                          [base64:encode(ClientPubKey)]),
                            {stop, already_registered, Data}
                    end;

                {error, Reason} ->
                    logger:warning("Failed to decrypt client info: ~p", [Reason]),
                    {stop, {decrypt_failed, Reason}, Data}
            end;
        _ ->
            {stop, invalid_client_info, Data}
    end.

send_server_info(ClientPubKey, #data{server_keypair = {_ServerPubKey, ServerSecKey}} = Data) ->
    Info = #{
        <<"version">> => ?PROTOCOL_VERSION,
        <<"tokenBucketBytesPerSecond">> => ?DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
        <<"tokenBucketBytesBurst">> => ?DEFAULT_RATE_LIMIT_BURST
    },
    {Nonce, EncInfo} = derp_crypto:encrypt_server_info(Info, ClientPubKey, ServerSecKey),
    Frame = derp_frame:server_info(Nonce, EncInfo),
    ok = send_data(Data#data.transport, Data#data.socket, Frame).

handle_send_packet(Payload, #data{client_pubkey = SrcKey} = Data) ->
    case Payload of
        <<DstKey:32/binary, PacketData/binary>> ->
            %% Check rate limit
            ByteCount = byte_size(PacketData),
            case derp_rate_limiter:check(SrcKey, ByteCount) of
                ok ->
                    %% Look up destination: try local first, then mesh forwarders
                    case derp_registry:lookup_client(DstKey) of
                        {ok, DstPid} ->
                            derp_conn:send_packet(DstPid, SrcKey, PacketData);
                        {error, not_found} ->
                            %% Try mesh forwarder
                            case derp_registry:lookup_forwarder(DstKey) of
                                {ok, FwdPid} ->
                                    derp_conn:send_forward_packet(
                                        FwdPid, SrcKey, DstKey, PacketData);
                                {error, not_found} ->
                                    %% No local or mesh route
                                    Frame = derp_frame:peer_gone(
                                        DstKey, ?PEER_GONE_NOT_HERE),
                                    ok = send_data(
                                        Data#data.transport,
                                        Data#data.socket, Frame)
                            end
                    end,
                    {keep_state, Data};

                {error, rate_limited} ->
                    %% Silently drop packet (don't want to leak rate limit info)
                    logger:debug("Rate limited packet from ~p",
                                [base64:encode(SrcKey)]),
                    {keep_state, Data}
            end;
        _ ->
            {stop, invalid_send_packet, Data}
    end.

handle_keepalive(#data{keepalive_timer = OldTimer} = Data) ->
    %% Cancel old timer and start new one
    _ = case OldTimer of
        undefined -> ok;
        _ -> erlang:cancel_timer(OldTimer)
    end,
    NewTimer = erlang:send_after(?KEEPALIVE_INTERVAL * 2, self(), keepalive_timeout),
    {keep_state, Data#data{keepalive_timer = NewTimer}}.

handle_ping(Payload, Data) when byte_size(Payload) =:= 8 ->
    %% Respond with pong
    Frame = derp_frame:pong(Payload),
    ok = send_data(Data#data.transport, Data#data.socket, Frame),
    {keep_state, Data};
handle_ping(_Payload, Data) ->
    {keep_state, Data}.

handle_note_preferred(<<Preferred:8>>, Data) ->
    IsPreferred = Preferred =/= 0,
    {keep_state, Data#data{preferred = IsPreferred}};
handle_note_preferred(_Payload, Data) ->
    {keep_state, Data}.

%% @private Handle WatchConns frame - mesh client subscribes to peer presence.
%% Only allowed for authenticated mesh clients with valid mesh_key.
handle_watch_conns(#data{is_mesh_client = true} = Data) ->
    derp_registry:add_watcher(self()),
    {keep_state, Data};
handle_watch_conns(Data) ->
    logger:warning("Non-mesh client attempted WatchConns"),
    {keep_state, Data}.

%% @private Handle ForwardPacket frame - mesh node forwarding a packet.
%% Only allowed for mesh clients. Delivers the packet to a local client.
handle_forward_packet(Payload, #data{is_mesh_client = true} = Data) ->
    case Payload of
        <<SrcKey:32/binary, DstKey:32/binary, PacketData/binary>> ->
            case derp_registry:lookup_client(DstKey) of
                {ok, DstPid} ->
                    derp_conn:send_packet(DstPid, SrcKey, PacketData);
                {error, not_found} ->
                    %% Destination not on this server either
                    logger:debug("ForwardPacket destination not found: ~p",
                                [base64:encode(DstKey)])
            end,
            {keep_state, Data};
        _ ->
            {stop, invalid_forward_packet, Data}
    end;
handle_forward_packet(_Payload, Data) ->
    logger:warning("Non-mesh client attempted ForwardPacket"),
    {keep_state, Data}.

%% @private Handle ClosePeer frame - mesh node requests closing a peer.
%% Only allowed for mesh clients.
handle_close_peer(Payload, #data{is_mesh_client = true} = Data) ->
    case Payload of
        <<PeerKey:32/binary>> ->
            case derp_registry:lookup_client(PeerKey) of
                {ok, PeerPid} ->
                    derp_conn:close(PeerPid);
                {error, not_found} ->
                    ok
            end,
            {keep_state, Data};
        _ ->
            {stop, invalid_close_peer, Data}
    end;
handle_close_peer(_Payload, Data) ->
    logger:warning("Non-mesh client attempted ClosePeer"),
    {keep_state, Data}.

%% @private Check if client has a valid mesh key.
%% A mesh client is one that presents a mesh_key matching the server's.
%% If the server has no mesh_key configured, no mesh operations are allowed.
is_valid_mesh_client(undefined, _ServerMeshKey) ->
    false;
is_valid_mesh_client(_ClientMeshKey, undefined) ->
    false;
is_valid_mesh_client(ClientMeshKey, ServerMeshKey) ->
    ClientMeshKey =:= ServerMeshKey.

send_data(derp_tls, TlsRef, Data) ->
    derp_tls:send(TlsRef, iolist_to_binary(Data));
send_data(ssl, Socket, Data) ->
    ssl:send(Socket, Data);
send_data(gen_tcp, Socket, Data) ->
    gen_tcp:send(Socket, Data).

set_active(derp_tls, TlsRef, _Mode) ->
    derp_tls:activate(TlsRef);
set_active(ssl, Socket, Mode) ->
    ssl:setopts(Socket, [{active, Mode}]);
set_active(gen_tcp, Socket, Mode) ->
    inet:setopts(Socket, [{active, Mode}]).

close_socket(#data{transport = derp_tls, socket = TlsRef}) ->
    derp_tls:close(TlsRef);
close_socket(#data{transport = ssl, socket = Socket}) ->
    ssl:close(Socket);
close_socket(#data{transport = gen_tcp, socket = Socket}) ->
    gen_tcp:close(Socket).
