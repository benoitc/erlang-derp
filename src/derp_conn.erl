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
    send_packet/3,
    send_peer_gone/3,
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
    awaiting_client_info/3,
    authenticated/3,
    closed/3
]).

-record(data, {
    socket :: ssl:sslsocket() | gen_tcp:socket(),
    transport :: ssl | gen_tcp,
    server_keypair :: {binary(), binary()},
    client_pubkey :: binary() | undefined,
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
-spec start_link(Socket, ServerKeypair) -> {ok, pid()} | {error, term()}
    when Socket :: ssl:sslsocket() | gen_tcp:socket(),
         ServerKeypair :: {binary(), binary()}.
start_link(Socket, ServerKeypair) ->
    gen_statem:start_link(?MODULE, {Socket, ServerKeypair}, []).

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
    %% Determine transport type
    Transport = case ssl:peername(Socket) of
        {ok, _} -> ssl;
        {error, _} -> gen_tcp
    end,

    {ServerPubKey, _ServerSecKey} = ServerKeypair,

    %% Send server key frame (magic + server pubkey)
    ServerKeyFrame = derp_frame:server_key(ServerPubKey),
    ok = send_data(Transport, Socket, ServerKeyFrame),

    %% Set socket to active mode for receiving
    ok = set_active(Transport, Socket, once),

    Data = #data{
        socket = Socket,
        transport = Transport,
        server_keypair = ServerKeypair,
        buffer = <<>>,
        preferred = false
    },

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
%% State: awaiting_client_info
%%--------------------------------------------------------------------

awaiting_client_info(state_timeout, handshake_timeout, Data) ->
    %% Client didn't complete handshake in time
    {stop, handshake_timeout, Data};

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

process_frames(State, #data{buffer = Buffer} = Data) ->
    case derp_frame:decode(Buffer) of
        {ok, Type, Payload, Rest} ->
            case handle_frame(State, Type, Payload, Data#data{buffer = Rest}) of
                {next_state, NewState, NewData} ->
                    process_frames(NewState, NewData);
                {keep_state, NewData} ->
                    process_frames(State, NewData);
                {stop, Reason, NewData} ->
                    {stop, Reason, NewData}
            end;
        {more, _Needed} ->
            %% Need more data, continue receiving
            ok = set_active(Data#data.transport, Data#data.socket, once),
            {keep_state, Data};
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
                {ok, _Info} ->
                    %% Register client
                    case derp_registry:register_client(ClientPubKey, self()) of
                        ok ->
                            %% Send server info
                            send_server_info(ClientPubKey, Data),

                            %% Start keepalive timer
                            TimerRef = erlang:send_after(
                                ?KEEPALIVE_INTERVAL * 2, self(), keepalive_timeout),

                            NewData = Data#data{
                                client_pubkey = ClientPubKey,
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
        <<"version">> => 1,
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
                    %% Look up destination and forward
                    case derp_registry:lookup_client(DstKey) of
                        {ok, DstPid} ->
                            derp_conn:send_packet(DstPid, SrcKey, PacketData);
                        {error, not_found} ->
                            %% Destination not connected, send peer gone
                            Frame = derp_frame:peer_gone(DstKey, ?PEER_GONE_NOT_HERE),
                            ok = send_data(Data#data.transport, Data#data.socket, Frame)
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

send_data(ssl, Socket, Data) ->
    ssl:send(Socket, Data);
send_data(gen_tcp, Socket, Data) ->
    gen_tcp:send(Socket, Data).

set_active(ssl, Socket, Mode) ->
    ssl:setopts(Socket, [{active, Mode}]);
set_active(gen_tcp, Socket, Mode) ->
    inet:setopts(Socket, [{active, Mode}]).

close_socket(#data{transport = ssl, socket = Socket}) ->
    ssl:close(Socket);
close_socket(#data{transport = gen_tcp, socket = Socket}) ->
    gen_tcp:close(Socket).
