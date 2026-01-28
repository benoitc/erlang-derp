%%%-------------------------------------------------------------------
%%% @doc WebSocket handler for DERP protocol.
%%%
%%% Implements a Cowboy WebSocket handler that wraps the DERP binary
%%% protocol in WebSocket binary frames. This allows DERP to work
%%% through HTTP proxies and in browser environments.
%%%
%%% Route: /derp
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_ws_handler).

-include("derp.hrl").

%% Cowboy WebSocket callbacks
-export([
    init/2,
    websocket_init/1,
    websocket_handle/2,
    websocket_info/2,
    terminate/3
]).

-record(state, {
    server_keypair :: {binary(), binary()},
    client_pubkey :: binary() | undefined,
    authenticated :: boolean(),
    buffer :: binary(),
    keepalive_timer :: reference() | undefined
}).

%%--------------------------------------------------------------------
%% Cowboy callbacks
%%--------------------------------------------------------------------

%% @doc Initialize the WebSocket connection.
init(Req, Opts) ->
    ServerKeypair = maps:get(keypair, Opts),
    State = #state{
        server_keypair = ServerKeypair,
        authenticated = false,
        buffer = <<>>
    },
    %% Upgrade to WebSocket
    {cowboy_websocket, Req, State, #{
        idle_timeout => ?KEEPALIVE_INTERVAL * 3,
        max_frame_size => ?MAX_PACKET_SIZE + 1024
    }}.

%% @doc WebSocket connection initialized.
websocket_init(State) ->
    #state{server_keypair = {ServerPubKey, _}} = State,

    %% Send server key frame
    ServerKeyFrame = iolist_to_binary(derp_frame:server_key(ServerPubKey)),

    %% Start handshake timeout
    erlang:send_after(?HANDSHAKE_TIMEOUT, self(), handshake_timeout),

    {[{binary, ServerKeyFrame}], State}.

%% @doc Handle incoming WebSocket frames.
websocket_handle({binary, Data}, State) ->
    handle_data(Data, State);

websocket_handle({text, _}, State) ->
    %% DERP uses binary frames only
    {[{close, 1003, <<"Binary frames only">>}], State};

websocket_handle({ping, Data}, State) ->
    {[{pong, Data}], State};

websocket_handle(_Frame, State) ->
    {ok, State}.

%% @doc Handle Erlang messages.
websocket_info(handshake_timeout, #state{authenticated = false} = State) ->
    %% Client didn't complete handshake in time
    {[{close, 1002, <<"Handshake timeout">>}], State};

websocket_info(handshake_timeout, State) ->
    %% Already authenticated, ignore
    {ok, State};

websocket_info(keepalive_timeout, State) ->
    %% Client didn't send keepalive in time
    {[{close, 1002, <<"Keepalive timeout">>}], State};

websocket_info({send_packet, SrcKey, Data}, #state{authenticated = true} = State) ->
    %% Forward packet from another peer
    Frame = iolist_to_binary(derp_frame:recv_packet(SrcKey, Data)),
    {[{binary, Frame}], State};

websocket_info({peer_gone, PeerKey, Reason}, #state{authenticated = true} = State) ->
    %% Notify client that a peer disconnected
    Frame = iolist_to_binary(derp_frame:peer_gone(PeerKey, Reason)),
    {[{binary, Frame}], State};

websocket_info(_Info, State) ->
    {ok, State}.

%% @doc Connection terminated.
terminate(_Reason, _Req, #state{client_pubkey = undefined}) ->
    ok;
terminate(_Reason, _Req, #state{client_pubkey = ClientPubKey}) ->
    derp_registry:unregister_client(ClientPubKey),
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

handle_data(Data, #state{buffer = Buffer} = State) ->
    NewBuffer = <<Buffer/binary, Data/binary>>,
    process_frames(State#state{buffer = NewBuffer}).

process_frames(#state{buffer = Buffer} = State) ->
    case derp_frame:decode(Buffer) of
        {ok, Type, Payload, Rest} ->
            case handle_frame(Type, Payload, State#state{buffer = Rest}) of
                {ok, NewState} ->
                    process_frames(NewState);
                {reply, Frames, NewState} ->
                    %% Process remaining frames
                    case process_frames(NewState) of
                        {ok, FinalState} ->
                            {Frames, FinalState};
                        {stop, FinalState} ->
                            {[{close, 1000, <<>>}], FinalState};
                        {MoreFrames, FinalState} when is_list(MoreFrames) ->
                            {Frames ++ MoreFrames, FinalState}
                    end;
                {stop, NewState} ->
                    {stop, NewState}
            end;
        {more, _} ->
            {ok, State};
        {error, Reason} ->
            logger:warning("DERP frame error: ~p", [Reason]),
            {[{close, 1002, <<"Protocol error">>}], State}
    end.

handle_frame(?FRAME_CLIENT_INFO, Payload, #state{authenticated = false} = State) ->
    #state{server_keypair = {_ServerPubKey, ServerSecKey}} = State,

    case Payload of
        <<ClientPubKey:32/binary, Nonce:24/binary, EncInfo/binary>> ->
            case derp_crypto:decrypt_client_info(EncInfo, Nonce, ClientPubKey, ServerSecKey) of
                {ok, _Info} ->
                    case derp_registry:register_client(ClientPubKey, self()) of
                        ok ->
                            %% Send server info
                            ServerInfoFrame = make_server_info(ClientPubKey, State),

                            %% Start keepalive timer
                            TimerRef = erlang:send_after(
                                ?KEEPALIVE_INTERVAL * 2, self(), keepalive_timeout),

                            NewState = State#state{
                                client_pubkey = ClientPubKey,
                                authenticated = true,
                                keepalive_timer = TimerRef
                            },
                            {reply, [{binary, ServerInfoFrame}], NewState};

                        {error, already_registered} ->
                            logger:warning("WebSocket client already registered"),
                            {stop, State}
                    end;

                {error, Reason} ->
                    logger:warning("WebSocket decrypt failed: ~p", [Reason]),
                    {stop, State}
            end;
        _ ->
            {stop, State}
    end;

handle_frame(?FRAME_SEND_PACKET, Payload, #state{authenticated = true,
                                                   client_pubkey = SrcKey} = State) ->
    case Payload of
        <<DstKey:32/binary, PacketData/binary>> ->
            ByteCount = byte_size(PacketData),
            case derp_rate_limiter:check(SrcKey, ByteCount) of
                ok ->
                    case derp_registry:lookup_client(DstKey) of
                        {ok, DstPid} ->
                            DstPid ! {send_packet, SrcKey, PacketData},
                            {ok, State};
                        {error, not_found} ->
                            %% Send peer gone
                            Frame = iolist_to_binary(
                                derp_frame:peer_gone(DstKey, ?PEER_GONE_NOT_HERE)),
                            {reply, [{binary, Frame}], State}
                    end;

                {error, rate_limited} ->
                    %% Silently drop
                    {ok, State}
            end;
        _ ->
            {ok, State}
    end;

handle_frame(?FRAME_KEEP_ALIVE, _Payload, #state{authenticated = true} = State) ->
    %% Reset keepalive timer
    _ = case State#state.keepalive_timer of
        undefined -> ok;
        OldTimer -> erlang:cancel_timer(OldTimer)
    end,
    NewTimer = erlang:send_after(?KEEPALIVE_INTERVAL * 2, self(), keepalive_timeout),
    {ok, State#state{keepalive_timer = NewTimer}};

handle_frame(?FRAME_PING, Payload, #state{authenticated = true} = State)
  when byte_size(Payload) =:= 8 ->
    Frame = iolist_to_binary(derp_frame:pong(Payload)),
    {reply, [{binary, Frame}], State};

handle_frame(?FRAME_NOTE_PREFERRED, _Payload, State) ->
    {ok, State};

handle_frame(Type, _Payload, State) ->
    logger:debug("Unexpected WebSocket DERP frame: ~p", [Type]),
    {ok, State}.

make_server_info(ClientPubKey, #state{server_keypair = {_ServerPubKey, ServerSecKey}}) ->
    Info = #{
        <<"version">> => 1,
        <<"tokenBucketBytesPerSecond">> => ?DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
        <<"tokenBucketBytesBurst">> => ?DEFAULT_RATE_LIMIT_BURST
    },
    {Nonce, EncInfo} = derp_crypto:encrypt_server_info(Info, ClientPubKey, ServerSecKey),
    iolist_to_binary(derp_frame:server_info(Nonce, EncInfo)).
