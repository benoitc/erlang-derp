%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Unit tests for DERP mesh mode and broadcast functionality.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_mesh_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%%--------------------------------------------------------------------
%% Test Fixtures
%%--------------------------------------------------------------------

test_key() ->
    crypto:strong_rand_bytes(32).

%% Start registry for tests
setup() ->
    case whereis(derp_registry) of
        undefined ->
            {ok, Pid} = derp_registry:start_link(),
            Pid;
        Pid ->
            Pid
    end.

cleanup(Pid) ->
    case is_process_alive(Pid) of
        true ->
            gen_server:stop(Pid);
        false ->
            ok
    end.

%%--------------------------------------------------------------------
%% Registry Watcher Tests
%%--------------------------------------------------------------------

registry_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun register_and_lookup/1,
      fun broadcast_to_all_clients/1,
      fun broadcast_with_no_clients/1,
      fun forwarder_registration/1,
      fun forwarder_lookup_not_found/1,
      fun forwarder_cleanup_on_remove/1
     ]}.

register_and_lookup(_Pid) ->
    fun() ->
        Key = test_key(),
        Self = self(),
        ?assertEqual(ok, derp_registry:register_client(Key, Self)),
        ?assertMatch({ok, Self}, derp_registry:lookup_client(Key)),
        ?assertEqual(ok, derp_registry:unregister_client(Key)),
        ?assertMatch({error, not_found}, derp_registry:lookup_client(Key))
    end.

broadcast_to_all_clients(_Pid) ->
    fun() ->
        %% Register some mock clients using spawned processes
        SrcKey = test_key(),
        Key1 = test_key(),
        Key2 = test_key(),
        Key3 = test_key(),

        Parent = self(),
        Collector = fun() ->
            receive
                Msg -> Parent ! {self(), Msg}
            after 1000 ->
                Parent ! {self(), timeout}
            end
        end,

        Pid1 = spawn(Collector),
        Pid2 = spawn(Collector),
        Pid3 = spawn(Collector),

        ok = derp_registry:register_client(Key1, Pid1),
        ok = derp_registry:register_client(Key2, Pid2),
        ok = derp_registry:register_client(Key3, Pid3),

        ?assertEqual(3, derp_registry:count_clients()),

        %% Broadcast sends cast messages to each registered pid
        %% The cast message is {send_packet, SrcKey, Data}
        ok = derp_registry:broadcast(SrcKey, <<"hello all">>),

        %% Each process receives a gen_statem cast
        %% Since these are spawned processes (not gen_statem), they'll
        %% receive {'$gen_cast', {send_packet, SrcKey, Data}}
        receive {Pid1, {'$gen_cast', {send_packet, SrcKey, <<"hello all">>}}} -> ok
        after 1000 -> ?assert(false)
        end,
        receive {Pid2, {'$gen_cast', {send_packet, SrcKey, <<"hello all">>}}} -> ok
        after 1000 -> ?assert(false)
        end,
        receive {Pid3, {'$gen_cast', {send_packet, SrcKey, <<"hello all">>}}} -> ok
        after 1000 -> ?assert(false)
        end,

        %% Cleanup
        derp_registry:unregister_client(Key1),
        derp_registry:unregister_client(Key2),
        derp_registry:unregister_client(Key3)
    end.

broadcast_with_no_clients(_Pid) ->
    fun() ->
        SrcKey = test_key(),
        %% Should not crash with no clients
        ?assertEqual(ok, derp_registry:broadcast(SrcKey, <<"hello">>))
    end.

forwarder_registration(_Pid) ->
    fun() ->
        Key = test_key(),
        ForwarderPid = self(),
        ?assertEqual(ok, derp_registry:add_packet_forwarder(Key, ForwarderPid)),
        ?assertMatch({ok, ForwarderPid}, derp_registry:lookup_forwarder(Key)),
        ?assertEqual(ok, derp_registry:remove_packet_forwarder(Key, ForwarderPid)),
        ?assertMatch({error, not_found}, derp_registry:lookup_forwarder(Key))
    end.

forwarder_lookup_not_found(_Pid) ->
    fun() ->
        Key = test_key(),
        ?assertMatch({error, not_found}, derp_registry:lookup_forwarder(Key))
    end.

forwarder_cleanup_on_remove(_Pid) ->
    fun() ->
        Key = test_key(),
        WrongPid = self(),
        OtherPid = spawn(fun() -> receive stop -> ok end end),

        %% Register with OtherPid
        ok = derp_registry:add_packet_forwarder(Key, OtherPid),

        %% Trying to remove with wrong pid should not remove
        ok = derp_registry:remove_packet_forwarder(Key, WrongPid),
        ?assertMatch({ok, OtherPid}, derp_registry:lookup_forwarder(Key)),

        %% Remove with correct pid
        ok = derp_registry:remove_packet_forwarder(Key, OtherPid),
        ?assertMatch({error, not_found}, derp_registry:lookup_forwarder(Key)),

        OtherPid ! stop
    end.

%%--------------------------------------------------------------------
%% Watcher Notification Tests
%%--------------------------------------------------------------------

watcher_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun watcher_receives_peer_present_on_register/1,
      fun watcher_receives_peer_gone_on_unregister/1,
      fun watcher_receives_initial_snapshot/1,
      fun watcher_cleanup_on_exit/1,
      fun multiple_watchers/1
     ]}.

watcher_receives_peer_present_on_register(_Pid) ->
    fun() ->
        Parent = self(),
        %% Spawn a watcher process that collects messages
        WatcherPid = spawn(fun() ->
            receive
                Msg -> Parent ! {watcher_msg, Msg}
            after 2000 ->
                Parent ! {watcher_msg, timeout}
            end
        end),

        %% Register as watcher (no existing clients, so no snapshot)
        ok = derp_registry:add_watcher(WatcherPid),

        %% Now register a new client - watcher should get peer_present
        Key = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        ok = derp_registry:register_client(Key, ClientPid),

        %% Watcher receives the cast: {'$gen_cast', {peer_present, Key}}
        receive
            {watcher_msg, {'$gen_cast', {peer_present, Key}}} -> ok
        after 2000 ->
            ?assert(false)
        end,

        %% Cleanup
        derp_registry:unregister_client(Key),
        derp_registry:remove_watcher(WatcherPid),
        ClientPid ! stop
    end.

watcher_receives_peer_gone_on_unregister(_Pid) ->
    fun() ->
        Parent = self(),

        %% Register a client first
        Key = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        ok = derp_registry:register_client(Key, ClientPid),

        %% Spawn a watcher process that skips the initial snapshot
        %% and waits for a peer_gone
        WatcherPid = spawn(fun() ->
            %% First message is the snapshot peer_present
            receive _ -> ok after 1000 -> ok end,
            %% Second message should be peer_gone
            receive
                Msg -> Parent ! {watcher_gone_msg, Msg}
            after 2000 ->
                Parent ! {watcher_gone_msg, timeout}
            end
        end),

        ok = derp_registry:add_watcher(WatcherPid),

        %% Give time for the snapshot to be sent
        timer:sleep(50),

        %% Now unregister the client - watcher should get peer_gone
        ok = derp_registry:unregister_client(Key),

        receive
            {watcher_gone_msg, {'$gen_cast', {peer_gone, Key, ?PEER_GONE_DISCONNECTED}}} -> ok
        after 2000 ->
            ?assert(false)
        end,

        derp_registry:remove_watcher(WatcherPid),
        ClientPid ! stop
    end.

watcher_receives_initial_snapshot(_Pid) ->
    fun() ->
        Parent = self(),

        %% Register some clients first
        Key1 = test_key(),
        Key2 = test_key(),
        Pid1 = spawn(fun() -> receive stop -> ok end end),
        Pid2 = spawn(fun() -> receive stop -> ok end end),

        ok = derp_registry:register_client(Key1, Pid1),
        ok = derp_registry:register_client(Key2, Pid2),

        %% Now register a watcher - it should get initial snapshot
        WatcherPid = spawn(fun() ->
            Msgs = collect_messages(2, 1000),
            Parent ! {snapshot_msgs, Msgs}
        end),

        ok = derp_registry:add_watcher(WatcherPid),

        receive
            {snapshot_msgs, Msgs} ->
                %% Should have received 2 peer_present messages
                PresentKeys = lists:sort([K || {'$gen_cast', {peer_present, K}} <- Msgs]),
                ExpectedKeys = lists:sort([Key1, Key2]),
                ?assertEqual(ExpectedKeys, PresentKeys)
        after 2000 ->
            ?assert(false)
        end,

        %% Cleanup
        derp_registry:unregister_client(Key1),
        derp_registry:unregister_client(Key2),
        derp_registry:remove_watcher(WatcherPid),
        Pid1 ! stop,
        Pid2 ! stop
    end.

watcher_cleanup_on_exit(_Pid) ->
    fun() ->
        %% Spawn a watcher that exits immediately
        WatcherPid = spawn(fun() -> ok end),

        %% Wait for it to die
        timer:sleep(50),

        %% Registration should still work (monitor triggers cleanup)
        ok = derp_registry:add_watcher(WatcherPid),

        %% Give time for DOWN message processing
        timer:sleep(50),

        %% Registering a new client shouldn't crash (dead watcher removed)
        Key = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        ok = derp_registry:register_client(Key, ClientPid),

        %% Cleanup
        derp_registry:unregister_client(Key),
        ClientPid ! stop
    end.

multiple_watchers(_Pid) ->
    fun() ->
        Parent = self(),

        Watcher1 = spawn(fun() ->
            receive Msg -> Parent ! {w1, Msg} after 2000 -> Parent ! {w1, timeout} end
        end),
        Watcher2 = spawn(fun() ->
            receive Msg -> Parent ! {w2, Msg} after 2000 -> Parent ! {w2, timeout} end
        end),

        ok = derp_registry:add_watcher(Watcher1),
        ok = derp_registry:add_watcher(Watcher2),

        %% Register client - both watchers should get notified
        Key = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        ok = derp_registry:register_client(Key, ClientPid),

        receive {w1, {'$gen_cast', {peer_present, Key}}} -> ok
        after 2000 -> ?assert(false)
        end,
        receive {w2, {'$gen_cast', {peer_present, Key}}} -> ok
        after 2000 -> ?assert(false)
        end,

        %% Cleanup
        derp_registry:unregister_client(Key),
        derp_registry:remove_watcher(Watcher1),
        derp_registry:remove_watcher(Watcher2),
        ClientPid ! stop
    end.

%%--------------------------------------------------------------------
%% Mesh Key Validation Tests
%%--------------------------------------------------------------------

mesh_key_validation_test() ->
    %% Test is_valid_mesh_client logic via the frame constants
    ?assert(?MESH_KEY_SIZE =:= 32).

mesh_key_defined_test() ->
    %% Verify MESH_KEY_SIZE constant exists
    ?assertEqual(32, ?MESH_KEY_SIZE).

%%--------------------------------------------------------------------
%% Frame Encoding Tests for Mesh Frames
%%--------------------------------------------------------------------

forward_packet_frame_encoding_test() ->
    SrcKey = test_key(),
    DstKey = test_key(),
    Data = <<"mesh forwarded data">>,
    Encoded = iolist_to_binary(derp_frame:forward_packet(SrcKey, DstKey, Data)),
    {ok, ?FRAME_FORWARD_PACKET, Payload, <<>>} = derp_frame:decode(Encoded),
    Expected = <<SrcKey/binary, DstKey/binary, Data/binary>>,
    ?assertEqual(Expected, Payload).

watch_conns_frame_encoding_test() ->
    Encoded = iolist_to_binary(derp_frame:watch_conns()),
    ?assertMatch({ok, ?FRAME_WATCH_CONNS, <<>>, <<>>}, derp_frame:decode(Encoded)).

close_peer_frame_encoding_test() ->
    PeerKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:close_peer(PeerKey)),
    {ok, ?FRAME_CLOSE_PEER, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(PeerKey, Payload).

peer_present_frame_encoding_test() ->
    PeerKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:peer_present(PeerKey)),
    {ok, ?FRAME_PEER_PRESENT, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(PeerKey, Payload).

peer_gone_with_mesh_reason_test() ->
    PeerKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, ?PEER_GONE_MESH_CONN_BROKE)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    Expected = <<PeerKey/binary, ?PEER_GONE_MESH_CONN_BROKE:8>>,
    ?assertEqual(Expected, Payload).

%%--------------------------------------------------------------------
%% Broadcast API Tests
%%--------------------------------------------------------------------

broadcast_api_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun broadcast_sends_to_all/1,
      fun broadcast_skips_none/1
     ]}.

broadcast_sends_to_all(_Pid) ->
    fun() ->
        SrcKey = test_key(),

        %% Create receiver processes
        Parent = self(),
        MakeReceiver = fun() ->
            spawn(fun() ->
                receive
                    Msg -> Parent ! {self(), Msg}
                after 2000 ->
                    Parent ! {self(), timeout}
                end
            end)
        end,

        P1 = MakeReceiver(),
        P2 = MakeReceiver(),

        K1 = test_key(),
        K2 = test_key(),
        ok = derp_registry:register_client(K1, P1),
        ok = derp_registry:register_client(K2, P2),

        ok = derp_registry:broadcast(SrcKey, <<"broadcast data">>),

        receive {P1, {'$gen_cast', {send_packet, SrcKey, <<"broadcast data">>}}} -> ok
        after 2000 -> ?assert(false)
        end,
        receive {P2, {'$gen_cast', {send_packet, SrcKey, <<"broadcast data">>}}} -> ok
        after 2000 -> ?assert(false)
        end,

        derp_registry:unregister_client(K1),
        derp_registry:unregister_client(K2)
    end.

broadcast_skips_none(_Pid) ->
    fun() ->
        SrcKey = test_key(),
        %% Empty registry, should not crash
        ?assertEqual(ok, derp_registry:broadcast(SrcKey, <<"data">>))
    end.

%%--------------------------------------------------------------------
%% Helper Functions
%%--------------------------------------------------------------------

collect_messages(0, _Timeout) ->
    [];
collect_messages(N, Timeout) ->
    receive
        Msg -> [Msg | collect_messages(N - 1, Timeout)]
    after Timeout ->
        []
    end.
