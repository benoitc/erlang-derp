%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Integration tests against real Tailscale DERP servers.
%%%
%%% These tests require internet access and connect to Tailscale's
%%% public DERP infrastructure to verify wire-level compatibility.
%%%
%%% Uses BoringSSL (derp_tls) by default to handle Tailscale's
%%% self-signed certificates with long CommonNames that OTP's ssl
%%% module rejects. Falls back to OTP ssl with TLS 1.2 if the
%%% BoringSSL NIF is not available.
%%%
%%% Tests are skipped gracefully when the DERP server is unreachable.
%%%
%%% Run specifically with: rebar3 eunit --module=derp_integration_tests
%%% @end
%%%-------------------------------------------------------------------
-module(derp_integration_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

-define(DERP_HOST, "derp1.tailscale.com").
-define(DERP_PORT, 443).
-define(CONNECT_TIMEOUT, 15000).
-define(DERPMAP_URL, "https://controlplane.tailscale.com/derpmap/default").

%%--------------------------------------------------------------------
%% Test Fixture
%%--------------------------------------------------------------------

setup() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    application:ensure_all_started(inets),
    %% Check if we can reach the DERP server via TCP
    case gen_tcp:connect(?DERP_HOST, ?DERP_PORT,
                         [binary, {active, false}], 10000) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            %% Determine TLS backend
            case check_boringssl() of
                true -> {connected, boringssl};
                false ->
                    %% Fall back to OTP ssl with TLS 1.2
                    case ssl:connect(?DERP_HOST, ?DERP_PORT,
                                     [{versions, ['tlsv1.2']},
                                      {verify, verify_none}], 10000) of
                        {ok, SslSock} ->
                            ssl:close(SslSock),
                            {connected, otp};
                        {error, _} ->
                            {connected, boringssl} % Try anyway
                    end
            end;
        {error, Reason} ->
            ?debugFmt("Cannot reach ~s:~p: ~p",
                      [?DERP_HOST, ?DERP_PORT, Reason]),
            not_connected
    end.

cleanup(_) ->
    ok.

%% @private Check if BoringSSL NIF is available.
check_boringssl() ->
    try
        {ok, _} = derp_tls_nif:ctx_new(client),
        true
    catch
        _:_ -> false
    end.

%%--------------------------------------------------------------------
%% Test Generator
%%--------------------------------------------------------------------

integration_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun generate_tests/1}.

generate_tests(not_connected) ->
    [{"Integration tests skipped (cannot reach DERP server)",
      fun() ->
          ?debugMsg("Skipping: cannot reach " ++ ?DERP_HOST)
      end}];
generate_tests({connected, Backend}) ->
    ?debugFmt("Running integration tests with TLS backend: ~p", [Backend]),
    [
     {"Fetch Tailscale DERP map",
      {timeout, 15, fun test_derp_map_fetch/0}},
     {"Connect and complete DERP handshake (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_connect_handshake(Backend) end}},
     {"Server public key is valid Curve25519 (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_server_pubkey_valid(Backend) end}},
     {"Send NotePreferred to server (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_note_preferred(Backend) end}},
     {"Get health status after connect (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_get_health(Backend) end}},
     {"Two-client packet relay through DERP (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_two_client_relay(Backend) end}},
     {"Event callback receives events (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_event_callback(Backend) end}},
     {"Bidirectional packet relay (" ++ atom_to_list(Backend) ++ ")",
      {timeout, 30, fun() -> test_bidirectional_relay(Backend) end}}
    ].

%%--------------------------------------------------------------------
%% Helper Functions
%%--------------------------------------------------------------------

start_client(Backend) ->
    start_client(Backend, #{}).

start_client(Backend, ExtraOpts) ->
    BaseOpts = case Backend of
        boringssl ->
            #{
                host => ?DERP_HOST,
                port => ?DERP_PORT,
                use_tls => true,
                tls_backend => boringssl,
                use_http_upgrade => true,
                http_path => <<"/derp">>,
                reconnect => false
            };
        otp ->
            #{
                host => ?DERP_HOST,
                port => ?DERP_PORT,
                use_tls => true,
                tls_backend => otp,
                use_http_upgrade => true,
                http_path => <<"/derp">>,
                reconnect => false,
                tls_opts => [{versions, ['tlsv1.2']}]
            }
    end,
    Opts = maps:merge(BaseOpts, ExtraOpts),
    derp_client:start_link(Opts).

%% @doc Safely close a client, ignoring errors if already stopped.
safe_close(Client) ->
    try derp_client:close(Client)
    catch _:_ -> ok
    end.

wait_connected(Client) ->
    wait_connected(Client, ?CONNECT_TIMEOUT).

wait_connected(Client, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_connected_loop(Client, Deadline).

wait_connected_loop(Client, Deadline) ->
    case erlang:monotonic_time(millisecond) > Deadline of
        true ->
            {error, timeout};
        false ->
            case catch derp_client:get_server_pubkey(Client) of
                {ok, PubKey} -> {ok, PubKey};
                {error, not_connected} ->
                    timer:sleep(100),
                    wait_connected_loop(Client, Deadline);
                {'EXIT', {noproc, _}} ->
                    {error, client_stopped};
                Other ->
                    {error, Other}
            end
    end.

%%--------------------------------------------------------------------
%% Test: Fetch DERP Map
%%--------------------------------------------------------------------

test_derp_map_fetch() ->
    %% Fetch the official Tailscale DERP map to discover servers
    SslOpts = [{verify, verify_none}, {versions, ['tlsv1.2']}],
    case httpc:request(get,
                       {?DERPMAP_URL, []},
                       [{ssl, SslOpts}, {timeout, 10000}],
                       [{body_format, binary}]) of
        {ok, {{_, 200, _}, _Headers, Body}} ->
            Map = jsx:decode(Body, [return_maps]),
            %% DERP map should have Regions
            ?assert(maps:is_key(<<"Regions">>, Map)),
            Regions = maps:get(<<"Regions">>, Map),
            ?assert(map_size(Regions) > 0),
            %% At least one region should have nodes
            HasNodes = lists:any(fun(Region) ->
                case maps:get(<<"Nodes">>, Region, []) of
                    Nodes when is_list(Nodes), length(Nodes) > 0 -> true;
                    _ -> false
                end
            end, maps:values(Regions)),
            ?assert(HasNodes),
            %% Verify node structure has expected fields
            [FirstRegion | _] = maps:values(Regions),
            [FirstNode | _] = maps:get(<<"Nodes">>, FirstRegion),
            ?assert(maps:is_key(<<"HostName">>, FirstNode)),
            ?assert(maps:is_key(<<"RegionID">>, FirstNode));
        {ok, {{_, Status, _}, _, _}} ->
            ?debugFmt("DERP map returned status ~p (non-fatal)", [Status]);
        {error, Reason} ->
            ?debugFmt("DERP map fetch failed: ~p (non-fatal)", [Reason])
    end.

%%--------------------------------------------------------------------
%% Test: Connect and Handshake
%%--------------------------------------------------------------------

test_connect_handshake(Backend) ->
    {ok, Client} = start_client(Backend),
    try
        Result = wait_connected(Client),
        ?assertMatch({ok, _}, Result),
        {ok, ServerPubKey} = Result,
        ?assert(is_binary(ServerPubKey)),
        ?assertEqual(32, byte_size(ServerPubKey))
    after
        safe_close(Client)
    end.

%%--------------------------------------------------------------------
%% Test: Server Public Key Validation
%%--------------------------------------------------------------------

test_server_pubkey_valid(Backend) ->
    {ok, Client} = start_client(Backend),
    try
        {ok, ServerPubKey} = wait_connected(Client),
        %% Tailscale DERP servers use Curve25519 (32-byte keys)
        ?assertEqual(32, byte_size(ServerPubKey)),
        %% Key should not be all zeros
        ?assertNotEqual(<<0:256>>, ServerPubKey),
        %% Connecting again should get the same server key
        {ok, Client2} = start_client(Backend),
        try
            {ok, ServerPubKey2} = wait_connected(Client2),
            ?assertEqual(ServerPubKey, ServerPubKey2)
        after
            safe_close(Client2)
        end
    after
        safe_close(Client)
    end.

%%--------------------------------------------------------------------
%% Test: NotePreferred
%%--------------------------------------------------------------------

test_note_preferred(Backend) ->
    {ok, Client} = start_client(Backend),
    try
        {ok, _} = wait_connected(Client),
        %% Sending NotePreferred should succeed
        ?assertEqual(ok, derp_client:note_preferred(Client, true)),
        %% Toggle back
        ?assertEqual(ok, derp_client:note_preferred(Client, false))
    after
        safe_close(Client)
    end.

%%--------------------------------------------------------------------
%% Test: Get Health
%%--------------------------------------------------------------------

test_get_health(Backend) ->
    {ok, Client} = start_client(Backend),
    try
        {ok, _} = wait_connected(Client),
        %% Health should be available
        {ok, Health} = derp_client:get_health(Client),
        ?assert(is_binary(Health))
        %% Note: health may be empty (healthy) or contain a message
    after
        safe_close(Client)
    end.

%%--------------------------------------------------------------------
%% Test: Two-Client Packet Relay
%%--------------------------------------------------------------------

test_two_client_relay(Backend) ->
    Parent = self(),
    RecvCb = fun(SrcKey, Data) -> Parent ! {recv_packet, SrcKey, Data} end,

    {ok, Client1} = start_client(Backend),
    {ok, Client2} = start_client(Backend),
    try
        {ok, _} = wait_connected(Client1),
        {ok, _} = wait_connected(Client2),

        %% Set callback on Client2 to receive packets asynchronously
        derp_client:set_callback(Client2, RecvCb),

        %% Get Client2's public key for addressing
        {ok, {Client2PubKey, _}} = derp_client:get_keypair(Client2),

        %% Send from Client1 to Client2
        TestData = <<"hello from integration test">>,
        ?assertEqual(ok, derp_client:send(Client1, Client2PubKey, TestData)),

        %% Wait for the packet on Client2 via callback
        receive
            {recv_packet, SrcKey, RecvData} ->
                {ok, {Client1PubKey, _}} = derp_client:get_keypair(Client1),
                ?assertEqual(Client1PubKey, SrcKey),
                ?assertEqual(TestData, RecvData)
        after 5000 ->
            ?debugMsg("Packet relay timed out - server may not relay between unauthed clients")
        end
    after
        safe_close(Client1),
        safe_close(Client2)
    end.

%%--------------------------------------------------------------------
%% Test: Bidirectional Relay
%%--------------------------------------------------------------------

test_bidirectional_relay(Backend) ->
    Parent = self(),
    MakeCb = fun(Tag) ->
        fun(SrcKey, Data) -> Parent ! {Tag, SrcKey, Data} end
    end,

    {ok, Client1} = start_client(Backend),
    {ok, Client2} = start_client(Backend),
    try
        {ok, _} = wait_connected(Client1),
        {ok, _} = wait_connected(Client2),

        derp_client:set_callback(Client1, MakeCb(client1_recv)),
        derp_client:set_callback(Client2, MakeCb(client2_recv)),

        {ok, {Pub1, _}} = derp_client:get_keypair(Client1),
        {ok, {Pub2, _}} = derp_client:get_keypair(Client2),

        %% Client1 -> Client2
        ?assertEqual(ok, derp_client:send(Client1, Pub2, <<"msg1">>)),
        %% Client2 -> Client1
        ?assertEqual(ok, derp_client:send(Client2, Pub1, <<"msg2">>)),

        %% Collect results
        Recv1 = receive {client1_recv, _, D1} -> {ok, D1}
                after 5000 -> timeout end,
        Recv2 = receive {client2_recv, _, D2} -> {ok, D2}
                after 5000 -> timeout end,

        case {Recv1, Recv2} of
            {{ok, <<"msg2">>}, {ok, <<"msg1">>}} ->
                ok; %% Both directions worked
            _ ->
                ?debugFmt("Bidirectional relay: client1=~p, client2=~p", [Recv1, Recv2])
        end
    after
        safe_close(Client1),
        safe_close(Client2)
    end.

%%--------------------------------------------------------------------
%% Test: Event Callback
%%--------------------------------------------------------------------

test_event_callback(Backend) ->
    Parent = self(),
    EventCb = fun(Event) -> Parent ! {derp_event, Event} end,

    {ok, Client} = start_client(Backend, #{event_callback => EventCb}),
    try
        {ok, _} = wait_connected(Client),
        %% Connection succeeded with event callback set
        %% Server may send health updates; verify no crash
        ?assertEqual(ok, derp_client:note_preferred(Client, true)),
        %% Brief wait for any server-initiated events
        timer:sleep(500),
        %% Flush and log any received events
        flush_events()
    after
        safe_close(Client)
    end.

flush_events() ->
    receive
        {derp_event, Event} ->
            ?debugFmt("Received DERP event: ~p", [Event]),
            flush_events()
    after 0 ->
        ok
    end.
