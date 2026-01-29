%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Common Test integration tests for DERP.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    two_clients_communicate/1,
    client_reconnects/1,
    rate_limiting_enforced/1,
    peer_gone_notification/1,
    multiple_packets/1,
    large_packet/1,
    ping_pong/1,
    keepalive_timeout/1
]).

%%--------------------------------------------------------------------
%% CT Callbacks
%%--------------------------------------------------------------------

all() ->
    [
        {group, basic},
        {group, stress}
    ].

groups() ->
    [
        {basic, [sequence], [
            two_clients_communicate,
            peer_gone_notification,
            ping_pong,
            multiple_packets
        ]},
        {stress, [sequence], [
            rate_limiting_enforced,
            large_packet,
            client_reconnects
            %% keepalive_timeout  % Takes too long for regular tests
        ]}
    ].

init_per_suite(Config) ->
    %% Start applications
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(ssl),

    %% Check if NIF is available
    case code:ensure_loaded(derp_sodium) of
        {module, _} ->
            try
                derp_sodium:randombytes(1),
                Config
            catch
                error:nif_not_loaded ->
                    {skip, "derp_sodium NIF not loaded"}
            end;
        _ ->
            {skip, "derp_sodium module not available"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    %% Stop any existing components from previous runs
    catch gen_server:stop(derp_registry),
    catch gen_server:stop(derp_rate_limiter),
    catch supervisor:stop(derp_server_sup),
    timer:sleep(100),

    %% Start derp application components manually for testing
    %% Use unique names where possible to avoid conflicts
    {ok, Registry} = derp_registry:start_link(),
    {ok, RateLimiter} = derp_rate_limiter:start_link(#{
        bytes_per_sec => 10000,  % Small limit for testing
        burst => 20000
    }),
    {ok, ServerSup} = derp_server_sup:start_link(),

    %% Generate server keypair
    ServerKeypair = derp_crypto:generate_keypair(),

    [{registry, Registry},
     {rate_limiter, RateLimiter},
     {server_sup, ServerSup},
     {server_keypair, ServerKeypair} | Config].

end_per_group(_Group, Config) ->
    %% Stop components gracefully
    ServerSup = ?config(server_sup, Config),
    RateLimiter = ?config(rate_limiter, Config),
    Registry = ?config(registry, Config),

    catch supervisor:stop(ServerSup),
    catch gen_server:stop(RateLimiter),
    catch gen_server:stop(Registry),
    timer:sleep(100),
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% Test Cases
%%--------------------------------------------------------------------

%% @doc Test that two clients can communicate through the relay.
two_clients_communicate(Config) ->
    ServerKeypair = ?config(server_keypair, Config),

    %% Create two clients
    {Client1Pub, Client1Sec} = derp_crypto:generate_keypair(),
    {Client2Pub, Client2Sec} = derp_crypto:generate_keypair(),

    %% Simulate client 1 connection
    {ok, Conn1} = derp_server_sup:start_connection(
        mock_socket(self(), client1),
        ServerKeypair
    ),

    %% Complete handshake for client 1
    ok = complete_handshake(Conn1, Client1Pub, Client1Sec, ServerKeypair),

    %% Simulate client 2 connection
    {ok, Conn2} = derp_server_sup:start_connection(
        mock_socket(self(), client2),
        ServerKeypair
    ),

    %% Complete handshake for client 2
    ok = complete_handshake(Conn2, Client2Pub, Client2Sec, ServerKeypair),

    %% Client 1 sends packet to Client 2
    TestData = <<"Hello from client 1!">>,
    derp_conn:send_packet(Conn1, Client1Pub, TestData),

    %% Verify client 2 receives the packet
    %% (via the mock socket message)
    ok = verify_received_packet(client2, Client1Pub, TestData),

    %% Clean up
    derp_conn:close(Conn1),
    derp_conn:close(Conn2),

    ok.

%% @doc Test peer gone notification when destination not found.
peer_gone_notification(Config) ->
    ServerKeypair = ?config(server_keypair, Config),

    %% Create one client
    {ClientPub, ClientSec} = derp_crypto:generate_keypair(),

    %% Simulate connection
    {ok, Conn} = derp_server_sup:start_connection(
        mock_socket(self(), test_client),
        ServerKeypair
    ),

    ok = complete_handshake(Conn, ClientPub, ClientSec, ServerKeypair),

    %% Try to send to non-existent peer
    NonExistentPeer = derp_crypto:random_bytes(32),

    %% Send packet frame directly (simulate client sending)
    SendFrame = derp_frame:send_packet(NonExistentPeer, <<"test">>),
    Conn ! {tcp, mock_socket, iolist_to_binary(SendFrame)},

    %% Should receive peer gone notification
    receive
        {mock_send, test_client, Data} ->
            {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Data),
            <<RecvKey:32/binary, Reason:8>> = Payload,
            ?assertEqual(NonExistentPeer, RecvKey),
            ?assertEqual(?PEER_GONE_NOT_HERE, Reason)
    after 1000 ->
        ct:fail("Did not receive peer gone notification")
    end,

    derp_conn:close(Conn),
    ok.

%% @doc Test ping/pong mechanism.
ping_pong(Config) ->
    ServerKeypair = ?config(server_keypair, Config),
    {ClientPub, ClientSec} = derp_crypto:generate_keypair(),

    {ok, Conn} = derp_server_sup:start_connection(
        mock_socket(self(), ping_client),
        ServerKeypair
    ),

    ok = complete_handshake(Conn, ClientPub, ClientSec, ServerKeypair),

    %% Send ping
    PingData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    PingFrame = derp_frame:ping(PingData),
    Conn ! {tcp, mock_socket, iolist_to_binary(PingFrame)},

    %% Should receive pong with same data
    receive
        {mock_send, ping_client, Data} ->
            {ok, ?FRAME_PONG, PongData, <<>>} = derp_frame:decode(Data),
            ?assertEqual(PingData, PongData)
    after 1000 ->
        ct:fail("Did not receive pong")
    end,

    derp_conn:close(Conn),
    ok.

%% @doc Test multiple packets in sequence.
multiple_packets(Config) ->
    ServerKeypair = ?config(server_keypair, Config),

    {Client1Pub, Client1Sec} = derp_crypto:generate_keypair(),
    {Client2Pub, Client2Sec} = derp_crypto:generate_keypair(),

    {ok, Conn1} = derp_server_sup:start_connection(
        mock_socket(self(), multi1),
        ServerKeypair
    ),
    ok = complete_handshake(Conn1, Client1Pub, Client1Sec, ServerKeypair),

    {ok, Conn2} = derp_server_sup:start_connection(
        mock_socket(self(), multi2),
        ServerKeypair
    ),
    ok = complete_handshake(Conn2, Client2Pub, Client2Sec, ServerKeypair),

    %% Send multiple packets
    Packets = [<<"packet1">>, <<"packet2">>, <<"packet3">>],
    lists:foreach(fun(P) ->
        derp_conn:send_packet(Conn1, Client1Pub, P)
    end, Packets),

    %% Verify all received
    lists:foreach(fun(ExpectedData) ->
        ok = verify_received_packet(multi2, Client1Pub, ExpectedData)
    end, Packets),

    derp_conn:close(Conn1),
    derp_conn:close(Conn2),
    ok.

%% @doc Test rate limiting.
rate_limiting_enforced(_Config) ->
    %% Create a test client key
    ClientKey = derp_crypto:random_bytes(32),

    %% Send data up to burst limit
    ok = derp_rate_limiter:check(ClientKey, 15000),

    %% Next request should be rate limited
    {error, rate_limited} = derp_rate_limiter:check(ClientKey, 10000),

    %% Reset and verify
    ok = derp_rate_limiter:reset(ClientKey),
    ok = derp_rate_limiter:check(ClientKey, 10000),

    ok.

%% @doc Test large packet handling.
large_packet(Config) ->
    ServerKeypair = ?config(server_keypair, Config),

    {Client1Pub, Client1Sec} = derp_crypto:generate_keypair(),
    {Client2Pub, Client2Sec} = derp_crypto:generate_keypair(),

    {ok, Conn1} = derp_server_sup:start_connection(
        mock_socket(self(), large1),
        ServerKeypair
    ),
    ok = complete_handshake(Conn1, Client1Pub, Client1Sec, ServerKeypair),

    {ok, Conn2} = derp_server_sup:start_connection(
        mock_socket(self(), large2),
        ServerKeypair
    ),
    ok = complete_handshake(Conn2, Client2Pub, Client2Sec, ServerKeypair),

    %% Reset rate limiter for this test
    ok = derp_rate_limiter:reset(Client1Pub),
    ok = derp_rate_limiter:set_limits(derp_rate_limiter, 1000000, 2000000),

    %% Send a large packet (but within limits)
    LargeData = crypto:strong_rand_bytes(10000),
    derp_conn:send_packet(Conn1, Client1Pub, LargeData),

    ok = verify_received_packet(large2, Client1Pub, LargeData),

    derp_conn:close(Conn1),
    derp_conn:close(Conn2),
    ok.

%% @doc Test client reconnection.
client_reconnects(_Config) ->
    %% This test verifies that when a client reconnects,
    %% the registry is properly updated
    ClientKey = derp_crypto:random_bytes(32),

    %% Simulate first connection
    Pid1 = spawn(fun() -> receive stop -> ok end end),
    ok = derp_registry:register_client(ClientKey, Pid1),
    {ok, Pid1} = derp_registry:lookup_client(ClientKey),

    %% Kill first connection
    Pid1 ! stop,
    timer:sleep(50),

    %% Should be unregistered
    {error, not_found} = derp_registry:lookup_client(ClientKey),

    %% Simulate reconnection
    Pid2 = spawn(fun() -> receive stop -> ok end end),
    ok = derp_registry:register_client(ClientKey, Pid2),
    {ok, Pid2} = derp_registry:lookup_client(ClientKey),

    Pid2 ! stop,
    ok.

%% @doc Test keepalive timeout (slow test, typically skipped).
keepalive_timeout(_Config) ->
    %% This test would verify keepalive timeout behavior
    %% but takes too long for regular test runs
    {skip, "Slow test - run manually"}.

%%--------------------------------------------------------------------
%% Helper Functions
%%--------------------------------------------------------------------

%% Create a mock socket that sends data back to the test process
mock_socket(TestPid, ClientId) ->
    spawn(fun() -> mock_socket_loop(TestPid, ClientId) end).

mock_socket_loop(TestPid, ClientId) ->
    receive
        {tcp, send, Data} ->
            TestPid ! {mock_send, ClientId, Data},
            mock_socket_loop(TestPid, ClientId);
        {ssl, send, Data} ->
            TestPid ! {mock_send, ClientId, Data},
            mock_socket_loop(TestPid, ClientId);
        stop ->
            ok
    end.

%% Complete DERP handshake for a connection
complete_handshake(Conn, ClientPub, ClientSec, {ServerPub, _ServerSec}) ->
    ExpectedMagic = ?DERP_MAGIC,
    %% Receive server key frame (already sent during init)
    receive
        {mock_send, _, ServerKeyData} ->
            {ok, ?FRAME_SERVER_KEY, ServerKeyPayload, <<>>} =
                derp_frame:decode(ServerKeyData),
            <<Magic:8/binary, RecvServerPub:32/binary>> = ServerKeyPayload,
            ?assertEqual(ExpectedMagic, Magic),
            ?assertEqual(ServerPub, RecvServerPub)
    after 1000 ->
        ct:fail("Did not receive server key")
    end,

    %% Send client info
    ClientInfo = #{<<"version">> => 1},
    {Nonce, EncInfo} = derp_crypto:encrypt_client_info(ClientInfo, ServerPub, ClientSec),
    ClientInfoFrame = derp_frame:client_info(ClientPub, Nonce, EncInfo),
    Conn ! {tcp, mock_socket, iolist_to_binary(ClientInfoFrame)},

    %% Receive server info
    receive
        {mock_send, _, ServerInfoData} ->
            {ok, ?FRAME_SERVER_INFO, _ServerInfoPayload, <<>>} =
                derp_frame:decode(ServerInfoData),
            ok
    after 1000 ->
        ct:fail("Did not receive server info")
    end,

    ok.

%% Verify a packet was received
verify_received_packet(ClientId, ExpectedSrcKey, ExpectedData) ->
    receive
        {mock_send, ClientId, Data} ->
            {ok, ?FRAME_RECV_PACKET, Payload, <<>>} = derp_frame:decode(Data),
            <<SrcKey:32/binary, PacketData/binary>> = Payload,
            ?assertEqual(ExpectedSrcKey, SrcKey),
            ?assertEqual(ExpectedData, PacketData),
            ok
    after 1000 ->
        ct:fail("Did not receive expected packet")
    end.
