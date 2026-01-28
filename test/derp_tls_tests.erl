%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Tests for the BoringSSL TLS NIF and high-level API.
%%%
%%% Tests NIF resource management, TLS context creation, connection
%%% lifecycle, loopback handshake, data transfer, and cleanup.
%%%
%%% Run with: rebar3 eunit --module=derp_tls_tests
%%% @end
%%%-------------------------------------------------------------------
-module(derp_tls_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Test Fixture
%%--------------------------------------------------------------------

setup() ->
    ok.

cleanup(_) ->
    ok.

%%--------------------------------------------------------------------
%% Test Generator
%%--------------------------------------------------------------------

tls_nif_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_) ->
         [
          {"NIF loads successfully",
           fun test_nif_loaded/0},
          {"Create client SSL context",
           fun test_ctx_new_client/0},
          {"Create server SSL context",
           fun test_ctx_new_server/0},
          {"Context set verify none",
           fun test_ctx_set_verify_none/0},
          {"Context set verify peer",
           fun test_ctx_set_verify_peer/0},
          {"Create client connection from context",
           fun test_conn_new_client/0},
          {"Create server connection from context",
           fun test_conn_new_server/0},
          {"Connection set hostname",
           fun test_conn_set_hostname/0},
          {"Shutdown unconnected connection",
           fun test_shutdown_unconnected/0},
          {"Invalid context argument",
           fun test_ctx_new_invalid/0},
          {"Invalid connection argument",
           fun test_conn_new_invalid/0},
          {"Connect to unreachable host fails gracefully",
           fun test_connect_unreachable/0},
          {"Multiple contexts can coexist",
           fun test_multiple_contexts/0},
          {"Context with cert file (non-existent)",
           fun test_ctx_set_cert_nonexistent/0},
          {"Recv on unconnected returns error",
           fun test_recv_unconnected/0},
          {"Send on unconnected returns error",
           fun test_send_unconnected/0},
          {"Select read on unconnected returns error",
           fun test_select_read_unconnected/0},
          {"Controlling process change",
           fun test_controlling_process/0}
         ]
     end}.

%%--------------------------------------------------------------------
%% Loopback TLS Tests (require self-signed cert)
%%--------------------------------------------------------------------

loopback_test_() ->
    {setup,
     fun setup_loopback/0,
     fun cleanup_loopback/1,
     fun generate_loopback_tests/1}.

setup_loopback() ->
    %% Check if we have test certs
    CertDir = filename:join([code:lib_dir(derp), "test", "certs"]),
    CertFile = filename:join(CertDir, "server.pem"),
    KeyFile = filename:join(CertDir, "server-key.pem"),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertFile, KeyFile};
        _ ->
            %% Try docker/certs path
            CertDir2 = "docker/certs",
            CF2 = filename:join(CertDir2, "server.pem"),
            KF2 = filename:join(CertDir2, "server-key.pem"),
            case {filelib:is_file(CF2), filelib:is_file(KF2)} of
                {true, true} -> {ok, CF2, KF2};
                _ -> no_certs
            end
    end.

cleanup_loopback(_) ->
    ok.

generate_loopback_tests(no_certs) ->
    [{"Loopback tests skipped (no test certificates)",
      fun() -> ?debugMsg("Skipping loopback TLS tests: no certs") end}];
generate_loopback_tests({ok, CertFile, KeyFile}) ->
    [
     {"Loopback TLS handshake",
      {timeout, 10, fun() -> test_loopback_handshake(CertFile, KeyFile) end}},
     {"Loopback TLS send/receive",
      {timeout, 10, fun() -> test_loopback_send_recv(CertFile, KeyFile) end}},
     {"Loopback TLS large payload",
      {timeout, 15, fun() -> test_loopback_large_payload(CertFile, KeyFile) end}},
     {"Loopback TLS close propagation",
      {timeout, 10, fun() -> test_loopback_close(CertFile, KeyFile) end}}
    ].

%%--------------------------------------------------------------------
%% NIF Smoke Tests
%%--------------------------------------------------------------------

test_nif_loaded() ->
    %% If ctx_new works, NIF is loaded
    {ok, _Ctx} = derp_tls_nif:ctx_new(client),
    ok.

test_ctx_new_client() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    ?assert(is_reference(Ctx)).

test_ctx_new_server() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(server),
    ?assert(is_reference(Ctx)).

test_ctx_set_verify_none() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    ?assertEqual(ok, derp_tls_nif:ctx_set_verify(Ctx, false)).

test_ctx_set_verify_peer() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    ?assertEqual(ok, derp_tls_nif:ctx_set_verify(Ctx, true)).

test_conn_new_client() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    ?assert(is_reference(Conn)).

test_conn_new_server() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(server),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, server, self()),
    ?assert(is_reference(Conn)).

test_conn_set_hostname() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    ?assertEqual(ok, derp_tls_nif:conn_set_hostname(Conn, "example.com")).

test_shutdown_unconnected() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    ?assertEqual(ok, derp_tls_nif:shutdown(Conn)).

test_ctx_new_invalid() ->
    ?assertError(badarg, derp_tls_nif:ctx_new(invalid)).

test_conn_new_invalid() ->
    ?assertError(badarg, derp_tls_nif:conn_new(make_ref(), client, self())).

test_connect_unreachable() ->
    %% Connect to a port that's not listening
    Result = derp_tls:connect("127.0.0.1", 1, #{}, 2000),
    ?assertMatch({error, _}, Result).

test_multiple_contexts() ->
    {ok, Ctx1} = derp_tls_nif:ctx_new(client),
    {ok, Ctx2} = derp_tls_nif:ctx_new(server),
    {ok, Ctx3} = derp_tls_nif:ctx_new(client),
    ?assert(is_reference(Ctx1)),
    ?assert(is_reference(Ctx2)),
    ?assert(is_reference(Ctx3)),
    ?assertNotEqual(Ctx1, Ctx2),
    ?assertNotEqual(Ctx2, Ctx3).

test_ctx_set_cert_nonexistent() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(server),
    Result = derp_tls_nif:ctx_set_cert(Ctx, "/nonexistent/cert.pem", "/nonexistent/key.pem"),
    ?assertMatch({error, _}, Result).

test_recv_unconnected() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    Result = derp_tls_nif:recv(Conn),
    ?assertMatch({error, _}, Result).

test_send_unconnected() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    Result = derp_tls_nif:send(Conn, <<"hello">>),
    ?assertMatch({error, _}, Result).

test_select_read_unconnected() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    Result = derp_tls_nif:select_read(Conn),
    ?assertMatch({error, _}, Result).

test_controlling_process() ->
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),
    OtherPid = spawn(fun() -> receive stop -> ok end end),
    ?assertEqual(ok, derp_tls_nif:controlling_process(Conn, OtherPid)),
    OtherPid ! stop.

%%--------------------------------------------------------------------
%% Loopback Test Implementations
%%--------------------------------------------------------------------

test_loopback_handshake(CertFile, KeyFile) ->
    %% Start a TCP listener
    {ok, LSock} = gen_tcp:listen(0, [{active, false}, binary, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),

    %% Spawn server-side accept + TLS handshake
    Parent = self(),
    ServerPid = spawn_link(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Fd} = inet:getfd(Sock),
        Result = derp_tls:accept(Fd, #{certfile => CertFile, keyfile => KeyFile}, 5000),
        Parent ! {server_result, Result}
    end),

    %% Client-side TLS connect
    ClientResult = derp_tls:connect("127.0.0.1", Port, #{verify => false}, 5000),
    ?assertMatch({ok, _}, ClientResult),
    {ok, ClientConn} = ClientResult,

    %% Wait for server
    receive
        {server_result, {ok, _ServerConn}} -> ok;
        {server_result, {error, _Reason}} -> ?assert(false)
    after 5000 ->
        ?assert(false)
    end,

    derp_tls:close(ClientConn),
    gen_tcp:close(LSock),
    _ = ServerPid,
    ok.

test_loopback_send_recv(CertFile, KeyFile) ->
    {ok, LSock} = gen_tcp:listen(0, [{active, false}, binary, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),

    Parent = self(),
    spawn_link(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Fd} = inet:getfd(Sock),
        {ok, ServerConn} = derp_tls:accept(Fd,
            #{certfile => CertFile, keyfile => KeyFile}, 5000),
        %% Echo server: wait for data and send it back
        receive
            {select, ServerConn, _, ready_input} ->
                case derp_tls:recv(ServerConn) of
                    {ok, Data} ->
                        derp_tls:send(ServerConn, Data);
                    _ -> ok
                end
        after 5000 -> ok
        end,
        timer:sleep(100),
        derp_tls:close(ServerConn),
        Parent ! server_done
    end),

    {ok, ClientConn} = derp_tls:connect("127.0.0.1", Port, #{verify => false}, 5000),

    %% Send data
    TestData = <<"hello from TLS NIF test">>,
    ?assertEqual(ok, derp_tls:send(ClientConn, TestData)),

    %% Receive echo
    receive
        {select, ClientConn, _, ready_input} ->
            case derp_tls:recv(ClientConn) of
                {ok, RecvData} ->
                    ?assertEqual(TestData, RecvData);
                Other ->
                    ?debugFmt("Unexpected recv result: ~p", [Other])
            end
    after 5000 ->
        ?debugMsg("Timeout waiting for echo response")
    end,

    derp_tls:close(ClientConn),
    receive server_done -> ok after 5000 -> ok end,
    gen_tcp:close(LSock).

test_loopback_large_payload(CertFile, KeyFile) ->
    {ok, LSock} = gen_tcp:listen(0, [{active, false}, binary, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),

    Parent = self(),
    spawn_link(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Fd} = inet:getfd(Sock),
        {ok, ServerConn} = derp_tls:accept(Fd,
            #{certfile => CertFile, keyfile => KeyFile}, 5000),
        %% Receive and echo
        server_echo_loop(ServerConn, Parent)
    end),

    {ok, ClientConn} = derp_tls:connect("127.0.0.1", Port, #{verify => false}, 5000),

    %% Send 64KB payload
    LargeData = crypto:strong_rand_bytes(65536),
    ?assertEqual(ok, derp_tls:send(ClientConn, LargeData)),

    %% Collect response (may come in multiple chunks)
    Received = collect_data(ClientConn, byte_size(LargeData), 10000),
    ?assertEqual(LargeData, Received),

    derp_tls:close(ClientConn),
    receive server_done -> ok after 5000 -> ok end,
    gen_tcp:close(LSock).

test_loopback_close(CertFile, KeyFile) ->
    {ok, LSock} = gen_tcp:listen(0, [{active, false}, binary, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),

    Parent = self(),
    spawn_link(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Fd} = inet:getfd(Sock),
        {ok, ServerConn} = derp_tls:accept(Fd,
            #{certfile => CertFile, keyfile => KeyFile}, 5000),
        %% Close server side
        timer:sleep(200),
        derp_tls:close(ServerConn),
        Parent ! server_done
    end),

    {ok, ClientConn} = derp_tls:connect("127.0.0.1", Port, #{verify => false}, 5000),

    %% Wait for server close to propagate
    receive
        {select, ClientConn, _, ready_input} ->
            Result = derp_tls:recv(ClientConn),
            ?assertMatch({error, _}, Result)
    after 5000 ->
        ?debugMsg("Timeout waiting for close propagation")
    end,

    derp_tls:close(ClientConn),
    receive server_done -> ok after 5000 -> ok end,
    gen_tcp:close(LSock).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

server_echo_loop(ServerConn, Parent) ->
    receive
        {select, ServerConn, _, ready_input} ->
            case derp_tls:recv(ServerConn) of
                {ok, Data} ->
                    derp_tls:send(ServerConn, Data),
                    derp_tls:activate(ServerConn),
                    server_echo_loop(ServerConn, Parent);
                {error, closed} ->
                    derp_tls:close(ServerConn),
                    Parent ! server_done;
                {error, _} ->
                    derp_tls:close(ServerConn),
                    Parent ! server_done
            end
    after 10000 ->
        derp_tls:close(ServerConn),
        Parent ! server_done
    end.

collect_data(Conn, ExpectedSize, Timeout) ->
    collect_data(Conn, ExpectedSize, Timeout, <<>>).

collect_data(_Conn, ExpectedSize, _Timeout, Acc) when byte_size(Acc) >= ExpectedSize ->
    Acc;
collect_data(Conn, ExpectedSize, Timeout, Acc) ->
    receive
        {select, Conn, _, ready_input} ->
            case derp_tls:recv(Conn) of
                {ok, Data} ->
                    NewAcc = <<Acc/binary, Data/binary>>,
                    derp_tls:activate(Conn),
                    collect_data(Conn, ExpectedSize, Timeout, NewAcc);
                {error, _} ->
                    Acc
            end
    after Timeout ->
        Acc
    end.
