%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP test client escript.
%%%
%%% Interactive test client for demonstrating two-client communication
%%% through a DERP server.
%%%
%%% Usage:
%%% ```
%%% derp_test_client receiver HOST PORT
%%% derp_test_client sender HOST PORT DST_PUBKEY_BASE64
%%% '''
%%%
%%% In receiver mode, the client connects and prints its public key,
%%% then waits for incoming messages.
%%%
%%% In sender mode, the client connects and sends test messages to the
%%% specified destination public key.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_test_client).

%% escript entry point
-export([main/1]).

-define(DEFAULT_PORT, 443).

%%--------------------------------------------------------------------
%% Escript Entry Point
%%--------------------------------------------------------------------

main(Args) ->
    %% Start required applications
    ok = start_applications(),

    %% Parse arguments and run
    case parse_args(Args) of
        {receiver, Host, Port} ->
            run_receiver(Host, Port);
        {sender, Host, Port, DstKey} ->
            run_sender(Host, Port, DstKey);
        {error, Reason} ->
            io:format(standard_error, "Error: ~s~n~n", [Reason]),
            print_usage(),
            halt(1)
    end.

%%--------------------------------------------------------------------
%% Argument Parsing
%%--------------------------------------------------------------------

parse_args(["receiver", Host, Port]) ->
    case parse_port(Port) of
        {ok, P} -> {receiver, Host, P};
        error -> {error, "Invalid port number"}
    end;
parse_args(["receiver", Host]) ->
    {receiver, Host, ?DEFAULT_PORT};
parse_args(["sender", Host, Port, DstKeyBase64]) ->
    case parse_port(Port) of
        {ok, P} ->
            case parse_pubkey(DstKeyBase64) of
                {ok, DstKey} -> {sender, Host, P, DstKey};
                error -> {error, "Invalid destination public key (must be base64 encoded)"}
            end;
        error ->
            {error, "Invalid port number"}
    end;
parse_args(["sender", Host, DstKeyBase64]) ->
    case parse_pubkey(DstKeyBase64) of
        {ok, DstKey} -> {sender, Host, ?DEFAULT_PORT, DstKey};
        error -> {error, "Invalid destination public key (must be base64 encoded)"}
    end;
parse_args(["-h" | _]) ->
    print_usage(),
    halt(0);
parse_args(["--help" | _]) ->
    print_usage(),
    halt(0);
parse_args(_) ->
    {error, "Invalid arguments"}.

parse_port(Port) ->
    try
        P = list_to_integer(Port),
        if
            P > 0, P < 65536 -> {ok, P};
            true -> error
        end
    catch
        _:_ -> error
    end.

parse_pubkey(Base64) ->
    try
        Key = base64:decode(Base64),
        case byte_size(Key) of
            32 -> {ok, Key};
            _ -> error
        end
    catch
        _:_ -> error
    end.

print_usage() ->
    io:format("DERP Test Client~n"),
    io:format("~n"),
    io:format("Usage:~n"),
    io:format("  derp_test_client receiver <host> [port]~n"),
    io:format("  derp_test_client sender <host> [port] <dst_pubkey_base64>~n"),
    io:format("~n"),
    io:format("Modes:~n"),
    io:format("  receiver  - Connect and wait for messages, prints own public key~n"),
    io:format("  sender    - Connect and send test messages to the destination key~n"),
    io:format("~n"),
    io:format("Arguments:~n"),
    io:format("  host              - DERP server hostname or IP~n"),
    io:format("  port              - DERP server port (default: 443)~n"),
    io:format("  dst_pubkey_base64 - Destination peer's public key (base64 encoded)~n"),
    io:format("~n"),
    io:format("Example:~n"),
    io:format("  # Terminal 1: Start receiver~n"),
    io:format("  derp_test_client receiver derp-server 443~n"),
    io:format("~n"),
    io:format("  # Terminal 2: Start sender (use pubkey from receiver)~n"),
    io:format("  derp_test_client sender derp-server 443 <pubkey_from_receiver>~n"),
    ok.

%%--------------------------------------------------------------------
%% Application Startup
%%--------------------------------------------------------------------

start_applications() ->
    %% Add lib directory to code path for escript execution
    setup_code_path(),

    %% Start SSL and related apps
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(jsx),

    %% Ensure derp_sodium NIF is loaded (triggers on_load)
    _ = derp_sodium:module_info(),

    ok.

setup_code_path() ->
    %% Get escript directory
    ScriptPath = escript:script_name(),
    ScriptDir = filename:dirname(ScriptPath),
    LibDir = filename:join(ScriptDir, "lib"),

    %% Add all app ebin directories to code path
    case filelib:is_dir(LibDir) of
        true ->
            Apps = filelib:wildcard(filename:join(LibDir, "*")),
            lists:foreach(fun(AppDir) ->
                EbinDir = filename:join(AppDir, "ebin"),
                case filelib:is_dir(EbinDir) of
                    true ->
                        code:add_patha(EbinDir);
                    false ->
                        ok
                end
            end, Apps);
        false ->
            ok
    end.

%%--------------------------------------------------------------------
%% Receiver Mode
%%--------------------------------------------------------------------

run_receiver(Host, Port) ->
    io:format("DERP Receiver Client~n"),
    io:format("Connecting to ~s:~p...~n", [Host, Port]),

    {ok, Client} = derp_client:start_link(#{
        host => Host,
        port => Port,
        use_tls => true,
        tls_opts => [{verify, verify_none}],
        reconnect => true
    }),

    %% Wait for connection
    wait_connected(Client),

    %% Get and print our public key
    {ok, {PubKey, _SecKey}} = derp_client:get_keypair(Client),
    PubKeyBase64 = base64:encode(PubKey),
    io:format("~n"),
    io:format("==========================================~n"),
    io:format("Connected! My public key:~n"),
    io:format("~s~n", [PubKeyBase64]),
    io:format("==========================================~n"),
    io:format("~n"),
    io:format("Waiting for messages... (Ctrl+C to exit)~n"),
    io:format("~n"),

    %% Set up callback for async receive
    derp_client:set_callback(Client, fun(SrcKey, Data) ->
        SrcKeyBase64 = base64:encode(SrcKey),
        io:format("[~s] Received from ~s:~n", [timestamp(), truncate_key(SrcKeyBase64)]),
        io:format("  ~s~n", [Data]),
        io:format("~n")
    end),

    %% Keep running
    receive_loop().

wait_connected(Client) ->
    wait_connected(Client, 50).  % 50 * 100ms = 5 seconds max

wait_connected(_Client, 0) ->
    io:format(standard_error, "Error: Connection timeout~n", []),
    halt(1);
wait_connected(Client, Retries) ->
    case derp_client:get_server_pubkey(Client) of
        {ok, _} ->
            ok;
        {error, not_connected} ->
            timer:sleep(100),
            wait_connected(Client, Retries - 1)
    end.

receive_loop() ->
    receive
        stop -> ok
    end.

%%--------------------------------------------------------------------
%% Sender Mode
%%--------------------------------------------------------------------

run_sender(Host, Port, DstKey) ->
    io:format("DERP Sender Client~n"),
    io:format("Connecting to ~s:~p...~n", [Host, Port]),

    {ok, Client} = derp_client:start_link(#{
        host => Host,
        port => Port,
        use_tls => true,
        tls_opts => [{verify, verify_none}],
        reconnect => true
    }),

    %% Wait for connection
    wait_connected(Client),

    %% Get and print our public key
    {ok, {PubKey, _SecKey}} = derp_client:get_keypair(Client),
    PubKeyBase64 = base64:encode(PubKey),
    DstKeyBase64 = base64:encode(DstKey),
    io:format("~n"),
    io:format("Connected!~n"),
    io:format("My public key: ~s~n", [truncate_key(PubKeyBase64)]),
    io:format("Destination:   ~s~n", [truncate_key(DstKeyBase64)]),
    io:format("~n"),

    %% Send test messages
    send_messages(Client, DstKey).

send_messages(Client, DstKey) ->
    Messages = [
        <<"Hello from the sender!">>,
        <<"This is message #2">>,
        <<"Testing DERP relay...">>,
        <<"Message #4: Still working!">>,
        <<"Final message: Goodbye!">>
    ],

    io:format("Sending ~p messages...~n", [length(Messages)]),
    io:format("~n"),

    lists:foreach(fun(Msg) ->
        io:format("[~s] Sending: ~s~n", [timestamp(), Msg]),
        case derp_client:send(Client, DstKey, Msg) of
            ok ->
                io:format("  -> Sent successfully~n");
            {error, Reason} ->
                io:format("  -> Error: ~p~n", [Reason])
        end,
        timer:sleep(1000)  % 1 second between messages
    end, Messages),

    io:format("~n"),
    io:format("All messages sent. Waiting 3 seconds before exit...~n"),
    timer:sleep(3000),

    derp_client:close(Client),
    io:format("Done.~n").

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

timestamp() ->
    {{Y, M, D}, {H, Mi, S}} = calendar:local_time(),
    io_lib:format("~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B",
                  [Y, M, D, H, Mi, S]).

truncate_key(Base64) when byte_size(Base64) > 20 ->
    <<First:8/binary, _/binary>> = Base64,
    <<First/binary, "...">>;
truncate_key(Base64) ->
    Base64.
