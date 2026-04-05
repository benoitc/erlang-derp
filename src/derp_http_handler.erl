%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc HTTP upgrade handler for DERP protocol.
%%%
%%% Handles HTTP upgrade requests at /derp path. When a client sends:
%%%   GET /derp HTTP/1.1
%%%   Upgrade: DERP
%%%   Connection: Upgrade
%%%
%%% The server responds with:
%%%   HTTP/1.1 101 Switching Protocols
%%%   Upgrade: DERP
%%%   Connection: Upgrade
%%%
%%% After upgrade, the connection switches to raw DERP binary protocol
%%% and is handed off to derp_conn for processing.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_http_handler).

-include("derp.hrl").

%% Cowboy handler callbacks
-export([init/2]).

%% Protocol takeover callback
-export([takeover/7]).

%%--------------------------------------------------------------------
%% Cowboy callbacks
%%--------------------------------------------------------------------

init(Req0, Opts) ->
    ServerKeypair = maps:get(keypair, Opts),

    %% Check for DERP upgrade request
    case check_derp_upgrade(Req0) of
        {ok, _FastStart} ->
            handle_upgrade(Req0, ServerKeypair, Opts);
        {error, not_upgrade} ->
            %% Not a DERP upgrade, check if it's a probe/health check
            case cowboy_req:method(Req0) of
                <<"GET">> ->
                    %% Return server info for probes
                    Body = <<"DERP server ready\n">>,
                    Req1 = cowboy_req:reply(200, #{
                        <<"content-type">> => <<"text/plain">>
                    }, Body, Req0),
                    {ok, Req1, Opts};
                _ ->
                    Req1 = cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"DERP upgrade required. Use Upgrade: DERP header.">>, Req0),
                    {ok, Req1, Opts}
            end
    end.

%%--------------------------------------------------------------------
%% Protocol takeover
%%--------------------------------------------------------------------

%% Called by Cowboy after switch_protocol to hand over the raw socket.
%% This function runs in a new process and should never return.
-spec takeover(pid(), term(), inet:socket() | {pid(), cowboy_stream:streamid()},
    module() | undefined, any(), binary(), any()) -> no_return().
takeover(_Parent, _Ref, Socket, Transport, _Opts, Buffer, {ServerKeypair, _HandlerOpts}) ->
    %% Start DERP protocol handler with deferred_init option.
    %% This tells derp_conn to wait before sending data on the socket.
    case derp_server_sup:start_connection(Socket, ServerKeypair, #{deferred_init => true}) of
        {ok, ConnPid} ->
            %% Transfer socket ownership FIRST before derp_conn uses the socket
            ok = controlling_process(Transport, Socket, ConnPid),
            %% Now tell derp_conn it can proceed with the handshake
            ConnPid ! {takeover_complete, Buffer},
            %% Monitor the connection and exit when it dies
            MonRef = monitor(process, ConnPid),
            receive
                {'DOWN', MonRef, process, ConnPid, _Reason} ->
                    exit(normal)
            end;
        {error, Reason} ->
            logger:warning("Failed to start DERP connection after upgrade: ~p", [Reason]),
            _ = close_socket(Transport, Socket),
            exit(normal)
    end.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

check_derp_upgrade(Req) ->
    Upgrade = cowboy_req:header(<<"upgrade">>, Req, <<>>),
    Connection = cowboy_req:header(<<"connection">>, Req, <<>>),
    FastStart = cowboy_req:header(<<"faststart">>, Req, <<"0">>),

    UpgradeLower = string:lowercase(Upgrade),
    HasUpgrade = has_upgrade_token(string:lowercase(Connection)),

    case {UpgradeLower, HasUpgrade} of
        {<<"derp">>, true} ->
            IsFastStart = FastStart =:= <<"1">>,
            {ok, IsFastStart};
        _ ->
            {error, not_upgrade}
    end.

has_upgrade_token(Connection) ->
    %% Connection header may contain multiple tokens: "Upgrade, Keep-Alive"
    Tokens = binary:split(Connection, [<<",">>, <<" ">>], [global, trim_all]),
    lists:member(<<"upgrade">>, Tokens).

handle_upgrade(Req0 = #{pid := Pid, streamid := StreamID}, ServerKeypair, HandlerOpts) ->
    %% Build upgrade response headers
    Headers = cowboy_req:response_headers(#{
        <<"connection">> => <<"Upgrade">>,
        <<"upgrade">> => <<"DERP">>
    }, Req0),

    %% Tell Cowboy to switch protocol - it will call our takeover/7
    Pid ! {{Pid, StreamID}, {switch_protocol, Headers, ?MODULE, {ServerKeypair, HandlerOpts}}},

    %% Return - Cowboy will handle the rest
    {ok, Req0, HandlerOpts}.

controlling_process(undefined, Socket, Pid) ->
    gen_tcp:controlling_process(Socket, Pid);
controlling_process(ssl, Socket, Pid) ->
    ssl:controlling_process(Socket, Pid);
controlling_process(gen_tcp, Socket, Pid) ->
    gen_tcp:controlling_process(Socket, Pid);
controlling_process(ranch_tcp, Socket, Pid) ->
    gen_tcp:controlling_process(Socket, Pid);
controlling_process(ranch_ssl, Socket, Pid) ->
    ssl:controlling_process(Socket, Pid).

close_socket(undefined, Socket) ->
    gen_tcp:close(Socket);
close_socket(ssl, Socket) ->
    ssl:close(Socket);
close_socket(gen_tcp, Socket) ->
    gen_tcp:close(Socket);
close_socket(ranch_tcp, Socket) ->
    gen_tcp:close(Socket);
close_socket(ranch_ssl, Socket) ->
    ssl:close(Socket).
