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
%%% Optional header:
%%%   FastStart: 1 - Skip HTTP response, go straight to DERP framing
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_http_handler).

-include("derp.hrl").

%% Cowboy handler callbacks
-export([init/2]).

%%--------------------------------------------------------------------
%% Cowboy callbacks
%%--------------------------------------------------------------------

init(Req0, Opts) ->
    ServerKeypair = maps:get(keypair, Opts),

    %% Check for DERP upgrade request
    case check_derp_upgrade(Req0) of
        {ok, FastStart} ->
            handle_upgrade(Req0, ServerKeypair, FastStart);
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

handle_upgrade(Req0, ServerKeypair, FastStart) ->
    %% Get the underlying transport and socket
    {Transport, Socket} = case cowboy_req:sock(Req0) of
        {tcp, S} -> {gen_tcp, S};
        {ssl, S} -> {ssl, S}
    end,

    %% Send 101 Switching Protocols (unless FastStart)
    case FastStart of
        false ->
            Response = [
                <<"HTTP/1.1 101 Switching Protocols\r\n">>,
                <<"Upgrade: DERP\r\n">>,
                <<"Connection: Upgrade\r\n">>,
                <<"\r\n">>
            ],
            ok = send_raw(Transport, Socket, Response);
        true ->
            %% FastStart: skip HTTP response
            ok
    end,

    %% Start a connection handler to take over the socket
    %% derp_conn will send the server key frame and handle the DERP protocol
    case derp_server_sup:start_connection(Socket, ServerKeypair) of
        {ok, ConnPid} ->
            %% Transfer socket ownership
            ok = controlling_process(Transport, Socket, ConnPid),
            %% Tell Cowboy we're done - connection is now owned by ConnPid
            {ok, Req0, #{upgraded => true}};
        {error, Reason} ->
            logger:warning("Failed to start DERP connection after upgrade: ~p", [Reason]),
            close_socket(Transport, Socket),
            {ok, Req0, #{error => Reason}}
    end.

send_raw(ssl, Socket, Data) ->
    ssl:send(Socket, Data);
send_raw(gen_tcp, Socket, Data) ->
    gen_tcp:send(Socket, Data).

controlling_process(ssl, Socket, Pid) ->
    ssl:controlling_process(Socket, Pid);
controlling_process(gen_tcp, Socket, Pid) ->
    gen_tcp:controlling_process(Socket, Pid).

close_socket(ssl, Socket) ->
    ssl:close(Socket);
close_socket(gen_tcp, Socket) ->
    gen_tcp:close(Socket).
