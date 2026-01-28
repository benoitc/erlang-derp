%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Supervisor for DERP server connection handlers.
%%%
%%% Uses a simple_one_for_one strategy to dynamically supervise
%%% connection handler processes.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_server_sup).

-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_connection/2,
    start_connection/3
]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the connection supervisor.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start a new connection handler for an accepted socket.
%%
%% @param Socket The accepted TLS/TCP socket
%% @param ServerKeypair The server's {PublicKey, SecretKey} tuple
-spec start_connection(Socket, ServerKeypair) -> {ok, pid()} | {error, term()}
    when Socket :: ssl:sslsocket() | gen_tcp:socket(),
         ServerKeypair :: {binary(), binary()}.
start_connection(Socket, ServerKeypair) ->
    start_connection(Socket, ServerKeypair, #{}).

%% @doc Start a new connection handler with additional options.
%%
%% @param Socket The accepted TLS/TCP socket
%% @param ServerKeypair The server's {PublicKey, SecretKey} tuple
%% @param Opts Options map (may include mesh_key)
-spec start_connection(Socket, ServerKeypair, Opts) -> {ok, pid()} | {error, term()}
    when Socket :: ssl:sslsocket() | gen_tcp:socket(),
         ServerKeypair :: {binary(), binary()},
         Opts :: map().
start_connection(Socket, ServerKeypair, Opts) ->
    supervisor:start_child(?SERVER, [Socket, ServerKeypair, Opts]).

%%--------------------------------------------------------------------
%% Supervisor callbacks
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 100,
        period => 60
    },

    ChildSpec = #{
        id => derp_conn,
        start => {derp_conn, start_link, []},
        restart => temporary,  % Don't restart failed connections
        shutdown => 5000,
        type => worker,
        modules => [derp_conn]
    },

    {ok, {SupFlags, [ChildSpec]}}.
