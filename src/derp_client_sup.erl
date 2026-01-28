%%%-------------------------------------------------------------------
%%% @doc Supervisor for DERP client connections.
%%%
%%% Uses a simple_one_for_one strategy to dynamically supervise
%%% client connection processes.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_client_sup).

-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_client/1
]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the client supervisor.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start a new DERP client.
%%
%% @param Opts Client options (host, port, keypair, etc.)
-spec start_client(map()) -> {ok, pid()} | {error, term()}.
start_client(Opts) ->
    supervisor:start_child(?SERVER, [Opts]).

%%--------------------------------------------------------------------
%% Supervisor callbacks
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 10,
        period => 60
    },

    ChildSpec = #{
        id => derp_client,
        start => {derp_client, start_link, []},
        restart => transient,  % Restart on abnormal exit
        shutdown => 5000,
        type => worker,
        modules => [derp_client]
    },

    {ok, {SupFlags, [ChildSpec]}}.
