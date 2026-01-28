%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP top-level supervisor.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% Supervisor callbacks
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },

    Children = [
        %% Client registry
        #{
            id => derp_registry,
            start => {derp_registry, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [derp_registry]
        },
        %% Rate limiter
        #{
            id => derp_rate_limiter,
            start => {derp_rate_limiter, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [derp_rate_limiter]
        },
        %% Server supervisor (for connection handlers)
        #{
            id => derp_server_sup,
            start => {derp_server_sup, start_link, []},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [derp_server_sup]
        },
        %% Client supervisor
        #{
            id => derp_client_sup,
            start => {derp_client_sup, start_link, []},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [derp_client_sup]
        }
    ],

    {ok, {SupFlags, Children}}.
