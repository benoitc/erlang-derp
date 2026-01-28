%%%-------------------------------------------------------------------
%%% @doc DERP application callback module.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_app).

-behaviour(application).

-export([start/2, stop/1]).

%%--------------------------------------------------------------------
%% Application callbacks
%%--------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    derp_sup:start_link().

stop(_State) ->
    ok.
