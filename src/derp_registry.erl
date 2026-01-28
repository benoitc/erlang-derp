%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Client registry for DERP server.
%%%
%%% Maintains an ETS-backed mapping of public keys to client connection
%%% pids. Automatically cleans up entries when client processes die.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_registry).

-behaviour(gen_server).

%% API
-export([
    start_link/0,
    register_client/2,
    unregister_client/1,
    lookup_client/1,
    list_clients/0,
    count_clients/0
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-define(SERVER, ?MODULE).
-define(TABLE, derp_registry_table).
-define(MONITORS_TABLE, derp_registry_monitors).

-record(state, {}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the registry server.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Register a client connection.
%%
%% Associates a public key with a connection pid. The registry monitors
%% the pid and automatically unregisters it when it dies.
%%
%% @param PubKey The client's 32-byte public key
%% @param Pid The connection handler pid
%% @returns ok | {error, already_registered}
-spec register_client(PubKey :: binary(), Pid :: pid()) ->
    ok | {error, already_registered}.
register_client(PubKey, Pid) when byte_size(PubKey) =:= 32, is_pid(Pid) ->
    gen_server:call(?SERVER, {register, PubKey, Pid}).

%% @doc Unregister a client by public key.
%%
%% @param PubKey The client's public key
%% @returns ok
-spec unregister_client(PubKey :: binary()) -> ok.
unregister_client(PubKey) when byte_size(PubKey) =:= 32 ->
    gen_server:call(?SERVER, {unregister, PubKey}).

%% @doc Look up a client's connection pid by public key.
%%
%% @param PubKey The client's public key
%% @returns {ok, Pid} | {error, not_found}
-spec lookup_client(PubKey :: binary()) -> {ok, pid()} | {error, not_found}.
lookup_client(PubKey) when byte_size(PubKey) =:= 32 ->
    case ets:lookup(?TABLE, PubKey) of
        [{PubKey, Pid}] -> {ok, Pid};
        [] -> {error, not_found}
    end.

%% @doc List all registered clients.
%%
%% @returns List of {PubKey, Pid} tuples
-spec list_clients() -> [{binary(), pid()}].
list_clients() ->
    ets:tab2list(?TABLE).

%% @doc Count registered clients.
%%
%% @returns Number of registered clients
-spec count_clients() -> non_neg_integer().
count_clients() ->
    ets:info(?TABLE, size).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init([]) ->
    %% Create ETS table for key -> pid mapping
    ?TABLE = ets:new(?TABLE, [
        named_table,
        public,              % Allow direct lookups from any process
        {read_concurrency, true}
    ]),

    %% Create ETS table for monitor ref -> key mapping
    %% (to find which key to remove when a process dies)
    ?MONITORS_TABLE = ets:new(?MONITORS_TABLE, [
        named_table,
        protected
    ]),

    {ok, #state{}}.

handle_call({register, PubKey, Pid}, _From, State) ->
    case ets:lookup(?TABLE, PubKey) of
        [{PubKey, ExistingPid}] when ExistingPid =:= Pid ->
            %% Same pid, already registered
            {reply, ok, State};
        [{PubKey, _OtherPid}] ->
            %% Different pid already registered
            {reply, {error, already_registered}, State};
        [] ->
            %% New registration
            MonitorRef = erlang:monitor(process, Pid),
            ets:insert(?TABLE, {PubKey, Pid}),
            ets:insert(?MONITORS_TABLE, {MonitorRef, PubKey}),
            {reply, ok, State}
    end;

handle_call({unregister, PubKey}, _From, State) ->
    do_unregister(PubKey),
    {reply, ok, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MonitorRef, process, _Pid, _Reason}, State) ->
    %% Client process died, clean up registration
    case ets:lookup(?MONITORS_TABLE, MonitorRef) of
        [{MonitorRef, PubKey}] ->
            ets:delete(?MONITORS_TABLE, MonitorRef),
            ets:delete(?TABLE, PubKey);
        [] ->
            ok
    end,
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch ets:delete(?TABLE),
    catch ets:delete(?MONITORS_TABLE),
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

do_unregister(PubKey) ->
    %% Find and demonitor the process
    case ets:lookup(?TABLE, PubKey) of
        [{PubKey, _Pid}] ->
            %% Find the monitor ref for this key
            case ets:match(?MONITORS_TABLE, {'$1', PubKey}) of
                [[MonitorRef]] ->
                    erlang:demonitor(MonitorRef, [flush]),
                    ets:delete(?MONITORS_TABLE, MonitorRef);
                [] ->
                    ok
            end,
            ets:delete(?TABLE, PubKey);
        [] ->
            ok
    end.
