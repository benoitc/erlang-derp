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

-include("derp.hrl").

%% API
-export([
    start_link/0,
    register_client/2,
    unregister_client/1,
    lookup_client/1,
    list_clients/0,
    count_clients/0,
    %% Mesh mode: watchers
    add_watcher/1,
    remove_watcher/1,
    %% Mesh mode: forwarders
    add_packet_forwarder/2,
    remove_packet_forwarder/2,
    lookup_forwarder/1,
    %% Broadcast
    broadcast/2
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
-define(WATCHERS_TABLE, derp_registry_watchers).
-define(FORWARDERS_TABLE, derp_registry_forwarders).

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

%% @doc Add a watcher (mesh client) that will be notified of peer presence changes.
%% The watcher pid will receive peer_present and peer_gone messages for all
%% currently connected and future clients.
-spec add_watcher(pid()) -> ok.
add_watcher(Pid) when is_pid(Pid) ->
    gen_server:call(?SERVER, {add_watcher, Pid}).

%% @doc Remove a watcher.
-spec remove_watcher(pid()) -> ok.
remove_watcher(Pid) when is_pid(Pid) ->
    gen_server:call(?SERVER, {remove_watcher, Pid}).

%% @doc Register a packet forwarder for a given public key.
%% When a local client lookup fails, the forwarder is tried for routing.
%% This is used by mesh nodes to forward packets to peers on other servers.
-spec add_packet_forwarder(binary(), pid()) -> ok.
add_packet_forwarder(PubKey, ForwarderPid)
  when byte_size(PubKey) =:= 32, is_pid(ForwarderPid) ->
    gen_server:call(?SERVER, {add_forwarder, PubKey, ForwarderPid}).

%% @doc Remove a packet forwarder for a given public key.
-spec remove_packet_forwarder(binary(), pid()) -> ok.
remove_packet_forwarder(PubKey, ForwarderPid)
  when byte_size(PubKey) =:= 32, is_pid(ForwarderPid) ->
    gen_server:call(?SERVER, {remove_forwarder, PubKey, ForwarderPid}).

%% @doc Look up a forwarder for a public key.
%% Called when a local client is not found, to check if a mesh node can forward.
-spec lookup_forwarder(binary()) -> {ok, pid()} | {error, not_found}.
lookup_forwarder(PubKey) when byte_size(PubKey) =:= 32 ->
    case ets:lookup(?FORWARDERS_TABLE, PubKey) of
        [{PubKey, Pid}] -> {ok, Pid};
        [] -> {error, not_found}
    end.

%% @doc Send a packet to all connected clients.
%% SrcKey is the sender's public key, Data is the packet payload.
%% Each client receives a recv_packet frame with the source key and data.
-spec broadcast(binary(), binary()) -> ok.
broadcast(SrcKey, Data) when byte_size(SrcKey) =:= 32, is_binary(Data) ->
    Clients = list_clients(),
    lists:foreach(fun({_PubKey, Pid}) ->
        derp_conn:send_packet(Pid, SrcKey, Data)
    end, Clients),
    ok.

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

    %% Create ETS table for watcher pids (mesh nodes subscribing to presence)
    ?WATCHERS_TABLE = ets:new(?WATCHERS_TABLE, [
        named_table,
        protected,
        set
    ]),

    %% Create ETS table for forwarder mappings (pubkey -> forwarder pid)
    %% Used when a local client is not found and we try mesh forwarding
    ?FORWARDERS_TABLE = ets:new(?FORWARDERS_TABLE, [
        named_table,
        public,
        {read_concurrency, true}
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
            %% Notify watchers of new peer
            notify_watchers({peer_present, PubKey}),
            {reply, ok, State}
    end;

handle_call({unregister, PubKey}, _From, State) ->
    do_unregister(PubKey),
    %% Notify watchers of peer gone
    notify_watchers({peer_gone, PubKey, ?PEER_GONE_DISCONNECTED}),
    {reply, ok, State};

handle_call({add_watcher, Pid}, _From, State) ->
    MonitorRef = erlang:monitor(process, Pid),
    ets:insert(?WATCHERS_TABLE, {Pid, MonitorRef}),
    %% Send current peer list as initial snapshot
    Clients = ets:tab2list(?TABLE),
    lists:foreach(fun({PeerKey, _ClientPid}) ->
        derp_conn:send_peer_present(Pid, PeerKey)
    end, Clients),
    {reply, ok, State};

handle_call({remove_watcher, Pid}, _From, State) ->
    case ets:lookup(?WATCHERS_TABLE, Pid) of
        [{Pid, MonitorRef}] ->
            erlang:demonitor(MonitorRef, [flush]),
            ets:delete(?WATCHERS_TABLE, Pid);
        [] ->
            ok
    end,
    {reply, ok, State};

handle_call({add_forwarder, PubKey, ForwarderPid}, _From, State) ->
    ets:insert(?FORWARDERS_TABLE, {PubKey, ForwarderPid}),
    {reply, ok, State};

handle_call({remove_forwarder, PubKey, ForwarderPid}, _From, State) ->
    case ets:lookup(?FORWARDERS_TABLE, PubKey) of
        [{PubKey, ForwarderPid}] ->
            ets:delete(?FORWARDERS_TABLE, PubKey);
        _ ->
            ok
    end,
    {reply, ok, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MonitorRef, process, Pid, _Reason}, State) ->
    %% Check if this is a client process
    case ets:lookup(?MONITORS_TABLE, MonitorRef) of
        [{MonitorRef, PubKey}] ->
            ets:delete(?MONITORS_TABLE, MonitorRef),
            ets:delete(?TABLE, PubKey),
            %% Clean up any forwarder entries pointing to this pid
            cleanup_forwarders_for_pid(Pid),
            %% Notify watchers of peer gone
            notify_watchers({peer_gone, PubKey, ?PEER_GONE_DISCONNECTED});
        [] ->
            ok
    end,
    %% Check if this is a watcher process
    case ets:lookup(?WATCHERS_TABLE, Pid) of
        [{Pid, _}] ->
            ets:delete(?WATCHERS_TABLE, Pid);
        [] ->
            ok
    end,
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch ets:delete(?TABLE),
    catch ets:delete(?MONITORS_TABLE),
    catch ets:delete(?WATCHERS_TABLE),
    catch ets:delete(?FORWARDERS_TABLE),
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

%% @private Notify all watchers of a presence change.
notify_watchers({peer_present, PubKey}) ->
    Watchers = ets:tab2list(?WATCHERS_TABLE),
    lists:foreach(fun({WatcherPid, _MonRef}) ->
        derp_conn:send_peer_present(WatcherPid, PubKey)
    end, Watchers);
notify_watchers({peer_gone, PubKey, Reason}) ->
    Watchers = ets:tab2list(?WATCHERS_TABLE),
    lists:foreach(fun({WatcherPid, _MonRef}) ->
        derp_conn:send_peer_gone(WatcherPid, PubKey, Reason)
    end, Watchers).

%% @private Clean up forwarder entries that point to a given pid.
cleanup_forwarders_for_pid(Pid) ->
    %% Scan forwarders table for entries pointing to this pid
    ets:foldl(fun({PubKey, FwdPid}, _Acc) ->
        case FwdPid of
            Pid -> ets:delete(?FORWARDERS_TABLE, PubKey);
            _ -> ok
        end
    end, ok, ?FORWARDERS_TABLE).
