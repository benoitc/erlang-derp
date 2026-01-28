%%%-------------------------------------------------------------------
%%% @doc Unit tests for derp_registry module.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_registry_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Test Fixtures
%%--------------------------------------------------------------------

test_key() ->
    crypto:strong_rand_bytes(32).

registry_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun register_lookup_/1,
      fun register_duplicate_pid_ok_/1,
      fun register_duplicate_key_fails_/1,
      fun unregister_/1,
      fun unregister_nonexistent_/1,
      fun auto_cleanup_on_death_/1,
      fun list_clients_/1,
      fun count_clients_/1,
      fun lookup_not_found_/1
     ]}.

setup() ->
    {ok, Pid} = derp_registry:start_link(),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%--------------------------------------------------------------------
%% Test Cases (instantiators)
%%--------------------------------------------------------------------

register_lookup_(_Pid) ->
    {"register and lookup", fun() ->
        PubKey = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(ok, derp_registry:register_client(PubKey, ClientPid)),
            ?assertEqual({ok, ClientPid}, derp_registry:lookup_client(PubKey))
        after
            ClientPid ! stop
        end
    end}.

register_duplicate_pid_ok_(_Pid) ->
    {"register duplicate pid ok", fun() ->
        PubKey = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(ok, derp_registry:register_client(PubKey, ClientPid)),
            ?assertEqual(ok, derp_registry:register_client(PubKey, ClientPid))
        after
            ClientPid ! stop
        end
    end}.

register_duplicate_key_fails_(_Pid) ->
    {"register duplicate key fails", fun() ->
        PubKey = test_key(),
        Pid1 = spawn(fun() -> receive stop -> ok end end),
        Pid2 = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(ok, derp_registry:register_client(PubKey, Pid1)),
            ?assertEqual({error, already_registered}, derp_registry:register_client(PubKey, Pid2))
        after
            Pid1 ! stop,
            Pid2 ! stop
        end
    end}.

unregister_(_Pid) ->
    {"unregister", fun() ->
        PubKey = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(ok, derp_registry:register_client(PubKey, ClientPid)),
            ?assertEqual({ok, ClientPid}, derp_registry:lookup_client(PubKey)),
            ?assertEqual(ok, derp_registry:unregister_client(PubKey)),
            ?assertEqual({error, not_found}, derp_registry:lookup_client(PubKey))
        after
            ClientPid ! stop
        end
    end}.

unregister_nonexistent_(_Pid) ->
    {"unregister nonexistent", fun() ->
        PubKey = test_key(),
        ?assertEqual(ok, derp_registry:unregister_client(PubKey))
    end}.

auto_cleanup_on_death_(_Pid) ->
    {"auto cleanup on death", fun() ->
        PubKey = test_key(),
        ClientPid = spawn(fun() -> receive stop -> ok end end),
        ?assertEqual(ok, derp_registry:register_client(PubKey, ClientPid)),
        ?assertEqual({ok, ClientPid}, derp_registry:lookup_client(PubKey)),
        ClientPid ! stop,
        timer:sleep(50),
        ?assertEqual({error, not_found}, derp_registry:lookup_client(PubKey))
    end}.

list_clients_(_Pid) ->
    {"list clients", fun() ->
        Key1 = test_key(),
        Key2 = test_key(),
        Key3 = test_key(),
        Pid1 = spawn(fun() -> receive stop -> ok end end),
        Pid2 = spawn(fun() -> receive stop -> ok end end),
        Pid3 = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(ok, derp_registry:register_client(Key1, Pid1)),
            ?assertEqual(ok, derp_registry:register_client(Key2, Pid2)),
            ?assertEqual(ok, derp_registry:register_client(Key3, Pid3)),
            Clients = derp_registry:list_clients(),
            ?assertEqual(3, length(Clients)),
            ?assert(lists:member({Key1, Pid1}, Clients)),
            ?assert(lists:member({Key2, Pid2}, Clients)),
            ?assert(lists:member({Key3, Pid3}, Clients))
        after
            Pid1 ! stop,
            Pid2 ! stop,
            Pid3 ! stop
        end
    end}.

count_clients_(_Pid) ->
    {"count clients", fun() ->
        Key1 = test_key(),
        Key2 = test_key(),
        Pid1 = spawn(fun() -> receive stop -> ok end end),
        Pid2 = spawn(fun() -> receive stop -> ok end end),
        try
            ?assertEqual(0, derp_registry:count_clients()),
            ?assertEqual(ok, derp_registry:register_client(Key1, Pid1)),
            ?assertEqual(1, derp_registry:count_clients()),
            ?assertEqual(ok, derp_registry:register_client(Key2, Pid2)),
            ?assertEqual(2, derp_registry:count_clients()),
            ?assertEqual(ok, derp_registry:unregister_client(Key1)),
            ?assertEqual(1, derp_registry:count_clients())
        after
            Pid1 ! stop,
            Pid2 ! stop
        end
    end}.

lookup_not_found_(_Pid) ->
    {"lookup not found", fun() ->
        PubKey = test_key(),
        ?assertEqual({error, not_found}, derp_registry:lookup_client(PubKey))
    end}.
