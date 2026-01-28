%%%-------------------------------------------------------------------
%%% @doc Unit tests for derp_rate_limiter module.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_rate_limiter_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Test Fixtures
%%--------------------------------------------------------------------

test_key() ->
    crypto:strong_rand_bytes(32).

rate_limiter_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun allow_within_limit_/1,
      fun block_excess_/1,
      fun token_refill_/1,
      fun reset_bucket_/1,
      fun multiple_clients_/1,
      fun zero_bytes_/1,
      fun burst_limit_/1,
      fun get_bucket_/1,
      fun set_limits_/1
     ]}.

setup() ->
    {ok, Pid} = derp_rate_limiter:start_link(#{
        bytes_per_sec => 1000,
        burst => 2000
    }),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%--------------------------------------------------------------------
%% Test Cases (instantiators)
%%--------------------------------------------------------------------

allow_within_limit_(_Pid) ->
    {"allow within limit", fun() ->
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 500)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 500)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 500))
    end}.

block_excess_(_Pid) ->
    {"block excess", fun() ->
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 2000)),
        ?assertEqual({error, rate_limited}, derp_rate_limiter:check(ClientKey, 1))
    end}.

token_refill_(_Pid) ->
    {"token refill", fun() ->
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 2000)),
        ?assertEqual({error, rate_limited}, derp_rate_limiter:check(ClientKey, 1)),
        timer:sleep(150),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 50))
    end}.

reset_bucket_(_Pid) ->
    {"reset bucket", fun() ->
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 2000)),
        ?assertEqual({error, rate_limited}, derp_rate_limiter:check(ClientKey, 1)),
        ?assertEqual(ok, derp_rate_limiter:reset(ClientKey)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 2000))
    end}.

multiple_clients_(_Pid) ->
    {"multiple clients", fun() ->
        Client1 = test_key(),
        Client2 = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(Client1, 2000)),
        ?assertEqual({error, rate_limited}, derp_rate_limiter:check(Client1, 1)),
        ?assertEqual(ok, derp_rate_limiter:check(Client2, 2000))
    end}.

zero_bytes_(_Pid) ->
    {"zero bytes", fun() ->
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 0)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 2000)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 0))
    end}.

burst_limit_(_Pid) ->
    {"burst limit", fun() ->
        ClientKey = test_key(),
        ?assertEqual({error, rate_limited}, derp_rate_limiter:check(ClientKey, 3000))
    end}.

get_bucket_(_Pid) ->
    {"get bucket", fun() ->
        ClientKey = test_key(),
        ?assertEqual({error, not_found}, derp_rate_limiter:get_bucket(ClientKey)),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 500)),
        {ok, Bucket} = derp_rate_limiter:get_bucket(ClientKey),
        ?assert(is_map(Bucket)),
        ?assert(maps:is_key(tokens, Bucket)),
        ?assert(maps:is_key(last_refill, Bucket)),
        ?assert(maps:get(tokens, Bucket) < 2000),
        ?assert(maps:get(tokens, Bucket) > 0)
    end}.

set_limits_(_Pid) ->
    {"set limits", fun() ->
        ?assertEqual(ok, derp_rate_limiter:set_limits(derp_rate_limiter, 5000, 10000)),
        ClientKey = test_key(),
        ?assertEqual(ok, derp_rate_limiter:check(ClientKey, 8000))
    end}.
