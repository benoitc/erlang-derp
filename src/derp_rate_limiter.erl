%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Token bucket rate limiter for DERP clients.
%%%
%%% Implements a token bucket algorithm to limit the rate of data
%%% that clients can send through the relay. Each client has their
%%% own bucket identified by their public key.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_rate_limiter).

-behaviour(gen_server).

%% API
-export([
    start_link/0,
    start_link/1,
    check/2,
    reset/1,
    get_bucket/1,
    set_limits/3
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-include("derp.hrl").

-define(SERVER, ?MODULE).
-define(TABLE, derp_rate_limiter_table).

%% How often to refill tokens (milliseconds)
-define(REFILL_INTERVAL, 100).

-record(state, {
    bytes_per_sec :: pos_integer(),
    burst :: pos_integer(),
    refill_timer :: reference() | undefined
}).

-record(bucket, {
    key :: binary(),
    tokens :: number(),
    last_refill :: integer()  % erlang:monotonic_time(millisecond)
}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the rate limiter with default limits.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    BytesPerSec = application:get_env(derp, rate_limit_bytes_per_sec,
                                      ?DEFAULT_RATE_LIMIT_BYTES_PER_SEC),
    Burst = application:get_env(derp, rate_limit_burst,
                                ?DEFAULT_RATE_LIMIT_BURST),
    start_link(#{bytes_per_sec => BytesPerSec, burst => Burst}).

%% @doc Start the rate limiter with custom limits.
%%
%% @param Opts Map with bytes_per_sec and burst values
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Opts, []).

%% @doc Check if a client can send bytes and consume tokens.
%%
%% @param ClientKey The client's public key
%% @param ByteCount Number of bytes to send
%% @returns ok | {error, rate_limited}
-spec check(ClientKey :: binary(), ByteCount :: non_neg_integer()) ->
    ok | {error, rate_limited}.
check(ClientKey, ByteCount) when byte_size(ClientKey) =:= 32, ByteCount >= 0 ->
    gen_server:call(?SERVER, {check, ClientKey, ByteCount}).

%% @doc Reset a client's token bucket to full.
%%
%% @param ClientKey The client's public key
-spec reset(ClientKey :: binary()) -> ok.
reset(ClientKey) when byte_size(ClientKey) =:= 32 ->
    gen_server:call(?SERVER, {reset, ClientKey}).

%% @doc Get a client's current bucket state (for testing/debugging).
%%
%% @param ClientKey The client's public key
%% @returns {ok, #{tokens, last_refill}} | {error, not_found}
-spec get_bucket(ClientKey :: binary()) ->
    {ok, map()} | {error, not_found}.
get_bucket(ClientKey) when byte_size(ClientKey) =:= 32 ->
    case ets:lookup(?TABLE, ClientKey) of
        [#bucket{tokens = Tokens, last_refill = LastRefill}] ->
            {ok, #{tokens => Tokens, last_refill => LastRefill}};
        [] ->
            {error, not_found}
    end.

%% @doc Set new rate limits (applies to new buckets).
%%
%% @param BytesPerSec New bytes per second limit
%% @param Burst New burst limit
-spec set_limits(pid() | atom(), pos_integer(), pos_integer()) -> ok.
set_limits(Server, BytesPerSec, Burst) when BytesPerSec > 0, Burst > 0 ->
    gen_server:call(Server, {set_limits, BytesPerSec, Burst}).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init(Opts) ->
    BytesPerSec = maps:get(bytes_per_sec, Opts, ?DEFAULT_RATE_LIMIT_BYTES_PER_SEC),
    Burst = maps:get(burst, Opts, ?DEFAULT_RATE_LIMIT_BURST),

    %% Create ETS table for buckets
    ?TABLE = ets:new(?TABLE, [
        named_table,
        {keypos, #bucket.key},
        protected
    ]),

    %% Start periodic refill timer
    TimerRef = erlang:send_after(?REFILL_INTERVAL, self(), refill),

    {ok, #state{
        bytes_per_sec = BytesPerSec,
        burst = Burst,
        refill_timer = TimerRef
    }}.

handle_call({check, ClientKey, ByteCount}, _From, State) ->
    #state{bytes_per_sec = BytesPerSec, burst = Burst} = State,
    Now = erlang:monotonic_time(millisecond),

    %% Get or create bucket
    Bucket = case ets:lookup(?TABLE, ClientKey) of
        [B] -> B;
        [] -> #bucket{key = ClientKey, tokens = Burst, last_refill = Now}
    end,

    %% Refill tokens based on elapsed time
    Elapsed = max(0, Now - Bucket#bucket.last_refill),
    TokensToAdd = (BytesPerSec * Elapsed) / 1000,
    NewTokens = min(Burst, Bucket#bucket.tokens + TokensToAdd),

    %% Check if enough tokens
    case NewTokens >= ByteCount of
        true ->
            %% Consume tokens
            UpdatedBucket = Bucket#bucket{
                tokens = NewTokens - ByteCount,
                last_refill = Now
            },
            ets:insert(?TABLE, UpdatedBucket),
            {reply, ok, State};
        false ->
            %% Rate limited, but still update refill time
            UpdatedBucket = Bucket#bucket{
                tokens = NewTokens,
                last_refill = Now
            },
            ets:insert(?TABLE, UpdatedBucket),
            {reply, {error, rate_limited}, State}
    end;

handle_call({reset, ClientKey}, _From, State) ->
    #state{burst = Burst} = State,
    Now = erlang:monotonic_time(millisecond),
    Bucket = #bucket{
        key = ClientKey,
        tokens = Burst,
        last_refill = Now
    },
    ets:insert(?TABLE, Bucket),
    {reply, ok, State};

handle_call({set_limits, BytesPerSec, Burst}, _From, State) ->
    {reply, ok, State#state{bytes_per_sec = BytesPerSec, burst = Burst}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refill, State) ->
    %% Clean up old buckets that haven't been used in a while
    %% (clients that have disconnected)
    Now = erlang:monotonic_time(millisecond),
    OldThreshold = Now - 300000,  % 5 minutes
    %% Use tuple form for match spec to avoid dialyzer warnings about record types
    MatchSpec = [{{bucket, '_', '_', '$1'}, [{'<', '$1', OldThreshold}], [true]}],
    _ = ets:select_delete(?TABLE, MatchSpec),

    %% Reschedule refill timer
    TimerRef = erlang:send_after(?REFILL_INTERVAL, self(), refill),
    {noreply, State#state{refill_timer = TimerRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{refill_timer = TimerRef}) ->
    _ = case TimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(TimerRef)
    end,
    catch ets:delete(?TABLE),
    ok.
