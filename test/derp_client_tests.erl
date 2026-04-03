%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Unit tests for DERP client improvements.
%%% Tests exponential backoff, health/restarting frame parsing,
%%% NotePreferred encoding, and event callbacks.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_client_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%%--------------------------------------------------------------------
%% Exponential Backoff Tests
%%--------------------------------------------------------------------

backoff_initial_attempt_test() ->
    %% First attempt (0): should return base delay
    ?assertEqual(1000, derp_client:calculate_reconnect_delay(1000, 0, 30000)).

backoff_first_retry_test() ->
    %% After 1 failed attempt: 1000 * 2^1 = 2000
    ?assertEqual(2000, derp_client:calculate_reconnect_delay(1000, 1, 30000)).

backoff_second_retry_test() ->
    %% After 2 failed attempts: 1000 * 2^2 = 4000
    ?assertEqual(4000, derp_client:calculate_reconnect_delay(1000, 2, 30000)).

backoff_third_retry_test() ->
    %% After 3 failed attempts: 1000 * 2^3 = 8000
    ?assertEqual(8000, derp_client:calculate_reconnect_delay(1000, 3, 30000)).

backoff_caps_at_max_test() ->
    %% After 5 failed attempts: 1000 * 2^5 = 32000, capped at 30000
    ?assertEqual(30000, derp_client:calculate_reconnect_delay(1000, 5, 30000)).

backoff_large_attempts_no_overflow_test() ->
    %% Large attempt count should not crash, caps at 16 shifts then max
    ?assertEqual(30000, derp_client:calculate_reconnect_delay(1000, 100, 30000)).

backoff_custom_base_test() ->
    %% Custom base delay of 500ms
    ?assertEqual(500, derp_client:calculate_reconnect_delay(500, 0, 30000)),
    ?assertEqual(1000, derp_client:calculate_reconnect_delay(500, 1, 30000)),
    ?assertEqual(2000, derp_client:calculate_reconnect_delay(500, 2, 30000)).

backoff_custom_max_test() ->
    %% Custom max of 5000ms
    ?assertEqual(1000, derp_client:calculate_reconnect_delay(1000, 0, 5000)),
    ?assertEqual(2000, derp_client:calculate_reconnect_delay(1000, 1, 5000)),
    ?assertEqual(4000, derp_client:calculate_reconnect_delay(1000, 2, 5000)),
    ?assertEqual(5000, derp_client:calculate_reconnect_delay(1000, 3, 5000)).

%%--------------------------------------------------------------------
%% Note Preferred Frame Tests
%%--------------------------------------------------------------------

note_preferred_true_encoding_test() ->
    %% NotePreferred(true) should encode as type 0x07, payload <<1>>
    Encoded = iolist_to_binary(derp_frame:note_preferred(true)),
    {ok, ?FRAME_NOTE_PREFERRED, <<1:8>>, <<>>} = derp_frame:decode(Encoded).

note_preferred_false_encoding_test() ->
    %% NotePreferred(false) should encode as type 0x07, payload <<0>>
    Encoded = iolist_to_binary(derp_frame:note_preferred(false)),
    {ok, ?FRAME_NOTE_PREFERRED, <<0:8>>, <<>>} = derp_frame:decode(Encoded).

%%--------------------------------------------------------------------
%% Health Frame Content Parsing Tests
%%--------------------------------------------------------------------

health_frame_empty_test() ->
    %% Empty health payload = server is healthy
    Encoded = iolist_to_binary(derp_frame:health()),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<>>, Payload).

health_frame_with_message_test() ->
    %% Non-empty health payload = health issue description
    Message = <<"detected duplicate client">>,
    Encoded = iolist_to_binary(derp_frame:health(Message)),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(Message, Payload).

health_frame_rate_limited_test() ->
    Message = <<"rate limited">>,
    Encoded = iolist_to_binary(derp_frame:health(Message)),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(Message, Payload).

health_frame_from_string_test() ->
    %% health/1 accepts string argument too
    Encoded = iolist_to_binary(derp_frame:health("connection overloaded")),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<"connection overloaded">>, Payload).

%%--------------------------------------------------------------------
%% Restarting Frame Timing Parsing Tests
%%--------------------------------------------------------------------

restarting_frame_with_timing_test() ->
    %% Restarting with 5000ms reconnect timing
    Encoded = iolist_to_binary(derp_frame:restarting(5000)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    <<Ms:32/big-unsigned>> = Payload,
    ?assertEqual(5000, Ms).

restarting_frame_zero_timing_test() ->
    %% Zero timing = reconnect immediately
    Encoded = iolist_to_binary(derp_frame:restarting(0)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    <<Ms:32/big-unsigned>> = Payload,
    ?assertEqual(0, Ms).

restarting_frame_large_timing_test() ->
    %% Large timing value (e.g. 60 seconds)
    Encoded = iolist_to_binary(derp_frame:restarting(60000)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    <<Ms:32/big-unsigned>> = Payload,
    ?assertEqual(60000, Ms).

restarting_frame_no_timing_test() ->
    %% Restarting frame with no timing (empty payload, older servers)
    Encoded = iolist_to_binary(derp_frame:restarting()),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<>>, Payload).

restarting_timing_extraction_test() ->
    %% Test the exact extraction logic the client uses
    Encoded = iolist_to_binary(derp_frame:restarting(15000)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ReconnectMs = case Payload of
        <<Ms:32/big-unsigned>> -> Ms;
        _ -> undefined
    end,
    ?assertEqual(15000, ReconnectMs).

restarting_timing_extraction_empty_test() ->
    %% Empty payload should give undefined
    Encoded = iolist_to_binary(derp_frame:restarting()),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ReconnectMs = case Payload of
        <<Ms:32/big-unsigned>> -> Ms;
        _ -> undefined
    end,
    ?assertEqual(undefined, ReconnectMs).

%%--------------------------------------------------------------------
%% Peer Present/Gone Frame Parsing Tests
%%--------------------------------------------------------------------

peer_present_frame_parsing_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_present(PeerKey)),
    {ok, ?FRAME_PEER_PRESENT, Payload, <<>>} = derp_frame:decode(Encoded),
    <<ParsedKey:32/binary>> = Payload,
    ?assertEqual(PeerKey, ParsedKey).

peer_gone_frame_parsing_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, ?PEER_GONE_DISCONNECTED)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    <<ParsedKey:32/binary, Reason:8>> = Payload,
    ?assertEqual(PeerKey, ParsedKey),
    ?assertEqual(?PEER_GONE_DISCONNECTED, Reason).

peer_gone_not_here_parsing_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, ?PEER_GONE_NOT_HERE)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    <<_Key:32/binary, Reason:8>> = Payload,
    ?assertEqual(?PEER_GONE_NOT_HERE, Reason).

peer_gone_mesh_broke_parsing_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, ?PEER_GONE_MESH_CONN_BROKE)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    <<_Key:32/binary, Reason:8>> = Payload,
    ?assertEqual(?PEER_GONE_MESH_CONN_BROKE, Reason).

%%--------------------------------------------------------------------
%% Event Callback Tests (via simulated frame handling)
%%--------------------------------------------------------------------

%% These tests verify that the frame decode produces correct data
%% that matches what the client's handle_frame would extract.

health_event_data_test() ->
    %% Verify the event data structure the callback would receive
    Msg = <<"server overloaded">>,
    Encoded = iolist_to_binary(derp_frame:health(Msg)),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    %% The client would call: notify_event({health, Payload}, Data)
    Event = {health, Payload},
    ?assertMatch({health, <<"server overloaded">>}, Event).

restarting_event_data_test() ->
    %% Verify the event data structure for restarting with timing
    Encoded = iolist_to_binary(derp_frame:restarting(10000)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ReconnectMs = case Payload of
        <<Ms:32/big-unsigned>> -> Ms;
        _ -> undefined
    end,
    Event = {restarting, ReconnectMs},
    ?assertMatch({restarting, 10000}, Event).

peer_present_event_data_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_present(PeerKey)),
    {ok, ?FRAME_PEER_PRESENT, Payload, <<>>} = derp_frame:decode(Encoded),
    <<Key:32/binary>> = Payload,
    ?assertEqual(PeerKey, Key),
    %% Verify event tuple structure
    Event = {peer_present, Key},
    ?assertEqual({peer_present, PeerKey}, Event).

peer_gone_event_data_test() ->
    PeerKey = crypto:strong_rand_bytes(32),
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, ?PEER_GONE_NOT_HERE)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    <<Key:32/binary, Reason:8>> = Payload,
    ?assertEqual(PeerKey, Key),
    ?assertEqual(?PEER_GONE_NOT_HERE, Reason),
    %% Verify event tuple structure
    Event = {peer_gone, Key, Reason},
    ?assertEqual({peer_gone, PeerKey, ?PEER_GONE_NOT_HERE}, Event).

%%--------------------------------------------------------------------
%% Frame Type Constants Verification
%%--------------------------------------------------------------------

frame_type_note_preferred_test() ->
    ?assertEqual(16#07, ?FRAME_NOTE_PREFERRED).

frame_type_health_test() ->
    ?assertEqual(16#0E, ?FRAME_HEALTH).

frame_type_restarting_test() ->
    ?assertEqual(16#0F, ?FRAME_RESTARTING).

frame_type_peer_present_test() ->
    ?assertEqual(16#09, ?FRAME_PEER_PRESENT).

frame_type_peer_gone_test() ->
    ?assertEqual(16#08, ?FRAME_PEER_GONE).
