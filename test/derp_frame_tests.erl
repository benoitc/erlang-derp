%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Unit tests for derp_frame module.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_frame_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%%--------------------------------------------------------------------
%% Test Fixtures
%%--------------------------------------------------------------------

test_key() ->
    crypto:strong_rand_bytes(32).

test_nonce() ->
    crypto:strong_rand_bytes(24).

%%--------------------------------------------------------------------
%% Encode/Decode Tests
%%--------------------------------------------------------------------

encode_decode_roundtrip_test() ->
    Payload = <<"test payload">>,
    Type = 42,
    Encoded = iolist_to_binary(derp_frame:encode(Type, Payload)),
    ?assertMatch({ok, Type, Payload, <<>>}, derp_frame:decode(Encoded)).

encode_decode_empty_payload_test() ->
    Type = ?FRAME_KEEP_ALIVE,
    Encoded = iolist_to_binary(derp_frame:encode(Type, <<>>)),
    ?assertMatch({ok, Type, <<>>, <<>>}, derp_frame:decode(Encoded)).

decode_with_remaining_data_test() ->
    Payload = <<"hello">>,
    Extra = <<"extra data">>,
    Encoded = iolist_to_binary(derp_frame:encode(1, Payload)),
    Combined = <<Encoded/binary, Extra/binary>>,
    ?assertMatch({ok, 1, Payload, Extra}, derp_frame:decode(Combined)).

decode_multiple_frames_test() ->
    Frame1 = iolist_to_binary(derp_frame:encode(1, <<"first">>)),
    Frame2 = iolist_to_binary(derp_frame:encode(2, <<"second">>)),
    Combined = <<Frame1/binary, Frame2/binary>>,
    {ok, 1, <<"first">>, Rest} = derp_frame:decode(Combined),
    ?assertMatch({ok, 2, <<"second">>, <<>>}, derp_frame:decode(Rest)).

%%--------------------------------------------------------------------
%% Truncated Frame Tests
%%--------------------------------------------------------------------

decode_truncated_header_test() ->
    ?assertMatch({more, _}, derp_frame:decode(<<1, 0, 0>>)),
    ?assertMatch({more, _}, derp_frame:decode(<<1>>)),
    ?assertMatch({more, _}, derp_frame:decode(<<>>)).

decode_truncated_payload_test() ->
    %% Header says 10 bytes, but only 5 provided
    Truncated = <<42, 0, 0, 0, 10, "hello">>,
    ?assertMatch({more, 5}, derp_frame:decode(Truncated)).

%%--------------------------------------------------------------------
%% Oversized Payload Tests
%%--------------------------------------------------------------------

encode_oversized_payload_test() ->
    OversizedPayload = binary:copy(<<0>>, ?MAX_PACKET_SIZE + 1),
    ?assertError({payload_too_large, _, _}, derp_frame:encode(1, OversizedPayload)).

decode_oversized_payload_test() ->
    %% Craft a header claiming a payload larger than max
    OversizedHeader = <<1, 16#00, 16#01, 16#00, 16#01>>,  % Size = 65537
    ?assertMatch({error, {payload_too_large, _}}, derp_frame:decode(OversizedHeader)).

%%--------------------------------------------------------------------
%% Server Key Frame Tests
%%--------------------------------------------------------------------

server_key_frame_test() ->
    PubKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:server_key(PubKey)),
    {ok, ?FRAME_SERVER_KEY, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<?DERP_MAGIC/binary, PubKey/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

server_key_invalid_key_size_test() ->
    ?assertError(function_clause, derp_frame:server_key(<<"short">>)).

%%--------------------------------------------------------------------
%% Client Info Frame Tests
%%--------------------------------------------------------------------

client_info_frame_test() ->
    PubKey = test_key(),
    Nonce = test_nonce(),
    EncInfo = <<"encrypted json">>,
    Encoded = iolist_to_binary(derp_frame:client_info(PubKey, Nonce, EncInfo)),
    {ok, ?FRAME_CLIENT_INFO, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<PubKey/binary, Nonce/binary, EncInfo/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

%%--------------------------------------------------------------------
%% Server Info Frame Tests
%%--------------------------------------------------------------------

server_info_frame_test() ->
    Nonce = test_nonce(),
    EncInfo = <<"encrypted response">>,
    Encoded = iolist_to_binary(derp_frame:server_info(Nonce, EncInfo)),
    {ok, ?FRAME_SERVER_INFO, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<Nonce/binary, EncInfo/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

%%--------------------------------------------------------------------
%% Send/Recv Packet Frame Tests
%%--------------------------------------------------------------------

send_packet_frame_test() ->
    DstKey = test_key(),
    Data = <<"packet data">>,
    Encoded = iolist_to_binary(derp_frame:send_packet(DstKey, Data)),
    {ok, ?FRAME_SEND_PACKET, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<DstKey/binary, Data/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

recv_packet_frame_test() ->
    SrcKey = test_key(),
    Data = <<"received data">>,
    Encoded = iolist_to_binary(derp_frame:recv_packet(SrcKey, Data)),
    {ok, ?FRAME_RECV_PACKET, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<SrcKey/binary, Data/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

%%--------------------------------------------------------------------
%% Keep-Alive Frame Tests
%%--------------------------------------------------------------------

keep_alive_frame_test() ->
    Encoded = iolist_to_binary(derp_frame:keep_alive()),
    ?assertMatch({ok, ?FRAME_KEEP_ALIVE, <<>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Ping/Pong Frame Tests
%%--------------------------------------------------------------------

ping_frame_test() ->
    Data = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Encoded = iolist_to_binary(derp_frame:ping(Data)),
    ?assertMatch({ok, ?FRAME_PING, Data, <<>>}, derp_frame:decode(Encoded)).

pong_frame_test() ->
    Data = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Encoded = iolist_to_binary(derp_frame:pong(Data)),
    ?assertMatch({ok, ?FRAME_PONG, Data, <<>>}, derp_frame:decode(Encoded)).

ping_invalid_size_test() ->
    ?assertError(function_clause, derp_frame:ping(<<"short">>)),
    ?assertError(function_clause, derp_frame:ping(<<"toolongdata">>)).

%%--------------------------------------------------------------------
%% Peer Gone Frame Tests
%%--------------------------------------------------------------------

peer_gone_frame_test() ->
    PeerKey = test_key(),
    Reason = ?PEER_GONE_DISCONNECTED,
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, Reason)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<PeerKey/binary, Reason:8>>,
    ?assertEqual(ExpectedPayload, Payload).

peer_gone_not_here_test() ->
    PeerKey = test_key(),
    Reason = ?PEER_GONE_NOT_HERE,
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, Reason)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<PeerKey/binary, Reason:8>>,
    ?assertEqual(ExpectedPayload, Payload).

%%--------------------------------------------------------------------
%% Peer Present Frame Tests
%%--------------------------------------------------------------------

peer_present_frame_test() ->
    PeerKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:peer_present(PeerKey)),
    ?assertMatch({ok, ?FRAME_PEER_PRESENT, PeerKey, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Note Preferred Frame Tests
%%--------------------------------------------------------------------

note_preferred_true_test() ->
    Encoded = iolist_to_binary(derp_frame:note_preferred(true)),
    ?assertMatch({ok, ?FRAME_NOTE_PREFERRED, <<1>>, <<>>}, derp_frame:decode(Encoded)).

note_preferred_false_test() ->
    Encoded = iolist_to_binary(derp_frame:note_preferred(false)),
    ?assertMatch({ok, ?FRAME_NOTE_PREFERRED, <<0>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Watch Conns Frame Tests
%%--------------------------------------------------------------------

watch_conns_frame_test() ->
    Encoded = iolist_to_binary(derp_frame:watch_conns()),
    ?assertMatch({ok, ?FRAME_WATCH_CONNS, <<>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Close Peer Frame Tests
%%--------------------------------------------------------------------

close_peer_frame_test() ->
    PeerKey = test_key(),
    Encoded = iolist_to_binary(derp_frame:close_peer(PeerKey)),
    ?assertMatch({ok, ?FRAME_CLOSE_PEER, PeerKey, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Health Frame Tests
%%--------------------------------------------------------------------

health_frame_test() ->
    Encoded = iolist_to_binary(derp_frame:health()),
    ?assertMatch({ok, ?FRAME_HEALTH, <<>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Restarting Frame Tests
%%--------------------------------------------------------------------

restarting_frame_test() ->
    Encoded = iolist_to_binary(derp_frame:restarting()),
    ?assertMatch({ok, ?FRAME_RESTARTING, <<>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Forward Packet Frame Tests
%%--------------------------------------------------------------------

forward_packet_frame_test() ->
    SrcKey = test_key(),
    DstKey = test_key(),
    Data = <<"forwarded data">>,
    Encoded = iolist_to_binary(derp_frame:forward_packet(SrcKey, DstKey, Data)),
    {ok, ?FRAME_FORWARD_PACKET, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<SrcKey/binary, DstKey/binary, Data/binary>>,
    ?assertEqual(ExpectedPayload, Payload).

%%--------------------------------------------------------------------
%% Type Name Tests
%%--------------------------------------------------------------------

type_name_test() ->
    ?assertEqual(server_key, derp_frame:type_name(?FRAME_SERVER_KEY)),
    ?assertEqual(client_info, derp_frame:type_name(?FRAME_CLIENT_INFO)),
    ?assertEqual(send_packet, derp_frame:type_name(?FRAME_SEND_PACKET)),
    ?assertEqual(recv_packet, derp_frame:type_name(?FRAME_RECV_PACKET)),
    ?assertEqual(keep_alive, derp_frame:type_name(?FRAME_KEEP_ALIVE)),
    ?assertEqual(ping, derp_frame:type_name(?FRAME_PING)),
    ?assertEqual(pong, derp_frame:type_name(?FRAME_PONG)),
    ?assertEqual({unknown, 255}, derp_frame:type_name(255)).

%%--------------------------------------------------------------------
%% Max Size Boundary Tests
%%--------------------------------------------------------------------

max_size_payload_test() ->
    %% Test payload at exactly max size
    MaxPayload = binary:copy(<<0>>, ?MAX_PACKET_SIZE),
    Encoded = iolist_to_binary(derp_frame:encode(1, MaxPayload)),
    {ok, 1, Decoded, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(?MAX_PACKET_SIZE, byte_size(Decoded)).

%%--------------------------------------------------------------------
%% Protocol Compliance Tests
%% These tests verify frame type values match official Tailscale DERP
%%--------------------------------------------------------------------

frame_type_hex_values_test() ->
    %% Verify all frame types match official protocol values
    %% Reference: https://github.com/tailscale/tailscale/blob/main/derp/derp.go
    ?assertEqual(16#01, ?FRAME_SERVER_KEY),
    ?assertEqual(16#02, ?FRAME_CLIENT_INFO),
    ?assertEqual(16#03, ?FRAME_SERVER_INFO),
    ?assertEqual(16#04, ?FRAME_SEND_PACKET),
    ?assertEqual(16#05, ?FRAME_RECV_PACKET),
    ?assertEqual(16#06, ?FRAME_KEEP_ALIVE),
    ?assertEqual(16#07, ?FRAME_NOTE_PREFERRED),
    ?assertEqual(16#08, ?FRAME_PEER_GONE),
    ?assertEqual(16#09, ?FRAME_PEER_PRESENT),
    ?assertEqual(16#0A, ?FRAME_FORWARD_PACKET),
    ?assertEqual(16#10, ?FRAME_WATCH_CONNS),
    ?assertEqual(16#11, ?FRAME_CLOSE_PEER),
    ?assertEqual(16#12, ?FRAME_PING),
    ?assertEqual(16#13, ?FRAME_PONG),
    ?assertEqual(16#14, ?FRAME_HEALTH),
    ?assertEqual(16#15, ?FRAME_RESTARTING).

peer_gone_reason_values_test() ->
    %% Verify peer gone reason codes match official protocol
    ?assertEqual(16#00, ?PEER_GONE_DISCONNECTED),
    ?assertEqual(16#01, ?PEER_GONE_NOT_HERE),
    ?assertEqual(16#F0, ?PEER_GONE_MESH_CONN_BROKE).

protocol_constants_test() ->
    %% Verify protocol constants match official values
    ?assertEqual(8, ?DERP_MAGIC_SIZE),
    ?assertEqual(5, ?FRAME_HEADER_SIZE),
    ?assertEqual(65536, ?MAX_PACKET_SIZE),
    ?assertEqual(32, ?KEY_SIZE),
    ?assertEqual(24, ?NONCE_SIZE),
    ?assertEqual(60000, ?KEEPALIVE_INTERVAL).

magic_bytes_test() ->
    %% Verify magic bytes: "DERP🔑" = 44 45 52 50 F0 9F 94 91
    Expected = <<16#44, 16#45, 16#52, 16#50, 16#F0, 16#9F, 16#94, 16#91>>,
    ?assertEqual(Expected, ?DERP_MAGIC).

peer_gone_mesh_conn_broke_test() ->
    %% Test the new mesh connection broke reason
    PeerKey = test_key(),
    Reason = ?PEER_GONE_MESH_CONN_BROKE,
    Encoded = iolist_to_binary(derp_frame:peer_gone(PeerKey, Reason)),
    {ok, ?FRAME_PEER_GONE, Payload, <<>>} = derp_frame:decode(Encoded),
    ExpectedPayload = <<PeerKey/binary, Reason:8>>,
    ?assertEqual(ExpectedPayload, Payload).

protocol_version_test() ->
    %% Verify protocol version is 2 for Tailscale compatibility
    ?assertEqual(2, ?PROTOCOL_VERSION).

%%--------------------------------------------------------------------
%% Health Frame with Message Tests
%%--------------------------------------------------------------------

health_with_message_test() ->
    Message = <<"detected duplicate client">>,
    Encoded = iolist_to_binary(derp_frame:health(Message)),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(Message, Payload).

health_with_string_message_test() ->
    Message = "rate limited",
    Encoded = iolist_to_binary(derp_frame:health(Message)),
    {ok, ?FRAME_HEALTH, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<"rate limited">>, Payload).

health_empty_message_test() ->
    Encoded = iolist_to_binary(derp_frame:health(<<>>)),
    ?assertMatch({ok, ?FRAME_HEALTH, <<>>, <<>>}, derp_frame:decode(Encoded)).

%%--------------------------------------------------------------------
%% Restarting Frame with Timing Tests
%%--------------------------------------------------------------------

restarting_with_timing_test() ->
    ReconnectMs = 5000,
    Encoded = iolist_to_binary(derp_frame:restarting(ReconnectMs)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<ReconnectMs:32/big-unsigned>>, Payload).

restarting_with_zero_timing_test() ->
    Encoded = iolist_to_binary(derp_frame:restarting(0)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<0:32/big-unsigned>>, Payload).

restarting_with_large_timing_test() ->
    %% Test with max uint32 value
    MaxMs = 16#FFFFFFFF,
    Encoded = iolist_to_binary(derp_frame:restarting(MaxMs)),
    {ok, ?FRAME_RESTARTING, Payload, <<>>} = derp_frame:decode(Encoded),
    ?assertEqual(<<MaxMs:32/big-unsigned>>, Payload).
