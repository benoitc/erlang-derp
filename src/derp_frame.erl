%%%-------------------------------------------------------------------
%%% @doc DERP protocol frame encoding and decoding.
%%%
%%% Frame format: [1B type][4B big-endian length][payload]
%%% @end
%%%-------------------------------------------------------------------
-module(derp_frame).

-include("derp.hrl").

%% API
-export([
    encode/2,
    decode/1,
    server_key/1,
    client_info/3,
    server_info/2,
    send_packet/2,
    recv_packet/2,
    keep_alive/0,
    ping/1,
    pong/1,
    peer_gone/2,
    peer_present/1,
    note_preferred/1,
    watch_conns/0,
    close_peer/1,
    health/0,
    restarting/0,
    forward_packet/3
]).

%% Frame type names for debugging
-export([type_name/1]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Encode a frame with type and payload.
-spec encode(non_neg_integer(), iodata()) -> iodata().
encode(Type, Payload) when is_integer(Type), Type >= 0, Type =< 255 ->
    PayloadBin = iolist_to_binary(Payload),
    Size = byte_size(PayloadBin),
    case Size > ?MAX_PACKET_SIZE of
        true -> error({payload_too_large, Size, ?MAX_PACKET_SIZE});
        false -> [<<Type:8, Size:32/big>>, PayloadBin]
    end.

%% @doc Decode a frame from binary data.
%% Returns {ok, Type, Payload, Rest} on success,
%% {more, N} if more bytes needed (N = minimum bytes needed),
%% {error, Reason} on failure.
-spec decode(binary()) ->
    {ok, non_neg_integer(), binary(), binary()} |
    {more, pos_integer()} |
    {error, term()}.
decode(<<Type:8, Size:32/big, Rest/binary>>) when Size =< ?MAX_PACKET_SIZE ->
    case Rest of
        <<Payload:Size/binary, Remaining/binary>> ->
            {ok, Type, Payload, Remaining};
        _ ->
            Needed = Size - byte_size(Rest),
            {more, Needed}
    end;
decode(<<_Type:8, Size:32/big, _Rest/binary>>) when Size > ?MAX_PACKET_SIZE ->
    {error, {payload_too_large, Size}};
decode(Binary) when byte_size(Binary) < ?FRAME_HEADER_SIZE ->
    {more, ?FRAME_HEADER_SIZE - byte_size(Binary)};
decode(<<>>) ->
    {more, ?FRAME_HEADER_SIZE}.

%% @doc Create server key frame (sent at start of connection).
%% Includes magic bytes followed by server's public key.
-spec server_key(binary()) -> iodata().
server_key(PubKey) when byte_size(PubKey) =:= ?KEY_SIZE ->
    encode(?FRAME_SERVER_KEY, [?DERP_MAGIC, PubKey]).

%% @doc Create client info frame.
%% Contains client's public key, nonce, and encrypted JSON info.
-spec client_info(binary(), binary(), binary()) -> iodata().
client_info(PubKey, Nonce, EncryptedInfo)
  when byte_size(PubKey) =:= ?KEY_SIZE,
       byte_size(Nonce) =:= ?NONCE_SIZE ->
    encode(?FRAME_CLIENT_INFO, [PubKey, Nonce, EncryptedInfo]).

%% @doc Create server info frame.
%% Contains nonce and encrypted JSON response.
-spec server_info(binary(), binary()) -> iodata().
server_info(Nonce, EncryptedInfo) when byte_size(Nonce) =:= ?NONCE_SIZE ->
    encode(?FRAME_SERVER_INFO, [Nonce, EncryptedInfo]).

%% @doc Create send packet frame.
%% Destination key followed by packet data.
-spec send_packet(binary(), binary()) -> iodata().
send_packet(DstKey, Data) when byte_size(DstKey) =:= ?KEY_SIZE ->
    encode(?FRAME_SEND_PACKET, [DstKey, Data]).

%% @doc Create recv packet frame.
%% Source key followed by packet data.
-spec recv_packet(binary(), binary()) -> iodata().
recv_packet(SrcKey, Data) when byte_size(SrcKey) =:= ?KEY_SIZE ->
    encode(?FRAME_RECV_PACKET, [SrcKey, Data]).

%% @doc Create keep-alive frame (empty payload).
-spec keep_alive() -> iodata().
keep_alive() ->
    encode(?FRAME_KEEP_ALIVE, <<>>).

%% @doc Create ping frame with 8 bytes of data.
-spec ping(binary()) -> iodata().
ping(Data) when byte_size(Data) =:= 8 ->
    encode(?FRAME_PING, Data).

%% @doc Create pong frame with 8 bytes of data.
-spec pong(binary()) -> iodata().
pong(Data) when byte_size(Data) =:= 8 ->
    encode(?FRAME_PONG, Data).

%% @doc Create peer gone frame.
%% Peer's key followed by reason byte.
-spec peer_gone(binary(), non_neg_integer()) -> iodata().
peer_gone(PeerKey, Reason)
  when byte_size(PeerKey) =:= ?KEY_SIZE,
       is_integer(Reason), Reason >= 0, Reason =< 255 ->
    encode(?FRAME_PEER_GONE, [PeerKey, <<Reason:8>>]).

%% @doc Create peer present frame (mesh mode).
-spec peer_present(binary()) -> iodata().
peer_present(PeerKey) when byte_size(PeerKey) =:= ?KEY_SIZE ->
    encode(?FRAME_PEER_PRESENT, PeerKey).

%% @doc Create note preferred frame.
-spec note_preferred(boolean()) -> iodata().
note_preferred(true) ->
    encode(?FRAME_NOTE_PREFERRED, <<1:8>>);
note_preferred(false) ->
    encode(?FRAME_NOTE_PREFERRED, <<0:8>>).

%% @doc Create watch connections frame.
-spec watch_conns() -> iodata().
watch_conns() ->
    encode(?FRAME_WATCH_CONNS, <<>>).

%% @doc Create close peer frame.
-spec close_peer(binary()) -> iodata().
close_peer(PeerKey) when byte_size(PeerKey) =:= ?KEY_SIZE ->
    encode(?FRAME_CLOSE_PEER, PeerKey).

%% @doc Create health check frame.
-spec health() -> iodata().
health() ->
    encode(?FRAME_HEALTH, <<>>).

%% @doc Create server restarting frame.
-spec restarting() -> iodata().
restarting() ->
    encode(?FRAME_RESTARTING, <<>>).

%% @doc Create forward packet frame (mesh mode).
%% Source key, destination key, and packet data.
-spec forward_packet(binary(), binary(), binary()) -> iodata().
forward_packet(SrcKey, DstKey, Data)
  when byte_size(SrcKey) =:= ?KEY_SIZE,
       byte_size(DstKey) =:= ?KEY_SIZE ->
    encode(?FRAME_FORWARD_PACKET, [SrcKey, DstKey, Data]).

%% @doc Get human-readable name for frame type.
-spec type_name(non_neg_integer()) -> atom().
type_name(?FRAME_SERVER_KEY) -> server_key;
type_name(?FRAME_CLIENT_INFO) -> client_info;
type_name(?FRAME_SERVER_INFO) -> server_info;
type_name(?FRAME_SEND_PACKET) -> send_packet;
type_name(?FRAME_RECV_PACKET) -> recv_packet;
type_name(?FRAME_KEEP_ALIVE) -> keep_alive;
type_name(?FRAME_NOTE_PREFERRED) -> note_preferred;
type_name(?FRAME_PEER_GONE) -> peer_gone;
type_name(?FRAME_PEER_PRESENT) -> peer_present;
type_name(?FRAME_WATCH_CONNS) -> watch_conns;
type_name(?FRAME_CLOSE_PEER) -> close_peer;
type_name(?FRAME_PING) -> ping;
type_name(?FRAME_PONG) -> pong;
type_name(?FRAME_HEALTH) -> health;
type_name(?FRAME_RESTARTING) -> restarting;
type_name(?FRAME_FORWARD_PACKET) -> forward_packet;
type_name(Other) -> {unknown, Other}.
