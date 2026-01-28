%%%-------------------------------------------------------------------
%%% @doc High-level cryptographic API for DERP protocol.
%%%
%%% Provides convenient wrappers around the low-level NIF operations
%%% for key generation, encryption, and decryption.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_crypto).

-include("derp.hrl").

%% API
-export([
    generate_keypair/0,
    box_seal/4,
    box_open/4,
    random_nonce/0,
    random_bytes/1
]).

%% Client info encryption (for handshake)
-export([
    encrypt_client_info/3,
    decrypt_client_info/4,
    encrypt_server_info/3,
    decrypt_server_info/4
]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Generate a new Curve25519 keypair.
%%
%% Returns {PublicKey, SecretKey} where:
%% - PublicKey: 32 bytes, safe to share
%% - SecretKey: 32 bytes, must be kept private
-spec generate_keypair() -> {PubKey :: binary(), SecKey :: binary()}.
generate_keypair() ->
    derp_sodium:box_keypair().

%% @doc Encrypt and authenticate a message.
%%
%% Uses NaCl box (Curve25519 + XSalsa20 + Poly1305).
%% The ciphertext is 16 bytes longer than the plaintext.
%%
%% @param Msg Plaintext to encrypt
%% @param Nonce 24-byte unique nonce
%% @param TheirPub Recipient's public key
%% @param MySec Sender's secret key
-spec box_seal(Msg :: binary(), Nonce :: binary(), TheirPub :: binary(), MySec :: binary()) ->
    CipherText :: binary().
box_seal(Msg, Nonce, TheirPub, MySec) when
    byte_size(Nonce) =:= ?NONCE_SIZE,
    byte_size(TheirPub) =:= ?KEY_SIZE,
    byte_size(MySec) =:= ?KEY_SIZE ->
    derp_sodium:box(Msg, Nonce, TheirPub, MySec).

%% @doc Decrypt and verify a message.
%%
%% Returns {ok, Plaintext} on success, {error, failed} if decryption
%% or authentication fails.
%%
%% @param Cipher Ciphertext to decrypt
%% @param Nonce 24-byte nonce used during encryption
%% @param TheirPub Sender's public key
%% @param MySec Recipient's secret key
-spec box_open(Cipher :: binary(), Nonce :: binary(), TheirPub :: binary(), MySec :: binary()) ->
    {ok, binary()} | {error, failed}.
box_open(Cipher, Nonce, TheirPub, MySec) when
    byte_size(Nonce) =:= ?NONCE_SIZE,
    byte_size(TheirPub) =:= ?KEY_SIZE,
    byte_size(MySec) =:= ?KEY_SIZE ->
    case derp_sodium:box_open(Cipher, Nonce, TheirPub, MySec) of
        {ok, Msg} -> {ok, Msg};
        error -> {error, failed}
    end.

%% @doc Generate a random 24-byte nonce.
%%
%% Each nonce must be unique for messages encrypted with the same keypair.
%% Using random nonces is safe for messages up to 2^64.
-spec random_nonce() -> binary().
random_nonce() ->
    derp_sodium:randombytes(?NONCE_SIZE).

%% @doc Generate N random bytes.
-spec random_bytes(N :: non_neg_integer()) -> binary().
random_bytes(N) ->
    derp_sodium:randombytes(N).

%%--------------------------------------------------------------------
%% Handshake Encryption
%%--------------------------------------------------------------------

%% @doc Encrypt client info JSON for handshake.
%%
%% Used during DERP handshake to send encrypted client information
%% to the server.
%%
%% @param Info Map or proplist to encode as JSON
%% @param ServerPub Server's public key
%% @param ClientSec Client's secret key
%% @returns {Nonce, EncryptedInfo}
-spec encrypt_client_info(Info :: map() | list(), ServerPub :: binary(), ClientSec :: binary()) ->
    {Nonce :: binary(), EncryptedInfo :: binary()}.
encrypt_client_info(Info, ServerPub, ClientSec) ->
    Json = jsx:encode(Info),
    Nonce = random_nonce(),
    Cipher = box_seal(Json, Nonce, ServerPub, ClientSec),
    {Nonce, Cipher}.

%% @doc Decrypt client info from handshake.
%%
%% Used by server to decrypt and parse client information.
%%
%% @param EncInfo Encrypted info blob
%% @param Nonce Nonce used for encryption
%% @param ClientPub Client's public key
%% @param ServerSec Server's secret key
%% @returns {ok, DecodedInfo} | {error, Reason}
-spec decrypt_client_info(EncInfo :: binary(), Nonce :: binary(),
                          ClientPub :: binary(), ServerSec :: binary()) ->
    {ok, map()} | {error, term()}.
decrypt_client_info(EncInfo, Nonce, ClientPub, ServerSec) ->
    case box_open(EncInfo, Nonce, ClientPub, ServerSec) of
        {ok, Json} ->
            try
                {ok, jsx:decode(Json, [return_maps])}
            catch
                _:_ -> {error, invalid_json}
            end;
        {error, failed} ->
            {error, decrypt_failed}
    end.

%% @doc Encrypt server info JSON for handshake.
%%
%% Used during DERP handshake to send encrypted server information
%% (like rate limits) to the client.
%%
%% @param Info Map or proplist to encode as JSON
%% @param ClientPub Client's public key
%% @param ServerSec Server's secret key
%% @returns {Nonce, EncryptedInfo}
-spec encrypt_server_info(Info :: map() | list(), ClientPub :: binary(), ServerSec :: binary()) ->
    {Nonce :: binary(), EncryptedInfo :: binary()}.
encrypt_server_info(Info, ClientPub, ServerSec) ->
    Json = jsx:encode(Info),
    Nonce = random_nonce(),
    Cipher = box_seal(Json, Nonce, ClientPub, ServerSec),
    {Nonce, Cipher}.

%% @doc Decrypt server info from handshake.
%%
%% Used by client to decrypt and parse server information.
%%
%% @param EncInfo Encrypted info blob
%% @param Nonce Nonce used for encryption
%% @param ServerPub Server's public key
%% @param ClientSec Client's secret key
%% @returns {ok, DecodedInfo} | {error, Reason}
-spec decrypt_server_info(EncInfo :: binary(), Nonce :: binary(),
                          ServerPub :: binary(), ClientSec :: binary()) ->
    {ok, map()} | {error, term()}.
decrypt_server_info(EncInfo, Nonce, ServerPub, ClientSec) ->
    case box_open(EncInfo, Nonce, ServerPub, ClientSec) of
        {ok, Json} ->
            try
                {ok, jsx:decode(Json, [return_maps])}
            catch
                _:_ -> {error, invalid_json}
            end;
        {error, failed} ->
            {error, decrypt_failed}
    end.
