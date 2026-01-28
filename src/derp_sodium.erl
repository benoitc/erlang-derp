%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc NIF wrapper for libsodium NaCl box operations.
%%%
%%% This module provides low-level bindings to libsodium for:
%%% - Curve25519 keypair generation
%%% - NaCl box encryption/decryption
%%% - Cryptographically secure random byte generation
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_sodium).

%% API
-export([
    box_keypair/0,
    box/4,
    box_open/4,
    randombytes/1
]).

%% NIF loading
-on_load(init/0).

-define(NIF_STUB, erlang:nif_error(nif_not_loaded)).

%%--------------------------------------------------------------------
%% NIF Loading
%%--------------------------------------------------------------------

init() ->
    SoName = find_nif_path("derp_sodium_nif"),
    case erlang:load_nif(SoName, 0) of
        ok -> ok;
        {error, {reload, _}} -> ok;  % Already loaded
        {error, Reason} ->
            logger:error("Failed to load derp_sodium NIF: ~p", [Reason]),
            {error, Reason}
    end.

%% @private
%% Find the NIF library path, trying multiple locations.
find_nif_path(NifName) ->
    %% Try these locations in order:
    %% 1. code:priv_dir (when app is properly started)
    %% 2. Relative to beam file location (../priv pattern)
    %% 3. Escript lib directory (/app/lib/derp/priv for Docker)
    %% 4. Current directory priv/
    Candidates = [
        priv_dir_candidate(NifName),
        beam_relative_candidate(NifName),
        escript_lib_candidate(NifName),
        filename:join("priv", NifName)
    ],
    find_existing_nif(Candidates).

priv_dir_candidate(NifName) ->
    case code:priv_dir(derp) of
        {error, _} -> undefined;
        Dir -> filename:join(Dir, NifName)
    end.

beam_relative_candidate(NifName) ->
    case code:which(?MODULE) of
        Filename when is_list(Filename) ->
            %% Beam is at .../ebin/derp_sodium.beam
            %% NIF is at .../priv/derp_sodium_nif.so
            EbinDir = filename:dirname(Filename),
            filename:join([EbinDir, "..", "priv", NifName]);
        _ ->
            undefined
    end.

escript_lib_candidate(NifName) ->
    %% For escript running in Docker with lib/ directory
    case escript:script_name() of
        [] -> undefined;
        ScriptPath ->
            ScriptDir = filename:dirname(ScriptPath),
            filename:join([ScriptDir, "lib", "derp", "priv", NifName])
    end.

find_existing_nif([]) ->
    %% Fallback - let load_nif find it or fail with useful error
    "derp_sodium_nif";
find_existing_nif([undefined | Rest]) ->
    find_existing_nif(Rest);
find_existing_nif([Path | Rest]) ->
    %% Try with .so extension (Linux) then without (let erlang add it)
    SoPath = Path ++ ".so",
    case filelib:is_file(SoPath) of
        true -> Path;
        false ->
            case filelib:is_file(Path) of
                true -> Path;
                false -> find_existing_nif(Rest)
            end
    end.

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Generate a Curve25519 keypair for NaCl box operations.
%%
%% Returns a tuple {PublicKey, SecretKey} where both keys are 32-byte binaries.
%% The public key can be shared, the secret key must be kept private.
%%
%% @returns {PublicKey :: binary(), SecretKey :: binary()}
-spec box_keypair() -> {PublicKey :: binary(), SecretKey :: binary()}.
box_keypair() ->
    ?NIF_STUB.

%% @doc Encrypt and authenticate a message using NaCl box.
%%
%% The nonce must be unique for each message encrypted with the same keypair.
%% The ciphertext will be 16 bytes longer than the plaintext (MAC overhead).
%%
%% @param Msg Plaintext message (any size)
%% @param Nonce 24-byte unique nonce
%% @param TheirPub Recipient's 32-byte public key
%% @param MySec Sender's 32-byte secret key
%% @returns Ciphertext including 16-byte authentication tag
-spec box(Msg :: binary(), Nonce :: binary(), TheirPub :: binary(), MySec :: binary()) ->
    CipherText :: binary().
box(_Msg, _Nonce, _TheirPub, _MySec) ->
    ?NIF_STUB.

%% @doc Decrypt and verify a message encrypted with NaCl box.
%%
%% Returns {ok, Plaintext} on success, or error if decryption or
%% authentication fails (wrong key, tampered ciphertext, etc.).
%%
%% @param Cipher Ciphertext (including 16-byte MAC)
%% @param Nonce 24-byte nonce used during encryption
%% @param TheirPub Sender's 32-byte public key
%% @param MySec Recipient's 32-byte secret key
%% @returns {ok, Plaintext} | error
-spec box_open(Cipher :: binary(), Nonce :: binary(), TheirPub :: binary(), MySec :: binary()) ->
    {ok, binary()} | error.
box_open(_Cipher, _Nonce, _TheirPub, _MySec) ->
    ?NIF_STUB.

%% @doc Generate cryptographically secure random bytes.
%%
%% @param N Number of bytes to generate (max 65536)
%% @returns Binary of N random bytes
-spec randombytes(N :: non_neg_integer()) -> binary().
randombytes(_N) ->
    ?NIF_STUB.
