%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Unit tests for derp_crypto module.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_crypto_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%%--------------------------------------------------------------------
%% Test Setup
%%--------------------------------------------------------------------

%% Skip tests if NIF not available
setup() ->
    case code:ensure_loaded(derp_sodium) of
        {module, derp_sodium} ->
            %% Try to call a NIF function to verify it's loaded
            try
                derp_sodium:randombytes(1),
                ok
            catch
                error:nif_not_loaded -> skip
            end;
        _ ->
            skip
    end.

skip_if_no_nif(TestFun) ->
    fun() ->
        case setup() of
            ok -> TestFun();
            skip -> {skip, "NIF not loaded"}
        end
    end.

%%--------------------------------------------------------------------
%% Keypair Generation Tests
%%--------------------------------------------------------------------

keypair_generation_test_() ->
    skip_if_no_nif(fun() ->
        {PubKey, SecKey} = derp_crypto:generate_keypair(),
        ?assertEqual(32, byte_size(PubKey)),
        ?assertEqual(32, byte_size(SecKey)),
        %% Keys should be different
        ?assertNotEqual(PubKey, SecKey)
    end).

keypair_unique_test_() ->
    skip_if_no_nif(fun() ->
        {PubKey1, SecKey1} = derp_crypto:generate_keypair(),
        {PubKey2, SecKey2} = derp_crypto:generate_keypair(),
        %% Each keypair should be unique
        ?assertNotEqual(PubKey1, PubKey2),
        ?assertNotEqual(SecKey1, SecKey2)
    end).

%%--------------------------------------------------------------------
%% Box Seal/Open Tests
%%--------------------------------------------------------------------

box_roundtrip_test_() ->
    skip_if_no_nif(fun() ->
        %% Generate keypairs for Alice and Bob
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),

        %% Alice encrypts message to Bob
        Msg = <<"Hello, Bob!">>,
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        %% Ciphertext should be 16 bytes longer (MAC)
        ?assertEqual(byte_size(Msg) + ?BOX_OVERHEAD, byte_size(Cipher)),

        %% Bob decrypts message from Alice
        {ok, Decrypted} = derp_crypto:box_open(Cipher, Nonce, AlicePub, BobSec),
        ?assertEqual(Msg, Decrypted)
    end).

box_empty_message_test_() ->
    skip_if_no_nif(fun() ->
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),

        Msg = <<>>,
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        ?assertEqual(?BOX_OVERHEAD, byte_size(Cipher)),

        {ok, Decrypted} = derp_crypto:box_open(Cipher, Nonce, AlicePub, BobSec),
        ?assertEqual(Msg, Decrypted)
    end).

box_large_message_test_() ->
    skip_if_no_nif(fun() ->
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),

        %% Test with a larger message
        Msg = derp_crypto:random_bytes(65536),
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        {ok, Decrypted} = derp_crypto:box_open(Cipher, Nonce, AlicePub, BobSec),
        ?assertEqual(Msg, Decrypted)
    end).

%%--------------------------------------------------------------------
%% Tamper Detection Tests
%%--------------------------------------------------------------------

box_tamper_detection_test_() ->
    skip_if_no_nif(fun() ->
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),

        Msg = <<"Secret message">>,
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        %% Tamper with ciphertext
        <<First:8, Rest/binary>> = Cipher,
        TamperedCipher = <<(First bxor 16#FF):8, Rest/binary>>,

        %% Decryption should fail
        ?assertEqual({error, failed}, derp_crypto:box_open(TamperedCipher, Nonce, AlicePub, BobSec))
    end).

box_wrong_nonce_test_() ->
    skip_if_no_nif(fun() ->
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),

        Msg = <<"Test message">>,
        Nonce1 = derp_crypto:random_nonce(),
        Nonce2 = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce1, BobPub, AliceSec),

        %% Using wrong nonce should fail
        ?assertEqual({error, failed}, derp_crypto:box_open(Cipher, Nonce2, AlicePub, BobSec))
    end).

%%--------------------------------------------------------------------
%% Wrong Key Tests
%%--------------------------------------------------------------------

box_wrong_sender_key_test_() ->
    skip_if_no_nif(fun() ->
        {_AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, BobSec} = derp_crypto:generate_keypair(),
        {EvilPub, _EvilSec} = derp_crypto:generate_keypair(),

        Msg = <<"Private message">>,
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        %% Bob tries to decrypt but thinks it's from Evil (wrong sender key)
        ?assertEqual({error, failed}, derp_crypto:box_open(Cipher, Nonce, EvilPub, BobSec))
    end).

box_wrong_recipient_key_test_() ->
    skip_if_no_nif(fun() ->
        {AlicePub, AliceSec} = derp_crypto:generate_keypair(),
        {BobPub, _BobSec} = derp_crypto:generate_keypair(),
        {_EvilPub, EvilSec} = derp_crypto:generate_keypair(),

        Msg = <<"Private message">>,
        Nonce = derp_crypto:random_nonce(),
        Cipher = derp_crypto:box_seal(Msg, Nonce, BobPub, AliceSec),

        %% Evil tries to decrypt message meant for Bob
        ?assertEqual({error, failed}, derp_crypto:box_open(Cipher, Nonce, AlicePub, EvilSec))
    end).

%%--------------------------------------------------------------------
%% Random Bytes Tests
%%--------------------------------------------------------------------

random_nonce_test_() ->
    skip_if_no_nif(fun() ->
        Nonce = derp_crypto:random_nonce(),
        ?assertEqual(24, byte_size(Nonce))
    end).

random_nonce_unique_test_() ->
    skip_if_no_nif(fun() ->
        Nonces = [derp_crypto:random_nonce() || _ <- lists:seq(1, 100)],
        UniqueNonces = lists:usort(Nonces),
        ?assertEqual(100, length(UniqueNonces))
    end).

random_bytes_test_() ->
    skip_if_no_nif(fun() ->
        Bytes = derp_crypto:random_bytes(1024),
        ?assertEqual(1024, byte_size(Bytes))
    end).

random_bytes_zero_test_() ->
    skip_if_no_nif(fun() ->
        Bytes = derp_crypto:random_bytes(0),
        ?assertEqual(0, byte_size(Bytes))
    end).

%%--------------------------------------------------------------------
%% Client/Server Info Encryption Tests
%%--------------------------------------------------------------------

client_info_roundtrip_test_() ->
    skip_if_no_nif(fun() ->
        {ServerPub, ServerSec} = derp_crypto:generate_keypair(),
        {ClientPub, ClientSec} = derp_crypto:generate_keypair(),

        ClientInfo = #{<<"version">> => 1, <<"mesh_key">> => null},
        {Nonce, EncInfo} = derp_crypto:encrypt_client_info(ClientInfo, ServerPub, ClientSec),

        ?assertEqual(24, byte_size(Nonce)),
        ?assert(byte_size(EncInfo) > 0),

        {ok, DecryptedInfo} = derp_crypto:decrypt_client_info(EncInfo, Nonce, ClientPub, ServerSec),
        ?assertEqual(ClientInfo, DecryptedInfo)
    end).

server_info_roundtrip_test_() ->
    skip_if_no_nif(fun() ->
        {ServerPub, ServerSec} = derp_crypto:generate_keypair(),
        {ClientPub, ClientSec} = derp_crypto:generate_keypair(),

        ServerInfo = #{
            <<"version">> => 1,
            <<"token_bucket_bytes_per_second">> => 1048576,
            <<"token_bucket_bytes_burst">> => 2097152
        },
        {Nonce, EncInfo} = derp_crypto:encrypt_server_info(ServerInfo, ClientPub, ServerSec),

        {ok, DecryptedInfo} = derp_crypto:decrypt_server_info(EncInfo, Nonce, ServerPub, ClientSec),
        ?assertEqual(ServerInfo, DecryptedInfo)
    end).

decrypt_wrong_key_test_() ->
    skip_if_no_nif(fun() ->
        {ServerPub, _ServerSec} = derp_crypto:generate_keypair(),
        {ClientPub, ClientSec} = derp_crypto:generate_keypair(),
        {_EvilPub, EvilSec} = derp_crypto:generate_keypair(),

        ClientInfo = #{<<"version">> => 1},
        {Nonce, EncInfo} = derp_crypto:encrypt_client_info(ClientInfo, ServerPub, ClientSec),

        %% Try to decrypt with wrong server secret key
        ?assertEqual({error, decrypt_failed},
                     derp_crypto:decrypt_client_info(EncInfo, Nonce, ClientPub, EvilSec))
    end).
