/*
 * Copyright (c) 2026 Benoit Chesneau
 * SPDX-License-Identifier: MIT
 *
 * derp_sodium_nif.c - NIF wrapper for libsodium NaCl box operations
 *
 * Provides Curve25519 keypair generation and NaCl box encryption/decryption
 * for the DERP protocol.
 */

#include <string.h>
#include <sodium.h>
#include "erl_nif.h"

/* Constants matching NaCl/libsodium */
#define PUBLICKEYBYTES crypto_box_PUBLICKEYBYTES  /* 32 */
#define SECRETKEYBYTES crypto_box_SECRETKEYBYTES  /* 32 */
#define NONCEBYTES     crypto_box_NONCEBYTES      /* 24 */
#define MACBYTES       crypto_box_MACBYTES        /* 16 */

/* Atom cache for commonly used atoms */
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_badarg;
static ERL_NIF_TERM atom_decrypt_failed;

/*
 * Initialize atoms on NIF load
 */
static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    /* Initialize libsodium */
    if (sodium_init() < 0) {
        /* sodium_init() returns -1 on failure, 0 on success, 1 if already initialized */
        return -1;
    }

    /* Create atom cache */
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_enomem = enif_make_atom(env, "enomem");
    atom_badarg = enif_make_atom(env, "badarg");
    atom_decrypt_failed = enif_make_atom(env, "decrypt_failed");

    *priv_data = NULL;
    return 0;
}

/*
 * box_keypair/0
 *
 * Generate a Curve25519 keypair for NaCl box operations.
 *
 * Returns: {PublicKey :: binary(), SecretKey :: binary()}
 */
static ERL_NIF_TERM
nif_box_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM pk_term, sk_term;
    unsigned char *pk, *sk;

    /* Allocate binaries for keys */
    pk = enif_make_new_binary(env, PUBLICKEYBYTES, &pk_term);
    if (pk == NULL) {
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    sk = enif_make_new_binary(env, SECRETKEYBYTES, &sk_term);
    if (sk == NULL) {
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    /* Generate keypair */
    crypto_box_keypair(pk, sk);

    return enif_make_tuple2(env, pk_term, sk_term);
}

/*
 * box/4
 *
 * Encrypt and authenticate a message using NaCl box.
 *
 * Args:
 *   Msg       :: binary()  - Plaintext message
 *   Nonce     :: binary()  - 24-byte nonce (must be unique per message)
 *   TheirPub  :: binary()  - Recipient's 32-byte public key
 *   MySec     :: binary()  - Sender's 32-byte secret key
 *
 * Returns: CipherText :: binary()
 *   Ciphertext is 16 bytes (MAC) longer than plaintext
 */
static ERL_NIF_TERM
nif_box(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, nonce, their_pk, my_sk;
    ERL_NIF_TERM cipher_term;
    unsigned char *cipher;
    size_t cipher_len;

    /* Validate and extract arguments */
    if (!enif_inspect_binary(env, argv[0], &msg)) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, argv[1], &nonce) || nonce.size != NONCEBYTES) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, argv[2], &their_pk) || their_pk.size != PUBLICKEYBYTES) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, argv[3], &my_sk) || my_sk.size != SECRETKEYBYTES) {
        return enif_make_badarg(env);
    }

    /* Allocate ciphertext buffer (plaintext + MAC) */
    cipher_len = msg.size + MACBYTES;
    cipher = enif_make_new_binary(env, cipher_len, &cipher_term);
    if (cipher == NULL) {
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    /* Encrypt */
    if (crypto_box_easy(cipher, msg.data, msg.size,
                        nonce.data, their_pk.data, my_sk.data) != 0) {
        /* crypto_box_easy should not fail with valid inputs */
        return enif_make_tuple2(env, atom_error, atom_badarg);
    }

    return cipher_term;
}

/*
 * box_open/4
 *
 * Decrypt and verify a message encrypted with NaCl box.
 *
 * Args:
 *   Cipher    :: binary()  - Ciphertext (including 16-byte MAC)
 *   Nonce     :: binary()  - 24-byte nonce used for encryption
 *   TheirPub  :: binary()  - Sender's 32-byte public key
 *   MySec     :: binary()  - Recipient's 32-byte secret key
 *
 * Returns: {ok, Plaintext :: binary()} | error
 */
static ERL_NIF_TERM
nif_box_open(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary cipher, nonce, their_pk, my_sk;
    ERL_NIF_TERM msg_term;
    unsigned char *msg;
    size_t msg_len;

    /* Validate and extract arguments */
    if (!enif_inspect_binary(env, argv[0], &cipher)) {
        return enif_make_badarg(env);
    }
    if (cipher.size < MACBYTES) {
        /* Ciphertext must be at least MAC size */
        return atom_error;
    }
    if (!enif_inspect_binary(env, argv[1], &nonce) || nonce.size != NONCEBYTES) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, argv[2], &their_pk) || their_pk.size != PUBLICKEYBYTES) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, argv[3], &my_sk) || my_sk.size != SECRETKEYBYTES) {
        return enif_make_badarg(env);
    }

    /* Allocate plaintext buffer */
    msg_len = cipher.size - MACBYTES;
    msg = enif_make_new_binary(env, msg_len, &msg_term);
    if (msg == NULL) {
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    /* Decrypt and verify */
    if (crypto_box_open_easy(msg, cipher.data, cipher.size,
                             nonce.data, their_pk.data, my_sk.data) != 0) {
        /* Decryption or verification failed */
        return atom_error;
    }

    return enif_make_tuple2(env, atom_ok, msg_term);
}

/*
 * randombytes/1
 *
 * Generate cryptographically secure random bytes.
 *
 * Args:
 *   N :: non_neg_integer()  - Number of bytes to generate
 *
 * Returns: binary()
 */
static ERL_NIF_TERM
nif_randombytes(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned int n;
    ERL_NIF_TERM bin_term;
    unsigned char *buf;

    if (!enif_get_uint(env, argv[0], &n)) {
        return enif_make_badarg(env);
    }

    /* Reasonable limit to prevent DoS */
    if (n > 65536) {
        return enif_make_badarg(env);
    }

    buf = enif_make_new_binary(env, n, &bin_term);
    if (buf == NULL) {
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    randombytes_buf(buf, n);

    return bin_term;
}

/*
 * NIF function definitions
 */
static ErlNifFunc nif_funcs[] = {
    {"box_keypair", 0, nif_box_keypair, 0},
    {"box", 4, nif_box, 0},
    {"box_open", 4, nif_box_open, 0},
    {"randombytes", 1, nif_randombytes, 0}
};

ERL_NIF_INIT(derp_sodium, nif_funcs, load, NULL, NULL, NULL)
