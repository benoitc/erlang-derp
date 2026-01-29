/*
 * Copyright (c) 2026 Benoit Chesneau
 * SPDX-License-Identifier: MIT
 *
 * derp_tls_nif.c - BoringSSL-based TLS NIF with enif_select
 *
 * Provides non-blocking TLS connections using BoringSSL Memory BIOs
 * and enif_select for I/O readiness notification. This bypasses OTP's
 * ssl module which rejects Tailscale DERP certificates with CommonName
 * exceeding the X.520 ub-common-name=64 limit.
 *
 * Architecture:
 *   - NIF resource owns: raw socket fd, SSL*, BIO pair, owner pid
 *   - enif_select(fd, READ/WRITE) for non-blocking I/O
 *   - Memory BIOs: SSL_read/SSL_write use BIOs, NIF does read(fd)/write(fd)
 *   - Owner process receives {select, Ref, _, ready_input/ready_output}
 *
 * Dirty NIF scheduling:
 *   Functions that perform BoringSSL crypto or blocking I/O run on dirty
 *   schedulers to avoid blocking normal BEAM schedulers:
 *   - conn_connect: DNS resolution via getaddrinfo() (dirty IO)
 *   - ctx_set_cert: reads cert/key files from disk (dirty IO)
 *   - handshake: SSL_do_handshake with key exchange (dirty CPU)
 *   - recv/send: socket I/O + symmetric crypto (dirty IO)
 *   - shutdown: SSL_shutdown + close (dirty IO)
 *   Lightweight functions (ctx_new, select_read/write, peername, etc.)
 *   run on normal schedulers.
 */

/* BoringSSL headers MUST be included before Windows headers to avoid
 * macro conflicts. Windows defines X509_NAME, X509, PKCS7, etc. as
 * macros that expand to function calls, which breaks BoringSSL's
 * type declarations. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include <string.h>
#include <errno.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define SOCK_CLOSE(s) closesocket(s)
#define SOCK_ERRNO WSAGetLastError()
#define SOCK_EAGAIN WSAEWOULDBLOCK
#define SOCK_EINPROGRESS WSAEWOULDBLOCK
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define SOCK_CLOSE(s) close(s)
#define SOCK_ERRNO errno
#define SOCK_EAGAIN EAGAIN
#define SOCK_EINPROGRESS EINPROGRESS
#endif

#include "erl_nif.h"

/* Buffer size for read/write operations */
#define IO_BUF_SIZE 65536

/* ------------------------------------------------------------------ */
/* Resource types                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    SSL_CTX *ctx;
} tls_ctx_t;

typedef struct {
    sock_t       fd;
    SSL         *ssl;
    BIO         *rbio;          /* network -> SSL (we write into this) */
    BIO         *wbio;          /* SSL -> network (we read from this)  */
    ErlNifPid    owner;
    int          handshake_done;
    int          closed;
    /* Pending write buffer: holds data read from wbio but not yet sent */
    unsigned char *pending_write;
    int          pending_write_len;
    int          pending_write_off;
} tls_conn_t;

static ErlNifResourceType *tls_ctx_type  = NULL;
static ErlNifResourceType *tls_conn_type = NULL;

/* Atom cache */
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_undefined;
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;
static ERL_NIF_TERM atom_client;
static ERL_NIF_TERM atom_server;
static ERL_NIF_TERM atom_want_read;
static ERL_NIF_TERM atom_want_write;
static ERL_NIF_TERM atom_closed;
static ERL_NIF_TERM atom_einval;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_eagain;
static ERL_NIF_TERM atom_einprogress;
static ERL_NIF_TERM atom_select;
static ERL_NIF_TERM atom_ready_input;
static ERL_NIF_TERM atom_ready_output;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env, atom_error, enif_make_atom(env, reason));
}

static ERL_NIF_TERM make_ssl_error(ErlNifEnv *env)
{
    unsigned long err = ERR_get_error();
    if (err == 0)
        return make_error(env, "unknown_ssl_error");

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    /* Clear remaining errors */
    ERR_clear_error();
    return enif_make_tuple2(env, atom_error,
                            enif_make_string(env, buf, ERL_NIF_LATIN1));
}

static int set_nonblocking(sock_t fd)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int set_nodelay(sock_t fd)
{
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                      (const char *)&one, sizeof(one));
}

/* Flush wbio -> fd: after SSL_write or SSL_do_handshake
 * Returns: 0 = all data sent, -1 = EAGAIN (call again when writable), -2 = error
 */
static int flush_wbio(tls_conn_t *conn)
{
    /* First, try to send any pending data from previous flush */
    while (conn->pending_write_len > 0) {
        int remaining = conn->pending_write_len - conn->pending_write_off;
        int n = (int)send(conn->fd, conn->pending_write + conn->pending_write_off,
                          remaining, 0);
        if (n > 0) {
            conn->pending_write_off += n;
            if (conn->pending_write_off >= conn->pending_write_len) {
                /* All pending data sent, free the buffer */
                enif_free(conn->pending_write);
                conn->pending_write = NULL;
                conn->pending_write_len = 0;
                conn->pending_write_off = 0;
            }
        } else if (n < 0) {
            int err = SOCK_ERRNO;
            if (err == SOCK_EAGAIN || err == SOCK_EINPROGRESS) {
                return -1; /* Try again later */
            }
            return -2; /* Real error */
        } else {
            return -2; /* Connection closed */
        }
    }

    /* Now drain the wbio */
    char buf[IO_BUF_SIZE];
    int pending;

    while ((pending = BIO_read(conn->wbio, buf, sizeof(buf))) > 0) {
        char *p = buf;
        int remaining = pending;
        while (remaining > 0) {
            int n = (int)send(conn->fd, p, remaining, 0);
            if (n > 0) {
                p += n;
                remaining -= n;
            } else if (n < 0) {
                int err = SOCK_ERRNO;
                if (err == SOCK_EAGAIN || err == SOCK_EINPROGRESS) {
                    /* Save unsent data to pending buffer */
                    conn->pending_write = enif_alloc(remaining);
                    if (!conn->pending_write) {
                        return -2; /* Out of memory */
                    }
                    memcpy(conn->pending_write, p, remaining);
                    conn->pending_write_len = remaining;
                    conn->pending_write_off = 0;
                    return -1; /* Try again later */
                }
                return -2; /* Real error */
            } else {
                return -2; /* Connection closed */
            }
        }
    }
    return 0;
}

/* Return values for feed_rbio:
 *   > 0 : bytes fed into rbio
 *   0   : EAGAIN, no data available (not EOF)
 *  -1   : real error
 *  -2   : EOF (peer closed TCP connection)
 */
#define FEED_EAGAIN  0
#define FEED_ERROR  (-1)
#define FEED_EOF    (-2)

/* Read fd -> rbio: before SSL_read or SSL_do_handshake */
static int feed_rbio(tls_conn_t *conn)
{
    char buf[IO_BUF_SIZE];
    int total = 0;

    for (;;) {
        int n = (int)recv(conn->fd, buf, sizeof(buf), 0);
        if (n > 0) {
            BIO_write(conn->rbio, buf, n);
            total += n;
        } else if (n == 0) {
            /* TCP FIN received (peer closed) */
            return total > 0 ? total : FEED_EOF;
        } else {
            int err = SOCK_ERRNO;
            if (err == SOCK_EAGAIN || err == SOCK_EINPROGRESS) {
                break; /* No more data available right now */
            }
            return FEED_ERROR; /* Real error */
        }
    }
    return total; /* >= 0: total bytes fed, or 0 for EAGAIN with nothing read */
}

/* ------------------------------------------------------------------ */
/* Resource destructors                                                */
/* ------------------------------------------------------------------ */

static void tls_ctx_dtor(ErlNifEnv *env, void *obj)
{
    tls_ctx_t *ctx = (tls_ctx_t *)obj;
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

static void tls_conn_dtor(ErlNifEnv *env, void *obj)
{
    tls_conn_t *conn = (tls_conn_t *)obj;
    if (conn->ssl) {
        SSL_free(conn->ssl); /* Also frees BIOs attached to SSL */
        conn->ssl = NULL;
        conn->rbio = NULL;
        conn->wbio = NULL;
    }
    if (conn->pending_write) {
        enif_free(conn->pending_write);
        conn->pending_write = NULL;
    }
    if (conn->fd != SOCK_INVALID) {
        /* Deselect before close */
        enif_select(env, (ErlNifEvent)(long)conn->fd,
                    ERL_NIF_SELECT_STOP, conn, NULL, atom_undefined);
        SOCK_CLOSE(conn->fd);
        conn->fd = SOCK_INVALID;
    }
}

static void tls_conn_stop(ErlNifEnv *env, void *obj,
                           ErlNifEvent event, int is_direct_call)
{
    /* Called when enif_select STOP completes. Nothing extra to do. */
}

/* ------------------------------------------------------------------ */
/* NIF: ctx_new/1                                                      */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_ctx_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int is_client;

    if (enif_is_identical(argv[0], atom_client)) {
        is_client = 1;
    } else if (enif_is_identical(argv[0], atom_server)) {
        is_client = 0;
    } else {
        return enif_make_badarg(env);
    }

    tls_ctx_t *ctx = enif_alloc_resource(tls_ctx_type, sizeof(tls_ctx_t));
    if (!ctx) return make_error(env, "enomem");

    const SSL_METHOD *method = is_client ? TLS_client_method() : TLS_server_method();
    ctx->ctx = SSL_CTX_new(method);
    if (!ctx->ctx) {
        enif_release_resource(ctx);
        return make_ssl_error(env);
    }

    /* Reasonable defaults */
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_2_VERSION);

    ERL_NIF_TERM res = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return enif_make_tuple2(env, atom_ok, res);
}

/* ------------------------------------------------------------------ */
/* NIF: ctx_set_verify/2                                               */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_ctx_set_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_ctx_t *ctx;
    if (!enif_get_resource(env, argv[0], tls_ctx_type, (void **)&ctx))
        return enif_make_badarg(env);

    int mode;
    if (enif_is_identical(argv[1], atom_true)) {
        mode = SSL_VERIFY_PEER;
    } else {
        mode = SSL_VERIFY_NONE;
    }

    SSL_CTX_set_verify(ctx->ctx, mode, NULL);
    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: ctx_set_cert/3                                                 */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_ctx_set_cert(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_ctx_t *ctx;
    if (!enif_get_resource(env, argv[0], tls_ctx_type, (void **)&ctx))
        return enif_make_badarg(env);

    char certfile[1024], keyfile[1024];
    if (!enif_get_string(env, argv[1], certfile, sizeof(certfile), ERL_NIF_LATIN1))
        return enif_make_badarg(env);
    if (!enif_get_string(env, argv[2], keyfile, sizeof(keyfile), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    if (SSL_CTX_use_certificate_chain_file(ctx->ctx, certfile) != 1)
        return make_ssl_error(env);
    if (SSL_CTX_use_PrivateKey_file(ctx->ctx, keyfile, SSL_FILETYPE_PEM) != 1)
        return make_ssl_error(env);
    if (SSL_CTX_check_private_key(ctx->ctx) != 1)
        return make_ssl_error(env);

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: conn_new/3                                                     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_conn_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_ctx_t *ctx;
    if (!enif_get_resource(env, argv[0], tls_ctx_type, (void **)&ctx))
        return enif_make_badarg(env);

    int is_client;
    if (enif_is_identical(argv[1], atom_client)) {
        is_client = 1;
    } else if (enif_is_identical(argv[1], atom_server)) {
        is_client = 0;
    } else {
        return enif_make_badarg(env);
    }

    ErlNifPid owner;
    if (!enif_get_local_pid(env, argv[2], &owner))
        return enif_make_badarg(env);

    tls_conn_t *conn = enif_alloc_resource(tls_conn_type, sizeof(tls_conn_t));
    if (!conn) return make_error(env, "enomem");

    memset(conn, 0, sizeof(tls_conn_t));
    conn->fd = SOCK_INVALID;
    conn->owner = owner;

    conn->ssl = SSL_new(ctx->ctx);
    if (!conn->ssl) {
        enif_release_resource(conn);
        return make_ssl_error(env);
    }

    /* Create memory BIO pair */
    conn->rbio = BIO_new(BIO_s_mem());
    conn->wbio = BIO_new(BIO_s_mem());
    if (!conn->rbio || !conn->wbio) {
        enif_release_resource(conn);
        return make_error(env, "bio_alloc_failed");
    }

    /* Set BIOs non-blocking (return retry instead of blocking) */
    BIO_set_nbio(conn->rbio, 1);
    BIO_set_nbio(conn->wbio, 1);

    /* Attach BIOs to SSL (SSL takes ownership) */
    SSL_set_bio(conn->ssl, conn->rbio, conn->wbio);

    if (is_client) {
        SSL_set_connect_state(conn->ssl);
    } else {
        SSL_set_accept_state(conn->ssl);
    }

    ERL_NIF_TERM res = enif_make_resource(env, conn);
    enif_release_resource(conn);
    return enif_make_tuple2(env, atom_ok, res);
}

/* ------------------------------------------------------------------ */
/* NIF: conn_set_hostname/2                                            */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_conn_set_hostname(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    char hostname[256];
    if (!enif_get_string(env, argv[1], hostname, sizeof(hostname), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    SSL_set_tlsext_host_name(conn->ssl, hostname);
    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: conn_connect/3 - create socket and initiate async connect      */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_conn_connect(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    char host[256];
    if (!enif_get_string(env, argv[1], host, sizeof(host), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    int port;
    if (!enif_get_int(env, argv[2], &port))
        return enif_make_badarg(env);

    /* Resolve hostname */
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int gai_err = getaddrinfo(host, port_str, &hints, &result);
    if (gai_err != 0) {
        return make_error(env, "resolve_failed");
    }

    /* Create socket */
    sock_t fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd == SOCK_INVALID) {
        freeaddrinfo(result);
        return make_error(env, "socket_failed");
    }

    /* Set non-blocking before connect */
    if (set_nonblocking(fd) < 0) {
        SOCK_CLOSE(fd);
        freeaddrinfo(result);
        return make_error(env, "nonblock_failed");
    }

    set_nodelay(fd);

    /* Initiate async connect */
    int ret = connect(fd, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (ret < 0) {
        int err = SOCK_ERRNO;
        if (err != SOCK_EINPROGRESS && err != SOCK_EAGAIN) {
            SOCK_CLOSE(fd);
            return make_error(env, "connect_failed");
        }
    }

    conn->fd = fd;

    /* If connect returned 0, we're already connected (loopback).
     * If EINPROGRESS, caller should select_write and wait. */
    if (ret == 0) {
        return atom_ok;
    }

    return enif_make_tuple2(env, atom_ok, atom_einprogress);
}

/* ------------------------------------------------------------------ */
/* NIF: conn_set_fd/2 - attach an existing fd (for server accept)      */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_conn_set_fd(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    int fd;
    if (!enif_get_int(env, argv[1], &fd))
        return enif_make_badarg(env);

    /* dup() the fd so the NIF owns its own copy.  The caller can
     * safely close the original (e.g. gen_tcp socket) without
     * affecting the NIF's connection. */
#ifdef _WIN32
    WSAPROTOCOL_INFOW info;
    if (WSADuplicateSocketW((SOCKET)fd, GetCurrentProcessId(), &info) != 0)
        return make_error(env, "dup_failed");
    SOCKET dup_fd = WSASocketW(info.iAddressFamily, info.iSocketType,
                                info.iProtocol, &info, 0, 0);
    if (dup_fd == INVALID_SOCKET)
        return make_error(env, "dup_failed");
    conn->fd = dup_fd;
#else
    int dup_fd = dup(fd);
    if (dup_fd < 0)
        return make_error(env, "dup_failed");
    conn->fd = (sock_t)dup_fd;
#endif

    if (set_nonblocking(conn->fd) < 0) {
        SOCK_CLOSE(conn->fd);
        conn->fd = SOCK_INVALID;
        return make_error(env, "nonblock_failed");
    }

    set_nodelay(conn->fd);

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: handshake/1 - one step of the TLS handshake                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_handshake(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    if (conn->handshake_done)
        return atom_ok;

    /* Feed any available network data into the rbio */
    feed_rbio(conn);

    /* Attempt handshake step */
    int ret = SSL_do_handshake(conn->ssl);
    if (ret == 1) {
        /* Handshake complete */
        conn->handshake_done = 1;
        /* Flush any remaining data in wbio */
        flush_wbio(conn);
        return atom_ok;
    }

    int ssl_err = SSL_get_error(conn->ssl, ret);

    /* Always flush wbio after handshake step (may have data to send) */
    flush_wbio(conn);

    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        return atom_want_read;
    case SSL_ERROR_WANT_WRITE:
        return atom_want_write;
    default:
        return make_ssl_error(env);
    }
}

/* ------------------------------------------------------------------ */
/* NIF: recv/1 - read decrypted data                                   */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_recv(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID || conn->closed)
        return make_error(env, "closed");

    /* Feed network data into rbio */
    int fed = feed_rbio(conn);
    if (fed == FEED_ERROR)
        return make_error(env, "recv_failed");

    /* Try to read decrypted data */
    unsigned char buf[IO_BUF_SIZE];
    int n = SSL_read(conn->ssl, buf, sizeof(buf));

    if (n > 0) {
        ERL_NIF_TERM bin;
        unsigned char *out = enif_make_new_binary(env, (size_t)n, &bin);
        if (!out) return make_error(env, "enomem");
        memcpy(out, buf, (size_t)n);

        /* Flush any renegotiation data */
        flush_wbio(conn);

        return enif_make_tuple2(env, atom_ok, bin);
    }

    int ssl_err = SSL_get_error(conn->ssl, n);

    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        if (fed == FEED_EOF) {
            /* TCP peer closed the connection */
            conn->closed = 1;
            return make_error(env, "closed");
        }
        /* No data available yet (EAGAIN) or incomplete TLS record */
        return atom_want_read;
    case SSL_ERROR_ZERO_RETURN:
        conn->closed = 1;
        return make_error(env, "closed");
    default:
        return make_ssl_error(env);
    }
}

/* ------------------------------------------------------------------ */
/* NIF: send/2 - encrypt and send data                                 */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_send(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[1], &data))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID || conn->closed)
        return make_error(env, "closed");

    if (data.size == 0)
        return atom_ok;

    /* First, try to flush any pending data from previous sends */
    int flush_ret = flush_wbio(conn);
    if (flush_ret == -2) {
        return make_error(env, "send_failed");
    } else if (flush_ret == -1) {
        /* Still have pending data, can't accept new data yet */
        return atom_want_write;
    }

    /* SSL_write encrypts data into wbio */
    int n = SSL_write(conn->ssl, data.data, (int)data.size);
    if (n <= 0) {
        int ssl_err = SSL_get_error(conn->ssl, n);
        switch (ssl_err) {
        case SSL_ERROR_WANT_WRITE:
            return atom_want_write;
        case SSL_ERROR_WANT_READ:
            return atom_want_read;
        default:
            return make_ssl_error(env);
        }
    }

    /* Flush encrypted data to the wire */
    flush_ret = flush_wbio(conn);
    if (flush_ret == -2) {
        return make_error(env, "send_failed");
    } else if (flush_ret == -1) {
        /* Partial send, need to wait for writable then retry flush */
        return atom_want_write;
    }

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: flush/1 - flush any pending encrypted data to the socket       */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_flush(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID || conn->closed)
        return make_error(env, "closed");

    int ret = flush_wbio(conn);
    if (ret == -2) {
        return make_error(env, "send_failed");
    } else if (ret == -1) {
        return atom_want_write;
    }
    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: select_read/1 - arm enif_select for read readiness             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_select_read(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    int ret = enif_select(env, (ErlNifEvent)(long)conn->fd,
                          ERL_NIF_SELECT_READ, conn, &conn->owner,
                          atom_undefined);
    if (ret < 0)
        return make_error(env, "select_failed");

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: select_write/1 - arm enif_select for write readiness           */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_select_write(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    int ret = enif_select(env, (ErlNifEvent)(long)conn->fd,
                          ERL_NIF_SELECT_WRITE, conn, &conn->owner,
                          atom_undefined);
    if (ret < 0)
        return make_error(env, "select_failed");

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: shutdown/1 - TLS shutdown + close fd                           */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_shutdown(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->ssl && !conn->closed) {
        SSL_shutdown(conn->ssl);
        flush_wbio(conn);
        conn->closed = 1;
    }

    if (conn->fd != SOCK_INVALID) {
        enif_select(env, (ErlNifEvent)(long)conn->fd,
                    ERL_NIF_SELECT_STOP, conn, NULL, atom_undefined);
        SOCK_CLOSE(conn->fd);
        conn->fd = SOCK_INVALID;
    }

    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: peername/1 - get remote address                                */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_peername(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(conn->fd, (struct sockaddr *)&addr, &len) < 0)
        return make_error(env, "getpeername_failed");

    char host[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&addr, len,
                    host, sizeof(host), port_str, sizeof(port_str),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return make_error(env, "getnameinfo_failed");

    int port = atoi(port_str);
    return enif_make_tuple2(env, atom_ok,
        enif_make_tuple2(env,
            enif_make_string(env, host, ERL_NIF_LATIN1),
            enif_make_int(env, port)));
}

/* ------------------------------------------------------------------ */
/* NIF: sockname/1 - get local address                                 */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_sockname(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getsockname(conn->fd, (struct sockaddr *)&addr, &len) < 0)
        return make_error(env, "getsockname_failed");

    char host[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&addr, len,
                    host, sizeof(host), port_str, sizeof(port_str),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return make_error(env, "getnameinfo_failed");

    int port = atoi(port_str);
    return enif_make_tuple2(env, atom_ok,
        enif_make_tuple2(env,
            enif_make_string(env, host, ERL_NIF_LATIN1),
            enif_make_int(env, port)));
}

/* ------------------------------------------------------------------ */
/* NIF: controlling_process/2 - change owner pid                       */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_controlling_process(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    ErlNifPid new_owner;
    if (!enif_get_local_pid(env, argv[1], &new_owner))
        return enif_make_badarg(env);

    conn->owner = new_owner;
    return atom_ok;
}

/* ------------------------------------------------------------------ */
/* NIF: get_fd/1 - get raw fd (for server accept integration)          */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM
nif_get_fd(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    tls_conn_t *conn;
    if (!enif_get_resource(env, argv[0], tls_conn_type, (void **)&conn))
        return enif_make_badarg(env);

    if (conn->fd == SOCK_INVALID)
        return make_error(env, "not_connected");

    return enif_make_tuple2(env, atom_ok, enif_make_int(env, (int)conn->fd));
}

/* ------------------------------------------------------------------ */
/* NIF lifecycle                                                       */
/* ------------------------------------------------------------------ */

static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;
#endif

    /* Initialize BoringSSL */
    SSL_library_init();

    /* Create resource types */
    ErlNifResourceTypeInit ctx_init = {
        .dtor = tls_ctx_dtor,
        .stop = NULL,
        .down = NULL
    };
    tls_ctx_type = enif_open_resource_type_x(env, "tls_ctx",
                                              &ctx_init,
                                              ERL_NIF_RT_CREATE, NULL);

    ErlNifResourceTypeInit conn_init = {
        .dtor = tls_conn_dtor,
        .stop = tls_conn_stop,
        .down = NULL
    };
    tls_conn_type = enif_open_resource_type_x(env, "tls_conn",
                                               &conn_init,
                                               ERL_NIF_RT_CREATE, NULL);

    if (!tls_ctx_type || !tls_conn_type)
        return -1;

    /* Atom cache */
    atom_ok           = enif_make_atom(env, "ok");
    atom_error        = enif_make_atom(env, "error");
    atom_undefined    = enif_make_atom(env, "undefined");
    atom_true         = enif_make_atom(env, "true");
    atom_false        = enif_make_atom(env, "false");
    atom_client       = enif_make_atom(env, "client");
    atom_server       = enif_make_atom(env, "server");
    atom_want_read    = enif_make_atom(env, "want_read");
    atom_want_write   = enif_make_atom(env, "want_write");
    atom_closed       = enif_make_atom(env, "closed");
    atom_einval       = enif_make_atom(env, "einval");
    atom_enomem       = enif_make_atom(env, "enomem");
    atom_eagain       = enif_make_atom(env, "eagain");
    atom_einprogress  = enif_make_atom(env, "einprogress");
    atom_select       = enif_make_atom(env, "select");
    atom_ready_input  = enif_make_atom(env, "ready_input");
    atom_ready_output = enif_make_atom(env, "ready_output");

    *priv_data = NULL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* NIF function table                                                  */
/* ------------------------------------------------------------------ */

static ErlNifFunc nif_funcs[] = {
    {"ctx_new",              1, nif_ctx_new,              0},
    {"ctx_set_verify",       2, nif_ctx_set_verify,       0},
    {"ctx_set_cert",         3, nif_ctx_set_cert,         ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"conn_new",             3, nif_conn_new,             0},
    {"conn_set_hostname",    2, nif_conn_set_hostname,    0},
    {"conn_connect",         3, nif_conn_connect,         ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"conn_set_fd",          2, nif_conn_set_fd,          0},
    {"handshake",            1, nif_handshake,            ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"recv",                 1, nif_recv,                 ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"send",                 2, nif_send,                 ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"flush",                1, nif_flush,                ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"select_read",          1, nif_select_read,          0},
    {"select_write",         1, nif_select_write,         0},
    {"shutdown",             1, nif_shutdown,             ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"peername",             1, nif_peername,             0},
    {"sockname",             1, nif_sockname,             0},
    {"controlling_process",  2, nif_controlling_process,  0},
    {"get_fd",               1, nif_get_fd,               0}
};

ERL_NIF_INIT(derp_tls_nif, nif_funcs, load, NULL, NULL, NULL)
