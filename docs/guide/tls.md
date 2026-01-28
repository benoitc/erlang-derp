# TLS with BoringSSL

This guide covers the BoringSSL-based TLS implementation used by the DERP client and server for transport encryption.

## Background

OTP 28's `ssl` module rejects Tailscale DERP server certificates. The self-signed DERP key certificate has a 71-character CommonName, exceeding X.520's `ub-common-name = 64` limit. The ASN.1 decode failure in `OTP-PKIX` is fatal and fires before any user callback (`partial_chain`, `verify_fun`, etc.) has a chance to intervene. There is no ssl option to skip or relax this constraint.

To work around this, the DERP library includes a BoringSSL-based TLS NIF that handles transport encryption directly. BoringSSL is lenient with non-conforming certificates and is the same TLS library used by Tailscale's Go stack.

## Architecture

```
derp_client / derp_conn (gen_statem)
    |  derp_tls:connect(Host, Port, Opts) -> {ok, ConnRef}
    |  derp_tls:send(ConnRef, Data)
    |  receives {select, ConnRef, _, ready_input}
    |  calls    derp_tls:recv(ConnRef) -> {ok, Plaintext}
    v
derp_tls_nif (NIF resource)
    |  enif_select(fd, READ/WRITE) for non-blocking I/O
    |  SSL_read / SSL_write via Memory BIOs
    v
BoringSSL (SSL*, BIO* rbio/wbio) + raw socket fd
```

### Key design points

- **No gen_server** -- the owning process (gen_statem) calls NIF functions directly and receives `{select, ConnRef, _, ready_input | ready_output}` messages via `enif_select`.
- **Memory BIOs** -- BoringSSL's `SSL_read`/`SSL_write` operate on in-memory BIO buffers. The NIF shuttles data between the raw socket fd and the BIOs using non-blocking `recv()`/`send()`.
- **Dirty schedulers** -- Functions that perform BoringSSL crypto or blocking system calls run on dirty schedulers to avoid stalling normal BEAM schedulers. See [Dirty NIF scheduling](#dirty-nif-scheduling) below.
- **NIF resource lifecycle** -- The `tls_conn_t` resource owns the socket fd, SSL handle, and BIO pair. When the resource is garbage collected, the destructor closes the socket and frees SSL state.

## Data Flow

### Receiving (network to application)

1. NIF arms `enif_select(fd, READ)` after handshake or after `activate/1`
2. BEAM delivers `{select, ConnRef, _, ready_input}` to the owner process
3. Owner calls `derp_tls:recv(ConnRef)` -- the NIF does `recv(fd)` into rbio, then `SSL_read` to decrypt
4. Returns `{ok, Plaintext}` or `{error, want_read}` if no complete TLS record is available
5. Owner calls `derp_tls:activate(ConnRef)` to arm for the next packet

### Sending (application to network)

1. Owner calls `derp_tls:send(ConnRef, Data)` -- the NIF does `SSL_write` (encrypts into wbio), then `BIO_read(wbio)` into `send(fd)`
2. Returns `ok` on success, or `want_write` if the socket buffer is full
3. On `want_write`, the NIF arms `enif_select(fd, WRITE)` and the owner retries after receiving `{select, ..., ready_output}`

### Handshake (multi-step)

1. Owner calls `derp_tls:connect/4` which creates the socket, does async TCP connect, then enters a handshake loop
2. Each `SSL_do_handshake` step returns `want_read` or `want_write`
3. The handshake loop uses `enif_select` and `receive` to wait for I/O readiness
4. On completion, `select_read` is armed for the first application data read

## Usage

### Client connection

```erlang
%% BoringSSL is the default TLS backend
{ok, Client} = derp_client:start_link(#{
    host => "derp1.tailscale.com",
    port => 443,
    use_tls => true,
    tls_backend => boringssl       %% default
}).
```

TLS connections always perform HTTP upgrade to the DERP protocol automatically. The upgrade path defaults to `/derp` and can be changed with `http_path`.

### Falling back to OTP ssl

```erlang
%% Use OTP ssl (requires certificates that conform to X.520 limits)
{ok, Client} = derp_client:start_link(#{
    host => "my-derp-server.example.com",
    port => 443,
    use_tls => true,
    tls_backend => otp,
    tls_opts => [{verify, verify_none}]
}).
```

### Direct TLS API

For lower-level control, use `derp_tls` directly:

```erlang
%% Connect with BoringSSL
{ok, Conn} = derp_tls:connect("derp1.tailscale.com", 443, #{verify => false}, 15000).

%% Send data
ok = derp_tls:send(Conn, <<"GET /derp HTTP/1.1\r\nHost: derp1.tailscale.com\r\n\r\n">>).

%% Wait for data
receive
    {select, Conn, _, ready_input} ->
        {ok, Data} = derp_tls:recv(Conn),
        ok = derp_tls:activate(Conn)  %% arm for next read
end.

%% Close
ok = derp_tls:close(Conn).
```

### Server-side accept

```erlang
%% Accept a TCP socket and wrap with TLS
{ok, LSock} = gen_tcp:listen(443, [{active, false}, binary, {reuseaddr, true}]),
{ok, Sock} = gen_tcp:accept(LSock),
{ok, Fd} = inet:getfd(Sock),
{ok, TlsConn} = derp_tls:accept(Fd, #{
    certfile => "/path/to/server.pem",
    keyfile => "/path/to/server-key.pem"
}, 10000).
```

## Dirty NIF Scheduling

BoringSSL crypto operations and blocking system calls run on dirty schedulers to avoid stalling normal BEAM schedulers:

| NIF function | Dirty type | Reason |
|---|---|---|
| `conn_connect/3` | IO | `getaddrinfo()` blocks on DNS resolution |
| `ctx_set_cert/3` | IO | Reads certificate/key files from disk |
| `handshake/1` | CPU | `SSL_do_handshake` -- asymmetric key exchange |
| `recv/1` | IO | `recv(fd)` + `SSL_read` (socket I/O + decryption) |
| `send/2` | IO | `SSL_write` + `send(fd)` (encryption + socket I/O) |
| `shutdown/1` | IO | `SSL_shutdown` + `close(fd)` |
| All others | Normal | Pure in-memory operations, no crypto or blocking I/O |

Sockets are set to `O_NONBLOCK`. The dirty scheduling ensures that the BoringSSL crypto work and blocking syscalls (`getaddrinfo`, file reads) do not interfere with normal Erlang scheduling.

## NIF Resource Types

### tls_ctx_t (SSL context)

Wraps an `SSL_CTX*`. Created by `derp_tls_nif:ctx_new(client | server)`. Configures TLS version, verification mode, and certificates. Multiple connections can share one context.

### tls_conn_t (TLS connection)

Wraps a raw socket fd, `SSL*`, and memory BIO pair. Created by `derp_tls_nif:conn_new(Ctx, Role, OwnerPid)`. The owner pid receives `{select, ...}` messages.

Fields:

- `fd` -- raw non-blocking TCP socket
- `ssl` -- BoringSSL SSL handle
- `rbio` -- memory BIO: network data flows in (NIF writes, SSL reads)
- `wbio` -- memory BIO: encrypted data flows out (SSL writes, NIF reads)
- `owner` -- Erlang pid receiving select messages
- `handshake_done` -- set after `SSL_do_handshake` completes
- `closed` -- set after shutdown or peer close detected

The resource destructor frees the SSL handle (which also frees the BIOs), deselects the fd, and closes the socket.

## Building

BoringSSL is built from source as part of the NIF compilation. The source is in `c_src/boringssl/` (not committed to git -- copy from a BoringSSL distribution or from `hackney`'s trimmed copy).

### Build dependencies

In addition to libsodium and CMake (required for the sodium NIF), BoringSSL requires:

- **C++ compiler** (g++ or clang++) -- BoringSSL has C++ components
- **Ninja** (ninja-build) -- used by BoringSSL's CMake build
- **Perl** -- used by BoringSSL code generation

### Build commands

```bash
# Full build (both NIFs)
make -C c_src

# Or via rebar3 (build hooks invoke make automatically)
rebar3 compile
```

The CMake build produces two NIF shared libraries:

- `priv/derp_sodium_nif.so` -- libsodium bindings (NaCl box crypto)
- `priv/derp_tls_nif.so` -- BoringSSL TLS with enif_select

### Platform notes

| Platform | Notes |
|----------|-------|
| Linux | Requires `g++`, `ninja-build`, `perl` packages |
| macOS | Requires Xcode command line tools (provides clang++) |
| Alpine | Requires `g++`, `ninja-build`, `perl` (musl-compatible) |
| Windows | Requires MSVC, CMake, Ninja, NASM; uses Winsock (`ws2_32.lib`) |

## Troubleshooting

### NIF not loaded

```
Failed to load derp_tls NIF: {error, {load_failed, "...file not found..."}}
```

The NIF shared library is missing. Run `make -C c_src` or `rebar3 compile` to build it. Check that `priv/derp_tls_nif.so` exists.

### BoringSSL source not found

```
CMake Error: add_subdirectory given source "...boringssl" which is not an existing directory
```

The `c_src/boringssl/` directory is empty. Copy a BoringSSL source tree into it. The directory must contain `CMakeLists.txt`, `include/openssl/`, `ssl/`, and `crypto/`.

### Certificate verification

BoringSSL defaults to `SSL_VERIFY_NONE` when `verify => false` is set (the default for client connections). To enable verification:

```erlang
{ok, Conn} = derp_tls:connect(Host, Port, #{verify => true}, Timeout).
```

Note that Tailscale's DERP servers use self-signed certificates that will fail peer verification. Use `verify => false` when connecting to Tailscale infrastructure.

### OTP ssl fallback

If BoringSSL is unavailable (NIF not built), set `tls_backend => otp` in client options:

```erlang
{ok, Client} = derp_client:start_link(#{
    host => "my-server.example.com",
    port => 443,
    tls_backend => otp,
    tls_opts => [{versions, ['tlsv1.2']}, {verify, verify_none}]
}).
```

This uses OTP's `ssl` module. Note: OTP ssl cannot connect to Tailscale's DERP servers due to the CommonName length issue.
