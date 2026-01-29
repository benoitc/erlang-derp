%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc NIF wrapper for BoringSSL TLS operations.
%%%
%%% Provides low-level bindings to BoringSSL via Memory BIOs and
%%% enif_select for non-blocking TLS connections. This bypasses OTP's
%%% ssl module which rejects Tailscale DERP certificates with
%%% CommonName exceeding X.520's ub-common-name=64 limit.
%%%
%%% Socket I/O is non-blocking (sockets set to O_NONBLOCK). I/O
%%% readiness is delivered via enif_select messages:
%%%   {select, ConnRef, _, ready_input}
%%%   {select, ConnRef, _, ready_output}
%%%
%%% Functions that perform BoringSSL crypto or blocking system calls
%%% run on dirty schedulers to avoid stalling normal BEAM schedulers:
%%%   - conn_connect/3: dirty IO (getaddrinfo DNS resolution)
%%%   - ctx_set_cert/3: dirty IO (reads cert/key files from disk)
%%%   - handshake/1:    dirty CPU (SSL_do_handshake key exchange)
%%%   - recv/1, send/2: dirty IO (socket I/O + symmetric crypto)
%%%   - shutdown/1:     dirty IO (SSL_shutdown + close)
%%% Lightweight functions (ctx_new, select_read/write, peername, etc.)
%%% run on normal schedulers.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_tls_nif).

%% API
-export([
    ctx_new/1,
    ctx_set_verify/2,
    ctx_set_cert/3,
    conn_new/3,
    conn_set_hostname/2,
    conn_connect/3,
    conn_set_fd/2,
    listen/2,
    accept_conn/3,
    close_listener/1,
    handshake/1,
    recv/1,
    send/2,
    flush/1,
    select_read/1,
    select_write/1,
    shutdown/1,
    peername/1,
    sockname/1,
    controlling_process/2,
    get_fd/1
]).

%% NIF loading
-on_load(init/0).

-define(NIF_STUB, erlang:nif_error(nif_not_loaded)).

%%--------------------------------------------------------------------
%% NIF Loading
%%--------------------------------------------------------------------

init() ->
    SoName = find_nif_path("derp_tls_nif"),
    case erlang:load_nif(SoName, 0) of
        ok -> ok;
        {error, {reload, _}} -> ok;
        {error, Reason} ->
            logger:error("Failed to load derp_tls NIF: ~p", [Reason]),
            {error, Reason}
    end.

%% @private
find_nif_path(NifName) ->
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
            EbinDir = filename:dirname(Filename),
            filename:join([EbinDir, "..", "priv", NifName]);
        _ ->
            undefined
    end.

escript_lib_candidate(NifName) ->
    try
        case escript:script_name() of
            [] -> undefined;
            ScriptPath ->
                ScriptDir = filename:dirname(ScriptPath),
                filename:join([ScriptDir, "lib", "derp", "priv", NifName])
        end
    catch
        _:_ -> undefined
    end.

find_existing_nif([]) ->
    "derp_tls_nif";
find_existing_nif([undefined | Rest]) ->
    find_existing_nif(Rest);
find_existing_nif([Path | Rest]) ->
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

%% @doc Create a new SSL context.
%% Role is `client' or `server'.
-spec ctx_new(client | server) -> {ok, reference()} | {error, term()}.
ctx_new(_Role) ->
    ?NIF_STUB.

%% @doc Set certificate verification mode.
%% When Verify is `true', peer certificate is verified (SSL_VERIFY_PEER).
%% When `false', verification is disabled (SSL_VERIFY_NONE).
-spec ctx_set_verify(reference(), boolean()) -> ok | {error, term()}.
ctx_set_verify(_Ctx, _Verify) ->
    ?NIF_STUB.

%% @doc Load certificate and private key files for server mode.
-spec ctx_set_cert(reference(), string(), string()) -> ok | {error, term()}.
ctx_set_cert(_Ctx, _CertFile, _KeyFile) ->
    ?NIF_STUB.

%% @doc Create a new TLS connection from a context.
%% Role is `client' or `server'. Owner receives select messages.
-spec conn_new(reference(), client | server, pid()) ->
    {ok, reference()} | {error, term()}.
conn_new(_Ctx, _Role, _Owner) ->
    ?NIF_STUB.

%% @doc Set the SNI hostname for a client connection.
-spec conn_set_hostname(reference(), string()) -> ok.
conn_set_hostname(_Conn, _Hostname) ->
    ?NIF_STUB.

%% @doc Create socket and initiate async TCP connect.
%% Returns `ok' if connected immediately, `{ok, einprogress}' for async.
-spec conn_connect(reference(), string(), integer()) ->
    ok | {ok, einprogress} | {error, term()}.
conn_connect(_Conn, _Host, _Port) ->
    ?NIF_STUB.

%% @doc Attach an existing file descriptor to the connection.
-spec conn_set_fd(reference(), integer()) -> ok | {error, term()}.
conn_set_fd(_Conn, _Fd) ->
    ?NIF_STUB.

%% @doc Create a TCP listener socket.
%% Returns {ok, ListenerRef, ActualPort} on success.
-spec listen(integer(), integer()) -> {ok, reference(), integer()} | {error, term()}.
listen(_Port, _Backlog) ->
    ?NIF_STUB.

%% @doc Accept a connection on a listener and create a TLS connection.
%% This is a blocking call that runs on a dirty scheduler.
-spec accept_conn(reference(), reference(), pid()) -> {ok, reference()} | {error, term()}.
accept_conn(_Listener, _Ctx, _Owner) ->
    ?NIF_STUB.

%% @doc Close a listener socket.
-spec close_listener(reference()) -> ok.
close_listener(_Listener) ->
    ?NIF_STUB.

%% @doc Perform one step of the TLS handshake.
%% Returns `ok' when complete, `want_read' or `want_write' when
%% waiting for I/O, or `{error, Reason}' on failure.
-spec handshake(reference()) -> ok | want_read | want_write | {error, term()}.
handshake(_Conn) ->
    ?NIF_STUB.

%% @doc Read decrypted data from the TLS connection.
%% Call after receiving a `{select, Conn, _, ready_input}' message.
-spec recv(reference()) -> {ok, binary()} | want_read | {error, term()}.
recv(_Conn) ->
    ?NIF_STUB.

%% @doc Encrypt and send data over the TLS connection.
-spec send(reference(), binary()) -> ok | want_write | want_read | {error, term()}.
send(_Conn, _Data) ->
    ?NIF_STUB.

%% @doc Flush any pending encrypted data to the socket.
%% Call this after send/2 returns `want_write' and the socket becomes writable.
%% Returns `ok' when all pending data is sent, `want_write' if more flushing
%% is needed, or `{error, Reason}' on failure.
-spec flush(reference()) -> ok | want_write | {error, term()}.
flush(_Conn) ->
    ?NIF_STUB.

%% @doc Arm enif_select for read readiness on the connection's fd.
%% Owner will receive `{select, Conn, _, ready_input}'.
-spec select_read(reference()) -> ok | {error, term()}.
select_read(_Conn) ->
    ?NIF_STUB.

%% @doc Arm enif_select for write readiness on the connection's fd.
%% Owner will receive `{select, Conn, _, ready_output}'.
-spec select_write(reference()) -> ok | {error, term()}.
select_write(_Conn) ->
    ?NIF_STUB.

%% @doc Perform TLS shutdown and close the underlying socket.
-spec shutdown(reference()) -> ok.
shutdown(_Conn) ->
    ?NIF_STUB.

%% @doc Get the remote address of the connection.
-spec peername(reference()) -> {ok, {string(), integer()}} | {error, term()}.
peername(_Conn) ->
    ?NIF_STUB.

%% @doc Get the local address of the connection.
-spec sockname(reference()) -> {ok, {string(), integer()}} | {error, term()}.
sockname(_Conn) ->
    ?NIF_STUB.

%% @doc Change the owner process that receives select messages.
-spec controlling_process(reference(), pid()) -> ok.
controlling_process(_Conn, _NewOwner) ->
    ?NIF_STUB.

%% @doc Get the raw file descriptor of the connection.
-spec get_fd(reference()) -> {ok, integer()} | {error, term()}.
get_fd(_Conn) ->
    ?NIF_STUB.
