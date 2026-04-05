%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc High-level TLS API using BoringSSL NIF.
%%%
%%% Provides a transport-level interface for TLS connections that
%%% bypasses OTP's ssl module. Uses BoringSSL via Memory BIOs and
%%% enif_select for non-blocking I/O.
%%%
%%% No gen_server — the owning process calls these functions directly.
%%% The owner receives `{select, ConnRef, _, ready_input}' messages
%%% when data is available.
%%%
%%% Example:
%%% ```
%%% {ok, Conn} = derp_tls:connect("host", 443, #{}),
%%% %% Owner receives {select, Conn, _, ready_input}
%%% {ok, Data} = derp_tls:recv(Conn),
%%% ok = derp_tls:activate(Conn),  %% arm for next read
%%% ok = derp_tls:send(Conn, <<"hello">>),
%%% ok = derp_tls:close(Conn).
%%% '''
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_tls).

-export([
    connect/3,
    connect/4,
    listen/2,
    accept_connection/3,
    accept_connection/4,
    close_listener/1,
    accept/2,
    accept/3,
    send/2,
    recv/1,
    activate/1,
    close/1,
    peername/1,
    sockname/1,
    controlling_process/2
]).

-define(DEFAULT_TIMEOUT, 15000).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Connect to a TLS server with default timeout.
-spec connect(string(), inet:port_number(), map()) ->
    {ok, reference()} | {error, term()}.
connect(Host, Port, Opts) ->
    connect(Host, Port, Opts, ?DEFAULT_TIMEOUT).

%% @doc Connect to a TLS server.
%%
%% Creates a TCP socket, performs async connect, then completes the
%% TLS handshake. On success, the connection is armed for the first
%% read via enif_select.
%%
%% Options:
%%   verify => boolean()  - Enable peer certificate verification (default: false)
%%
%% Returns {ok, ConnRef} where ConnRef is a NIF resource reference.
-spec connect(string(), inet:port_number(), map(), timeout()) ->
    {ok, reference()} | {error, term()}.
connect(Host, Port, Opts, Timeout) ->
    Verify = maps:get(verify, Opts, false),

    %% Create SSL context
    {ok, Ctx} = derp_tls_nif:ctx_new(client),
    ok = derp_tls_nif:ctx_set_verify(Ctx, Verify),

    %% Create connection
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, client, self()),

    %% Set SNI hostname
    HostStr = to_list(Host),
    ok = derp_tls_nif:conn_set_hostname(Conn, HostStr),

    %% Initiate async TCP connect
    case derp_tls_nif:conn_connect(Conn, HostStr, Port) of
        ok ->
            %% Connected immediately (loopback)
            do_handshake(Conn, Timeout);
        {ok, einprogress} ->
            %% Wait for connect to complete
            ok = derp_tls_nif:select_write(Conn),
            case wait_select_output(Conn, Timeout) of
                ok ->
                    do_handshake(Conn, Timeout);
                {error, _} = Err ->
                    derp_tls_nif:shutdown(Conn),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Create a TLS server listener.
%%
%% Creates a TCP listener socket and an SSL context with the given certificate.
%% Options must include certfile and keyfile for the server certificate.
%% Returns {ok, ListenerRef, CtxRef, ActualPort}.
-spec listen(inet:port_number(), map()) ->
    {ok, reference(), reference(), inet:port_number()} | {error, term()}.
listen(Port, Opts) ->
    CertFile = maps:get(certfile, Opts),
    KeyFile = maps:get(keyfile, Opts),
    Backlog = maps:get(backlog, Opts, 128),

    %% Create SSL context for server
    {ok, Ctx} = derp_tls_nif:ctx_new(server),
    ok = derp_tls_nif:ctx_set_cert(Ctx, to_list(CertFile), to_list(KeyFile)),

    %% Create listener socket
    case derp_tls_nif:listen(Port, Backlog) of
        {ok, Listener, ActualPort} ->
            {ok, Listener, Ctx, ActualPort};
        {error, _} = Err ->
            Err
    end.

%% @doc Accept a TLS connection from a listener with default timeout.
-spec accept_connection(reference(), reference(), pid()) ->
    {ok, reference()} | {error, term()}.
accept_connection(Listener, Ctx, Owner) ->
    accept_connection(Listener, Ctx, Owner, ?DEFAULT_TIMEOUT).

%% @doc Accept a TLS connection from a listener.
%%
%% Accepts a TCP connection and performs the TLS handshake.
%% The connection is owned by Owner who will receive select messages.
-spec accept_connection(reference(), reference(), pid(), timeout()) ->
    {ok, reference()} | {error, term()}.
accept_connection(Listener, Ctx, Owner, Timeout) ->
    case derp_tls_nif:accept_conn(Listener, Ctx, Owner) of
        {ok, Conn} ->
            do_handshake(Conn, Timeout);
        {error, _} = Err ->
            Err
    end.

%% @doc Close a TLS listener.
-spec close_listener(reference()) -> ok.
close_listener(Listener) ->
    derp_tls_nif:close_listener(Listener).

%% @doc Accept and TLS-wrap an existing TCP socket for server mode.
%% @deprecated Use listen/2 and accept_connection/4 instead.
-spec accept(integer(), map()) -> {ok, reference()} | {error, term()}.
accept(Fd, Opts) ->
    accept(Fd, Opts, ?DEFAULT_TIMEOUT).

%% @doc Accept and TLS-wrap an existing TCP socket with timeout.
%%
%% The Fd should be a raw file descriptor from an accepted TCP connection.
%% Options must include certfile and keyfile for the server certificate.
-spec accept(integer(), map(), timeout()) ->
    {ok, reference()} | {error, term()}.
accept(Fd, Opts, Timeout) ->
    CertFile = maps:get(certfile, Opts),
    KeyFile = maps:get(keyfile, Opts),

    %% Create SSL context for server
    {ok, Ctx} = derp_tls_nif:ctx_new(server),
    ok = derp_tls_nif:ctx_set_cert(Ctx, to_list(CertFile), to_list(KeyFile)),

    %% Create connection in server mode
    {ok, Conn} = derp_tls_nif:conn_new(Ctx, server, self()),

    %% Attach existing fd
    ok = derp_tls_nif:conn_set_fd(Conn, Fd),

    %% Perform TLS handshake
    do_handshake(Conn, Timeout).

%% @doc Send data over a TLS connection.
%%
%% Encrypts and sends the data. Returns ok on success, or
%% {error, Reason} on failure.
-spec send(reference(), iodata()) -> ok | {error, term()}.
send(Conn, Data) ->
    Bin = iolist_to_binary(Data),
    case derp_tls_nif:send(Conn, Bin) of
        ok ->
            ok;
        want_write ->
            %% Socket buffer full, need to flush pending data
            flush_pending(Conn);
        want_read ->
            %% TLS renegotiation needs read
            ok = derp_tls_nif:select_read(Conn),
            receive
                {select, Conn, _, ready_input} ->
                    send(Conn, Bin)
            after 10000 ->
                {error, send_timeout}
            end;
        {error, _} = Err ->
            Err
    end.

%% @private Flush pending data after send returned want_write.
flush_pending(Conn) ->
    ok = derp_tls_nif:select_write(Conn),
    receive
        {select, Conn, _, ready_output} ->
            case derp_tls_nif:flush(Conn) of
                ok -> ok;
                want_write -> flush_pending(Conn);
                {error, _} = Err -> Err
            end
    after 10000 ->
        {error, send_timeout}
    end.

%% @doc Read decrypted data from a TLS connection.
%%
%% Call this after receiving a {select, Conn, _, ready_input} message.
%% Returns {ok, Data} with the decrypted plaintext.
-spec recv(reference()) -> {ok, binary()} | {error, term()}.
recv(Conn) ->
    case derp_tls_nif:recv(Conn) of
        {ok, _Data} = Ok ->
            Ok;
        want_read ->
            %% No complete TLS record yet, need more data
            {error, want_read};
        {error, _} = Err ->
            Err
    end.

%% @doc Arm the connection for the next read notification.
%%
%% After processing data from recv/1, call this to receive the
%% next {select, Conn, _, ready_input} message.
-spec activate(reference()) -> ok | {error, term()}.
activate(Conn) ->
    derp_tls_nif:select_read(Conn).

%% @doc Close a TLS connection.
%%
%% Performs TLS shutdown and closes the underlying socket.
-spec close(reference()) -> ok.
close(Conn) ->
    derp_tls_nif:shutdown(Conn).

%% @doc Get the remote address of the connection.
-spec peername(reference()) -> {ok, {string(), integer()}} | {error, term()}.
peername(Conn) ->
    derp_tls_nif:peername(Conn).

%% @doc Get the local address of the connection.
-spec sockname(reference()) -> {ok, {string(), integer()}} | {error, term()}.
sockname(Conn) ->
    derp_tls_nif:sockname(Conn).

%% @doc Change the controlling process for the connection.
-spec controlling_process(reference(), pid()) -> ok.
controlling_process(Conn, NewOwner) ->
    derp_tls_nif:controlling_process(Conn, NewOwner).

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

%% @private Handshake loop using enif_select for async I/O.
do_handshake(Conn, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    handshake_loop(Conn, Deadline).

handshake_loop(Conn, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    if Remaining =< 0 ->
        derp_tls_nif:shutdown(Conn),
        {error, handshake_timeout};
    true ->
        case derp_tls_nif:handshake(Conn) of
            ok ->
                %% Handshake complete, arm for first read
                ok = derp_tls_nif:select_read(Conn),
                {ok, Conn};
            want_read ->
                ok = derp_tls_nif:select_read(Conn),
                receive
                    {select, Conn, _, ready_input} ->
                        handshake_loop(Conn, Deadline)
                after Remaining ->
                    derp_tls_nif:shutdown(Conn),
                    {error, handshake_timeout}
                end;
            want_write ->
                ok = derp_tls_nif:select_write(Conn),
                receive
                    {select, Conn, _, ready_output} ->
                        handshake_loop(Conn, Deadline)
                after Remaining ->
                    derp_tls_nif:shutdown(Conn),
                    {error, handshake_timeout}
                end;
            {error, _} = Err ->
                derp_tls_nif:shutdown(Conn),
                Err
        end
    end.

%% @private Wait for async connect to complete.
wait_select_output(Conn, Timeout) ->
    receive
        {select, Conn, _, ready_output} ->
            ok
    after Timeout ->
        {error, connect_timeout}
    end.

%% @private Convert to list for NIF string parameters.
to_list(S) when is_list(S) -> S;
to_list(S) when is_binary(S) -> binary_to_list(S).
