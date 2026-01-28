%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP TLS server.
%%%
%%% Listens for TLS connections and spawns connection handlers via
%%% the connection supervisor. Manages the server's keypair and
%%% provides an API for starting/stopping the server.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_server).

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    start_link/0,
    stop/1,
    get_public_key/0,
    get_public_key/1,
    get_port/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-include("derp.hrl").

-define(SERVER, ?MODULE).

-record(state, {
    listen_socket :: ssl:sslsocket() | undefined,
    port :: inet:port_number(),
    keypair :: {binary(), binary()},
    acceptor :: pid() | undefined
}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the DERP server with default options from app config.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    Port = application:get_env(derp, port, 443),
    CertFile = application:get_env(derp, certfile, "priv/cert.pem"),
    KeyFile = application:get_env(derp, keyfile, "priv/key.pem"),
    start_link(#{port => Port, certfile => CertFile, keyfile => KeyFile}).

%% @doc Start the DERP server with custom options.
%%
%% Options:
%% - port: Port to listen on (default: 443)
%% - certfile: Path to TLS certificate file
%% - keyfile: Path to TLS private key file
%% - keypair: Optional {PubKey, SecKey} tuple (generated if not provided)
%%
%% @param Opts Server options map
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Opts, []).

%% @doc Stop the DERP server.
-spec stop(pid() | atom()) -> ok.
stop(Server) ->
    gen_server:stop(Server).

%% @doc Get the server's public key.
-spec get_public_key() -> binary().
get_public_key() ->
    get_public_key(?SERVER).

%% @doc Get the server's public key.
-spec get_public_key(pid() | atom()) -> binary().
get_public_key(Server) ->
    gen_server:call(Server, get_public_key).

%% @doc Get the port the server is listening on.
-spec get_port(pid() | atom()) -> inet:port_number().
get_port(Server) ->
    gen_server:call(Server, get_port).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init(Opts) ->
    process_flag(trap_exit, true),

    Port = maps:get(port, Opts, 443),
    CertFile = maps:get(certfile, Opts, undefined),
    KeyFile = maps:get(keyfile, Opts, undefined),

    %% Generate or use provided keypair
    Keypair = case maps:get(keypair, Opts, undefined) of
        undefined -> derp_crypto:generate_keypair();
        KP -> KP
    end,

    %% Build SSL options
    BaseOpts = [
        {mode, binary},
        {packet, raw},
        {active, false},
        {reuseaddr, true},
        {nodelay, true}
    ],

    SslOpts = case {CertFile, KeyFile} of
        {undefined, _} ->
            %% No TLS, use plain TCP
            {tcp, BaseOpts};
        {_, undefined} ->
            {tcp, BaseOpts};
        {Cert, Key} ->
            TlsOpts = BaseOpts ++ [
                {certfile, Cert},
                {keyfile, Key},
                {versions, ['tlsv1.2', 'tlsv1.3']},
                {honor_cipher_order, true}
            ],
            {ssl, TlsOpts}
    end,

    case SslOpts of
        {tcp, TcpOpts} ->
            case gen_tcp:listen(Port, TcpOpts) of
                {ok, ListenSocket} ->
                    {ok, ActualPort} = inet:port(ListenSocket),
                    State = #state{
                        listen_socket = ListenSocket,
                        port = ActualPort,
                        keypair = Keypair
                    },
                    %% Start acceptor
                    self() ! start_acceptor,
                    {ok, State};
                {error, Reason} ->
                    {stop, {listen_failed, Reason}}
            end;
        {ssl, SslListenOpts} ->
            case ssl:listen(Port, SslListenOpts) of
                {ok, ListenSocket} ->
                    {ok, {_, ActualPort}} = ssl:sockname(ListenSocket),
                    State = #state{
                        listen_socket = ListenSocket,
                        port = ActualPort,
                        keypair = Keypair
                    },
                    %% Start acceptor
                    self() ! start_acceptor,
                    {ok, State};
                {error, Reason} ->
                    {stop, {listen_failed, Reason}}
            end
    end.

handle_call(get_public_key, _From, #state{keypair = {PubKey, _}} = State) ->
    {reply, PubKey, State};

handle_call(get_port, _From, #state{port = Port} = State) ->
    {reply, Port, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(start_acceptor, #state{listen_socket = ListenSocket} = State) ->
    %% Start acceptor in a separate process
    Parent = self(),
    AcceptorPid = spawn_link(fun() -> acceptor_loop(Parent, ListenSocket) end),
    {noreply, State#state{acceptor = AcceptorPid}};

handle_info({accepted, Socket}, #state{keypair = Keypair} = State) ->
    %% Start connection handler
    _ = case derp_server_sup:start_connection(Socket, Keypair) of
        {ok, ConnPid} ->
            %% Transfer socket ownership to connection handler
            transfer_socket(Socket, ConnPid);
        {error, Reason} ->
            logger:warning("Failed to start connection handler: ~p", [Reason]),
            close_socket(Socket)
    end,
    {noreply, State};

handle_info({'EXIT', Pid, Reason}, #state{acceptor = Pid} = State) ->
    case Reason of
        normal -> ok;
        shutdown -> ok;
        _ -> logger:error("Acceptor crashed: ~p", [Reason])
    end,
    %% Restart acceptor
    self() ! start_acceptor,
    {noreply, State#state{acceptor = undefined}};

handle_info({'EXIT', _Pid, _Reason}, State) ->
    %% Connection handler exited
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_socket = Socket}) ->
    _ = close_socket(Socket),
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

acceptor_loop(Parent, ListenSocket) ->
    case accept(ListenSocket) of
        {ok, Socket} ->
            Parent ! {accepted, Socket},
            acceptor_loop(Parent, ListenSocket);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("Accept failed: ~p", [Reason]),
            timer:sleep(100),  % Back off on errors
            acceptor_loop(Parent, ListenSocket)
    end.

accept(Socket) ->
    %% Try SSL first, fall back to TCP
    case ssl:transport_accept(Socket, 5000) of
        {ok, TlsSocket} ->
            case ssl:handshake(TlsSocket, 5000) of
                {ok, SslSocket} -> {ok, SslSocket};
                {error, _} = Err -> Err
            end;
        {error, {tls_alert, _}} ->
            %% Not a TLS connection, shouldn't happen with ssl listener
            {error, not_tls};
        {error, timeout} ->
            %% Recursive call to continue accepting
            accept(Socket);
        {error, _} = Err ->
            Err
    end.

transfer_socket(Socket, Pid) ->
    ssl:controlling_process(Socket, Pid).

close_socket(undefined) ->
    ok;
close_socket(Socket) ->
    ssl:close(Socket).
