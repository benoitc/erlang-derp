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
    listen_socket :: ssl:sslsocket() | gen_tcp:socket() | undefined,
    port :: inet:port_number(),
    keypair :: {binary(), binary()},
    mesh_key :: binary() | undefined,
    acceptor :: pid() | undefined,
    tls_backend :: boringssl | otp | none,
    tls_opts :: map()
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
    TlsBackend = maps:get(tls_backend, Opts, boringssl),

    %% Get keypair from: options > app config > generate new
    Keypair = case maps:get(keypair, Opts, undefined) of
        undefined ->
            case application:get_env(derp, keypair) of
                {ok, KP} -> KP;
                undefined -> derp_crypto:generate_keypair()
            end;
        KP -> KP
    end,

    %% Get optional mesh key from: options > app config
    MeshKey = case maps:get(mesh_key, Opts, undefined) of
        undefined ->
            case application:get_env(derp, mesh_key) of
                {ok, MK} -> MK;
                undefined -> undefined
            end;
        MK -> MK
    end,

    %% Determine effective TLS mode
    {EffectiveBackend, TlsOptsMap} = case {CertFile, KeyFile} of
        {undefined, _} ->
            {none, #{}};
        {_, undefined} ->
            {none, #{}};
        {Cert, Key} ->
            {TlsBackend, #{certfile => Cert, keyfile => Key}}
    end,

    %% Build listen options
    BaseOpts = [
        {mode, binary},
        {packet, raw},
        {active, false},
        {reuseaddr, true},
        {nodelay, true}
    ],

    case EffectiveBackend of
        boringssl ->
            %% BoringSSL mode: listen with plain TCP, TLS handled per-connection
            case gen_tcp:listen(Port, BaseOpts) of
                {ok, ListenSocket} ->
                    {ok, ActualPort} = inet:port(ListenSocket),
                    State = #state{
                        listen_socket = ListenSocket,
                        port = ActualPort,
                        keypair = Keypair,
                        mesh_key = MeshKey,
                        tls_backend = boringssl,
                        tls_opts = TlsOptsMap
                    },
                    self() ! start_acceptor,
                    {ok, State};
                {error, Reason} ->
                    {stop, {listen_failed, Reason}}
            end;
        otp ->
            %% OTP ssl mode
            SslListenOpts = BaseOpts ++ [
                {certfile, maps:get(certfile, TlsOptsMap)},
                {keyfile, maps:get(keyfile, TlsOptsMap)},
                {versions, ['tlsv1.2', 'tlsv1.3']},
                {honor_cipher_order, true}
            ],
            case ssl:listen(Port, SslListenOpts) of
                {ok, ListenSocket} ->
                    {ok, {_, ActualPort}} = ssl:sockname(ListenSocket),
                    State = #state{
                        listen_socket = ListenSocket,
                        port = ActualPort,
                        keypair = Keypair,
                        mesh_key = MeshKey,
                        tls_backend = otp,
                        tls_opts = TlsOptsMap
                    },
                    self() ! start_acceptor,
                    {ok, State};
                {error, Reason} ->
                    {stop, {listen_failed, Reason}}
            end;
        none ->
            %% Plain TCP mode (no TLS)
            case gen_tcp:listen(Port, BaseOpts) of
                {ok, ListenSocket} ->
                    {ok, ActualPort} = inet:port(ListenSocket),
                    State = #state{
                        listen_socket = ListenSocket,
                        port = ActualPort,
                        keypair = Keypair,
                        mesh_key = MeshKey,
                        tls_backend = none,
                        tls_opts = #{}
                    },
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

handle_info(start_acceptor, #state{listen_socket = ListenSocket,
                                    tls_backend = TlsBackend} = State) ->
    %% Start acceptor in a separate process
    Parent = self(),
    AcceptorPid = spawn_link(fun() -> acceptor_loop(Parent, ListenSocket, TlsBackend) end),
    {noreply, State#state{acceptor = AcceptorPid}};

handle_info({accepted, Socket}, #state{keypair = Keypair, mesh_key = MeshKey,
                                        tls_backend = boringssl,
                                        tls_opts = TlsOpts} = State) ->
    %% BoringSSL mode: Socket is a plain TCP socket, wrap with TLS
    ConnOpts0 = case MeshKey of
        undefined -> #{};
        _ -> #{mesh_key => MeshKey}
    end,
    %% Extract fd from the TCP socket and perform BoringSSL TLS accept
    case inet:getfd(Socket) of
        {ok, Fd} ->
            case derp_tls:accept(Fd, TlsOpts) of
                {ok, TlsRef} ->
                    ConnOpts = ConnOpts0#{transport => derp_tls},
                    _ = case derp_server_sup:start_connection(TlsRef, Keypair, ConnOpts) of
                        {ok, ConnPid} ->
                            derp_tls:controlling_process(TlsRef, ConnPid);
                        {error, Reason} ->
                            logger:warning("Failed to start connection handler: ~p", [Reason]),
                            derp_tls:close(TlsRef)
                    end;
                {error, Reason} ->
                    logger:warning("BoringSSL TLS accept failed: ~p", [Reason]),
                    gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            logger:warning("Failed to get fd from socket: ~p", [Reason]),
            gen_tcp:close(Socket)
    end,
    {noreply, State};

handle_info({accepted, Socket}, #state{keypair = Keypair, mesh_key = MeshKey} = State) ->
    %% OTP ssl / plain TCP mode
    ConnOpts = case MeshKey of
        undefined -> #{};
        _ -> #{mesh_key => MeshKey}
    end,
    _ = case derp_server_sup:start_connection(Socket, Keypair, ConnOpts) of
        {ok, ConnPid} ->
            transfer_socket(Socket, ConnPid, State#state.tls_backend);
        {error, Reason} ->
            logger:warning("Failed to start connection handler: ~p", [Reason]),
            close_socket(Socket, State#state.tls_backend)
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

terminate(_Reason, #state{listen_socket = Socket, tls_backend = Backend}) ->
    _ = close_socket(Socket, Backend),
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

acceptor_loop(Parent, ListenSocket, boringssl) ->
    %% BoringSSL mode: plain TCP accept (TLS handled in handle_info)
    case gen_tcp:accept(ListenSocket, 5000) of
        {ok, Socket} ->
            Parent ! {accepted, Socket},
            acceptor_loop(Parent, ListenSocket, boringssl);
        {error, timeout} ->
            acceptor_loop(Parent, ListenSocket, boringssl);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("Accept failed: ~p", [Reason]),
            timer:sleep(100),
            acceptor_loop(Parent, ListenSocket, boringssl)
    end;
acceptor_loop(Parent, ListenSocket, otp) ->
    %% OTP SSL mode
    case ssl:transport_accept(ListenSocket, 5000) of
        {ok, TlsSocket} ->
            case ssl:handshake(TlsSocket, 5000) of
                {ok, SslSocket} ->
                    Parent ! {accepted, SslSocket},
                    acceptor_loop(Parent, ListenSocket, otp);
                {error, _} = _Err ->
                    acceptor_loop(Parent, ListenSocket, otp)
            end;
        {error, timeout} ->
            acceptor_loop(Parent, ListenSocket, otp);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("Accept failed: ~p", [Reason]),
            timer:sleep(100),
            acceptor_loop(Parent, ListenSocket, otp)
    end;
acceptor_loop(Parent, ListenSocket, none) ->
    %% Plain TCP mode
    case gen_tcp:accept(ListenSocket, 5000) of
        {ok, Socket} ->
            Parent ! {accepted, Socket},
            acceptor_loop(Parent, ListenSocket, none);
        {error, timeout} ->
            acceptor_loop(Parent, ListenSocket, none);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("Accept failed: ~p", [Reason]),
            timer:sleep(100),
            acceptor_loop(Parent, ListenSocket, none)
    end.

transfer_socket(Socket, Pid, otp) ->
    ssl:controlling_process(Socket, Pid);
transfer_socket(Socket, Pid, _) ->
    gen_tcp:controlling_process(Socket, Pid).

close_socket(undefined, _) ->
    ok;
close_socket(Socket, otp) ->
    ssl:close(Socket);
close_socket(Socket, _) ->
    gen_tcp:close(Socket).
