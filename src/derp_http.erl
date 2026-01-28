%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc DERP HTTP/WebSocket listener.
%%%
%%% Starts a Cowboy HTTP listener that handles:
%%% - GET /derp with Upgrade: DERP header - HTTP upgrade to DERP protocol
%%% - GET /derp/websocket - WebSocket transport for DERP
%%% - GET /derp - Health check (without upgrade header)
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(derp_http).

-include("derp.hrl").

%% API
-export([
    start_link/1,
    start_link/0,
    stop/0,
    get_port/0
]).

-define(LISTENER, derp_http_listener).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the HTTP listener with default options from app config.
%%
%% The keypair is read from application config `derp.keypair`.
%% If not configured, a new keypair is generated (not recommended for production).
%%
%% For production use, configure the same keypair for both derp_server and
%% derp_http to ensure consistent server identity.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    Port = application:get_env(derp, http_port, 80),
    Keypair = case application:get_env(derp, keypair) of
        {ok, KP} -> KP;
        undefined -> derp_crypto:generate_keypair()
    end,
    start_link(#{port => Port, keypair => Keypair}).

%% @doc Start the HTTP listener with custom options.
%%
%% Options:
%% - port: Port to listen on (default: 80)
%% - keypair: {PubKey, SecKey} tuple for DERP handshake (required)
%% - certfile/keyfile: TLS certificate (for HTTPS)
%%
%% The keypair should be the same as configured for derp_server to ensure
%% consistent server identity across all transports.
%%
%% @param Opts Listener options map
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    Port = maps:get(port, Opts, 80),
    Keypair = case maps:get(keypair, Opts, undefined) of
        undefined ->
            case application:get_env(derp, keypair) of
                {ok, KP} -> KP;
                undefined -> derp_crypto:generate_keypair()
            end;
        KP -> KP
    end,
    CertFile = maps:get(certfile, Opts, undefined),
    KeyFile = maps:get(keyfile, Opts, undefined),

    %% Handler options
    HandlerOpts = #{keypair => Keypair},

    %% Routes
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/derp", derp_http_handler, HandlerOpts},
            {"/derp/websocket", derp_ws_handler, HandlerOpts}
        ]}
    ]),

    %% Transport options
    TransOpts = #{
        socket_opts => [{port, Port}],
        num_acceptors => 100
    },

    %% Protocol options
    ProtoOpts = #{
        env => #{dispatch => Dispatch},
        idle_timeout => ?KEEPALIVE_INTERVAL * 3
    },

    %% Start listener (TLS or plain)
    case {CertFile, KeyFile} of
        {undefined, _} ->
            cowboy:start_clear(?LISTENER, TransOpts, ProtoOpts);
        {_, undefined} ->
            cowboy:start_clear(?LISTENER, TransOpts, ProtoOpts);
        {Cert, Key} ->
            TlsTransOpts = TransOpts#{
                socket_opts => [
                    {port, Port},
                    {certfile, Cert},
                    {keyfile, Key},
                    {versions, ['tlsv1.2', 'tlsv1.3']}
                ]
            },
            cowboy:start_tls(?LISTENER, TlsTransOpts, ProtoOpts)
    end.

%% @doc Stop the HTTP listener.
-spec stop() -> ok | {error, term()}.
stop() ->
    cowboy:stop_listener(?LISTENER).

%% @doc Get the port the listener is on.
-spec get_port() -> inet:port_number().
get_port() ->
    ranch:get_port(?LISTENER).

