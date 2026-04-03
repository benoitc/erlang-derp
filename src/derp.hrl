%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%% DERP Protocol Constants
%% Designated Encrypted Relay for Packets

-ifndef(DERP_HRL).
-define(DERP_HRL, true).

%% Protocol magic bytes: "DERP🔑" (DERP + key emoji in UTF-8)
-define(DERP_MAGIC, <<16#44, 16#45, 16#52, 16#50, 16#f0, 16#9f, 16#94, 16#91>>).
-define(DERP_MAGIC_SIZE, 8).

%% Frame header: 1 byte type + 4 bytes big-endian length
-define(FRAME_HEADER_SIZE, 5).

%% Maximum packet payload size (64KB)
-define(MAX_PACKET_SIZE, 65536).

%% Crypto constants (NaCl/libsodium)
-define(KEY_SIZE, 32).           % Curve25519 public/private key size
-define(NONCE_SIZE, 24).         % NaCl box nonce size
-define(BOX_OVERHEAD, 16).       % NaCl box authentication tag size

%% Keep-alive interval (milliseconds)
-define(KEEPALIVE_INTERVAL, 60000).

%% Protocol version (must be 2 for compatibility with Tailscale)
-define(PROTOCOL_VERSION, 2).

%% Frame types (values must match official Tailscale DERP protocol)
-define(FRAME_SERVER_KEY,       16#01).  % Server's public key
-define(FRAME_CLIENT_INFO,      16#02).  % Client's encrypted info
-define(FRAME_SERVER_INFO,      16#03).  % Server's encrypted response
-define(FRAME_SEND_PACKET,      16#04).  % Send packet to peer
-define(FRAME_RECV_PACKET,      16#05).  % Receive packet from peer
-define(FRAME_KEEP_ALIVE,       16#06).  % Keep connection alive
-define(FRAME_NOTE_PREFERRED,   16#07).  % Mark preferred connection
-define(FRAME_PEER_GONE,        16#08).  % Peer disconnected
-define(FRAME_PEER_PRESENT,     16#09).  % Peer connected (mesh)
-define(FRAME_WATCH_CONNS,      16#0A).  % Watch peer connections (mesh)
-define(FRAME_CLOSE_PEER,       16#0B).  % Close specific peer (privileged)
-define(FRAME_PING,             16#0C).  % Ping request (8 bytes)
-define(FRAME_PONG,             16#0D).  % Pong response (8 bytes)
-define(FRAME_HEALTH,           16#0E).  % Health status message
-define(FRAME_RESTARTING,       16#0F).  % Server restarting notification
-define(FRAME_FORWARD_PACKET,   16#10).  % Forward to mesh peer

%% Peer gone reasons
-define(PEER_GONE_DISCONNECTED,     16#00).  % Normal disconnect
-define(PEER_GONE_NOT_HERE,         16#01).  % Peer not on this server
-define(PEER_GONE_MESH_CONN_BROKE,  16#F0).  % Mesh connection broke

%% Connection states (for derp_conn gen_statem)
-define(STATE_AWAITING_CLIENT_INFO, awaiting_client_info).
-define(STATE_AUTHENTICATED, authenticated).
-define(STATE_CLOSED, closed).

%% Client states (for derp_client gen_statem)
-define(CLIENT_STATE_CONNECTING, connecting).
-define(CLIENT_STATE_HTTP_UPGRADING, http_upgrading).
-define(CLIENT_STATE_HANDSHAKING, handshaking).
-define(CLIENT_STATE_CONNECTED, connected).
-define(CLIENT_STATE_RECONNECTING, reconnecting).

%% Default rate limits
-define(DEFAULT_RATE_LIMIT_BYTES_PER_SEC, 1048576).  % 1 MB/s
-define(DEFAULT_RATE_LIMIT_BURST, 2097152).          % 2 MB burst

%% Handshake timeout
-define(HANDSHAKE_TIMEOUT, 10000).  % 10 seconds

%% Mesh key size (optional pre-shared key for mesh node authentication)
%% When configured, only clients presenting this key can use privileged
%% mesh operations (WatchConns, ForwardPacket, ClosePeer).
-define(MESH_KEY_SIZE, 32).

%% Records
-record(client_info, {
    version = ?PROTOCOL_VERSION :: pos_integer(),
    mesh_key :: binary() | undefined
}).

-record(server_info, {
    version = ?PROTOCOL_VERSION :: pos_integer(),
    token_bucket_bytes_per_second :: pos_integer(),
    token_bucket_bytes_burst :: pos_integer()
}).

-endif.
