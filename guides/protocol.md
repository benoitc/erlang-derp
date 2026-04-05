# Protocol Reference

This document describes the DERP wire protocol.

## Overview

DERP (Designated Encrypted Relay for Packets) is a relay protocol for routing encrypted packets when direct peer-to-peer connections aren't possible.

- **Transport**: TLS or WebSocket (binary frames)
- **Encoding**: Big-endian binary
- **Maximum packet**: 65,536 bytes
- **Keep-alive**: 60 seconds

## Frame Format

All frames follow this structure:

```
+--------+------------------+-------------------+
| Type   | Length           | Payload           |
| 1 byte | 4 bytes (BE)     | variable          |
+--------+------------------+-------------------+
```

- **Type**: Frame type (see Frame Types below)
- **Length**: Payload length in big-endian uint32
- **Payload**: Frame-specific data

## Magic Header

The server sends a magic header before the first frame:

```
44 45 52 50 f0 9f 94 91
D  E  R  P  🔑 (UTF-8)
```

This identifies the DERP protocol and version.

## Frame Types

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0x01 | ServerKey | S→C | Server's public key |
| 0x02 | ClientInfo | C→S | Client's encrypted info |
| 0x03 | ServerInfo | S→C | Server's encrypted response |
| 0x04 | SendPacket | C→S | Send packet to peer |
| 0x05 | RecvPacket | S→C | Receive packet from peer |
| 0x06 | KeepAlive | C→S | Keep connection alive |
| 0x07 | NotePreferred | C→S | Mark preferred connection |
| 0x08 | PeerGone | S→C | Peer disconnected |
| 0x09 | PeerPresent | S→C | Peer connected (mesh) |
| 0x0A | WatchConns | C→S | Watch connections (mesh) |
| 0x0B | ClosePeer | C→S | Close peer connection (mesh) |
| 0x0C | Ping | C→S | Ping request |
| 0x0D | Pong | S→C | Pong response |
| 0x0E | Health | S→C | Server health status |
| 0x0F | Restarting | S→C | Server restarting |
| 0x10 | ForwardPacket | S→S | Forward packet (mesh) |

## Connection Handshake

### 1. Magic Header (Server → Client)

```
+--------------------------------------------+
| Magic: "DERP🔑" (8 bytes)                  |
+--------------------------------------------+
```

### 2. ServerKey Frame (Server → Client)

```
+--------+--------+---------------------------+
| 0x01   | 32     | Server Public Key         |
| 1 byte | 4 bytes| 32 bytes (Curve25519)     |
+--------+--------+---------------------------+
```

### 3. ClientInfo Frame (Client → Server)

```
+--------+--------+---------------------------+---------------------------+
| 0x02   | Length | Client Public Key         | Encrypted Payload         |
| 1 byte | 4 bytes| 32 bytes                  | variable                  |
+--------+--------+---------------------------+---------------------------+

Encrypted Payload = NaCl box(JSON, nonce, server_pubkey, client_seckey)

JSON format:
{
  "version": 2,
  "meshKey": "optional-mesh-key"
}
```

### 4. ServerInfo Frame (Server → Client)

```
+--------+--------+---------------------------+
| 0x03   | Length | Encrypted Payload         |
| 1 byte | 4 bytes| variable                  |
+--------+--------+---------------------------+

Encrypted Payload = NaCl box(JSON, nonce, client_pubkey, server_seckey)

JSON format:
{
  "tokenBucketBytesPerSecond": 1048576,
  "tokenBucketBytesBurst": 2097152
}
```

## Data Frames

### SendPacket (Client → Server)

```
+--------+--------+---------------------------+---------------------------+
| 0x04   | Length | Destination Key           | Data                      |
| 1 byte | 4 bytes| 32 bytes                  | variable                  |
+--------+--------+---------------------------+---------------------------+
```

### RecvPacket (Server → Client)

```
+--------+--------+---------------------------+---------------------------+
| 0x05   | Length | Source Key                | Data                      |
| 1 byte | 4 bytes| 32 bytes                  | variable                  |
+--------+--------+---------------------------+---------------------------+
```

### PeerGone (Server → Client)

```
+--------+--------+---------------------------+--------+
| 0x08   | Length | Peer Key                  | Reason |
| 1 byte | 4 bytes| 32 bytes                  | 1 byte |
+--------+--------+---------------------------+--------+

Reason:
  0x00 = Unknown
  0x01 = Disconnected
  0x02 = Not here (peer not registered)
```

## Control Frames

### KeepAlive (Client → Server)

```
+--------+--------+
| 0x06   | 0      |
| 1 byte | 4 bytes|
+--------+--------+
```

Empty payload. Must be sent at least every 60 seconds.

### Ping (Client → Server)

```
+--------+--------+---------------------------+
| 0x0C   | 8      | Ping Data                 |
| 1 byte | 4 bytes| 8 bytes                   |
+--------+--------+---------------------------+
```

### Pong (Server → Client)

```
+--------+--------+---------------------------+
| 0x0D   | 8      | Ping Data (echoed)        |
| 1 byte | 4 bytes| 8 bytes                   |
+--------+--------+---------------------------+
```

### NotePreferred (Client → Server)

```
+--------+--------+--------+
| 0x07   | 1      | Flag   |
| 1 byte | 4 bytes| 1 byte |
+--------+--------+--------+

Flag:
  0x01 = This is the preferred DERP connection
  0x00 = Not preferred
```

## Cryptography

### Key Format

- **Algorithm**: Curve25519
- **Key size**: 32 bytes
- **Encoding**: Raw binary (base64 for display)

### NaCl Box

- **Algorithm**: Curve25519 + XSalsa20 + Poly1305
- **Nonce**: 24 bytes, unique per message
- **MAC**: 16 bytes prepended to ciphertext

```
Ciphertext = Poly1305_MAC || XSalsa20_encrypted_message
           = 16 bytes     || message_length bytes
```

### Key Generation

```erlang
%% Generate a new keypair
{PubKey, SecKey} = derp_sodium:box_keypair().
```

### Encryption

```erlang
%% Encrypt a message
Nonce = derp_sodium:randombytes(24),
Cipher = derp_sodium:box(Message, Nonce, TheirPubKey, MySecKey).
```

### Decryption

```erlang
%% Decrypt a message
case derp_sodium:box_open(Cipher, Nonce, TheirPubKey, MySecKey) of
    {ok, Message} -> handle(Message);
    error -> authentication_failed
end.
```

## Timing

| Parameter | Value |
|-----------|-------|
| Keep-alive interval | 60 seconds |
| Keep-alive timeout | 120 seconds |
| Handshake timeout | 10 seconds |
| Reconnect initial delay | 1 second |
| Reconnect max delay | 30 seconds |

## Limits

| Parameter | Value |
|-----------|-------|
| Maximum frame size | 65,536 bytes |
| Maximum packet data | 65,535 bytes (frame - header) |
| Public key size | 32 bytes |
| Secret key size | 32 bytes |
| Nonce size | 24 bytes |
| MAC size | 16 bytes |

## Error Handling

### Connection Errors

- **Handshake timeout**: Server closes connection if handshake not completed within 10 seconds
- **Keep-alive timeout**: Server closes connection if no traffic for 120 seconds
- **Authentication failure**: Server closes connection on invalid ClientInfo

### Packet Errors

- **Unknown destination**: Server sends PeerGone with reason "not here"
- **Rate limited**: Server may drop packets or close connection
- **Oversized packet**: Server closes connection

## WebSocket Transport

When using WebSocket transport:

- **Endpoint**: `/derp`
- **Frame type**: Binary
- **Protocol**: Standard DERP frames wrapped in WebSocket binary frames

The magic header is sent as the first WebSocket message after connection.
