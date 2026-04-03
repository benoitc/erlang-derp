#!/usr/bin/env python3
"""
Test Python DERP client connectivity to Erlang DERP server.

This implements a minimal DERP client to verify protocol compatibility.
"""

import argparse
import json
import os
import socket
import traceback
import struct
import sys
import time
from typing import Optional, Tuple

try:
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.utils import random as nacl_random
except ImportError:
    print("ERROR: pynacl required. Install with: pip install pynacl")
    sys.exit(1)

# DERP Protocol Constants
DERP_MAGIC = b'DERP\xf0\x9f\x94\x91'  # DERP + key emoji

# Frame types
FRAME_SERVER_KEY = 0x01
FRAME_CLIENT_INFO = 0x02
FRAME_SERVER_INFO = 0x03
FRAME_SEND_PACKET = 0x04
FRAME_RECV_PACKET = 0x05
FRAME_KEEP_ALIVE = 0x06
FRAME_NOTE_PREFERRED = 0x07
FRAME_PEER_GONE = 0x08
FRAME_PEER_PRESENT = 0x09
FRAME_WATCH_CONNS = 0x0A
FRAME_PING = 0x0C
FRAME_PONG = 0x0D
FRAME_HEALTH = 0x14
FRAME_RESTARTING = 0x15


class DERPClient:
    """Minimal DERP client for interoperability testing."""

    def __init__(self, host: str, port: int, use_tls: bool = False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.sock: Optional[socket.socket] = None
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.server_public_key: Optional[PublicKey] = None
        self.connected = False

    def connect(self) -> None:
        """Connect to DERP server via HTTP upgrade."""
        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))

        if self.use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)

        # Send HTTP upgrade request
        request = (
            f"GET /derp HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: DERP\r\n"
            f"Connection: Upgrade\r\n"
            f"\r\n"
        )
        self.sock.sendall(request.encode())

        # Read HTTP response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed during HTTP upgrade")
            response += chunk

        if b"101" not in response:
            raise ConnectionError(f"HTTP upgrade failed: {response.decode()}")

        # Check if there's leftover data after HTTP headers (beginning of DERP frames)
        header_end = response.find(b"\r\n\r\n") + 4
        self._buffer = response[header_end:] if header_end < len(response) else b""

        # Complete DERP handshake
        self._handshake()
        self.connected = True

    def _handshake(self) -> None:
        """Complete DERP handshake after HTTP upgrade."""
        # Receive server key frame
        frame_type, payload = self._recv_frame()
        if frame_type != FRAME_SERVER_KEY:
            raise ProtocolError(f"Expected server key frame, got {frame_type:#x}")

        # Parse server key: magic (8) + pubkey (32)
        if len(payload) != 40:
            raise ProtocolError(f"Invalid server key payload length: {len(payload)}")

        magic = payload[:8]
        if magic != DERP_MAGIC:
            raise ProtocolError(f"Invalid magic: {magic!r}")

        server_pub_bytes = payload[8:40]
        self.server_public_key = PublicKey(server_pub_bytes)

        # Send client info
        client_info = {"version": 2}
        client_info_json = json.dumps(client_info).encode()

        # Encrypt client info with server's public key
        box = Box(self.private_key, self.server_public_key)
        nonce = nacl_random(24)
        encrypted = box.encrypt(client_info_json, nonce)
        # encrypted includes nonce prefix, we need just ciphertext
        ciphertext = encrypted.ciphertext

        # Client info frame: pubkey (32) + nonce (24) + encrypted
        client_info_payload = bytes(self.public_key) + nonce + ciphertext
        self._send_frame(FRAME_CLIENT_INFO, client_info_payload)

        # Receive server info frame
        frame_type, payload = self._recv_frame()
        if frame_type != FRAME_SERVER_INFO:
            raise ProtocolError(f"Expected server info frame, got {frame_type:#x}")

        # Decrypt server info (nonce + ciphertext)
        if len(payload) < 24:
            raise ProtocolError("Server info payload too short")

        server_nonce = payload[:24]
        server_ciphertext = payload[24:]
        server_info_json = box.decrypt(server_ciphertext, server_nonce)
        # Server info received (we don't need to parse it for basic connectivity)

    def _send_frame(self, frame_type: int, payload: bytes) -> None:
        """Send a DERP frame."""
        header = struct.pack(">BI", frame_type, len(payload))
        if os.environ.get('DERP_DEBUG'):
            print(f"  [DEBUG] Sending frame type={frame_type}, len={len(payload)}, header={header.hex()}")
        self.sock.sendall(header + payload)

    def _recv_frame(self) -> Tuple[int, bytes]:
        """Receive a DERP frame."""
        # Read header: type (1) + length (4)
        header = self._recv_exact(5)
        frame_type = header[0]
        length = struct.unpack(">I", header[1:5])[0]

        if os.environ.get('DERP_DEBUG'):
            print(f"  [DEBUG] Recv frame type={frame_type}, len={length}, header={header.hex()}")

        if length > 64 * 1024:  # 64KB max
            raise ProtocolError(f"Frame too large: {length}")

        payload = self._recv_exact(length) if length > 0 else b""
        return frame_type, payload

    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes, using buffer first."""
        # Use buffered data first
        if hasattr(self, '_buffer') and self._buffer:
            if len(self._buffer) >= n:
                data = self._buffer[:n]
                self._buffer = self._buffer[n:]
                return data
            data = self._buffer
            self._buffer = b""
        else:
            data = b""

        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def ping(self, data: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08") -> bytes:
        """Send ping and wait for pong."""
        if len(data) != 8:
            raise ValueError("Ping data must be 8 bytes")

        self._send_frame(FRAME_PING, data)

        # Wait for pong
        start = time.time()
        while time.time() - start < 5:
            frame_type, payload = self._recv_frame()
            if frame_type == FRAME_PONG:
                if payload != data:
                    raise ProtocolError(f"Pong data mismatch: {payload!r} != {data!r}")
                return payload

        raise TimeoutError("Pong not received within 5 seconds")

    def send_packet(self, dest_key: bytes, data: bytes) -> None:
        """Send a packet to another client."""
        payload = dest_key + data
        self._send_frame(FRAME_SEND_PACKET, payload)

    def recv_packet(self, timeout: float = 5.0) -> Tuple[bytes, bytes]:
        """Receive a packet. Returns (source_key, data)."""
        self.sock.settimeout(timeout)
        try:
            while True:
                frame_type, payload = self._recv_frame()
                if frame_type == FRAME_RECV_PACKET:
                    if len(payload) < 32:
                        raise ProtocolError("Recv packet payload too short")
                    src_key = payload[:32]
                    data = payload[32:]
                    return src_key, data
                # Ignore other frame types
        finally:
            self.sock.settimeout(10)

    def close(self) -> None:
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False


class ProtocolError(Exception):
    """DERP protocol error."""
    pass


def test_http_upgrade(host: str, port: int, use_tls: bool, verbose: bool) -> bool:
    """Test HTTP upgrade connection and ping/pong."""
    print("Test: HTTP upgrade connection...")

    client = DERPClient(host, port, use_tls)
    try:
        client.connect()
        if verbose:
            print(f"  - Connected, server key: {bytes(client.server_public_key).hex()}")

        # Send ping
        pong = client.ping()
        print("  - Ping/Pong successful")
        print("  PASS")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False
    finally:
        client.close()


def test_two_clients(host: str, port: int, use_tls: bool, verbose: bool) -> bool:
    """Test two clients communicating."""
    print("Test: Two clients communication...")

    client1 = DERPClient(host, port, use_tls)
    client2 = DERPClient(host, port, use_tls)

    try:
        client1.connect()
        client2.connect()
        if verbose:
            print(f"  - Client1 key: {bytes(client1.public_key).hex()[:16]}...")
            print(f"  - Client2 key: {bytes(client2.public_key).hex()[:16]}...")

        # Send from client1 to client2
        test_data = b"Hello from Python client!"
        client1.send_packet(bytes(client2.public_key), test_data)
        print("  - Sent packet from client1 to client2")

        # Receive on client2
        src_key, recv_data = client2.recv_packet(timeout=5.0)

        if src_key != bytes(client1.public_key):
            print(f"  FAIL: Source key mismatch")
            return False

        if recv_data != test_data:
            print(f"  FAIL: Data mismatch: {recv_data!r} != {test_data!r}")
            return False

        print("  - Client2 received packet correctly")
        print("  PASS")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client1.close()
        client2.close()


def main():
    parser = argparse.ArgumentParser(description="Test Python DERP client against Erlang server")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--tls", action="store_true", help="Use TLS")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    passed = 0
    failed = 0

    if test_http_upgrade(args.host, args.port, args.tls, args.verbose):
        passed += 1
    else:
        failed += 1

    if test_two_clients(args.host, args.port, args.tls, args.verbose):
        passed += 1
    else:
        failed += 1

    print()
    if failed == 0:
        print(f"PASS: All {passed} tests passed")
        sys.exit(0)
    else:
        print(f"FAIL: {failed} tests failed, {passed} passed")
        sys.exit(1)


if __name__ == "__main__":
    main()
