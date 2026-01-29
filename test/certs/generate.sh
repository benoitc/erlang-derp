#!/bin/sh
# Generate self-signed certificates for TLS loopback tests.
#
# Produces server.pem (certificate) and server-key.pem (private key)
# in the same directory as this script.

set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Skip if certs already exist
if [ -f "$CERT_DIR/server.pem" ] && [ -f "$CERT_DIR/server-key.pem" ]; then
    exit 0
fi

# Generate RSA private key
openssl genrsa -out "$CERT_DIR/server-key.pem" 2048 2>/dev/null

# Generate self-signed certificate with SAN for localhost/127.0.0.1
openssl req -new -x509 -days 3650 \
    -key "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
    2>/dev/null

chmod 644 "$CERT_DIR/server.pem"
chmod 600 "$CERT_DIR/server-key.pem"
