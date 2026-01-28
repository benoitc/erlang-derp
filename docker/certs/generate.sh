#!/bin/sh
# Generate self-signed certificates for testing

set -e

CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=Test/L=Test/O=DERP Test CA/CN=DERP Test CA"

# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=DERP Test/CN=localhost"

# Create extensions file for SAN
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = derp-server
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server.ext

# Clean up
rm -f server.csr server.ext ca.srl

# Set permissions
chmod 644 *.crt
chmod 600 *.key

echo "Certificates generated successfully:"
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
