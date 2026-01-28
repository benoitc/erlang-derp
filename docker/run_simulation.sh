#!/bin/bash
#
# DERP Two-Client Simulation Script
#
# This script demonstrates two clients communicating through the DERP relay server.
#
# Usage:
#   ./docker/run_simulation.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$SCRIPT_DIR"

echo "=========================================="
echo "DERP Two-Client Simulation"
echo "=========================================="
echo ""

# Check if certificates exist
if [ ! -f "$SCRIPT_DIR/certs/server.crt" ] || [ ! -f "$SCRIPT_DIR/certs/server.key" ]; then
    echo "Generating test certificates..."
    cd "$SCRIPT_DIR/certs"
    ./generate.sh
    cd "$SCRIPT_DIR"
    echo ""
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    docker-compose -f docker-compose.simulation.yml down --remove-orphans 2>/dev/null || true
}

trap cleanup EXIT

# Stop any existing containers
echo "Stopping any existing containers..."
docker-compose -f docker-compose.simulation.yml down --remove-orphans 2>/dev/null || true

# Build images
echo ""
echo "Building Docker images..."
docker-compose -f docker-compose.simulation.yml build

# Start the server
echo ""
echo "Starting DERP server..."
docker-compose -f docker-compose.simulation.yml up -d derp-server

# Wait for server to be healthy
echo "Waiting for server to be healthy..."
for i in {1..30}; do
    if docker-compose -f docker-compose.simulation.yml ps derp-server | grep -q "healthy"; then
        echo "Server is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Error: Server failed to become healthy"
        docker-compose -f docker-compose.simulation.yml logs derp-server
        exit 1
    fi
    sleep 1
done

# Start Bob (receiver) in background and capture output
echo ""
echo "Starting client-bob (receiver)..."
BOB_LOG=$(mktemp)
docker-compose -f docker-compose.simulation.yml run --rm -T client-bob receiver derp-server 443 > "$BOB_LOG" 2>&1 &
BOB_PID=$!

# Wait for Bob to print its public key
echo "Waiting for Bob's public key..."
for i in {1..20}; do
    if grep -q "My public key:" "$BOB_LOG" 2>/dev/null; then
        break
    fi
    if [ $i -eq 20 ]; then
        echo "Error: Bob failed to connect"
        cat "$BOB_LOG"
        exit 1
    fi
    sleep 0.5
done

# Extract Bob's public key
BOB_PUBKEY=$(grep -A1 "My public key:" "$BOB_LOG" | tail -1 | tr -d '[:space:]')

if [ -z "$BOB_PUBKEY" ]; then
    echo "Error: Could not extract Bob's public key"
    cat "$BOB_LOG"
    exit 1
fi

echo ""
echo "=========================================="
echo "Bob's public key: $BOB_PUBKEY"
echo "=========================================="
echo ""

# Start Alice (sender)
echo "Starting client-alice (sender)..."
echo ""
docker-compose -f docker-compose.simulation.yml run --rm client-alice sender derp-server 443 "$BOB_PUBKEY"

# Show Bob's received messages
echo ""
echo "=========================================="
echo "Bob's received messages:"
echo "=========================================="
cat "$BOB_LOG"

# Cleanup
rm -f "$BOB_LOG"
kill $BOB_PID 2>/dev/null || true

echo ""
echo "Simulation complete!"
