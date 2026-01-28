# Docker Deployment

This guide covers deploying DERP with Docker.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/benoitc/erlang-derp.git
cd erlang-derp

# Generate certificates
cd docker/certs && ./generate.sh && cd ..

# Start the server
docker-compose up -d
```

## Docker Images

### Server Image

Build the server image:

```bash
docker build -t derp -f docker/Dockerfile .
```

The image:

- Based on `erlang:27-alpine` (build) and `alpine:3.22` (runtime)
- Multi-platform: `linux/amd64`, `linux/arm64`
- Includes libsodium runtime
- Runs as non-root user

### Client Image

Build the test client image:

```bash
docker build -t derp-client -f docker/Dockerfile.client .
```

## Docker Compose

### Basic Configuration

`docker-compose.yml`:

```yaml
services:
  derp-server:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - DERP_PORT=443
      - DERP_WS_PORT=80
      - DERP_CERTFILE=/app/certs/server.crt
      - DERP_KEYFILE=/app/certs/server.key
    restart: unless-stopped
```

### Production Configuration

```yaml
services:
  derp-server:
    image: derp:latest
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - /etc/letsencrypt/live/derp.example.com:/app/certs:ro
    environment:
      - DERP_PORT=443
      - DERP_WS_PORT=80
      - DERP_CERTFILE=/app/certs/fullchain.pem
      - DERP_KEYFILE=/app/certs/privkey.pem
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "443"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Two-Client Simulation

Test the relay with two clients:

### Automated

```bash
./docker/run_simulation.sh
```

### Manual

```bash
# Start the server
docker-compose -f docker-compose.simulation.yml up -d derp-server

# Start receiver (Bob)
docker-compose -f docker-compose.simulation.yml run --rm client-bob \
    receiver derp-server 443

# Note Bob's public key, then in another terminal:
docker-compose -f docker-compose.simulation.yml run --rm client-alice \
    sender derp-server 443 <BOB_PUBKEY>
```

### Simulation Compose File

`docker-compose.simulation.yml`:

```yaml
services:
  derp-server:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - DERP_CERTFILE=/app/certs/server.crt
      - DERP_KEYFILE=/app/certs/server.key
    networks:
      - derp-net

  client-alice:
    build:
      context: ..
      dockerfile: docker/Dockerfile.client
    depends_on:
      - derp-server
    networks:
      - derp-net

  client-bob:
    build:
      context: ..
      dockerfile: docker/Dockerfile.client
    depends_on:
      - derp-server
    networks:
      - derp-net

networks:
  derp-net:
    driver: bridge
```

## Certificate Generation

### Development Certificates

The `docker/certs/generate.sh` script creates self-signed certificates:

```bash
#!/bin/bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 365 \
    -subj "/CN=DERP Test CA" -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
    -subj "/CN=derp-server" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 365 -sha256 \
    -extfile <(echo "subjectAltName=DNS:derp-server,DNS:localhost") \
    -out server.crt
```

### Production Certificates

For production, use Let's Encrypt:

```bash
# Install certbot
apt-get install certbot

# Get certificate
certbot certonly --standalone -d derp.example.com

# Mount in container
volumes:
  - /etc/letsencrypt/live/derp.example.com:/app/certs:ro
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DERP_PORT` | 443 | TLS listen port |
| `DERP_WS_PORT` | 80 | WebSocket listen port |
| `DERP_CERTFILE` | - | Path to TLS certificate |
| `DERP_KEYFILE` | - | Path to TLS private key |

## Health Checks

The container includes a health check:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 443 || exit 1
```

Check health status:

```bash
docker inspect --format='{{.State.Health.Status}}' derp-server
```

## Logging

View container logs:

```bash
# Follow logs
docker-compose logs -f derp-server

# Last 100 lines
docker-compose logs --tail=100 derp-server
```

## Troubleshooting

### Connection Refused

```bash
# Check if container is running
docker-compose ps

# Check logs for errors
docker-compose logs derp-server
```

### Certificate Errors

```bash
# Verify certificate is mounted
docker-compose exec derp-server ls -la /app/certs/

# Check certificate validity
openssl x509 -in docker/certs/server.crt -text -noout
```

### NIF Loading Errors

```bash
# Check libsodium is installed
docker-compose exec derp-server ldd /app/lib/derp-*/priv/derp_sodium_nif.so
```

## Multi-Platform Build

Build for multiple architectures:

```bash
# Create builder
docker buildx create --name derp-builder --use

# Build and push
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t derp:latest \
    -f docker/Dockerfile \
    --push \
    .
```
