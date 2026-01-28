# DERP Server Dockerfile
# Supports: linux/amd64, linux/arm64

# Build stage
FROM erlang:27-alpine AS builder

# Install build dependencies (includes BoringSSL: cmake, g++, perl, ninja)
RUN apk add --no-cache \
    git \
    make \
    cmake \
    ninja-build \
    gcc \
    g++ \
    musl-dev \
    perl \
    libsodium-dev \
    openssl-dev

WORKDIR /app

# Copy rebar.config first for dependency caching
COPY rebar.config rebar.lock* ./

# Fetch dependencies
RUN rebar3 get-deps

# Copy source code
COPY src/ src/
COPY c_src/ c_src/
COPY config/ config/

# Create priv directory (don't copy from host to avoid architecture mismatch)
RUN mkdir -p priv

# Clean any cached NIF and rebuild from scratch
RUN make -C c_src clean || true && rebar3 as prod release

# Runtime stage - use same Alpine version as erlang:27-alpine for compatibility
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache \
    libsodium \
    openssl \
    ncurses-libs \
    libstdc++ \
    libgcc \
    netcat-openbsd

# Create non-root user
RUN addgroup -g 1000 derp && \
    adduser -u 1000 -G derp -s /bin/sh -D derp

WORKDIR /app

# Copy release from builder
COPY --from=builder /app/_build/prod/rel/derp ./

# Copy certificates directory (will be mounted)
RUN mkdir -p /app/certs

# Fix permissions for RELX_REPLACE_OS_VARS (release needs to write to releases dir)
RUN chown -R derp:derp /app

# Switch to non-root user
USER derp

# Expose ports
EXPOSE 443 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 443 || exit 1

# Environment variables
ENV RELX_REPLACE_OS_VARS=true
ENV DERP_PORT=443
ENV DERP_WS_PORT=80

# Entrypoint
ENTRYPOINT ["/app/bin/derp"]
CMD ["foreground"]
