# DERP Server Dockerfile
# Supports: linux/amd64, linux/arm64

# Build stage
FROM erlang:27-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    cmake \
    gcc \
    g++ \
    musl-dev \
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
COPY priv/ priv/

# Build release
RUN rebar3 as prod release

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    libsodium \
    openssl \
    ncurses-libs \
    libstdc++ \
    libgcc

# Create non-root user
RUN addgroup -g 1000 derp && \
    adduser -u 1000 -G derp -s /bin/sh -D derp

WORKDIR /app

# Copy release from builder
COPY --from=builder /app/_build/prod/rel/derp ./

# Copy certificates directory (will be mounted)
RUN mkdir -p /app/certs && chown derp:derp /app/certs

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
