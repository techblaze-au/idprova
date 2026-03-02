# IDProva Registry Server
# Multi-stage build for minimal production image

# Stage 1: Build
FROM rust:1.77-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build --release --package idprova-registry

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r idprova && useradd -r -g idprova idprova

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/idprova-registry /app/idprova-registry

# Create data directory for SQLite
RUN mkdir -p /app/data && chown -R idprova:idprova /app

USER idprova

# Environment defaults
ENV IDPROVA_HOST=0.0.0.0
ENV IDPROVA_PORT=3000
ENV IDPROVA_DB_PATH=/app/data/registry.db
ENV RUST_LOG=info

EXPOSE 3000

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["/app/idprova-registry"]
