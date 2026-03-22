# IDProva Registry Server
# Multi-stage build with cargo-chef for optimal layer caching

# ── Stage 1: Chef — prepare dependency recipe ────────────────────────────────
FROM rust:1.85-slim-bookworm AS chef

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /build

# ── Stage 2: Planner — compute the dependency recipe ─────────────────────────
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# sdks/ intentionally excluded — registry build does not need them

RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Builder — cache deps layer then build the binary ─────────────────
FROM chef AS builder

# Restore only the dependency layer (cached unless Cargo.lock changes)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json \
    --package idprova-registry

# Now copy full source and build the binary
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --package idprova-registry

# ── Stage 4: Runtime — minimal Debian slim image ──────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r idprova \
    && useradd -r -g idprova -d /app -s /sbin/nologin idprova

WORKDIR /app

COPY --from=builder /build/target/release/idprova-registry /app/idprova-registry

RUN mkdir -p /app/data && chown -R idprova:idprova /app

USER idprova

ENV REGISTRY_PORT=3000
ENV REGISTRY_DB_PATH=/app/data/registry.db
ENV RUST_LOG=info

EXPOSE 3000

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${REGISTRY_PORT}/health || exit 1

ENTRYPOINT ["/app/idprova-registry"]
