#!/usr/bin/env bash
# run-registry.sh — Start the IDProva registry server locally
#
# Usage:
#   ./scripts/run-registry.sh              # default config
#   ./scripts/run-registry.sh --release    # build in release mode first
#
# Environment variables (all optional, override defaults):
#   IDPROVA_HOST     Listen address   (default: 127.0.0.1)
#   IDPROVA_PORT     Listen port      (default: 3000)
#   IDPROVA_DB_PATH  SQLite DB path   (default: ./data/registry.db)
#   RUST_LOG         Log level        (default: info)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_MODE="${1:-}"

log() { echo "[run-registry] $*"; }
err() { echo "[run-registry] ERROR: $*" >&2; exit 1; }

cd "$REPO_ROOT"

# ── Resolve config from env (with defaults) ───────────────────────────────────
export IDPROVA_HOST="${IDPROVA_HOST:-127.0.0.1}"
export IDPROVA_PORT="${IDPROVA_PORT:-3000}"
# The registry binary reads REGISTRY_PORT; bridge from IDPROVA_PORT for consistency
export REGISTRY_PORT="${REGISTRY_PORT:-$IDPROVA_PORT}"
export IDPROVA_DB_PATH="${IDPROVA_DB_PATH:-$REPO_ROOT/data/registry.db}"
export RUST_LOG="${RUST_LOG:-info}"

# ── Ensure data directory exists ──────────────────────────────────────────────
DATA_DIR="$(dirname "$IDPROVA_DB_PATH")"
mkdir -p "$DATA_DIR"

# ── Build ─────────────────────────────────────────────────────────────────────
if [[ "$BUILD_MODE" == "--release" ]]; then
    log "Building idprova-registry (release)..."
    cargo build --release --package idprova-registry
    BINARY="$REPO_ROOT/target/release/idprova-registry"
else
    log "Building idprova-registry (debug)..."
    cargo build --package idprova-registry
    BINARY="$REPO_ROOT/target/debug/idprova-registry"
fi

if [[ ! -x "$BINARY" ]]; then
    err "Binary not found at: $BINARY"
fi

# ── Launch ────────────────────────────────────────────────────────────────────
log "Starting registry..."
log "  Host:    $IDPROVA_HOST"
log "  Port:    $IDPROVA_PORT"
log "  DB:      $IDPROVA_DB_PATH"
log "  Log:     $RUST_LOG"
log ""
log "  Press Ctrl+C to stop"
log ""

exec "$BINARY"
