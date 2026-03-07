#!/usr/bin/env bash
# dev-setup.sh — IDProva development environment setup
#
# Usage: ./scripts/dev-setup.sh [--skip-tests]
#
# Installs required tooling, verifies the workspace builds, and runs the
# test suite. Safe to re-run; all steps are idempotent.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_TESTS="${1:-}"

log()  { echo "[dev-setup] $*"; }
info() { echo "[dev-setup] INFO: $*"; }
ok()   { echo "[dev-setup] OK: $*"; }
err()  { echo "[dev-setup] ERROR: $*" >&2; exit 1; }

cd "$REPO_ROOT"

# ── 1. Check Rust toolchain ───────────────────────────────────────────────────
log "Checking Rust toolchain..."
if ! command -v rustup &>/dev/null; then
    err "rustup not found. Install from https://rustup.rs and re-run."
fi

REQUIRED_MSRV="1.75"
INSTALLED_VERSION=$(rustc --version | awk '{print $2}')
log "  Rust $INSTALLED_VERSION detected (MSRV: $REQUIRED_MSRV)"

# Ensure stable channel is available
rustup toolchain install stable --no-self-update >/dev/null 2>&1 || true
ok "Rust toolchain ready"

# ── 2. Install cargo tools ────────────────────────────────────────────────────
log "Installing cargo tools..."

if ! cargo clippy --version &>/dev/null 2>&1; then
    log "  Installing clippy..."
    rustup component add clippy
fi

if ! cargo fmt --version &>/dev/null 2>&1; then
    log "  Installing rustfmt..."
    rustup component add rustfmt
fi

if ! command -v cargo-audit &>/dev/null; then
    log "  Installing cargo-audit..."
    cargo install cargo-audit --locked
fi

ok "Cargo tools ready"

# ── 3. Build workspace ────────────────────────────────────────────────────────
log "Building workspace (excluding SDK crates)..."
cargo build --workspace \
    --exclude idprova-python \
    --exclude idprova-typescript
ok "Build successful"

# ── 4. Lint ───────────────────────────────────────────────────────────────────
log "Running clippy..."
cargo clippy --workspace \
    --exclude idprova-python \
    --exclude idprova-typescript \
    -- -D warnings
ok "Clippy clean"

log "Checking formatting..."
cargo fmt --all -- --check
ok "Format check passed"

# ── 5. Tests ──────────────────────────────────────────────────────────────────
if [[ "$SKIP_TESTS" == "--skip-tests" ]]; then
    info "Skipping tests (--skip-tests passed)"
else
    log "Running tests..."
    cargo test --workspace \
        --exclude idprova-python \
        --exclude idprova-typescript
    ok "All tests passed"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "  Development environment is ready."
echo "  Start the registry with: ./scripts/run-registry.sh"
echo ""
