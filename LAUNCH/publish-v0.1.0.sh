#!/bin/bash
# IDProva v0.1.0 Publishing Script
# Run from: C:\Users\praty\toon_conversations\aidspec\
# Prerequisites: cargo login, maturin, npm login
#
# IMPORTANT: Run each section one at a time, verifying between steps.
# Don't run this as a batch script — things can fail and need manual intervention.

set -e

echo "=========================================="
echo "  IDProva v0.1.0 Publishing Checklist"
echo "=========================================="
echo ""

# ─────────────────────────────────────────
# STEP 0: Pre-flight checks
# ─────────────────────────────────────────
echo "--- STEP 0: Pre-flight checks ---"
echo ""

# Verify all tests pass
echo "Running workspace tests..."
cargo test --workspace
echo "✓ All tests passing"
echo ""

# Verify we're on main and clean
echo "Git status:"
git status --short
echo ""
echo "Current branch: $(git branch --show-current)"
echo ""

# ─────────────────────────────────────────
# STEP 1: Push all commits to origin
# ─────────────────────────────────────────
echo "--- STEP 1: Push commits to origin/main ---"
echo "Run: git push origin main"
echo ""
read -p "Press Enter after pushing (or Ctrl+C to abort)..."

# ─────────────────────────────────────────
# STEP 2: Make repo public on GitHub
# ─────────────────────────────────────────
echo ""
echo "--- STEP 2: Make repo PUBLIC ---"
echo "Go to: https://github.com/techblaze-au/idprova/settings"
echo "Scroll to 'Danger Zone' → Change repository visibility → Make public"
echo ""
read -p "Press Enter after making repo public..."

# ─────────────────────────────────────────
# STEP 3: Publish Rust crates (dependency order)
# ─────────────────────────────────────────
echo ""
echo "--- STEP 3: Publish Rust crates to crates.io ---"
echo "Publishing in dependency order..."
echo ""

echo "3a. Publishing idprova-core..."
cargo publish -p idprova-core
echo "✓ idprova-core published. Waiting 30s for crates.io index update..."
sleep 30

echo "3b. Publishing idprova-verify..."
cargo publish -p idprova-verify
echo "✓ idprova-verify published. Waiting 30s..."
sleep 30

echo "3c. Publishing idprova-middleware..."
cargo publish -p idprova-middleware
echo "✓ idprova-middleware published. Waiting 30s..."
sleep 30

echo "3d. Publishing idprova-registry..."
cargo publish -p idprova-registry
echo "✓ idprova-registry published. Waiting 30s..."
sleep 30

echo "3e. Publishing idprova-cli..."
cargo publish -p idprova-cli
echo "✓ idprova-cli published!"
echo ""

# ─────────────────────────────────────────
# STEP 4: Publish Python SDK to PyPI
# ─────────────────────────────────────────
echo "--- STEP 4: Publish Python SDK to PyPI ---"
echo ""
cd sdks/python

echo "Building Python wheel..."
maturin build --release

echo "Publishing to PyPI..."
maturin publish
echo "✓ Python SDK published to PyPI"
cd ../..
echo ""

# ─────────────────────────────────────────
# STEP 5: Publish TypeScript SDK to npm
# ─────────────────────────────────────────
echo "--- STEP 5: Publish TypeScript SDK to npm ---"
echo ""
cd sdks/typescript/packages/core

echo "Building native module..."
npm run build

echo "Publishing to npm..."
npm publish --access public
echo "✓ TypeScript SDK published to npm (@idprova/core)"
cd ../../../..
echo ""

# ─────────────────────────────────────────
# STEP 6: Tag and release
# ─────────────────────────────────────────
echo "--- STEP 6: Create git tag v0.1.0 ---"
echo ""
git tag -a v0.1.0 -m "IDProva v0.1.0 — Cryptographic identity for AI agents

First public release. Feature-complete protocol implementation:
- Agent Identity Documents (AIDs) with W3C DID method
- Delegation Attestation Tokens (DATs) with scope/time/depth controls
- Hash-chained Action Receipts for tamper-evident audit
- RBAC Policy Engine with 7 constraint evaluators
- Registry server (Axum + SQLite)
- CLI tool, Tower middleware
- Python SDK (PyO3), TypeScript SDK (napi-rs)
- 230+ tests, Ed25519 + BLAKE3, zeroize, post-quantum ready

https://idprova.dev"

echo "Pushing tag to origin (triggers release workflow)..."
git push origin v0.1.0
echo "✓ Tag v0.1.0 pushed — GitHub Actions will build cross-platform binaries + Docker image"
echo ""

# ─────────────────────────────────────────
# STEP 7: Verify everything works
# ─────────────────────────────────────────
echo "=========================================="
echo "  VERIFICATION CHECKLIST"
echo "=========================================="
echo ""
echo "Run these manually to verify:"
echo ""
echo "  # Rust CLI from crates.io"
echo "  cargo install idprova-cli"
echo "  idprova --help"
echo ""
echo "  # Python SDK from PyPI"
echo "  pip install idprova"
echo "  python -c \"import idprova; print('OK')\""
echo ""
echo "  # TypeScript SDK from npm"
echo "  npm install @idprova/core"
echo ""
echo "  # Docker image (after release workflow completes)"
echo "  docker pull ghcr.io/techblaze-au/idprova-registry:v0.1.0"
echo ""
echo "  # GitHub Release page"
echo "  open https://github.com/techblaze-au/idprova/releases/tag/v0.1.0"
echo ""
echo "=========================================="
echo "  DONE! 🎉"
echo "=========================================="
