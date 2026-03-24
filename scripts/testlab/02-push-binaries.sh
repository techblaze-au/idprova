#!/usr/bin/env bash
# 02-push-binaries.sh
# Run ON Proxmox host (198.51.100.10).
# Pushes IDProva binaries from /tmp/idprova-bins/ to all test lab containers.
#
# Usage: bash scripts/testlab/02-push-binaries.sh
# Prerequisites: Binaries built and placed in /tmp/idprova-bins/

set -euo pipefail

BINS_DIR="/tmp/idprova-bins"

# Container IPs
CT_REGISTRY=401    # 198.51.100.41
CT_ADMIN=402       # 198.51.100.42
CT_ORCHESTRATOR=403 # 198.51.100.43
CT_WORKER_A=404    # 198.51.100.44
CT_WORKER_B=405    # 198.51.100.45

ALL_CTS=($CT_REGISTRY $CT_ADMIN $CT_ORCHESTRATOR $CT_WORKER_A $CT_WORKER_B)

echo "=== IDProva Test Lab: Push Binaries ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo "Bins: $BINS_DIR"
echo ""

# ── 1. Verify binaries exist ────────────────────────────────────────────────
echo "[1/3] Checking binaries in $BINS_DIR..."

for bin in idprova idprova-registry idprova-mcp-demo; do
    if [[ ! -f "$BINS_DIR/$bin" ]]; then
        echo "ERROR: $BINS_DIR/$bin not found."
        echo "       Build with: cargo build --release"
        echo "       Then copy to $BINS_DIR/"
        exit 1
    fi
    echo "      $bin OK ($(stat -c%s "$BINS_DIR/$bin" 2>/dev/null || echo '?') bytes)"
done

# ── 2. Verify all containers are running ────────────────────────────────────
echo ""
echo "[2/3] Checking containers are running..."

for ct in "${ALL_CTS[@]}"; do
    status=$(pct status "$ct" 2>/dev/null | awk '{print $2}')
    if [[ "$status" != "running" ]]; then
        echo "ERROR: CT $ct is not running (status: ${status:-unknown})."
        echo "       Start it: pct start $ct"
        exit 1
    fi
    echo "      CT $ct: running"
done

# ── 3. Push binaries ────────────────────────────────────────────────────────
echo ""
echo "[3/3] Pushing binaries to containers..."

# All containers get the CLI
for ct in "${ALL_CTS[@]}"; do
    echo "      CT $ct: pushing idprova CLI..."
    pct push "$ct" "$BINS_DIR/idprova" /usr/local/bin/idprova
    pct exec "$ct" -- chmod 755 /usr/local/bin/idprova
done

# Registry container also gets registry and MCP demo binaries
echo ""
echo "      CT $CT_REGISTRY: pushing idprova-registry..."
pct push "$CT_REGISTRY" "$BINS_DIR/idprova-registry" /usr/local/bin/idprova-registry
pct exec "$CT_REGISTRY" -- chmod 755 /usr/local/bin/idprova-registry

echo "      CT $CT_REGISTRY: pushing idprova-mcp-demo..."
pct push "$CT_REGISTRY" "$BINS_DIR/idprova-mcp-demo" /usr/local/bin/idprova-mcp-demo
pct exec "$CT_REGISTRY" -- chmod 755 /usr/local/bin/idprova-mcp-demo

# ── Verify ──────────────────────────────────────────────────────────────────
echo ""
echo "Verifying installations..."
for ct in "${ALL_CTS[@]}"; do
    ver=$(pct exec "$ct" -- /usr/local/bin/idprova --version 2>&1 || echo "FAILED")
    echo "      CT $ct: $ver"
done

echo ""
echo "=== Binaries pushed to all containers ==="
echo ""
echo "Next: run 03-setup-registry.sh"
