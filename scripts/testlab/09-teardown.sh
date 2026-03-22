#!/usr/bin/env bash
# 09-teardown.sh
# Run ON Proxmox host (192.168.8.90).
# Stops and destroys all test lab containers (400-405) and cleans up binaries.
#
# Usage: bash scripts/testlab/09-teardown.sh
# WARNING: This is destructive. All test lab data will be lost.

set -euo pipefail

ALL_CTS=(401 402 403 404 405)
BINS_DIR="/tmp/idprova-bins"

echo "=== IDProva Test Lab: Teardown ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""
echo "WARNING: This will DESTROY containers: ${ALL_CTS[*]}"
echo "         and clean up $BINS_DIR"
echo ""

# ── Confirmation ────────────────────────────────────────────────────────────
read -p "Type 'yes' to confirm teardown: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""

# ── Stop and destroy containers ─────────────────────────────────────────────
for ct in "${ALL_CTS[@]}"; do
    echo "[CT $ct] Checking status..."
    status=$(pct status "$ct" 2>/dev/null | awk '{print $2}' || echo "not found")

    if [[ "$status" == "running" ]]; then
        echo "      Stopping CT $ct..."
        pct stop "$ct" 2>/dev/null || true
        # Wait for it to actually stop
        for i in {1..10}; do
            s=$(pct status "$ct" 2>/dev/null | awk '{print $2}' || echo "stopped")
            if [[ "$s" != "running" ]]; then break; fi
            sleep 1
        done
    fi

    if pct status "$ct" &>/dev/null; then
        echo "      Destroying CT $ct..."
        pct destroy "$ct" --purge 2>/dev/null || true
        echo "      CT $ct destroyed."
    else
        echo "      CT $ct does not exist, skipping."
    fi
done

# ── Clean up binaries ──────────────────────────────────────────────────────
echo ""
if [[ -d "$BINS_DIR" ]]; then
    echo "Cleaning up $BINS_DIR..."
    rm -rf "$BINS_DIR"
    echo "      Removed."
else
    echo "$BINS_DIR does not exist, nothing to clean."
fi

echo ""
echo "=== Teardown complete ==="
echo ""
echo "Destroyed containers: ${ALL_CTS[*]}"
echo "Cleaned up: $BINS_DIR"
