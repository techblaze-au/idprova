#!/usr/bin/env bash
# 04-admin-setup.sh
# Run ON CT 402 (idp-admin) at 198.51.100.42.
# Generates admin keypair, writes admin.env, pushes to CT 401, starts registry.
# Bash equivalent of production/02-admin-setup.ps1.
#
# Usage: pct exec 402 -- bash /root/04-admin-setup.sh
#    or: ssh root@198.51.100.42 'bash -s' < scripts/testlab/04-admin-setup.sh
# Prerequisites: 03-setup-registry.sh completed.

set -euo pipefail

REGISTRY_HOST="198.51.100.41"
REGISTRY_URL="http://${REGISTRY_HOST}:4242"
KEYS_DIR="/root/.idprova/keys"
KEY_PATH="$KEYS_DIR/admin-root.key"
PUB_PATH="$KEYS_DIR/admin-root.pub"

echo "=== IDProva Test Lab: Admin Setup ==="
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Registry: $REGISTRY_URL"
echo "Date: $(date)"
echo ""

# ── 1. Verify binary exists ────────────────────────────────────────────────
if [[ ! -x /usr/local/bin/idprova ]]; then
    echo "ERROR: /usr/local/bin/idprova not found. Run 02-push-binaries.sh first."
    exit 1
fi

# ── 2. Generate admin keypair ──────────────────────────────────────────────
mkdir -p "$KEYS_DIR"

echo "[1/4] Generating admin keypair..."
if [[ -f "$KEY_PATH" ]]; then
    echo "      WARN: admin-root.key already exists. Using existing key."
    echo "      Delete it first if you want to rotate: rm $KEY_PATH $PUB_PATH"
else
    idprova keygen --output "$KEY_PATH"
    echo "      Written: $KEY_PATH"
    echo "      Written: $PUB_PATH"
fi

# ── 3. Convert multibase pubkey to hex ─────────────────────────────────────
echo ""
echo "[2/4] Converting admin public key to hex..."

PUBKEY_MULTIBASE=$(cat "$PUB_PATH" | tr -d '[:space:]')
echo "      Multibase: $PUBKEY_MULTIBASE"

# Try CLI subcommand first
PUBKEY_HEX=""
if CLI_OUT=$(idprova pubkey-hex --key "$KEY_PATH" 2>/dev/null); then
    PUBKEY_HEX=$(echo "$CLI_OUT" | tr -d '[:space:]')
    echo "      Hex (via CLI): ${PUBKEY_HEX:0:8}..."
else
    # Fallback: decode base58btc multibase via python3
    echo "      pubkey-hex subcommand not available, decoding base58 manually..."

    if ! command -v python3 &>/dev/null; then
        echo "ERROR: python3 not found. Install it: apt install python3"
        exit 1
    fi

    PUBKEY_HEX=$(python3 - <<PYEOF
mb = "${PUBKEY_MULTIBASE}"
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
encoded = mb.lstrip('z')
n = 0
for c in encoded:
    n = n * 58 + B58_CHARS.index(c)
b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
# Skip 2-byte multicodec prefix (0xed01 for ed25519-pub), take last 32 bytes
b = b[-32:]
print(b.hex())
PYEOF
)
    echo "      Hex (decoded): ${PUBKEY_HEX:0:8}..."
fi

if [[ ${#PUBKEY_HEX} -ne 64 ]]; then
    echo "ERROR: Expected 32-byte (64 hex char) pubkey, got ${#PUBKEY_HEX} chars."
    echo "       Value: $PUBKEY_HEX"
    exit 1
fi

# ── 4. Write admin.env and push to registry ────────────────────────────────
echo ""
echo "[3/4] Writing admin.env and pushing to CT 401 ($REGISTRY_HOST)..."

ADMIN_ENV_CONTENT="REGISTRY_ADMIN_PUBKEY=$PUBKEY_HEX"
TMP_ENV=$(mktemp)
echo -n "$ADMIN_ENV_CONTENT" > "$TMP_ENV"

scp -o StrictHostKeyChecking=no "$TMP_ENV" "root@${REGISTRY_HOST}:/opt/idprova/keys/admin.env"
rm -f "$TMP_ENV"

ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
    "chmod 600 /opt/idprova/keys/admin.env && chown idprova:idprova /opt/idprova/keys/admin.env"

echo "      admin.env written: REGISTRY_ADMIN_PUBKEY=${PUBKEY_HEX:0:8}...[truncated]"

# ── 5. Start registry service ──────────────────────────────────────────────
echo ""
echo "[4/4] Starting idprova-registry on CT 401..."

ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
    "systemctl start idprova-registry && sleep 2 && systemctl is-active idprova-registry"

# Health check
echo "      Checking health endpoint..."
sleep 1

HEALTH=$(curl -sf "${REGISTRY_URL}/health" 2>&1 || true)
if [[ -n "$HEALTH" ]] && echo "$HEALTH" | grep -q '"status"'; then
    echo "      Health: $HEALTH"
    echo "      Registry is UP."
else
    echo "      WARNING: Health check failed or returned unexpected response."
    echo "      Check: ssh root@${REGISTRY_HOST} 'journalctl -u idprova-registry -n 20 --no-pager'"
fi

echo ""
echo "=== Admin setup complete ==="
echo ""
echo "Admin keypair location (on CT 402):"
echo "  Private: $KEY_PATH"
echo "  Public:  $PUB_PATH"
echo "  Hex pub: $PUBKEY_HEX"
echo ""
echo "Next: run 05-register-agents.sh"
