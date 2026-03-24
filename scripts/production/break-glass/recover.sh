#!/usr/bin/env bash
# break-glass/recover.sh
# Run ON R710 via: ssh root@198.51.100.12 'bash -s' < scripts/production/break-glass/recover.sh
#
# Stops idprova-registry, swaps admin.env to a break-glass public key, restarts.
# After recovery, re-issue main admin keypair and restore normal admin.env.
#
# EDIT BEFORE RUNNING:
#   Set BG_PUBKEY_FILE to either bg-a.pub or bg-b.pub depending on which
#   break-glass key you are using. Or set BG_PUBKEY_HEX directly.

set -euo pipefail

# ── CONFIGURATION — edit these before running ─────────────────────────────────
BG_PUBKEY_FILE="/opt/idprova/keys/bg-a.pub"   # or bg-b.pub
BG_PUBKEY_HEX=""   # set this directly if you have the hex, otherwise leave empty

# ──────────────────────────────────────────────────────────────────────────────

echo "=== IDProva Break-Glass Recovery ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""

# ── Determine pubkey ──────────────────────────────────────────────────────────
if [[ -n "$BG_PUBKEY_HEX" ]]; then
    PUBKEY_HEX="$BG_PUBKEY_HEX"
    echo "[1/4] Using provided hex pubkey: ${PUBKEY_HEX:0:8}..."
elif [[ -f "$BG_PUBKEY_FILE" ]]; then
    PUBKEY_MULTIBASE=$(cat "$BG_PUBKEY_FILE")
    echo "[1/4] Found pubkey file: $BG_PUBKEY_FILE"
    echo "      Multibase: $PUBKEY_MULTIBASE"
    # For the registry, provide the multibase value directly if supported,
    # or convert to hex. The conversion here uses python3 (usually available).
    if command -v python3 &>/dev/null; then
        PUBKEY_HEX=$(python3 - <<EOF
import base64, sys
mb = "$PUBKEY_MULTIBASE"
# z prefix = base58btc
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
encoded = mb.lstrip('z')
n = 0
for c in encoded:
    n = n * 58 + B58_CHARS.index(c)
b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
# Take last 32 bytes
b = b[-32:]
print(b.hex())
EOF
)
        echo "      Hex: ${PUBKEY_HEX:0:8}..."
    else
        echo "ERROR: python3 not found for base58 decoding."
        echo "       Set BG_PUBKEY_HEX directly in this script."
        exit 1
    fi
else
    echo "ERROR: Neither BG_PUBKEY_HEX nor BG_PUBKEY_FILE is set/found."
    echo "       Edit BG_PUBKEY_FILE or BG_PUBKEY_HEX at the top of this script."
    exit 1
fi

# ── Backup current admin.env ──────────────────────────────────────────────────
echo ""
echo "[2/4] Backing up current admin.env..."
BACKUP="/opt/idprova/keys/admin.env.bak.$(date +%Y%m%d-%H%M%S)"
cp /opt/idprova/keys/admin.env "$BACKUP"
echo "      Backed up to: $BACKUP"

# ── Stop registry ─────────────────────────────────────────────────────────────
echo ""
echo "[3/4] Stopping idprova-registry..."
systemctl stop idprova-registry
echo "      Stopped."

# ── Swap admin.env ────────────────────────────────────────────────────────────
echo "      Writing break-glass pubkey to admin.env..."
echo "REGISTRY_ADMIN_PUBKEY=$PUBKEY_HEX" > /opt/idprova/keys/admin.env
chmod 600 /opt/idprova/keys/admin.env
chown idprova:idprova /opt/idprova/keys/admin.env

# ── Start registry ────────────────────────────────────────────────────────────
echo ""
echo "[4/4] Starting idprova-registry with break-glass key..."
systemctl start idprova-registry
sleep 2

if systemctl is-active --quiet idprova-registry; then
    echo "      idprova-registry is ACTIVE"
else
    echo "ERROR: Registry failed to start."
    echo "       Check: journalctl -u idprova-registry -n 30 --no-pager"
    exit 1
fi

# Health check
HEALTH=$(curl -s http://localhost:4242/health 2>&1 || true)
echo "      Health: $HEALTH"

if echo "$HEALTH" | grep -q '"status"'; then
    echo ""
    echo "=== Break-glass recovery: REGISTRY IS UP ==="
    echo ""
    echo "NEXT STEPS (from Windows dev machine):"
    echo ""
    echo "  1. Issue admin DAT with break-glass private key:"
    echo "     .\\target\\release\\idprova.exe dat issue \\"
    echo "         --issuer did:aid:admin-root \\"
    echo "         --subject did:aid:admin-root \\"
    echo "         --scope '*:*:*:*' \\"
    echo "         --expires-in 2h \\"
    echo "         --key <path/to/bg-key.key>"
    echo ""
    echo "  2. Use that DAT to re-register agents and issue new main admin keypair."
    echo ""
    echo "  3. Once recovered, restore admin.env:"
    echo "     scp demo-keys\\production\\admin-root.pub root@198.51.100.12:/tmp/new-admin.pub"
    echo "     ssh root@198.51.100.12 '(on R710):"
    echo "       echo REGISTRY_ADMIN_PUBKEY=\$(cat /tmp/new-admin.pub) > /opt/idprova/keys/admin.env"
    echo "       chmod 600 /opt/idprova/keys/admin.env"
    echo "       systemctl restart idprova-registry'"
    echo ""
    echo "  4. Delete any temp key files immediately after use."
    echo ""
    echo "Backup of previous admin.env: $BACKUP"
else
    echo "WARNING: Health check returned unexpected response."
    echo "         Check: journalctl -u idprova-registry -n 20 --no-pager"
fi
