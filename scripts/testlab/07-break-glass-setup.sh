#!/usr/bin/env bash
# 07-break-glass-setup.sh
# Run ON CT 402 (idp-admin) at 198.51.100.42.
# Generates BG-A and BG-B break-glass keypairs, uploads public keys to CT 401,
# and deploys the recovery script.
#
# Usage: pct exec 402 -- bash /root/07-break-glass-setup.sh
#    or: ssh root@198.51.100.42 'bash -s' < scripts/testlab/07-break-glass-setup.sh
# Prerequisites: 04-admin-setup.sh completed, registry running on CT 401.

set -euo pipefail

REGISTRY_HOST="198.51.100.41"
KEYS_DIR="/root/.idprova/keys"
BG_DIR="$KEYS_DIR/break-glass"

echo "=== IDProva Test Lab: Break-Glass Setup ==="
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Date: $(date)"
echo ""
echo "NOTE: In a real deployment, private keys would be stored offline."
echo "      For testing, they remain on CT 402."
echo ""

# ── Verify binary ──────────────────────────────────────────────────────────
if [[ ! -x /usr/local/bin/idprova ]]; then
    echo "ERROR: /usr/local/bin/idprova not found."
    exit 1
fi

mkdir -p "$BG_DIR"

# ── 1. Generate BG-A keypair ───────────────────────────────────────────────
echo "[1/4] Generating Break-Glass A keypair..."

BGA_KEY="$BG_DIR/bg-a.key"
BGA_PUB="$BG_DIR/bg-a.pub"

if [[ -f "$BGA_KEY" ]]; then
    echo "      WARN: bg-a.key exists. Using existing key."
else
    idprova keygen --output "$BGA_KEY"
fi

BGA_PRIV_HEX=$(cat "$BGA_KEY" | tr -d '[:space:]')
BGA_PUB_MULTIBASE=$(cat "$BGA_PUB" | tr -d '[:space:]')
echo "      BG-A pubkey: $BGA_PUB_MULTIBASE"

# ── 2. Generate BG-B keypair ───────────────────────────────────────────────
echo ""
echo "[2/4] Generating Break-Glass B keypair..."

BGB_KEY="$BG_DIR/bg-b.key"
BGB_PUB="$BG_DIR/bg-b.pub"

if [[ -f "$BGB_KEY" ]]; then
    echo "      WARN: bg-b.key exists. Using existing key."
else
    idprova keygen --output "$BGB_KEY"
fi

BGB_PRIV_HEX=$(cat "$BGB_KEY" | tr -d '[:space:]')
BGB_PUB_MULTIBASE=$(cat "$BGB_PUB" | tr -d '[:space:]')
echo "      BG-B pubkey: $BGB_PUB_MULTIBASE"

# ── 3. Upload public keys to CT 401 ────────────────────────────────────────
echo ""
echo "[3/4] Uploading public keys to CT 401 ($REGISTRY_HOST)..."

scp -o StrictHostKeyChecking=no "$BGA_PUB" "root@${REGISTRY_HOST}:/opt/idprova/keys/bg-a.pub"
scp -o StrictHostKeyChecking=no "$BGB_PUB" "root@${REGISTRY_HOST}:/opt/idprova/keys/bg-b.pub"
ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
    "chmod 644 /opt/idprova/keys/bg-a.pub /opt/idprova/keys/bg-b.pub && \
     chown idprova:idprova /opt/idprova/keys/bg-a.pub /opt/idprova/keys/bg-b.pub"
echo "      Public keys deployed."

# Deploy recovery script to CT 401
echo "      Deploying recover.sh to CT 401..."

cat > /tmp/recover.sh << 'RECOVER_SCRIPT'
#!/usr/bin/env bash
# recover.sh — break-glass recovery for test lab
# Run ON CT 401: bash /opt/idprova/keys/recover.sh
#
# EDIT BEFORE RUNNING:
#   Set BG_PUBKEY_FILE to either bg-a.pub or bg-b.pub

set -euo pipefail

BG_PUBKEY_FILE="/opt/idprova/keys/bg-a.pub"
BG_PUBKEY_HEX=""

echo "=== IDProva Break-Glass Recovery ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""

# Determine pubkey
if [[ -n "$BG_PUBKEY_HEX" ]]; then
    PUBKEY_HEX="$BG_PUBKEY_HEX"
    echo "[1/4] Using provided hex pubkey: ${PUBKEY_HEX:0:8}..."
elif [[ -f "$BG_PUBKEY_FILE" ]]; then
    PUBKEY_MULTIBASE=$(cat "$BG_PUBKEY_FILE")
    echo "[1/4] Found pubkey file: $BG_PUBKEY_FILE"
    echo "      Multibase: $PUBKEY_MULTIBASE"

    if command -v python3 &>/dev/null; then
        PUBKEY_HEX=$(python3 - <<PYEOF
mb = "${PUBKEY_MULTIBASE}"
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
encoded = mb.lstrip('z')
n = 0
for c in encoded:
    n = n * 58 + B58_CHARS.index(c)
b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
b = b[-32:]
print(b.hex())
PYEOF
)
        echo "      Hex: ${PUBKEY_HEX:0:8}..."
    else
        echo "ERROR: python3 not found for base58 decoding."
        echo "       Set BG_PUBKEY_HEX directly in this script."
        exit 1
    fi
else
    echo "ERROR: Neither BG_PUBKEY_HEX nor BG_PUBKEY_FILE is set/found."
    exit 1
fi

# Backup current admin.env
echo ""
echo "[2/4] Backing up current admin.env..."
BACKUP="/opt/idprova/keys/admin.env.bak.$(date +%Y%m%d-%H%M%S)"
if [[ -f /opt/idprova/keys/admin.env ]]; then
    cp /opt/idprova/keys/admin.env "$BACKUP"
    echo "      Backed up to: $BACKUP"
else
    echo "      No existing admin.env to back up."
fi

# Stop registry
echo ""
echo "[3/4] Stopping idprova-registry..."
systemctl stop idprova-registry || true
echo "      Stopped."

# Swap admin.env
echo "      Writing break-glass pubkey to admin.env..."
echo "REGISTRY_ADMIN_PUBKEY=$PUBKEY_HEX" > /opt/idprova/keys/admin.env
chmod 600 /opt/idprova/keys/admin.env
chown idprova:idprova /opt/idprova/keys/admin.env

# Start registry
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

HEALTH=$(curl -s http://localhost:4242/health 2>&1 || true)
echo "      Health: $HEALTH"

echo ""
echo "=== Break-glass recovery complete ==="
echo "Registry is running with break-glass key."
echo "Issue new admin DAT with the BG private key to regain full control."
echo "Previous admin.env: $BACKUP"
RECOVER_SCRIPT

scp -o StrictHostKeyChecking=no /tmp/recover.sh "root@${REGISTRY_HOST}:/opt/idprova/keys/recover.sh"
ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" "chmod 755 /opt/idprova/keys/recover.sh"
rm -f /tmp/recover.sh
echo "      recover.sh deployed to CT 401."

# ── 4. Write BREAK-GLASS.txt on CT 401 ─────────────────────────────────────
echo ""
echo "[4/4] Writing BREAK-GLASS.txt to CT 401..."

cat > /tmp/BREAK-GLASS.txt << EOF
IDProva Test Lab — Break-Glass Recovery Procedure
===================================================
Written: $(date '+%Y-%m-%d %H:%M:%S')

If locked out (admin key lost or service failing):

OPTION A — Use Break-Glass Key A:
  1. SSH to CT 401: ssh root@198.51.100.41
  2. Run: bash /opt/idprova/keys/recover.sh
     (defaults to bg-a.pub)
  3. From CT 402: issue admin DAT with BG-A private key:
     idprova dat issue --issuer did:aid:testlab.local:admin \\
       --subject did:aid:testlab.local:admin --scope '*:*:*:*' \\
       --expires-in 2h --key /root/.idprova/keys/break-glass/bg-a.key
  4. Use that DAT to re-register agents and issue new admin keypair.

OPTION B — Use Break-Glass Key B:
  1. Edit recover.sh: set BG_PUBKEY_FILE="/opt/idprova/keys/bg-b.pub"
  2. Same procedure as Option A but with bg-b.key

BREAK-GLASS PUBLIC KEYS:
BG-A pubkey (multibase): $BGA_PUB_MULTIBASE
BG-B pubkey (multibase): $BGB_PUB_MULTIBASE
EOF

scp -o StrictHostKeyChecking=no /tmp/BREAK-GLASS.txt "root@${REGISTRY_HOST}:/opt/idprova/keys/BREAK-GLASS.txt"
ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
    "chmod 640 /opt/idprova/keys/BREAK-GLASS.txt && chown root:idprova /opt/idprova/keys/BREAK-GLASS.txt"
rm -f /tmp/BREAK-GLASS.txt
echo "      BREAK-GLASS.txt deployed."

echo ""
echo "=== Break-glass setup complete ==="
echo ""
echo "Break-glass keys on CT 402:"
echo "  BG-A private: $BGA_KEY"
echo "  BG-A public:  $BGA_PUB"
echo "  BG-B private: $BGB_KEY"
echo "  BG-B public:  $BGB_PUB"
echo ""
echo "Public keys deployed to CT 401: /opt/idprova/keys/bg-{a,b}.pub"
echo "Recovery script: /opt/idprova/keys/recover.sh"
echo ""
echo "Next: run 08-run-scenarios.sh"
