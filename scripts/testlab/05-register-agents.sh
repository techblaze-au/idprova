#!/usr/bin/env bash
# 05-register-agents.sh
# Run ON CT 402 (idp-admin) at 198.51.100.42.
# Generates keypairs for all agents, creates AID documents, registers them with
# the registry, and deploys key files to their respective containers.
# Bash equivalent of production/03-register-agents.ps1.
#
# Usage: pct exec 402 -- bash /root/05-register-agents.sh
#    or: ssh root@198.51.100.42 'bash -s' < scripts/testlab/05-register-agents.sh
# Prerequisites: 04-admin-setup.sh completed, registry is running.

set -euo pipefail

REGISTRY_HOST="198.51.100.41"
REGISTRY_URL="http://${REGISTRY_HOST}:4242"
KEYS_DIR="/root/.idprova/keys"
ADMIN_KEY="$KEYS_DIR/admin-root.key"
WORK_DIR=$(mktemp -d)

# Agent definitions: name, DID suffix, controller DID suffix, target host
declare -A AGENT_HOSTS=(
    ["orchestrator"]="198.51.100.43"
    ["worker-a"]="198.51.100.44"
    ["worker-b"]="198.51.100.45"
)
declare -A AGENT_NAMES=(
    ["orchestrator"]="Test Lab Orchestrator"
    ["worker-a"]="Test Lab Worker A"
    ["worker-b"]="Test Lab Worker B"
)
declare -A AGENT_CONTROLLERS=(
    ["orchestrator"]="admin"
    ["worker-a"]="orchestrator"
    ["worker-b"]="orchestrator"
)

echo "=== IDProva Test Lab: Agent Registration ==="
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Registry: $REGISTRY_URL"
echo "Date: $(date)"
echo ""

# ── Helper: multibase to hex ────────────────────────────────────────────────
multibase_to_hex() {
    local mb="$1"
    python3 - <<PYEOF
mb = "${mb}"
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
encoded = mb.lstrip('z')
n = 0
for c in encoded:
    n = n * 58 + B58_CHARS.index(c)
b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
b = b[-32:]
print(b.hex())
PYEOF
}

# ── Verify prerequisites ───────────────────────────────────────────────────
if [[ ! -x /usr/local/bin/idprova ]]; then
    echo "ERROR: /usr/local/bin/idprova not found."
    exit 1
fi

if [[ ! -f "$ADMIN_KEY" ]]; then
    echo "ERROR: Admin key not found: $ADMIN_KEY"
    echo "       Run 04-admin-setup.sh first."
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 required for base58 decoding. Install: apt install python3"
    exit 1
fi

# Verify registry is reachable
echo "Checking registry health..."
HEALTH=$(curl -sf "${REGISTRY_URL}/health" 2>&1 || true)
if [[ -z "$HEALTH" ]]; then
    echo "ERROR: Registry not reachable at $REGISTRY_URL"
    exit 1
fi
echo "      Registry: OK"
echo ""

# ── Step 1: Create admin AID and issue admin DAT ───────────────────────────
echo "[1/5] Creating admin AID and issuing admin DAT..."

cd "$WORK_DIR"

# Create admin AID document
idprova aid create \
    --id "did:aid:testlab.local:admin" \
    --name "Test Lab Admin" \
    --controller "did:aid:testlab.local:admin" \
    --key "$ADMIN_KEY"

# Find the generated AID file
ADMIN_AID_FILE=$(ls did_aid_testlab.local_admin*.json 2>/dev/null | head -1)
if [[ -z "$ADMIN_AID_FILE" ]]; then
    ADMIN_AID_FILE=$(ls *.json 2>/dev/null | grep -i admin | head -1)
fi
if [[ -z "$ADMIN_AID_FILE" ]]; then
    echo "ERROR: Could not find generated admin AID JSON file in $WORK_DIR"
    ls -la "$WORK_DIR"
    exit 1
fi
echo "      Admin AID file: $ADMIN_AID_FILE"

# Issue admin DAT for write operations (2h expiry)
ADMIN_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:admin" \
    --subject "did:aid:testlab.local:admin" \
    --scope "*:*:*:*" \
    --expires-in "2h" \
    --key "$ADMIN_KEY" 2>&1)

if [[ -z "$ADMIN_DAT" ]]; then
    echo "ERROR: Failed to issue admin DAT."
    exit 1
fi
ADMIN_DAT=$(echo "$ADMIN_DAT" | tr -d '[:space:]')
echo "      Admin DAT issued (2h expiry, ${#ADMIN_DAT} chars)"

# Register admin AID
echo "      Registering: did:aid:testlab.local:admin"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "${REGISTRY_URL}/v1/aid/testlab.local:admin" \
    -H "Authorization: Bearer $ADMIN_DAT" \
    -H "Content-Type: application/json" \
    -d @"$ADMIN_AID_FILE")

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
    echo "      Admin AID registered (HTTP $HTTP_CODE)"
else
    echo "ERROR: Failed to register admin AID (HTTP $HTTP_CODE)"
    # Show response body for debugging
    curl -s -X PUT "${REGISTRY_URL}/v1/aid/testlab.local:admin" \
        -H "Authorization: Bearer $ADMIN_DAT" \
        -H "Content-Type: application/json" \
        -d @"$ADMIN_AID_FILE"
    echo ""
    exit 1
fi
rm -f "$ADMIN_AID_FILE"

# ── Step 2-4: Generate keypairs and register each agent ─────────────────────
STEP=2
for agent in orchestrator worker-a worker-b; do
    echo ""
    echo "[$STEP/5] Generating keypair and registering: $agent"

    agent_key="$KEYS_DIR/${agent}.key"
    agent_pub="$KEYS_DIR/${agent}.pub"
    agent_host="${AGENT_HOSTS[$agent]}"
    agent_name="${AGENT_NAMES[$agent]}"
    agent_controller="did:aid:testlab.local:${AGENT_CONTROLLERS[$agent]}"

    # Generate keypair
    if [[ -f "$agent_key" ]]; then
        echo "      WARN: ${agent}.key exists, using existing key."
    else
        idprova keygen --output "$agent_key"
        echo "      Keypair generated: $agent_key"
    fi

    # Read pubkey for verification
    agent_pub_multibase=$(cat "$agent_pub" | tr -d '[:space:]')
    agent_pub_hex=$(multibase_to_hex "$agent_pub_multibase")
    echo "      Pubkey hex: ${agent_pub_hex:0:8}..."

    # Create AID document
    cd "$WORK_DIR"
    idprova aid create \
        --id "did:aid:testlab.local:${agent}" \
        --name "$agent_name" \
        --controller "$agent_controller" \
        --key "$agent_key"

    # Find generated file
    AID_FILE=$(ls did_aid_testlab.local_${agent}*.json 2>/dev/null | head -1)
    if [[ -z "$AID_FILE" ]]; then
        AID_FILE=$(ls *.json 2>/dev/null | grep -i "${agent}" | head -1)
    fi
    if [[ -z "$AID_FILE" ]]; then
        echo "ERROR: Could not find generated AID JSON file for $agent"
        ls -la "$WORK_DIR"
        exit 1
    fi

    # Register with registry
    echo "      Registering: did:aid:testlab.local:${agent}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${REGISTRY_URL}/v1/aid/testlab.local:${agent}" \
        -H "Authorization: Bearer $ADMIN_DAT" \
        -H "Content-Type: application/json" \
        -d @"$AID_FILE")

    if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
        echo "      Registered (HTTP $HTTP_CODE)"
    else
        echo "ERROR: Failed to register $agent AID (HTTP $HTTP_CODE)"
        curl -s -X PUT "${REGISTRY_URL}/v1/aid/testlab.local:${agent}" \
            -H "Authorization: Bearer $ADMIN_DAT" \
            -H "Content-Type: application/json" \
            -d @"$AID_FILE"
        echo ""
        exit 1
    fi
    rm -f "$AID_FILE"

    # Deploy key to target container
    echo "      Deploying key to $agent_host..."
    ssh -o StrictHostKeyChecking=no "root@${agent_host}" "mkdir -p /root/.idprova/keys"
    scp -o StrictHostKeyChecking=no "$agent_key" "root@${agent_host}:/root/.idprova/keys/machine.key"
    ssh -o StrictHostKeyChecking=no "root@${agent_host}" "chmod 600 /root/.idprova/keys/machine.key"
    echo "      Key deployed to $agent ($agent_host)"

    STEP=$((STEP + 1))
done

# ── Step 5: Verify registrations ───────────────────────────────────────────
echo ""
echo "[5/5] Verifying registrations..."

for agent in admin orchestrator worker-a worker-b; do
    RESP=$(curl -sf "${REGISTRY_URL}/v1/aid/testlab.local:${agent}" 2>&1 || true)
    if echo "$RESP" | grep -q "did:aid:testlab.local:${agent}"; then
        echo "      did:aid:testlab.local:${agent} [OK]"
    else
        echo "      did:aid:testlab.local:${agent} [FAIL]"
        echo "      Response: $RESP"
    fi
done

# ── Cleanup ─────────────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"

echo ""
echo "=== Agent registration complete ==="
echo ""
echo "Key files on CT 402 ($KEYS_DIR):"
ls -la "$KEYS_DIR/"
echo ""
echo "Next: run 06-issue-dats.sh"
