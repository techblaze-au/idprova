#!/usr/bin/env bash
# 06-issue-dats.sh
# Run ON CT 402 (idp-admin) at 192.168.8.142.
# Issues DATs in a delegation chain: admin -> orchestrator -> worker-a -> worker-b.
# Each level narrows scope. DATs are deployed to their respective containers.
#
# Usage: pct exec 402 -- bash /root/06-issue-dats.sh
#    or: ssh root@192.168.8.142 'bash -s' < scripts/testlab/06-issue-dats.sh
# Prerequisites: 05-register-agents.sh completed.

set -euo pipefail

REGISTRY_HOST="192.168.8.141"
REGISTRY_URL="http://${REGISTRY_HOST}:4242"
MCP_URL="http://${REGISTRY_HOST}:3001"
KEYS_DIR="/root/.idprova/keys"
ADMIN_KEY="$KEYS_DIR/admin-root.key"

ORCH_HOST="192.168.8.143"
WORKER_A_HOST="192.168.8.144"
WORKER_B_HOST="192.168.8.145"

echo "=== IDProva Test Lab: DAT Issuance ==="
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Registry: $REGISTRY_URL"
echo "Date: $(date)"
echo ""

# ── Verify prerequisites ───────────────────────────────────────────────────
for f in "$ADMIN_KEY" "$KEYS_DIR/orchestrator.key" "$KEYS_DIR/worker-a.key"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Key not found: $f"
        echo "       Run 05-register-agents.sh first."
        exit 1
    fi
done

# ── Step 1: Admin issues DAT for orchestrator (7 days, full MCP scope) ─────
echo "[1/4] Issuing DAT: admin -> orchestrator (7d, mcp:tool:*:call)..."

ORCH_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:admin" \
    --subject "did:aid:testlab.local:orchestrator" \
    --scope "mcp:tool:*:call" \
    --expires-in "168h" \
    --key "$ADMIN_KEY" 2>&1)

ORCH_DAT=$(echo "$ORCH_DAT" | tr -d '[:space:]')
if [[ -z "$ORCH_DAT" ]]; then
    echo "ERROR: Failed to issue orchestrator DAT."
    exit 1
fi
echo "      DAT issued (${#ORCH_DAT} chars)"

# Deploy to orchestrator
TMP_DAT=$(mktemp)
echo -n "$ORCH_DAT" > "$TMP_DAT"
ssh -o StrictHostKeyChecking=no "root@${ORCH_HOST}" "mkdir -p /root/.idprova"
scp -o StrictHostKeyChecking=no "$TMP_DAT" "root@${ORCH_HOST}:/root/.idprova/current-dat.txt"
ssh -o StrictHostKeyChecking=no "root@${ORCH_HOST}" "chmod 600 /root/.idprova/current-dat.txt"
rm -f "$TMP_DAT"
echo "      Deployed to CT 403 ($ORCH_HOST):/root/.idprova/current-dat.txt"

# ── Step 2: Orchestrator issues sub-DAT for worker-a (narrowed scope) ──────
echo ""
echo "[2/4] Issuing sub-DAT: orchestrator -> worker-a (7d, echo+calculate)..."

# We issue from CT 402 using the orchestrator's key (which we have here)
WORKER_A_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:orchestrator" \
    --subject "did:aid:testlab.local:worker-a" \
    --scope "mcp:tool:echo:call,mcp:tool:calculate:call" \
    --expires-in "168h" \
    --parent "$ORCH_DAT" \
    --key "$KEYS_DIR/orchestrator.key" 2>&1)

WORKER_A_DAT=$(echo "$WORKER_A_DAT" | tr -d '[:space:]')
if [[ -z "$WORKER_A_DAT" ]]; then
    echo "ERROR: Failed to issue worker-a DAT."
    exit 1
fi
echo "      Sub-DAT issued (${#WORKER_A_DAT} chars)"
echo "      Scope: mcp:tool:echo:call,mcp:tool:calculate:call"

# Deploy to worker-a
TMP_DAT=$(mktemp)
echo -n "$WORKER_A_DAT" > "$TMP_DAT"
ssh -o StrictHostKeyChecking=no "root@${WORKER_A_HOST}" "mkdir -p /root/.idprova"
scp -o StrictHostKeyChecking=no "$TMP_DAT" "root@${WORKER_A_HOST}:/root/.idprova/current-dat.txt"
ssh -o StrictHostKeyChecking=no "root@${WORKER_A_HOST}" "chmod 600 /root/.idprova/current-dat.txt"
rm -f "$TMP_DAT"
echo "      Deployed to CT 404 ($WORKER_A_HOST):/root/.idprova/current-dat.txt"

# ── Step 3: Worker-a issues sub-sub-DAT for worker-b (narrowest scope) ─────
echo ""
echo "[3/4] Issuing sub-sub-DAT: worker-a -> worker-b (7d, echo only)..."

WORKER_B_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:worker-a" \
    --subject "did:aid:testlab.local:worker-b" \
    --scope "mcp:tool:echo:call" \
    --expires-in "168h" \
    --parent "$WORKER_A_DAT" \
    --key "$KEYS_DIR/worker-a.key" 2>&1)

WORKER_B_DAT=$(echo "$WORKER_B_DAT" | tr -d '[:space:]')
if [[ -z "$WORKER_B_DAT" ]]; then
    echo "ERROR: Failed to issue worker-b DAT."
    exit 1
fi
echo "      Sub-sub-DAT issued (${#WORKER_B_DAT} chars)"
echo "      Scope: mcp:tool:echo:call"

# Deploy to worker-b
TMP_DAT=$(mktemp)
echo -n "$WORKER_B_DAT" > "$TMP_DAT"
ssh -o StrictHostKeyChecking=no "root@${WORKER_B_HOST}" "mkdir -p /root/.idprova"
scp -o StrictHostKeyChecking=no "$TMP_DAT" "root@${WORKER_B_HOST}:/root/.idprova/current-dat.txt"
ssh -o StrictHostKeyChecking=no "root@${WORKER_B_HOST}" "chmod 600 /root/.idprova/current-dat.txt"
rm -f "$TMP_DAT"
echo "      Deployed to CT 405 ($WORKER_B_HOST):/root/.idprova/current-dat.txt"

# ── Step 4: Start MCP service and verify ────────────────────────────────────
echo ""
echo "[4/4] Starting MCP service and verifying DAT chain..."

ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
    "systemctl start idprova-mcp && sleep 2 && systemctl is-active idprova-mcp"

# Quick verification: orchestrator calls echo
echo ""
echo "Verifying orchestrator can call MCP echo..."
RESP=$(curl -sf -X POST "$MCP_URL/" \
    -H "Authorization: Bearer $ORCH_DAT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"DAT chain test from orchestrator"}}}' 2>&1 || true)

if echo "$RESP" | grep -q "DAT chain test"; then
    echo "      Orchestrator MCP call: OK"
else
    echo "      WARNING: Unexpected response: $RESP"
fi

# Verify worker-a can call echo
echo "Verifying worker-a can call MCP echo..."
RESP=$(ssh -o StrictHostKeyChecking=no "root@${WORKER_A_HOST}" \
    "curl -sf -X POST ${MCP_URL}/ \
     -H 'Authorization: Bearer \$(cat /root/.idprova/current-dat.txt)' \
     -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"DAT test from worker-a\"}}}'" 2>&1 || true)

if echo "$RESP" | grep -q "DAT test from worker-a"; then
    echo "      Worker-a MCP call: OK"
else
    echo "      WARNING: Unexpected response: $RESP"
fi

echo ""
echo "=== DAT issuance complete ==="
echo ""
echo "Delegation chain:"
echo "  admin (168h, *:*:*:*)"
echo "    -> orchestrator (168h, mcp:tool:*:call)"
echo "       -> worker-a (168h, mcp:tool:echo:call,mcp:tool:calculate:call)"
echo "          -> worker-b (168h, mcp:tool:echo:call)"
echo ""
echo "Next: run 07-break-glass-setup.sh, then 08-run-scenarios.sh"
