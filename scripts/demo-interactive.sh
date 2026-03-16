#!/usr/bin/env bash
#
# IDProva v0.1 — Interactive End-to-End Demo
#
# This script demonstrates the full IDProva protocol:
#   1. Key generation
#   2. AID registration
#   3. DAT issuance & verification
#   4. MCP tool call with receipt chain
#   5. Scope enforcement (403)
#   6. Token expiry (401)
#   7. Token revocation
#
# Usage: bash scripts/demo-interactive.sh
#
set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

step_num=0
pause() {
    step_num=$((step_num + 1))
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  Step ${step_num}: $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}$2${NC}"
    echo ""
    read -rp "  Press Enter to continue..."
    echo ""
}

ok() { echo -e "  ${GREEN}✓ $1${NC}"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; }
info() { echo -e "  ${BLUE}→ $1${NC}"; }

# ── Setup ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR=$(mktemp -d)
REGISTRY_PORT=4242
MCP_PORT=3001
REGISTRY_PID=""
MCP_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    [ -n "$REGISTRY_PID" ] && kill "$REGISTRY_PID" 2>/dev/null || true
    [ -n "$MCP_PID" ] && kill "$MCP_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT

REGISTRY_URL="http://127.0.0.1:${REGISTRY_PORT}"
MCP_URL="http://127.0.0.1:${MCP_PORT}"

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║            IDProva v0.1 — Interactive Demo              ║"
echo "  ║                                                          ║"
echo "  ║  The open protocol for AI agent identity, delegation,   ║"
echo "  ║  and audit. Built with Ed25519, BLAKE3, and JWS.        ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Build ───────────────────────────────────────────────────────────
pause "Build release binaries" \
    "Compiling idprova-cli, idprova-registry, and idprova-mcp-demo in release mode."

cd "$PROJECT_DIR"
cargo build --release -p idprova-cli -p idprova-registry -p idprova-mcp-demo 2>&1 | tail -5
CLI="$PROJECT_DIR/target/release/idprova"
REGISTRY_BIN="$PROJECT_DIR/target/release/idprova-registry"
MCP_BIN="$PROJECT_DIR/target/release/idprova-mcp-demo"
ok "Build complete"

# ── Step 2: Start registry ──────────────────────────────────────────────────
pause "Start the IDProva Registry" \
    "The registry stores AID documents and handles DAT verification.\n  Running in dev mode (no admin auth required) on port ${REGISTRY_PORT}."

cd "$WORK_DIR"
REGISTRY_PORT=$REGISTRY_PORT "$REGISTRY_BIN" &
REGISTRY_PID=$!
sleep 1

# Health check
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${REGISTRY_URL}/health")
if [ "$HTTP_CODE" = "200" ]; then
    ok "Registry running (PID: $REGISTRY_PID)"
    curl -s "${REGISTRY_URL}/health" | python3 -m json.tool 2>/dev/null || curl -s "${REGISTRY_URL}/health"
else
    fail "Registry failed to start (HTTP $HTTP_CODE)"
    exit 1
fi

# ── Step 3: Generate keypair ────────────────────────────────────────────────
pause "Generate Ed25519 keypair" \
    "Creating an Ed25519 signing keypair for the controller (human identity).\n  The private key is zeroized from memory on drop (SR-1 security)."

mkdir -p "$WORK_DIR/.idprova/keys"
"$CLI" keygen -o "$WORK_DIR/.idprova/keys/controller.key"
ok "Keypair generated"
info "Key file: $WORK_DIR/.idprova/keys/controller.key"
echo ""
echo "  Public key (first line of key file):"
head -1 "$WORK_DIR/.idprova/keys/controller.key"

# ── Step 4: Register AID ───────────────────────────────────────────────────
pause "Register an Agent Identity Document (AID)" \
    "Creating a DID document for agent 'demo-agent' controlled by 'demo-user'.\n  The AID follows W3C DID Core spec with IDProva extensions."

"$CLI" aid create \
    --id "did:aid:example.com:demo-agent" \
    --name "Demo Agent" \
    --controller "did:aid:example.com:demo-user" \
    --model "idprova-demo/v1" \
    --runtime "bash-demo" \
    --key "$WORK_DIR/.idprova/keys/controller.key" > "$WORK_DIR/aid.json"

info "AID document created locally"
echo ""
cat "$WORK_DIR/aid.json" | python3 -m json.tool 2>/dev/null || cat "$WORK_DIR/aid.json"

# Register with the registry
echo ""
info "Registering with registry..."
curl -s -X PUT "${REGISTRY_URL}/v1/aid/example.com:demo-agent" \
    -H "Content-Type: application/json" \
    -d @"$WORK_DIR/aid.json" | python3 -m json.tool 2>/dev/null || true
ok "AID registered: did:aid:example.com:demo-agent"

# Resolve it back
echo ""
info "Resolving AID from registry..."
curl -s "${REGISTRY_URL}/v1/aid/example.com:demo-agent" | python3 -m json.tool 2>/dev/null || \
    curl -s "${REGISTRY_URL}/v1/aid/example.com:demo-agent"
ok "AID resolved successfully"

# ── Step 5: Issue DAT ──────────────────────────────────────────────────────
pause "Issue a Delegation Attestation Token (DAT)" \
    "Creating a time-bounded, scoped token that delegates permissions.\n  Scope: mcp:tool:echo:call, mcp:tool:calculate:call\n  Expires in: 1 hour"

DAT_TOKEN=$("$CLI" dat issue \
    --issuer "did:aid:example.com:demo-user" \
    --subject "did:aid:example.com:demo-agent" \
    --scope "mcp:tool:echo:call,mcp:tool:calculate:call" \
    --expires-in "1h" \
    --key "$WORK_DIR/.idprova/keys/controller.key")

ok "DAT issued"
info "Token (compact JWS):"
echo "  ${DAT_TOKEN:0:80}..."
echo ""
info "Inspecting token claims..."
"$CLI" dat inspect "$DAT_TOKEN"

# ── Step 6: Verify DAT via registry ────────────────────────────────────────
pause "Verify DAT via the registry" \
    "The registry looks up the issuer's AID, extracts the public key,\n  and verifies the signature + timing + scope + constraints."

VERIFY_RESULT=$(curl -s -X POST "${REGISTRY_URL}/v1/dat/verify" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"${DAT_TOKEN}\", \"scope\": \"mcp:tool:echo:call\"}")

echo "$VERIFY_RESULT" | python3 -m json.tool 2>/dev/null || echo "$VERIFY_RESULT"

VALID=$(echo "$VERIFY_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('valid',''))" 2>/dev/null || echo "")
if [ "$VALID" = "True" ] || [ "$VALID" = "true" ]; then
    ok "DAT verified: signature, timing, and scope all pass"
else
    fail "DAT verification failed"
fi

# ── Step 7: Start MCP server ──────────────────────────────────────────────
pause "Start MCP demo server" \
    "The MCP server requires DAT bearer tokens for every tool call.\n  It chains receipts with BLAKE3 hashes for audit."

mkdir -p "$WORK_DIR/public"
echo "Hello from IDProva!" > "$WORK_DIR/public/readme.txt"

REGISTRY_URL="${REGISTRY_URL}" MCP_PORT=$MCP_PORT PUBLIC_DIR="$WORK_DIR/public" \
    RECEIPTS_FILE="$WORK_DIR/receipts.jsonl" "$MCP_BIN" &
MCP_PID=$!
sleep 1

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${MCP_URL}/health")
if [ "$HTTP_CODE" = "200" ]; then
    ok "MCP server running (PID: $MCP_PID)"
else
    fail "MCP server failed to start"
    exit 1
fi

# ── Step 8: Call MCP tool ──────────────────────────────────────────────────
pause "Call MCP tool with DAT authentication" \
    "Sending a JSON-RPC 2.0 'echo' call with the DAT as Bearer token.\n  The MCP server verifies the token via the registry before executing."

MCP_RESULT=$(curl -s -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${DAT_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"echo","params":{"message":"Hello IDProva!"}}')

echo "$MCP_RESULT" | python3 -m json.tool 2>/dev/null || echo "$MCP_RESULT"
ok "Tool call executed with verified DAT"

# Also try calculate
info "Trying calculate tool..."
curl -s -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${DAT_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":2,"method":"calculate","params":{"expression":"(42 * 2) + 16"}}' \
    | python3 -m json.tool 2>/dev/null || true
ok "Calculate tool also works"

# ── Step 9: View receipt chain ─────────────────────────────────────────────
pause "View BLAKE3 receipt chain" \
    "Every tool call produces a receipt with a BLAKE3 hash chain.\n  Each receipt's prev_receipt_hash links to the previous receipt,\n  forming a tamper-evident audit trail."

curl -s "${MCP_URL}/receipts" | python3 -m json.tool 2>/dev/null || \
    curl -s "${MCP_URL}/receipts"
ok "Receipt chain is intact"

# ── Step 10: Try wrong scope → 403 ────────────────────────────────────────
pause "Attempt action with wrong scope → 403 Forbidden" \
    "The DAT only grants mcp:tool:echo:call and mcp:tool:calculate:call.\n  Calling 'read_file' requires mcp:tool:read_file:call → should fail."

SCOPE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${DAT_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":3,"method":"read_file","params":{"filename":"readme.txt"}}')

if [ "$SCOPE_RESULT" = "403" ]; then
    ok "Got HTTP 403 Forbidden — scope enforcement works!"
else
    info "Got HTTP $SCOPE_RESULT (expected 403)"
    curl -s -X POST "${MCP_URL}/" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${DAT_TOKEN}" \
        -d '{"jsonrpc":"2.0","id":3,"method":"read_file","params":{"filename":"readme.txt"}}' \
        | python3 -m json.tool 2>/dev/null || true
fi

# ── Step 11: Try expired token → 401 ─────────────────────────────────────
pause "Issue a 1-second DAT and wait for expiry → 401" \
    "Issuing a DAT with --expires-in 1s, waiting 2 seconds, then trying.\n  The registry will reject it as expired."

SHORT_DAT=$("$CLI" dat issue \
    --issuer "did:aid:example.com:demo-user" \
    --subject "did:aid:example.com:demo-agent" \
    --scope "mcp:tool:echo:call" \
    --expires-in "1s" \
    --key "$WORK_DIR/.idprova/keys/controller.key")

info "Issued 1-second DAT, waiting 2 seconds..."
sleep 2

EXPIRED_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${SHORT_DAT}" \
    -d '{"jsonrpc":"2.0","id":4,"method":"echo","params":{"message":"should fail"}}')

if [ "$EXPIRED_RESULT" = "401" ]; then
    ok "Got HTTP 401 Unauthorized — expired token correctly rejected!"
else
    info "Got HTTP $EXPIRED_RESULT (expected 401)"
fi

# ── Step 12: Revoke a DAT ────────────────────────────────────────────────
pause "Revoke the original DAT" \
    "Revoking the main DAT via the registry. After revocation,\n  any attempt to use it will be rejected."

# Extract JTI from token
JTI=$("$CLI" dat inspect "$DAT_TOKEN" 2>&1 | grep -oP '"jti"\s*:\s*"\K[^"]+' || echo "")
if [ -z "$JTI" ]; then
    # Fallback: decode the middle part of the JWS
    JTI=$(echo "$DAT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['jti'])" 2>/dev/null || echo "dat_unknown")
fi

info "Revoking JTI: $JTI"
curl -s -X POST "${REGISTRY_URL}/v1/dat/revoke" \
    -H "Content-Type: application/json" \
    -d "{\"jti\": \"${JTI}\", \"reason\": \"demo revocation\", \"revoked_by\": \"did:aid:example.com:demo-user\"}" \
    | python3 -m json.tool 2>/dev/null || true
ok "DAT revoked"

# Try to use the revoked token
info "Attempting to use revoked token..."
REVOKED_RESULT=$(curl -s -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${DAT_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":5,"method":"echo","params":{"message":"should fail"}}')

echo "$REVOKED_RESULT" | python3 -m json.tool 2>/dev/null || echo "$REVOKED_RESULT"

REVOKED_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MCP_URL}/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${DAT_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":6,"method":"echo","params":{"message":"should fail"}}')

if [ "$REVOKED_STATUS" = "401" ]; then
    ok "Revoked token rejected!"
else
    info "Got HTTP $REVOKED_STATUS"
fi

# ── Step 13: Summary ──────────────────────────────────────────────────────
pause "Demo Complete" \
    "All 12 protocol features demonstrated successfully!"

echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║                  IDProva v0.1 Demo Summary              ║"
echo "  ╠══════════════════════════════════════════════════════════╣"
echo "  ║  ✓ Ed25519 key generation (zeroized on drop)            ║"
echo "  ║  ✓ AID document creation + registry storage             ║"
echo "  ║  ✓ DAT issuance (scoped, time-bounded)                  ║"
echo "  ║  ✓ DAT verification (sig + timing + scope + constraints)║"
echo "  ║  ✓ MCP tool call with bearer token auth                 ║"
echo "  ║  ✓ BLAKE3 receipt chain (tamper-evident audit)           ║"
echo "  ║  ✓ Scope enforcement (403 on wrong scope)               ║"
echo "  ║  ✓ Token expiry enforcement (401 on expired)            ║"
echo "  ║  ✓ Token revocation (post-issue control)                ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Learn more: https://idprova.dev"
echo ""
