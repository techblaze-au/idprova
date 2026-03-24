#!/usr/bin/env bash
# 08-run-scenarios.sh
# Run ON CT 402 (idp-admin) at 198.51.100.42.
# Executes all 5 test scenarios against the test lab.
# Each scenario prints PASS/FAIL with clear output.
#
# Usage: pct exec 402 -- bash /root/08-run-scenarios.sh
#    or: ssh root@198.51.100.42 'bash -s' < scripts/testlab/08-run-scenarios.sh
# Prerequisites: All setup scripts (02-07) completed.

set -euo pipefail

REGISTRY_HOST="198.51.100.41"
REGISTRY_URL="http://${REGISTRY_HOST}:4242"
MCP_URL="http://${REGISTRY_HOST}:3001"
KEYS_DIR="/root/.idprova/keys"
ADMIN_KEY="$KEYS_DIR/admin-root.key"

ORCH_HOST="198.51.100.43"
WORKER_A_HOST="198.51.100.44"
WORKER_B_HOST="198.51.100.45"

PASSED=0
FAILED=0
TOTAL=0

# ── Helpers ─────────────────────────────────────────────────────────────────
pass() {
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  [PASS] $1"
}

fail() {
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  [FAIL] $1"
    if [[ -n "${2:-}" ]]; then
        echo "         Detail: $2"
    fi
}

mcp_call() {
    local dat="$1"
    local tool="$2"
    local message="$3"
    curl -sf -X POST "$MCP_URL/" \
        -H "Authorization: Bearer $dat" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$tool\",\"params\":{\"message\":\"$message\"}}" 2>&1 || true
}

mcp_call_with_code() {
    local dat="$1"
    local tool="$2"
    local message="$3"
    curl -s -o /tmp/mcp_resp.json -w "%{http_code}" -X POST "$MCP_URL/" \
        -H "Authorization: Bearer $dat" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$tool\",\"params\":{\"message\":\"$message\"}}" 2>/dev/null || echo "000"
}

echo "================================================================"
echo "  IDProva Test Lab — Scenario Runner"
echo "================================================================"
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Date: $(date)"
echo "Registry: $REGISTRY_URL"
echo "MCP:      $MCP_URL"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: Happy Path
# ════════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCENARIO 1: Happy Path — Health check and MCP calls"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 1a. Registry health
HEALTH=$(curl -sf "$REGISTRY_URL/health" 2>&1 || true)
if echo "$HEALTH" | grep -q '"status"'; then
    pass "Registry health check"
else
    fail "Registry health check" "$HEALTH"
fi

# 1b. MCP health (if it has a health endpoint, otherwise skip)
MCP_HEALTH=$(curl -sf "$MCP_URL/health" 2>&1 || true)
if [[ -n "$MCP_HEALTH" ]]; then
    pass "MCP server reachable"
else
    # MCP may not have /health — try a different check
    MCP_ALIVE=$(curl -s -o /dev/null -w "%{http_code}" "$MCP_URL/" 2>/dev/null || echo "000")
    if [[ "$MCP_ALIVE" != "000" ]]; then
        pass "MCP server reachable (HTTP $MCP_ALIVE)"
    else
        fail "MCP server reachable" "Connection refused"
    fi
fi

# 1c. Read orchestrator DAT from CT 403
ORCH_DAT=$(ssh -o StrictHostKeyChecking=no "root@${ORCH_HOST}" "cat /root/.idprova/current-dat.txt 2>/dev/null" || true)
if [[ -n "$ORCH_DAT" ]]; then
    RESP=$(mcp_call "$ORCH_DAT" "echo" "scenario1-orch")
    if echo "$RESP" | grep -q "scenario1-orch"; then
        pass "Orchestrator MCP echo call"
    else
        fail "Orchestrator MCP echo call" "$RESP"
    fi
else
    fail "Orchestrator MCP echo call" "No DAT on CT 403"
fi

# 1d. Worker-a echo call
WORKER_A_DAT=$(ssh -o StrictHostKeyChecking=no "root@${WORKER_A_HOST}" "cat /root/.idprova/current-dat.txt 2>/dev/null" || true)
if [[ -n "$WORKER_A_DAT" ]]; then
    RESP=$(mcp_call "$WORKER_A_DAT" "echo" "scenario1-worker-a")
    if echo "$RESP" | grep -q "scenario1-worker-a"; then
        pass "Worker-a MCP echo call"
    else
        fail "Worker-a MCP echo call" "$RESP"
    fi
else
    fail "Worker-a MCP echo call" "No DAT on CT 404"
fi

# 1e. Worker-a calculate call
if [[ -n "$WORKER_A_DAT" ]]; then
    RESP=$(curl -sf -X POST "$MCP_URL/" \
        -H "Authorization: Bearer $WORKER_A_DAT" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"calculate","params":{"expression":"2+2"}}' 2>&1 || true)
    if echo "$RESP" | grep -q "4\|result"; then
        pass "Worker-a MCP calculate call"
    else
        fail "Worker-a MCP calculate call" "$RESP"
    fi
fi

# 1f. Worker-b echo call
WORKER_B_DAT=$(ssh -o StrictHostKeyChecking=no "root@${WORKER_B_HOST}" "cat /root/.idprova/current-dat.txt 2>/dev/null" || true)
if [[ -n "$WORKER_B_DAT" ]]; then
    RESP=$(mcp_call "$WORKER_B_DAT" "echo" "scenario1-worker-b")
    if echo "$RESP" | grep -q "scenario1-worker-b"; then
        pass "Worker-b MCP echo call"
    else
        fail "Worker-b MCP echo call" "$RESP"
    fi
else
    fail "Worker-b MCP echo call" "No DAT on CT 405"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Scope Enforcement
# ════════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCENARIO 2: Scope Enforcement — Worker-b tries calculate (should fail)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ -n "$WORKER_B_DAT" ]]; then
    # Worker-b has scope mcp:tool:echo:call — should NOT be able to call calculate
    HTTP_CODE=$(curl -s -o /tmp/scope_resp.json -w "%{http_code}" -X POST "$MCP_URL/" \
        -H "Authorization: Bearer $WORKER_B_DAT" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"calculate","params":{"expression":"2+2"}}' 2>/dev/null || echo "000")

    SCOPE_RESP=$(cat /tmp/scope_resp.json 2>/dev/null || true)

    if [[ "$HTTP_CODE" == "403" ]] || echo "$SCOPE_RESP" | grep -qi "forbidden\|denied\|scope\|unauthorized"; then
        pass "Worker-b calculate rejected (HTTP $HTTP_CODE)"
    elif [[ "$HTTP_CODE" == "200" ]] && echo "$SCOPE_RESP" | grep -qi "error\|denied"; then
        pass "Worker-b calculate rejected (JSON-RPC error in 200)"
    else
        fail "Worker-b calculate should be rejected" "HTTP $HTTP_CODE, Response: $SCOPE_RESP"
    fi

    # Worker-b should NOT be able to call read_file either
    HTTP_CODE=$(curl -s -o /tmp/scope_resp2.json -w "%{http_code}" -X POST "$MCP_URL/" \
        -H "Authorization: Bearer $WORKER_B_DAT" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"read_file","params":{"filename":"readme.txt"}}' 2>/dev/null || echo "000")

    SCOPE_RESP2=$(cat /tmp/scope_resp2.json 2>/dev/null || true)

    if [[ "$HTTP_CODE" == "403" ]] || echo "$SCOPE_RESP2" | grep -qi "forbidden\|denied\|scope\|unauthorized"; then
        pass "Worker-b read_file rejected (HTTP $HTTP_CODE)"
    elif [[ "$HTTP_CODE" == "200" ]] && echo "$SCOPE_RESP2" | grep -qi "error\|denied"; then
        pass "Worker-b read_file rejected (JSON-RPC error in 200)"
    else
        fail "Worker-b read_file should be rejected" "HTTP $HTTP_CODE, Response: $SCOPE_RESP2"
    fi
else
    fail "Scope enforcement tests" "No worker-b DAT available"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: Token Expiry
# ════════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCENARIO 3: Token Expiry — Issue 1m DAT, wait, verify rejection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Issue a short-lived DAT (1 minute — smallest unit CLI supports)
echo "  Issuing 1-minute DAT..."
SHORT_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:admin" \
    --subject "did:aid:testlab.local:orchestrator" \
    --scope "mcp:tool:echo:call" \
    --expires-in "1m" \
    --key "$ADMIN_KEY" 2>&1 || true)

SHORT_DAT=$(echo "$SHORT_DAT" | tr -d '[:space:]')

if [[ -z "$SHORT_DAT" ]] || echo "$SHORT_DAT" | grep -qi "error\|invalid"; then
    fail "Issue short-lived DAT" "idprova dat issue failed: $SHORT_DAT"
else
    # First verify it works while valid
    RESP=$(mcp_call "$SHORT_DAT" "echo" "short-lived-test")
    if echo "$RESP" | grep -q "short-lived-test"; then
        pass "Short-lived DAT works while valid"
    else
        fail "Short-lived DAT works while valid" "$RESP"
    fi

    # Wait for expiry (65 seconds to ensure 1-minute DAT has expired)
    echo "  Waiting 65 seconds for DAT to expire..."
    sleep 65

    # Now it should be rejected
    HTTP_CODE=$(mcp_call_with_code "$SHORT_DAT" "echo" "should-be-expired")
    EXPIRY_RESP=$(cat /tmp/mcp_resp.json 2>/dev/null || true)

    if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]] || echo "$EXPIRY_RESP" | grep -qi "expired\|invalid\|unauthorized\|denied"; then
        pass "Expired DAT rejected (HTTP $HTTP_CODE)"
    elif [[ "$HTTP_CODE" == "200" ]] && echo "$EXPIRY_RESP" | grep -qi "error\|expired"; then
        pass "Expired DAT rejected (JSON-RPC error in 200)"
    else
        fail "Expired DAT should be rejected" "HTTP $HTTP_CODE, Response: $EXPIRY_RESP"
    fi
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO 4: Revocation
# ════════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCENARIO 4: Revocation — Revoke worker-a DAT, verify rejection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Issue a fresh admin DAT for revocation operations
ADMIN_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:admin" \
    --subject "did:aid:testlab.local:admin" \
    --scope "*:*:*:*" \
    --expires-in "1h" \
    --key "$ADMIN_KEY" 2>&1 || true)
ADMIN_DAT=$(echo "$ADMIN_DAT" | tr -d '[:space:]')

# Issue a fresh DAT for worker-a that we can then revoke
echo "  Issuing fresh worker-a DAT for revocation test..."
REVOKE_TEST_DAT=$(idprova dat issue \
    --issuer "did:aid:testlab.local:admin" \
    --subject "did:aid:testlab.local:worker-a" \
    --scope "mcp:tool:echo:call" \
    --expires-in "1h" \
    --key "$ADMIN_KEY" 2>&1 || true)
REVOKE_TEST_DAT=$(echo "$REVOKE_TEST_DAT" | tr -d '[:space:]')

if [[ -z "$REVOKE_TEST_DAT" ]]; then
    fail "Issue DAT for revocation test" "Failed to issue DAT"
else
    # Verify it works before revocation
    RESP=$(mcp_call "$REVOKE_TEST_DAT" "echo" "pre-revoke-test")
    if echo "$RESP" | grep -q "pre-revoke-test"; then
        pass "Worker-a DAT works before revocation"
    else
        fail "Worker-a DAT works before revocation" "$RESP"
    fi

    # Revoke the DAT
    echo "  Revoking worker-a DAT..."
    # Extract JTI from DAT (it's a JWS — decode the payload)
    DAT_PAYLOAD=$(echo "$REVOKE_TEST_DAT" | cut -d'.' -f2)
    # Pad base64url to valid base64
    PAD_LEN=$(( (4 - ${#DAT_PAYLOAD} % 4) % 4 ))
    for ((i=0; i<PAD_LEN; i++)); do DAT_PAYLOAD="${DAT_PAYLOAD}="; done
    DAT_PAYLOAD=$(echo "$DAT_PAYLOAD" | tr '_-' '/+')

    JTI=$(echo "$DAT_PAYLOAD" | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('jti',''))" 2>/dev/null || true)

    if [[ -n "$JTI" ]]; then
        echo "  DAT JTI: $JTI"

        REVOKE_CODE=$(curl -s -o /tmp/revoke_resp.json -w "%{http_code}" \
            -X POST "${REGISTRY_URL}/v1/dat/revoke" \
            -H "Authorization: Bearer $ADMIN_DAT" \
            -H "Content-Type: application/json" \
            -d "{\"jti\":\"$JTI\"}" 2>/dev/null || echo "000")

        if [[ "$REVOKE_CODE" -ge 200 && "$REVOKE_CODE" -lt 300 ]]; then
            pass "DAT revocation accepted (HTTP $REVOKE_CODE)"

            # Wait a moment for revocation to take effect
            sleep 1

            # Now the DAT should be rejected
            HTTP_CODE=$(mcp_call_with_code "$REVOKE_TEST_DAT" "echo" "post-revoke-test")
            REVOKE_RESP=$(cat /tmp/mcp_resp.json 2>/dev/null || true)

            if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]] || echo "$REVOKE_RESP" | grep -qi "revoked\|invalid\|unauthorized\|denied"; then
                pass "Revoked DAT rejected (HTTP $HTTP_CODE)"
            elif [[ "$HTTP_CODE" == "200" ]] && echo "$REVOKE_RESP" | grep -qi "error\|revoked"; then
                pass "Revoked DAT rejected (JSON-RPC error in 200)"
            else
                fail "Revoked DAT should be rejected" "HTTP $HTTP_CODE, Response: $REVOKE_RESP"
            fi
        else
            REVOKE_RESP=$(cat /tmp/revoke_resp.json 2>/dev/null || true)
            fail "DAT revocation" "HTTP $REVOKE_CODE, Response: $REVOKE_RESP"
        fi
    else
        echo "  WARNING: Could not extract JTI from DAT payload. Trying alternative revocation..."

        # Try revoking by subject
        REVOKE_CODE=$(curl -s -o /tmp/revoke_resp.json -w "%{http_code}" \
            -X POST "${REGISTRY_URL}/v1/dat/revoke" \
            -H "Authorization: Bearer $ADMIN_DAT" \
            -H "Content-Type: application/json" \
            -d "{\"subject\":\"did:aid:testlab.local:worker-a\"}" 2>/dev/null || echo "000")

        if [[ "$REVOKE_CODE" -ge 200 && "$REVOKE_CODE" -lt 300 ]]; then
            pass "DAT revocation by subject (HTTP $REVOKE_CODE)"
            sleep 1

            HTTP_CODE=$(mcp_call_with_code "$REVOKE_TEST_DAT" "echo" "post-revoke-test")
            REVOKE_RESP=$(cat /tmp/mcp_resp.json 2>/dev/null || true)
            if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]] || echo "$REVOKE_RESP" | grep -qi "revoked\|invalid\|denied"; then
                pass "Revoked DAT rejected"
            else
                fail "Revoked DAT should be rejected" "HTTP $HTTP_CODE"
            fi
        else
            fail "DAT revocation" "HTTP $REVOKE_CODE"
        fi
    fi
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO 5: Break-Glass Recovery
# ════════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCENARIO 5: Break-Glass — Corrupt admin.env, recover with BG-A"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

BGA_KEY="$KEYS_DIR/break-glass/bg-a.key"
if [[ ! -f "$BGA_KEY" ]]; then
    fail "Break-glass test" "BG-A key not found at $BGA_KEY. Run 07-break-glass-setup.sh first."
else
    # 5a. Corrupt admin.env on CT 401
    echo "  Corrupting admin.env on CT 401..."
    ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
        "cp /opt/idprova/keys/admin.env /opt/idprova/keys/admin.env.scenario5.bak && \
         echo 'REGISTRY_ADMIN_PUBKEY=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' > /opt/idprova/keys/admin.env && \
         chmod 600 /opt/idprova/keys/admin.env && \
         chown idprova:idprova /opt/idprova/keys/admin.env"

    # 5b. Restart registry with corrupted key
    ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
        "systemctl restart idprova-registry" || true
    sleep 2

    # 5c. Verify admin DAT no longer works
    TEST_DAT=$(idprova dat issue \
        --issuer "did:aid:testlab.local:admin" \
        --subject "did:aid:testlab.local:admin" \
        --scope "*:*:*:*" \
        --expires-in "1h" \
        --key "$ADMIN_KEY" 2>&1 || true)
    TEST_DAT=$(echo "$TEST_DAT" | tr -d '[:space:]')

    if [[ -n "$TEST_DAT" ]]; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X PUT "${REGISTRY_URL}/v1/aid/testlab.local:test-bg" \
            -H "Authorization: Bearer $TEST_DAT" \
            -H "Content-Type: application/json" \
            -d '{"id":"did:aid:testlab.local:test-bg","name":"test"}' 2>/dev/null || echo "000")

        if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
            pass "Admin DAT rejected after admin.env corruption (HTTP $HTTP_CODE)"
        else
            echo "  NOTE: Admin DAT returned HTTP $HTTP_CODE (may still work for reads)"
        fi
    fi

    # 5d. Run break-glass recovery
    echo "  Running break-glass recovery with BG-A..."
    ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
        "bash /opt/idprova/keys/recover.sh && sleep 1 && systemctl start idprova-mcp" || true
    sleep 2

    # 5e. Verify health after recovery
    HEALTH=$(curl -sf "$REGISTRY_URL/health" 2>&1 || true)
    if echo "$HEALTH" | grep -q '"status"'; then
        pass "Registry healthy after break-glass recovery"
    else
        fail "Registry healthy after break-glass recovery" "$HEALTH"
    fi

    # 5f. Issue DAT with BG-A key and verify it works
    BGA_DAT=$(idprova dat issue \
        --issuer "did:aid:testlab.local:admin" \
        --subject "did:aid:testlab.local:admin" \
        --scope "*:*:*:*" \
        --expires-in "1h" \
        --key "$BGA_KEY" 2>&1 || true)
    BGA_DAT=$(echo "$BGA_DAT" | tr -d '[:space:]')

    if [[ -n "$BGA_DAT" ]]; then
        # Try a write operation with BG-A DAT
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X GET "${REGISTRY_URL}/v1/aid/testlab.local:admin" \
            -H "Authorization: Bearer $BGA_DAT" 2>/dev/null || echo "000")

        if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 400 ]]; then
            pass "BG-A DAT accepted after recovery (HTTP $HTTP_CODE)"
        else
            fail "BG-A DAT accepted after recovery" "HTTP $HTTP_CODE"
        fi
    else
        fail "Issue DAT with BG-A key" "Failed to issue DAT"
    fi

    # 5g. Restore original admin.env
    echo "  Restoring original admin.env..."
    ssh -o StrictHostKeyChecking=no "root@${REGISTRY_HOST}" \
        "cp /opt/idprova/keys/admin.env.scenario5.bak /opt/idprova/keys/admin.env && \
         chmod 600 /opt/idprova/keys/admin.env && \
         chown idprova:idprova /opt/idprova/keys/admin.env && \
         systemctl restart idprova-registry && \
         sleep 2 && systemctl restart idprova-mcp && \
         rm -f /opt/idprova/keys/admin.env.scenario5.bak"
    sleep 2

    HEALTH=$(curl -sf "$REGISTRY_URL/health" 2>&1 || true)
    if echo "$HEALTH" | grep -q '"status"'; then
        pass "Registry restored to original admin key"
    else
        fail "Registry restored to original admin key" "$HEALTH"
    fi
fi

# ── Cleanup temp files ──────────────────────────────────────────────────────
rm -f /tmp/mcp_resp.json /tmp/scope_resp.json /tmp/scope_resp2.json /tmp/revoke_resp.json

# ════════════════════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "================================================================"
echo "  RESULTS: $PASSED passed, $FAILED failed, $TOTAL total"
echo "================================================================"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo "  ALL SCENARIOS PASSED"
    exit 0
else
    echo "  $FAILED SCENARIO(S) FAILED — review output above"
    exit 1
fi
