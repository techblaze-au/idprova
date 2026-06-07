#!/usr/bin/env bash
# IDProva golden-path demo — reproducible CLI walkthrough.
#
# Every command here is the repo's own blessed quickstart (README
# "60-Second Quickstart") run against the real `idprova` CLI. Nothing is faked.
# Run this once as a dress rehearsal BEFORE recording the asciinema (DIM 5 of the
# GTM plan calls for exactly that), so the recorded take is clean.
#
# Usage:
#   ./docs/demo/run.sh                 # uses an installed `idprova` on PATH
#   IDPROVA="cargo run -q -p idprova-cli --" ./docs/demo/run.sh   # from source
set -euo pipefail

IDPROVA="${IDPROVA:-idprova}"
WORKDIR="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/idprova-demo.$$")"
mkdir -p "$WORKDIR"; cd "$WORKDIR"
echo "# demo workspace: $WORKDIR"
echo

echo "## 1. The operator generates an Ed25519 keypair"
$IDPROVA keygen --output operator.key
echo

echo "## 2. Create the agent's identity document (AID)"
$IDPROVA aid create \
  --id "did:aid:example.com:support-agent" \
  --name "Customer Support Agent" \
  --controller "did:aid:example.com:operator" \
  --key operator.key
echo

echo "## 3. Verify the AID document is well-formed"
$IDPROVA aid verify did_aid_example.com_support-agent.json
echo

echo "## 4. The operator issues a scoped, time-boxed delegation token (DAT)"
echo "##    read-only on one tool, expires in 1h"
TOKEN=$($IDPROVA dat issue \
  --issuer "did:aid:example.com:operator" \
  --subject "did:aid:example.com:support-agent" \
  --scope "mcp:tool:knowledge-base:read" \
  --expires-in 1h \
  --key operator.key)
echo "$TOKEN"
echo

echo "## 5. ANYONE verifies that token OFFLINE with just the public key."
echo "##    No call to IDProva. No network. No trust in us."
$IDPROVA dat verify "$TOKEN" \
  --key operator.key.pub \
  --scope "mcp:tool:knowledge-base:read"
echo

echo "# Done. Workspace left at: $WORKDIR"
echo "# Next (run from the repo root, not here):"
echo "#   cargo run -q -p idprova-mcp --example multi_agent"
echo "#   -> 4-agent delegation chain, scope narrowing enforced, receipt chain VALID"
