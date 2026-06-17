#!/usr/bin/env bash
set -euo pipefail

# Recreate the demo identities under ./identities/ using the idprova CLI.
# Idempotent: re-running overwrites the existing artifacts.

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p identities
cd identities

echo "=== IDProva Identity Setup ==="

# 1. Issuer (self-controlled)
echo "[1/3] issuer"
idprova keygen --output issuer.key
idprova aid create \
  --id "did:aid:techblaze.com.au:issuer" \
  --name "Issuer" \
  --controller "did:aid:techblaze.com.au:issuer" \
  --key issuer.key \
  > issuer.aid.json

# 2. Researcher (read-only DAT)
echo "[2/3] researcher"
idprova keygen --output researcher.key
idprova aid create \
  --id "did:aid:techblaze.com.au:researcher" \
  --name "Researcher" \
  --controller "did:aid:techblaze.com.au:issuer" \
  --key researcher.key \
  > researcher.aid.json
idprova dat issue \
  --issuer "did:aid:techblaze.com.au:issuer" \
  --subject "did:aid:techblaze.com.au:researcher" \
  --scope "mcp:tool:web-search:read,mcp:tool:knowledge-base:read" \
  --expires-in 8h \
  --key issuer.key \
  > researcher.dat

# 3. Writer (write DAT)
echo "[3/3] writer"
idprova keygen --output writer.key
idprova aid create \
  --id "did:aid:techblaze.com.au:writer" \
  --name "Writer" \
  --controller "did:aid:techblaze.com.au:issuer" \
  --key writer.key \
  > writer.aid.json
idprova dat issue \
  --issuer "did:aid:techblaze.com.au:issuer" \
  --subject "did:aid:techblaze.com.au:writer" \
  --scope "mcp:tool:document:write" \
  --expires-in 8h \
  --key issuer.key \
  > writer.dat

echo
echo "=== Setup complete (in $(pwd)) ==="
echo "  researcher DAT scopes : mcp:tool:web-search:read, mcp:tool:knowledge-base:read"
echo "  writer     DAT scopes : mcp:tool:document:write"
echo
echo "These files contain private keys and are gitignored. Never commit identities/."
