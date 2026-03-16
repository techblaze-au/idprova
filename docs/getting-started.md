# Getting Started with IDProva

This guide walks you through installing IDProva, creating an agent identity, issuing delegation tokens, and running the registry.

## Prerequisites

- Rust 1.75+ (`rustup install stable`)
- Cargo (`rustup` installs this automatically)

## Install the CLI

```bash
cargo install idprova-cli
```

Verify the install:

```bash
idprova --version
```

## Step 1: Generate a Keypair

Every agent needs an Ed25519 keypair. The private key signs your Agent Identity Document and any tokens you issue.

```bash
idprova keygen --output ~/.idprova/keys/my-agent.key
```

Output:

```
Generated Ed25519 keypair:
  Private key: /home/user/.idprova/keys/my-agent.key
  Public key:  /home/user/.idprova/keys/my-agent.key.pub
  Public key (multibase): z6Mk...
```

The private key is written with mode `0600` (owner-read only on Unix).

**Key files:**
- `my-agent.key` — hex-encoded 32-byte Ed25519 secret key (keep private)
- `my-agent.key.pub` — multibase-encoded Ed25519 public key (safe to share)

## Step 2: Create an Agent Identity Document (AID)

An AID is a W3C DID document that describes your agent — its DID, public key, capabilities, and metadata.

```bash
idprova aid create \
  --id "did:aid:example.com:my-agent" \
  --name "My Agent" \
  --controller "did:aid:example.com:operator" \
  --key ~/.idprova/keys/my-agent.key
```

Optional fields:

```bash
idprova aid create \
  --id "did:aid:example.com:my-agent" \
  --name "My Agent" \
  --controller "did:aid:example.com:operator" \
  --model "gpt-4o" \
  --runtime "langchain-0.3" \
  --key ~/.idprova/keys/my-agent.key
```

The command prints the AID JSON and saves it to `did_idprova_example.com_my-agent.json`.

Example AID document:

```json
{
  "id": "did:aid:example.com:my-agent",
  "controller": "did:aid:example.com:operator",
  "verificationMethod": [
    {
      "id": "did:aid:example.com:my-agent#key-ed25519",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aid:example.com:my-agent",
      "publicKeyMultibase": "z6Mk..."
    }
  ],
  "metadata": {
    "name": "My Agent",
    "model": "gpt-4o",
    "runtime": "langchain-0.3"
  }
}
```

Verify a locally-created AID document:

```bash
idprova aid verify did_idprova_example.com_my-agent.json
# AID document is valid.
```

## Step 3: Start the Registry

The registry is an HTTP server that stores AID documents and verifies DATs.

```bash
# Development mode (write endpoints are open — no auth)
cargo run -p idprova-registry

# Production mode (require signed admin token for writes)
export REGISTRY_ADMIN_PUBKEY=<64-char-hex-ed25519-public-key>
export REGISTRY_PORT=3000
cargo run -p idprova-registry
```

Or with Docker:

```bash
docker run -p 3000:3000 \
  -e REGISTRY_ADMIN_PUBKEY=<hex-pubkey> \
  idprova/registry
```

Check health:

```bash
curl http://localhost:3000/health
# {"status":"ok","version":"0.1.0","protocol":"idprova/0.1"}
```

## Step 4: Register the AID

Push your AID document to the registry:

```bash
curl -X PUT http://localhost:3000/v1/aid/example.com:my-agent \
  -H "Content-Type: application/json" \
  -d @did_idprova_example.com_my-agent.json
# {"id":"did:aid:example.com:my-agent","status":"created"}
```

> In production mode, add `-H "Authorization: Bearer <admin-dat>"`.

Resolve it back:

```bash
curl http://localhost:3000/v1/aid/example.com:my-agent
```

Or via CLI:

```bash
idprova aid resolve did:aid:example.com:my-agent \
  --registry http://localhost:3000
```

## Step 5: Issue a Delegation Attestation Token (DAT)

A DAT grants a subject agent permission to act within a defined scope. The issuer signs it with their private key.

```bash
# Operator generates their own keypair first
idprova keygen --output ~/.idprova/keys/operator.key

# Issue a DAT from operator to my-agent, granting filesystem read for 24h
idprova dat issue \
  --issuer "did:aid:example.com:operator" \
  --subject "did:aid:example.com:my-agent" \
  --scope "mcp:tool:filesystem:read" \
  --expires-in 24h \
  --key ~/.idprova/keys/operator.key
```

The command prints the compact JWS token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImRpZD...
```

Duration formats: `30m`, `24h`, `7d`.

Multiple scopes (comma-separated):

```bash
--scope "mcp:tool:filesystem:read,mcp:tool:filesystem:write"
```

## Step 6: Verify a DAT

**Offline** (fastest, no network):

```bash
idprova dat verify <TOKEN> \
  --key ~/.idprova/keys/operator.key.pub \
  --scope "mcp:tool:filesystem:read"
```

Output:

```
IDProva DAT Verification
────────────────────────────────────────
Issuer:  did:aid:example.com:operator
Subject: did:aid:example.com:my-agent
JTI:     <uuid>
Scopes:  mcp:tool:filesystem:read
Expires: in 86399s

✓ Signature:  VALID
✓ Timing:     VALID
✓ Scope:      'mcp:tool:filesystem:read' GRANTED

Result: VALID
```

**Via registry** (resolves issuer key automatically):

```bash
idprova dat verify <TOKEN> \
  --registry http://localhost:3000 \
  --scope "mcp:tool:filesystem:read"
```

**Inspect without verification** (decode only):

```bash
idprova dat inspect <TOKEN>
```

## Step 7: Log and Verify Action Receipts

The receipt log is an append-only JSONL file of hash-chained action records.

Verify integrity of an existing log:

```bash
idprova receipt verify agent-actions.jsonl
# ✓ Hash chain intact (47 entries)
# ✓ No gaps detected
# ✓ All signatures valid
```

Show statistics:

```bash
idprova receipt stats agent-actions.jsonl
```

## Step 8: Verify a DAT via the Registry API

Services integrating IDProva can call the registry directly:

```bash
curl -X POST http://localhost:3000/v1/dat/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<compact-jws>",
    "scope": "mcp:tool:filesystem:read",
    "trust_level": 1,
    "delegation_depth": 0
  }'
```

Response:

```json
{
  "valid": true,
  "issuer": "did:aid:example.com:operator",
  "subject": "did:aid:example.com:my-agent",
  "scopes": ["mcp:tool:filesystem:read"],
  "jti": "<uuid>"
}
```

## Complete Example Flow

```bash
# 1. Generate keys
idprova keygen --output operator.key
idprova keygen --output agent.key

# 2. Create AIDs
idprova aid create --id "did:aid:example.com:operator" \
  --name "Operator" --controller "did:aid:example.com:operator" \
  --key operator.key

idprova aid create --id "did:aid:example.com:agent" \
  --name "Worker Agent" --controller "did:aid:example.com:operator" \
  --key agent.key

# 3. Start registry
cargo run -p idprova-registry &

# 4. Register AIDs
curl -sX PUT http://localhost:3000/v1/aid/example.com:operator \
  -H "Content-Type: application/json" \
  -d @did_idprova_example.com_operator.json

curl -sX PUT http://localhost:3000/v1/aid/example.com:agent \
  -H "Content-Type: application/json" \
  -d @did_idprova_example.com_agent.json

# 5. Issue DAT
TOKEN=$(idprova dat issue \
  --issuer "did:aid:example.com:operator" \
  --subject "did:aid:example.com:agent" \
  --scope "mcp:tool:search:execute" \
  --expires-in 1h \
  --key operator.key)

# 6. Verify
idprova dat verify "$TOKEN" \
  --registry http://localhost:3000 \
  --scope "mcp:tool:search:execute"
```

## Configuration File

Place a `~/.idprova/config.toml` to set defaults:

```toml
registry_url = "http://localhost:3000"
```

## Next Steps

- [API Reference](api-reference.md) — registry HTTP endpoints
- [Core Library API](core-api.md) — embed IDProva in your Rust application
- [Protocol Concepts](concepts.md) — DIDs, DATs, trust levels, policy engine
- [Security Model](security.md) — threat model and key management
