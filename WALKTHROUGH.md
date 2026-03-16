# IDProva — Manual Verification Walkthrough

A step-by-step, screen-recordable demonstration of the IDProva protocol.
Copy-paste every command — no placeholders, no thinking required.

---

## Recording Setup

Pick one:
- **OBS Studio** — best for YouTube/social. Record region or full screen.
- **ShareX** — lightweight, good for GIFs. `Ctrl+Shift+PrintScreen` to start.
- **Windows Game Bar** — `Win+G`, click record. Quick but lower quality.

**Tips:**
- Use a dark terminal theme with large font (16pt+) for readability
- Increase terminal width to ~120 columns so output doesn't wrap
- Record each Act as a separate clip if editing later

---

## Prerequisites

### One-time setup

1. **Rust toolchain** — install from https://rustup.rs if not already present
2. **Node.js 18+** — for the web demo (`node --version` to check)
3. **Build the workspace:**

```bash
cd ~/toon_conversations/aidspec
cargo build --workspace --release --exclude idprova-python --exclude idprova-typescript
```

> Build takes 2-5 minutes on first run. The `--exclude` flags skip SDK crates that need special environment variables.

4. **Install web dependencies:**

```bash
cd web && npm install && cd ..
```

5. **Create a convenience alias** (add to your shell session):

```bash
alias idprova="$(pwd)/target/release/idprova"
```

Verify it works:

```bash
idprova --version
```

---

## Terminal Setup

Open **3 terminals** side-by-side. All terminals should start in the repo root:

```bash
cd ~/toon_conversations/aidspec
```

| Terminal | Purpose | What's running |
|----------|---------|----------------|
| **T1** | Registry server | `cargo run` (stays running) |
| **T2** | Web dev server | `npm run dev` (stays running) |
| **T3** | CLI commands | Where you type all demo commands |

### Terminal 1 — Start the Registry

```bash
cd ~/toon_conversations/aidspec/crates/idprova-registry
REGISTRY_PORT=3001 IDPROVA_ALLOW_LOCALHOST=1 cargo run --release
```

> You should see output like:
> ```
> IDProva Registry listening on 0.0.0.0:3001
> REGISTRY_ADMIN_PUBKEY not set — write endpoints are OPEN (development mode only)
> ```

> **📹 SCREENSHOT THIS** — shows the registry is running on port 3001 in dev mode.

### Terminal 2 — Start the Web Demo

```bash
cd ~/toon_conversations/aidspec/web
npm run dev
```

> You should see:
> ```
> VITE v5.x.x ready in Xms
>   ➜ Local: http://localhost:5173/
> ```

### Terminal 3 — Verify connectivity

```bash
cd ~/toon_conversations/aidspec
alias idprova="$(pwd)/target/release/idprova"
curl -s http://localhost:3001/health | python3 -m json.tool
```

> Expected: `{ "status": "ok" }`

> **📹 SCREENSHOT THIS** — proves registry is healthy and reachable.

---

## Act 1: Identity Creation

> **🎬 START RECORDING** — "Creating cryptographic identities from scratch"

### Step 1.1 — Generate keypairs for two entities

```bash
idprova keygen --output ./demo/operator.key
idprova keygen --output ./demo/agent.key
```

> Expected output (for each):
> ```
> Generated Ed25519 keypair:
>   Private key: ./demo/operator.key
>   Public key:  ./demo/operator.pub
>   Public key (multibase): z3AGS...
> ```

> **📹 SCREENSHOT THIS** — shows two independent Ed25519 keypairs created.

### Step 1.2 — Create the Operator AID

```bash
idprova aid create \
  --id "did:aid:demo.local:operator" \
  --name "Demo Operator" \
  --controller "did:aid:demo.local:operator" \
  --key ./demo/operator.key
```

> This prints the full AID document (JSON) and saves it to `did_idprova_demo.local_operator.json`.

> **📹 SCREENSHOT THIS** — the AID document with DID, verification method, and trust level.

### Step 1.3 — Create the Agent AID

```bash
idprova aid create \
  --id "did:aid:demo.local:agent" \
  --name "Demo AI Agent" \
  --controller "did:aid:demo.local:operator" \
  --model "claude-3-opus" \
  --runtime "docker" \
  --key ./demo/agent.key
```

> Note: the agent's `controller` is the operator — this establishes the trust relationship.

> **📹 SCREENSHOT THIS** — show the agent AID with `model` and `runtime` metadata.

### Step 1.4 — Verify AID documents locally

```bash
idprova aid verify did_idprova_demo.local_operator.json
idprova aid verify did_idprova_demo.local_agent.json
```

> Expected: `AID document is valid.` for both.

---

## Act 2: Registration

> **🎬 RECORDING** — "Registering identities with the decentralized registry"

### Step 2.1 — Register both AIDs with the registry

```bash
curl -s -X PUT http://localhost:3001/v1/aid/demo.local:operator \
  -H "Content-Type: application/json" \
  -d @did_idprova_demo.local_operator.json | python3 -m json.tool
```

```bash
curl -s -X PUT http://localhost:3001/v1/aid/demo.local:agent \
  -H "Content-Type: application/json" \
  -d @did_idprova_demo.local_agent.json | python3 -m json.tool
```

> Expected: `201 Created` response with the registered AID.

> **📹 SCREENSHOT THIS** — both registrations succeed.

### Step 2.2 — Resolve AIDs from the registry (CLI)

```bash
IDPROVA_ALLOW_LOCALHOST=1 idprova aid resolve "demo.local:operator" \
  --registry http://localhost:3001
```

```bash
IDPROVA_ALLOW_LOCALHOST=1 idprova aid resolve "demo.local:agent" \
  --registry http://localhost:3001
```

> This fetches the AID from the registry and displays it — proving the registry stored it correctly.

> **📹 SCREENSHOT THIS** — round-trip proof: create → register → resolve.

### Step 2.3 — List all registered AIDs

```bash
curl -s http://localhost:3001/v1/aids | python3 -m json.tool
```

> Shows both AIDs in the registry listing.

---

## Act 3: Delegation

> **🎬 RECORDING** — "Delegating capabilities with cryptographic tokens"

### Step 3.1 — Issue a DAT (Delegation Attestation Token)

The operator delegates specific capabilities to the agent:

```bash
DAT_TOKEN=$(idprova dat issue \
  --issuer "did:aid:demo.local:operator" \
  --subject "did:aid:demo.local:agent" \
  --scope "mcp:tool:read,mcp:resource:data:read" \
  --expires-in "1h" \
  --key ./demo/operator.key)

echo "$DAT_TOKEN"
```

> This outputs a compact JWS token (three Base64URL segments separated by dots).
> The token is stored in `$DAT_TOKEN` for use in subsequent commands.

> **📹 SCREENSHOT THIS** — the raw DAT token, visually dramatic cryptographic output.

### Step 3.2 — Inspect the DAT

```bash
idprova dat inspect "$DAT_TOKEN"
```

> Expected output (formatted):
> ```
> ┌─ Header ─────────────────────────────────────────────────────
> │  Algorithm: EdDSA
> │  Type:      idprova-dat+jwt
> │  Key ID:    did:aid:demo.local:operator
> ├─ Claims ─────────────────────────────────────────────────────
> │  Issuer:    did:aid:demo.local:operator
> │  Subject:   did:aid:demo.local:agent
> │  Scopes:    mcp:tool:read, mcp:resource:data:read
> │  ...
> └─ Status ─────────────────────────────────────────────────────
>    ACTIVE (expires in 3599s)
> ```

> **📹 SCREENSHOT THIS** — the full decoded token showing issuer, subject, scopes, and expiry.

---

## Act 4: Verification

> **🎬 RECORDING** — "Verifying delegation tokens — the core security check"

### Step 4.1 — Offline verification (PASS)

Verify using the operator's public key — no network required:

```bash
idprova dat verify "$DAT_TOKEN" \
  --key ./demo/operator.pub \
  --scope "mcp:tool:read"
```

> Expected:
> ```
> ✓ Signature:  VALID
> ✓ Timing:     VALID
> ✓ Scope:      'mcp:tool:read' GRANTED
>
> Result: VALID
> ```

> **📹 SCREENSHOT THIS** — all green checkmarks, offline verification succeeds.

### Step 4.2 — Wrong scope (FAIL)

Try verifying a scope the token doesn't grant:

```bash
idprova dat verify "$DAT_TOKEN" \
  --key ./demo/operator.pub \
  --scope "mcp:tool:delete"
```

> Expected:
> ```
> ✗ Verification FAILED: scope 'mcp:tool:delete' not granted
> ```

> **📹 SCREENSHOT THIS** — proves scope enforcement works. The agent can read but NOT delete.

### Step 4.3 — Online verification via registry (PASS)

Verify without providing a key — the CLI fetches the issuer's public key from the registry:

```bash
IDPROVA_ALLOW_LOCALHOST=1 idprova dat verify "$DAT_TOKEN" \
  --registry http://localhost:3001 \
  --scope "mcp:tool:read"
```

> Expected:
> ```
> No key supplied — resolving issuer public key from registry...
>   GET http://localhost:3001/v1/aid/demo.local:operator/key
> ✓ Signature:  VALID (verified via registry)
> ✓ Timing:     VALID
> ✓ Scope:      'mcp:tool:read' GRANTED
>
> Result: VALID
> ```

> **📹 SCREENSHOT THIS** — shows the full trust chain: token → registry → key resolution → verification.

---

## Act 5: Revocation

> **🎬 RECORDING** — "Revoking a token — instant capability removal"

### Step 5.1 — Extract the JTI (token ID) for revocation

```bash
JTI=$(idprova dat inspect "$DAT_TOKEN" | grep "JTI:" | awk '{print $NF}')
echo "Token ID to revoke: $JTI"
```

> **📹 SCREENSHOT THIS** — shows the unique token identifier we're about to revoke.

### Step 5.2 — Revoke the DAT

```bash
curl -s -X POST http://localhost:3001/v1/dat/revoke \
  -H "Content-Type: application/json" \
  -d "{\"jti\": \"$JTI\", \"reason\": \"Demo revocation\", \"revoked_by\": \"did:aid:demo.local:operator\"}" \
  | python3 -m json.tool
```

> Expected: `{ "status": "revoked" }`

> **📹 SCREENSHOT THIS** — token revoked instantly.

### Step 5.3 — Confirm revocation

```bash
curl -s http://localhost:3001/v1/dat/revoked/$JTI | python3 -m json.tool
```

> Expected: `{ "revoked": true, ... }`

> **📹 SCREENSHOT THIS** — registry confirms the token is revoked.

### Step 5.4 — Verify the offline signature still passes (but revocation is a registry concern)

```bash
idprova dat verify "$DAT_TOKEN" \
  --key ./demo/operator.pub \
  --scope "mcp:tool:read"
```

> This still says VALID — because offline verification checks the cryptographic signature,
> not the revocation list. Revocation is enforced at the registry/middleware layer.
> This is by design: offline = crypto only, online = crypto + policy.

> **📹 SCREENSHOT THIS** — explains the two-layer verification model.

---

## Act 6: GUI Demo

> **🎬 RECORDING** — "Web-based demo — full protocol lifecycle in the browser"

### Step 6.1 — Open the web demo

Open your browser to: **http://localhost:5173**

> **📹 SCREENSHOT THIS** — the IDProva web demo landing page.

### Step 6.2 — Run the guided demo

1. Click **"Run Full Demo"** button (top-right area)
2. Watch all 7 steps execute:
   - Step 1: Generate 3 keypairs (issuer, agent, verifier)
   - Step 2: Create 3 AID documents
   - Step 3: Register AIDs with registry
   - Step 4: Issue DAT (delegation)
   - Step 5: Verify DAT offline
   - Step 6: Revoke DAT
   - Step 7: Verify revocation status
3. All 7 steps should show ✓ (green checkmarks)

> **📹 RECORD THE FULL SEQUENCE** — each step lights up green as it completes.
> This is the most visually impressive part of the demo.

### Step 6.3 — Explore individual tabs

Click through the tabs to show:
- **Keygen** — client-side key generation in the browser
- **AID** — identity document creation and registration
- **DAT** — token issuance and verification
- **Revocation** — token lifecycle management

> **📹 SCREENSHOT EACH TAB** — shows the full UI surface.

---

## Act 7: Cross-Tool Interop

> **🎬 RECORDING** — "The money shot — GUI-issued tokens verified by CLI"

This proves the protocol works across implementations (TypeScript in browser ↔ Rust CLI).

### Step 7.1 — Issue a DAT from the GUI

1. In the browser, go to the **DAT** tab
2. Issue a new delegation token using the GUI
3. **Copy the compact JWS token** from the output

### Step 7.2 — Verify GUI-issued token with CLI

```bash
# Paste the token from the GUI into this variable:
GUI_TOKEN="<paste the token from the browser here>"

# Inspect it with the CLI
idprova dat inspect "$GUI_TOKEN"
```

> The CLI successfully decodes a token created by the JavaScript implementation.

### Step 7.3 — Verify via registry

```bash
IDPROVA_ALLOW_LOCALHOST=1 idprova dat verify "$GUI_TOKEN" \
  --registry http://localhost:3001
```

> If the GUI registered the issuer's AID, this resolves the key from the registry
> and verifies the signature — cross-implementation interoperability proven.

> **📹 SCREENSHOT THIS** — Rust CLI verifying a JavaScript-issued token via a shared registry.
> This is the strongest proof that IDProva is a real protocol, not just a demo.

---

## Cleanup

### Stop services

- **Terminal 1**: `Ctrl+C` to stop the registry
- **Terminal 2**: `Ctrl+C` to stop the Vite dev server

### Delete demo files

```bash
cd ~/toon_conversations/aidspec
rm -rf demo/
rm -f did_idprova_demo.local_*.json
rm -f idprova_registry.db
```

---

## Checklist — What Was Proven

Use this as your social media caption or demo summary:

- [ ] **Ed25519 key generation** — cryptographic identity creation from scratch
- [ ] **AID documents** — W3C DID-compatible identity documents with metadata
- [ ] **Local verification** — AID documents validated without network
- [ ] **Registry registration** — identities stored in a decentralized registry
- [ ] **Registry resolution** — identities retrieved by DID
- [ ] **DAT issuance** — scoped, time-limited delegation tokens (JWS format)
- [ ] **DAT inspection** — human-readable token decoding
- [ ] **Offline verification** — signature + timing + scope checking without network
- [ ] **Scope enforcement** — unauthorized scopes correctly rejected
- [ ] **Online verification** — registry-assisted key resolution and verification
- [ ] **Revocation** — instant token invalidation via registry
- [ ] **Revocation confirmation** — registry reports revocation status
- [ ] **GUI demo** — 7-step lifecycle in the browser (all green)
- [ ] **Cross-implementation interop** — TypeScript (browser) ↔ Rust (CLI) via shared registry

---

## Troubleshooting

### "Port 3001 already in use"

Something else is using port 3001. Either stop it or use a different port:

```bash
REGISTRY_PORT=3002 IDPROVA_ALLOW_LOCALHOST=1 cargo run --release
```

Then update all `localhost:3001` references to `localhost:3002` in the commands above.

### "invalid registry URL" or SSRF error

You forgot `IDPROVA_ALLOW_LOCALHOST=1`. The CLI blocks localhost URLs by default (SSRF protection). Set the env var:

```bash
IDPROVA_ALLOW_LOCALHOST=1 idprova aid resolve ...
```

### "AID not found" on resolve

Make sure you registered the AID first (Act 2). The resolve command queries the registry — if you skipped registration, it won't find anything.

### Web demo steps fail

Check that:
1. Registry is running on port 3001 (not 3000)
2. Vite dev server is running (`npm run dev` in `web/`)
3. The Vite proxy is configured to forward to port 3001 (check `web/vite.config.ts`)

### Build errors with Python/TypeScript SDK crates

Use the `--exclude` flags:

```bash
cargo build --workspace --release --exclude idprova-python --exclude idprova-typescript
```
