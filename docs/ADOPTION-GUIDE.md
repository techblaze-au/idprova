# IDProva Adoption Guide

> **AD is to human identity in networks as IDProva is to agent identity in AI systems.**

IDProva sits at the foundation of your AI agent infrastructure — every agent gets a cryptographic identity, every delegation is signed and scoped, every action is receipted. Just as you wouldn't connect a user to your network without Active Directory authenticating them first, you shouldn't let an AI agent act without IDProva verifying its identity and permissions.

---

## Architectural Positioning

### AD ↔ IDProva Concept Map

| Active Directory | IDProva | Purpose |
|-----------------|---------|---------|
| User Account | **AID** (Agent Identity Document) | Unique, verifiable identity for an entity |
| Kerberos Ticket | **DAT** (Delegation Attestation Token) | Time-bounded, scoped proof of authorization |
| Domain Controller | **Registry** | Centralized identity resolution & verification |
| Event Log / Audit Trail | **Receipts** (hash-chained) | Tamper-evident record of every action |
| GPO / ACL | **DAT Scopes** (`namespace:resource:action`) | Fine-grained permission model |
| Kerberos Delegation | **DAT Chain** (sub-delegation) | Agent A delegates to Agent B delegates to Agent C |
| Domain Trust Levels | **Trust Levels L0–L4** | Graduated trust from anonymous to hardware-attested |
| Service Principal | **Agent AID with controller** | Machine identity managed by an operator |
| Certificate Authority | **Operator keypair** | Root of trust for identity issuance |

### Where IDProva Sits in Your Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Your AI Application                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Agent A  │  │ Agent B  │  │ Agent C  │  │ Agent D  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │              │              │              │          │
│  ╔════╧══════════════╧══════════════╧══════════════╧════╗    │
│  ║              IDProva Identity Layer                   ║    │
│  ║  ┌─────────┐  ┌──────────┐  ┌──────────┐            ║    │
│  ║  │  AIDs   │  │   DATs   │  │ Receipts │            ║    │
│  ║  │(identity)│  │(delegation)│ │ (audit)  │            ║    │
│  ║  └────┬────┘  └────┬─────┘  └────┬─────┘            ║    │
│  ║       └─────────────┼─────────────┘                   ║    │
│  ║                     │                                 ║    │
│  ║              ┌──────┴──────┐                          ║    │
│  ║              │  Registry   │                          ║    │
│  ║              │ (resolution)│                          ║    │
│  ║              └─────────────┘                          ║    │
│  ╚═══════════════════════════════════════════════════════╝    │
│       │              │              │              │          │
│  ┌────┴────┐  ┌──────┴─────┐  ┌────┴────┐  ┌─────┴────┐    │
│  │  MCP    │  │  LangChain │  │  A2A    │  │ REST API │    │
│  │ Servers │  │  / CrewAI  │  │ Agents  │  │ Services │    │
│  └─────────┘  └────────────┘  └─────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Key insight:** IDProva is not another framework — it's the identity *layer* that sits between your agents and whatever they interact with. Just as AD doesn't replace your applications, IDProva doesn't replace LangChain/CrewAI/MCP — it secures them.

---

## Day 0 — Bootstrap (30 minutes)

### Prerequisites
- Rust toolchain (for building from source) or download pre-built binaries
- Docker (optional, for registry)

### Step 1: Install the CLI

```bash
# From source
cargo install --path crates/idprova-cli

# Or build release binaries
cargo build --release -p idprova-cli -p idprova-registry
# Binaries at: target/release/idprova(.exe) and target/release/idprova-registry(.exe)
```

### Step 2: Generate your operator keypair

```bash
# Generate Ed25519 keypair
idprova keygen --output ~/.idprova/operator.key
# Creates: operator.key (private, hex-encoded) + operator.pub (public, multibase)
```

> **Security:** The `.key` file is your root of trust. Store it like you'd store an AD domain admin password. Never commit it to git.

### Step 3: Create your operator AID

```bash
idprova aid create \
  --id "did:aid:yourorg.com:operator" \
  --name "Org Operator" \
  --controller "did:aid:yourorg.com:operator" \
  --key ~/.idprova/operator.key \
  > ~/.idprova/operator-aid.json
```

The `controller` matching `id` makes this a self-sovereign identity — equivalent to a domain admin in AD.

### Step 4: Start the registry

```bash
# Option A: Direct binary
REGISTRY_PORT=3000 ./target/release/idprova-registry

# Option B: Docker (coming soon)
# docker run -p 3000:3000 -v idprova-data:/data ghcr.io/techblaze-au/idprova-registry
```

The registry is your "Domain Controller" — agents resolve identities and verify tokens through it.

### Step 5: Register your operator AID

```bash
# Register the operator identity
curl -X PUT http://localhost:3000/v1/aid/yourorg.com:operator \
  -H "Content-Type: application/json" \
  -d @~/.idprova/operator-aid.json
```

### Step 6: Configure CLI defaults

Create `~/.idprova/config.toml`:

```toml
registry_url = "http://localhost:3000"
default_identity = "operator"
```

**Checkpoint:** Run `curl http://localhost:3000/health` — you should see `{"status":"ok","version":"0.1.0","protocol":"idprova"}`.

---

## Day 1 — Register Your Agents

Each AI agent gets its own cryptographic identity — like creating user accounts in AD.

### CLI Workflow

```bash
# 1. Generate agent keypair
idprova keygen --output agent-alpha.key

# 2. Create AID (operator is the controller)
idprova aid create \
  --id "did:aid:yourorg.com:agent-alpha" \
  --name "Agent Alpha (Code Review)" \
  --controller "did:aid:yourorg.com:operator" \
  --model "claude-sonnet-4-6" \
  --runtime "langchain/0.3" \
  --key agent-alpha.key \
  > agent-alpha-aid.json

# 3. Register with registry
curl -X PUT http://localhost:3000/v1/aid/yourorg.com:agent-alpha \
  -H "Content-Type: application/json" \
  -d @agent-alpha-aid.json
```

### Python SDK

```python
from idprova import AgentIdentity

# Create + register in one flow
agent = AgentIdentity.create(
    name="agent-alpha",
    domain="yourorg.com",
    controller="did:aid:yourorg.com:operator"
)

# Persist identity to ~/.idprova/identities/agent-alpha/
agent.save()

# Later: reload
agent = AgentIdentity.load("~/.idprova/identities/agent-alpha")
print(agent.did)  # did:aid:yourorg.com:agent-alpha
```

### TypeScript SDK

```typescript
import { AgentIdentity } from '@idprova/core';

const agent = AgentIdentity.create(
  'agent-alpha',
  'yourorg.com',
  'did:aid:yourorg.com:operator'
);

agent.save();  // ~/.idprova/identities/agent-alpha/

// Reload
const loaded = AgentIdentity.load('~/.idprova/identities/agent-alpha');
console.log(loaded.did);  // did:aid:yourorg.com:agent-alpha
```

---

## Day 2 — Issue Delegation Tokens

DATs are the IDProva equivalent of Kerberos tickets — they prove that Agent A has been authorized by Operator X to perform specific actions, with specific constraints, for a specific time window.

### Delegation Patterns by Organization Size

#### Solo Developer (Flat)

```
Operator → Agent
           (broad scope, short expiry)
```

```bash
idprova dat issue \
  --issuer "did:aid:yourorg.com:operator" \
  --subject "did:aid:yourorg.com:agent-alpha" \
  --scope "mcp:tool:*,mcp:resource:*:read" \
  --expires-in "8h" \
  --key ~/.idprova/operator.key
```

#### Team (Two-tier)

```
Operator → Team Lead Agent → Worker Agents
           (full scope)       (narrowed scope)
```

```bash
# Operator → team-lead (broad)
idprova dat issue \
  --issuer "did:aid:yourorg.com:operator" \
  --subject "did:aid:yourorg.com:team-lead" \
  --scope "mcp:tool:*,a2a:agent:*:execute" \
  --expires-in "24h" \
  --key ~/.idprova/operator.key

# Team-lead → worker (narrowed — can only grant what it holds)
idprova dat issue \
  --issuer "did:aid:yourorg.com:team-lead" \
  --subject "did:aid:yourorg.com:worker-1" \
  --scope "mcp:tool:read" \
  --expires-in "1h" \
  --key team-lead.key
```

#### Enterprise (Multi-tier chain)

```
Operator → Department Head → Team Lead → Agents
(all scopes)  (dept scopes)  (team scopes) (task scopes)
```

Each level can only grant a subset of what it holds. The delegation chain is embedded in the DAT and verified end-to-end.

### Common Scope Patterns

| Scope | Meaning |
|-------|---------|
| `mcp:tool:read` | Read-only tool access |
| `mcp:tool:*` | All tool operations |
| `mcp:resource:data:read` | Read data resources |
| `mcp:*:*` | Full MCP access (use sparingly) |
| `a2a:agent:*:execute` | Execute any A2A agent |
| `a2a:agent:billing:execute` | Execute only the billing agent |
| `idprova:delegate:L2` | Can issue DATs up to trust level L2 |

### Python SDK — Issue DAT

```python
from idprova import AgentIdentity

operator = AgentIdentity.load("~/.idprova/identities/operator")
dat = operator.issue_dat(
    subject_did="did:aid:yourorg.com:agent-alpha",
    scope=["mcp:tool:read", "mcp:resource:data:read"],
    expires_in_seconds=3600  # 1 hour
)

token = dat.to_compact()  # JWS string — send this to the agent
```

### TypeScript SDK — Issue DAT

```typescript
import { AgentIdentity } from '@idprova/core';

const operator = AgentIdentity.load('~/.idprova/identities/operator');
const dat = operator.issueDat(
  'did:aid:yourorg.com:agent-alpha',
  ['mcp:tool:read', 'mcp:resource:data:read'],
  3600  // 1 hour
);

const token = dat.toCompact();  // JWS string
```

---

## Ongoing Operations

### Verification Flow

Every time an agent presents a DAT (e.g., in an `Authorization: Bearer <token>` header), verification follows this pipeline:

```
Request with Bearer token
         │
    ┌────┴────┐
    │ Extract │  → 401 if missing/malformed
    │ Bearer  │
    └────┬────┘
         │
    ┌────┴────┐
    │Revocation│  → 401 if revoked (fast-fail, no crypto needed)
    │  Check  │
    └────┬────┘
         │
    ┌────┴────┐
    │Signature │  → 401 if invalid Ed25519 signature
    │ Verify  │
    └────┬────┘
         │
    ┌────┴────┐
    │ Timing  │  → 401 if expired or not-yet-valid
    │  Check  │
    └────┬────┘
         │
    ┌────┴────┐
    │  Scope  │  → 403 if requested scope not granted
    │  Check  │
    └────┬────┘
         │
    ┌────┴────┐
    │Constraint│  → 403 if IP/rate/trust/geo/config violated
    │Evaluators│
    └────┬────┘
         │
     ✅ PASS → inject VerifiedDat into request context
```

#### Offline Verification (CLI)

```bash
idprova dat verify <token> --key issuer.pub --scope "mcp:tool:read"
```

#### Online Verification (via Registry)

```bash
idprova dat verify <token> --registry http://localhost:3000 --scope "mcp:tool:read"
```

#### Registry HTTP API

```bash
curl -X POST http://localhost:3000/v1/dat/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<compact-jws>",
    "scope": "mcp:tool:read",
    "request_ip": "203.0.113.42",
    "trust_level": 80
  }'
# Response: {"valid":true,"issuer":"did:aid:...","subject":"did:aid:...","scopes":["mcp:tool:read"]}
```

### Revocation

```bash
# Revoke by JTI
curl -X POST http://localhost:3000/v1/dat/revoke \
  -H "Content-Type: application/json" \
  -d '{"jti":"<token-jti>","reason":"compromised","revoked_by":"did:aid:yourorg.com:operator"}'

# Check revocation status
curl http://localhost:3000/v1/dat/revoked/<jti>
# Response: {"revoked":true,"jti":"...","reason":"compromised","revoked_at":"2026-03-08T..."}
```

### Key Rotation

```bash
# 1. Generate new keypair
idprova keygen --output agent-alpha-v2.key

# 2. Update AID document with new key
idprova aid create \
  --id "did:aid:yourorg.com:agent-alpha" \
  --name "Agent Alpha (Code Review)" \
  --controller "did:aid:yourorg.com:operator" \
  --key agent-alpha-v2.key \
  > agent-alpha-aid-v2.json

# 3. Re-register (PUT is idempotent)
curl -X PUT http://localhost:3000/v1/aid/yourorg.com:agent-alpha \
  -H "Content-Type: application/json" \
  -d @agent-alpha-aid-v2.json

# 4. Revoke all DATs issued with the old key
# 5. Issue new DATs with the new key
```

### Audit & Compliance Mapping

IDProva maps directly to common compliance frameworks:

| Control | NIST 800-53 | ISM (AU) | SOC 2 | IDProva Feature |
|---------|-------------|----------|-------|-----------------|
| Identity Management | IA-2, IA-4 | ISM-0414 | CC6.1 | AIDs with Ed25519 keys |
| Access Control | AC-3, AC-6 | ISM-1508 | CC6.3 | DAT scopes + constraints |
| Least Privilege | AC-6(1) | ISM-1175 | CC6.3 | Scope narrowing in delegation chains |
| Audit Logging | AU-2, AU-3 | ISM-0580 | CC7.2 | Hash-chained receipts (BLAKE3) |
| Non-repudiation | AU-10 | ISM-0988 | CC7.2 | Ed25519-signed receipts |
| Session Management | SC-23, AC-12 | ISM-1164 | CC6.1 | DAT expiry + revocation |
| Credential Management | IA-5 | ISM-1590 | CC6.1 | Ed25519 keypairs, key rotation |
| Separation of Duties | AC-5 | ISM-1380 | CC6.1 | Controller ≠ subject in DATs |
| Incident Response | IR-4, IR-6 | ISM-0123 | CC7.3 | Receipt chain integrity + revocation |

### Receipt Chain Integrity

```bash
# Verify receipt chain hasn't been tampered with
idprova receipt verify receipts.jsonl

# Show receipt stats
idprova receipt stats receipts.jsonl
```

---

## Integration Patterns

### 1. MCP (Model Context Protocol) — Middleware Pattern

IDProva provides `DatVerificationLayer`, a Tower/Axum middleware that drops into any MCP server:

**Server-side (Rust/Axum):**

```rust
use axum::{Router, routing::post, Extension};
use idprova_middleware::{DatVerificationLayer, VerifiedDat};

async fn handle_tool_call(Extension(verified): Extension<VerifiedDat>) -> String {
    // verified.subject_did — who is calling
    // verified.scopes — what they're allowed to do
    format!("Authorized: {} with scopes {:?}", verified.subject_did, verified.scopes)
}

let pub_key: [u8; 32] = /* operator's public key bytes */;
let app = Router::new()
    .route("/tools/execute", post(handle_tool_call))
    .layer(DatVerificationLayer::new(pub_key, "mcp:tool:execute"));
```

**Client-side (Agent attaching DAT):**

```python
import httpx

headers = {"Authorization": f"Bearer {dat_token}"}
response = httpx.post("http://mcp-server/tools/execute",
    json={"tool": "read_file", "args": {"path": "/data/report.csv"}},
    headers=headers
)
```

**Where identity lives:**
- AID: Registered in IDProva Registry
- DAT: Attached as `Authorization: Bearer <token>` header
- Verification: `DatVerificationLayer` middleware (automatic)
- Receipts: Logged after each tool invocation

### 2. LangChain — Callback Handler Pattern

```python
from langchain.callbacks.base import BaseCallbackHandler
from idprova import AgentIdentity, DAT, ReceiptLog

class IDProvaAuditCallbackHandler(BaseCallbackHandler):
    def __init__(self, identity: AgentIdentity, dat: DAT):
        self.identity = identity
        self.dat = dat
        self.receipts = ReceiptLog()

    def on_tool_start(self, tool, input_str, **kwargs):
        # Verify DAT is still valid before tool execution
        self.dat.validate_timing()

    def on_tool_end(self, output, **kwargs):
        # Log receipt for audit trail
        self.receipts.append(
            agent_did=self.identity.did,
            dat_jti=self.dat.jti,
            action_type="tool_call",
            input_data=input_str.encode(),
            signing_key=self.identity.keypair(),
            tool=kwargs.get("name", "unknown"),
            output_data=output.encode() if output else None,
            status="success"
        )

# Usage
agent_identity = AgentIdentity.load("~/.idprova/identities/agent-alpha")
dat = DAT.from_compact(token_string)
handler = IDProvaAuditCallbackHandler(agent_identity, dat)

llm = ChatOpenAI(callbacks=[handler])
```

### 3. CrewAI — Agent Factory Pattern

```python
from crewai import Agent
from idprova import AgentIdentity

def create_idprova_agent(name: str, role: str, goal: str, domain: str = "yourorg.com") -> tuple[Agent, AgentIdentity]:
    # Create IDProva identity
    identity = AgentIdentity.create(name=name, domain=domain)
    identity.save()

    # Create CrewAI agent with identity metadata
    agent = Agent(
        role=role,
        goal=goal,
        backstory=f"IDProva DID: {identity.did}",
        verbose=True
    )

    return agent, identity

# Usage
researcher, researcher_id = create_idprova_agent(
    name="researcher",
    role="Senior Researcher",
    goal="Find relevant papers"
)

# Issue DAT for this agent
operator = AgentIdentity.load("~/.idprova/identities/operator")
dat = operator.issue_dat(
    subject_did=researcher_id.did,
    scope=["mcp:tool:search:read", "mcp:resource:papers:read"],
    expires_in_seconds=7200
)
```

### 4. AutoGen — Assistant Wrapper Pattern

```python
from autogen import AssistantAgent
from idprova import AgentIdentity, DAT

class IDProvaAssistant:
    def __init__(self, name: str, operator: AgentIdentity, scopes: list[str]):
        self.identity = AgentIdentity.create(name=name)
        self.identity.save()

        self.dat = operator.issue_dat(
            subject_did=self.identity.did,
            scope=scopes,
            expires_in_seconds=3600
        )

        self.agent = AssistantAgent(
            name=name,
            system_message=f"You are {name}. Your DID is {self.identity.did}."
        )

    @property
    def token(self) -> str:
        return self.dat.to_compact()

# Usage
operator = AgentIdentity.load("~/.idprova/identities/operator")
assistant = IDProvaAssistant("coder", operator, ["mcp:tool:*"])
```

### 5. A2A Protocol — Mutual Verification Pattern

In agent-to-agent communication, both sides verify each other:

```python
from idprova import AgentIdentity, DAT, EvaluationContext

class A2ASecureChannel:
    def __init__(self, my_identity: AgentIdentity, my_dat: DAT):
        self.identity = my_identity
        self.dat = my_dat

    def send_request(self, peer_url: str, payload: dict) -> dict:
        """Send authenticated request to peer agent."""
        import httpx
        response = httpx.post(peer_url, json={
            "from": self.identity.did,
            "dat": self.dat.to_compact(),
            "payload": payload
        })
        return response.json()

    def verify_incoming(self, request: dict, peer_public_key: bytes, required_scope: str) -> bool:
        """Verify incoming request from peer agent."""
        peer_dat = DAT.from_compact(request["dat"])
        ctx = EvaluationContext()
        peer_dat.verify(peer_public_key, required_scope, ctx)
        return True  # Raises on failure
```

### 6. Custom HTTP — REST Middleware Pattern

For any HTTP framework, the pattern is the same — extract Bearer token, verify, proceed:

```python
# Flask example
from flask import Flask, request, jsonify, g
from idprova import DAT, EvaluationContext
from functools import wraps

app = Flask(__name__)
OPERATOR_PUB_KEY = bytes.fromhex("...")  # 32 bytes

def require_dat(required_scope: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing bearer token"}), 401
            token = auth[7:]
            try:
                dat = DAT.from_compact(token)
                ctx = EvaluationContext()
                ctx.request_ip = request.remote_addr
                dat.verify(OPERATOR_PUB_KEY, required_scope, ctx)
                g.verified_dat = dat
            except ValueError as e:
                return jsonify({"error": str(e)}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/api/data")
@require_dat("mcp:resource:data:read")
def get_data():
    return jsonify({"data": "...", "authorized_by": g.verified_dat.issuer})
```

```typescript
// Express.js example
import express from 'express';
import { Dat, EvaluationContext } from '@idprova/core';

const OPERATOR_PUB_KEY = Buffer.from('...', 'hex');  // 32 bytes

function requireDat(requiredScope: string) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'missing bearer token' });
    }
    try {
      const dat = Dat.fromCompact(auth.slice(7));
      const ctx = new EvaluationContext();
      dat.verify(OPERATOR_PUB_KEY, requiredScope, ctx);
      (req as any).verifiedDat = dat;
      next();
    } catch (e) {
      res.status(401).json({ error: String(e) });
    }
  };
}

app.get('/api/data', requireDat('mcp:resource:data:read'), (req, res) => {
  res.json({ data: '...', authorized_by: (req as any).verifiedDat.issuer });
});
```

---

## Persona Quick-Starts

### Solo Developer — 15 Minutes

You're building a personal agent setup. Skip the delegation chain complexity.

1. **Install:** `cargo build --release -p idprova-cli -p idprova-registry` (5 min)
2. **Bootstrap:** Generate one keypair, create one AID (self-controller), start registry (3 min)
3. **Use the operator DAT directly:** Issue a DAT from operator to your agent with broad scopes (2 min)
4. **Verify works:** `idprova dat verify <token> --registry http://localhost:3000` (1 min)
5. **Add to your agent code:** Attach DAT as Bearer token in API calls (4 min)

Skip: Multi-tier delegation, compliance mapping, HA registry.

### Team Lead — 2 Hours

You manage 5-10 agents across a project.

1. **Day 0 complete** (30 min) — bootstrap operator + registry
2. **Register all agents** (30 min) — one AID per agent, operator as controller
3. **Design scope hierarchy** (15 min) — map your tools to `namespace:resource:action`
4. **Issue DATs** (15 min) — operator → team lead → workers
5. **Integrate with CI/CD** (30 min) — add DAT issuance to agent startup scripts
6. **Verify audit trail** (15 min) — check receipt chain integrity

### Enterprise Architect — 1 Day

You're deploying IDProva across departments with compliance requirements.

| Time | Task |
|------|------|
| Morning (2h) | Day 0 bootstrap + multi-department AID hierarchy design |
| Late Morning (1h) | Registry HA planning (multiple instances, shared SQLite or Postgres migration) |
| Early Afternoon (2h) | Compliance mapping (NIST/ISM/SOC 2 controls → IDProva features, see table above) |
| Late Afternoon (2h) | Integration proof-of-concept with existing agent framework |
| End of Day (1h) | Documentation: operational runbook, key rotation schedule, incident response for DAT compromise |

---

## Registry API Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/health` | Health check (`{"status":"ok","version":"0.1.0","protocol":"idprova"}`) |
| `GET` | `/v1/meta` | Protocol metadata (version, DID method, algorithms) |
| `GET` | `/v1/aids` | List all registered AIDs |
| `PUT` | `/v1/aid/{id}` | Register or update an AID document |
| `GET` | `/v1/aid/{id}` | Resolve AID by DID suffix |
| `DELETE` | `/v1/aid/{id}` | Deactivate an AID |
| `GET` | `/v1/aid/{id}/key` | Get public keys for an AID |
| `POST` | `/v1/dat/verify` | Verify a DAT token (with optional scope/constraints) |
| `POST` | `/v1/dat/revoke` | Revoke a DAT by JTI |
| `GET` | `/v1/dat/revoked/{jti}` | Check if a DAT is revoked |

**Rate limiting:** 120 requests per 60-second window per IP.

**Admin auth:** Set `REGISTRY_ADMIN_PUBKEY` env var to require admin DAT for write operations. Without it, the registry runs in dev mode (open writes).

---

## Next Steps

- **Demo GUI:** Run the interactive web GUI (`web/` directory) to explore all operations visually
- **Protocol Spec:** See `docs/protocol-spec-v0.1.md` for the full technical specification
- **Threat Model:** See `docs/STRIDE-THREAT-MODEL.md` for security analysis
- **NIST Response:** See `docs/NIST-RFI-Response-Draft.md` for our response to NIST's AI identity RFI
