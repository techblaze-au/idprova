<div align="center">

# IDProva

**Verifiable identity for the agent era**

[![CI](https://github.com/techblaze-au/idprova/actions/workflows/ci.yml/badge.svg)](https://github.com/techblaze-au/idprova/actions)
[![Crates.io](https://img.shields.io/crates/v/idprova-core.svg)](https://crates.io/crates/idprova-core)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1--draft-orange.svg)](https://idprova.dev)
[![NIST](https://img.shields.io/badge/NIST-2025--0035-green.svg)](#compliance)

An open protocol for cryptographically verifiable identity, scoped delegation, and tamper-evident audit trails for autonomous AI agents.

[Documentation](https://idprova.dev) · [Specification](https://idprova.dev/docs/protocol/overview) · [Quick Start](#quick-start) · [Blog](https://idprova.dev/blog)

</div>

---

## The Problem

AI agents are making decisions, calling APIs, delegating tasks to other agents, and accessing sensitive systems — but there's no standard way to know **which agent did what, with whose permission, and whether you can prove it**.

92% of organizations lack visibility into AI agent identities. Existing identity systems (OAuth, API keys, SPIFFE) were designed for humans or workloads, not autonomous agents that delegate to other agents.

## The Solution: Three Pillars

IDProva solves this with three interlocking components:

### 🪪 Agent Identity Documents (AIDs)
W3C DID-based cryptographic identities purpose-built for AI agents. Not humans, not workloads — agents.

```
did:idprova:techblaze.com.au:kai
│   │       │                 │
│   │       │                 └─ agent name
│   │       └─ domain (verification anchor)
│   └─ method
└─ DID scheme
```

### 🔐 Delegation Authority Tokens (DATs)
Signed, scoped, time-bounded, chainable permission tokens. A human delegates to an agent, that agent can sub-delegate with automatic scope narrowing.

```
Operator → Agent A (full access) → Agent B (read-only, 1 hour, max 10 actions)
```

### 📋 Action Receipts
Hash-chained, tamper-evident audit logs of every agent action. Mappable to NIST 800-53, Australian ISM, and SOC 2 compliance frameworks.

## Quick Start

### Install

```bash
cargo install idprova-cli
```

### Generate keys

```bash
idprova keygen --output my-agent.key
# Output: Private key file + public key file + public key (multibase)
```

### Create an Agent Identity

```bash
idprova aid create \
  --id "did:idprova:example.com:my-agent" \
  --name "My Agent" \
  --controller "did:idprova:example.com:operator" \
  --key my-agent.key
```

### Issue a Delegation Token

```bash
idprova dat issue \
  --issuer "did:idprova:example.com:operator" \
  --subject "did:idprova:example.com:my-agent" \
  --scope "mcp:tool:filesystem:read" \
  --expires-in 24h \
  --key operator.key
```

### Verify an Agent Identity

```bash
idprova aid verify my-agent.aid.json
# ✓ AID signature valid
# ✓ DID format correct
```

### Verify Receipt Chain Integrity

```bash
idprova receipt verify agent-actions.jsonl
# ✓ Hash chain intact (47 entries)
# ✓ No gaps detected
# ✓ All signatures valid
```

## Architecture

```
HUMAN OPERATOR (key holder)
    │ issues DAT (scoped, time-bounded)
    ▼
AGENT RUNTIME                    IDProva Registry
  ┌───────────────┐              ┌──────────────────────┐
  │ IDProva SDK   │──────────►   │  DID Resolution      │
  │ - AID Store   │              │  AID CRUD             │
  │ - DAT Wallet  │              │  Trust Verification   │
  │ - Receipt Log │              └──────────────────────┘
  └───────┬───────┘
          │ presents AID + DAT
          ▼
MCP SERVER / A2A SERVICE
  ┌──────────────────────────────────┐
  │  IDProva Verification Middleware │
  │  1. Resolve AID → public key    │
  │  2. Verify DAT signature chain  │
  │  3. Check scope vs operation    │
  │  4. Log Action Receipt          │
  │  5. Allow / Deny                │
  └──────────────────────────────────┘
```

## Trust Levels

| Level | Name | Verification | Use Case |
|-------|------|-------------|----------|
| L0 | Self-declared | None | Development, testing |
| L1 | Domain-verified | DNS TXT record | Production agents |
| L2 | Organization-verified | CA-like process | Enterprise agents |
| L3 | Third-party audited | External audit | Regulated industries |
| L4 | Continuously monitored | Runtime monitoring | Critical infrastructure |

## Cryptography

| Purpose | Algorithm | Status |
|---------|-----------|--------|
| Signatures | Ed25519 | ✅ Active |
| Hashing | BLAKE3 | ✅ Active |
| Interop | SHA-256 | ✅ Active |
| Post-Quantum | ML-DSA-65 (FIPS 204) | 🔜 Planned |

IDProva is designed to be **PQC-agile** from day one. Hybrid Ed25519 + ML-DSA-65 support is on the roadmap, with a migration path to PQC-only by 2029+.

## Workspace Structure

```
idprova/
├── crates/
│   ├── idprova-core/       # Core library (crypto, AID, DAT, receipts, trust)
│   ├── idprova-cli/        # Command-line tool
│   └── idprova-registry/   # Registry server (Axum + SQLite)
├── sdks/
│   ├── python/             # Python SDK (PyO3) — coming soon
│   └── typescript/         # TypeScript SDK — planned
├── test-vectors/           # Interoperability test vectors
├── docs/                   # Protocol specification
└── examples/               # Integration examples
```

## Compliance

IDProva maps to major compliance frameworks:

| Framework | Controls | IDProva Component |
|-----------|----------|-------------------|
| **NIST 800-53** | AU-2, AU-3, AU-8, AU-9, AU-10, AU-12, IA-2, AC-6 | Receipts, AIDs, DATs |
| **Australian ISM** | Agent identity, access control, audit logging | All three pillars |
| **SOC 2** | CC6.1, CC6.3, CC7.2 | DATs, Receipts |

IDProva has been submitted to NIST as **NIST-2025-0035** under the Collaborative AI Security Initiative (CAISI).

## Why Not...?

| Solution | Limitation |
|----------|-----------|
| OAuth 2.0 / OIDC | Designed for humans. No delegation chains, no agent metadata, no audit trail. |
| SPIFFE / SPIRE | Workload identity. No delegation, no scope narrowing, no receipts. |
| API Keys | Shared secrets. No identity, no delegation, no rotation, no audit. |
| Verifiable Credentials | Credential format only. No agent-specific semantics, no receipt chain. |
| **IDProva** | **All three pillars: identity + delegation + audit. Agent-native.** |

## Running the Registry

```bash
# Using Docker
docker run -p 3000:3000 idprova/registry

# From source
cd crates/idprova-registry
cargo run
```

The registry exposes:
- `GET /health` — Health check
- `GET /v1/meta` — Protocol metadata
- `GET /v1/aid/{did}` — Resolve an AID
- `PUT /v1/aid/{did}` — Register/update an AID
- `DELETE /v1/aid/{did}` — Deactivate an AID

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is especially welcome:
- Python SDK (PyO3 bindings)
- TypeScript SDK (napi-rs)
- MCP authentication middleware
- Agent framework integrations (LangChain, CrewAI, AutoGen)
- Additional compliance framework mappings

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Links

- 📖 [Documentation](https://idprova.dev)
- 🏠 [Tech Blaze Consulting](https://techblaze.com.au/idprova)
- 🔒 [Security Policy](SECURITY.md)
- 📝 [Changelog](CHANGELOG.md)

---

<div align="center">

Built by [Tech Blaze Consulting](https://techblaze.com.au) · Submitted to NIST · Apache 2.0

</div>
