<div align="center">

<h1>IDProva</h1>

<h3>Identity for AI agents — the layer your existing IdP was never designed for</h3>

<p>An open protocol for cryptographically verifiable agent identity, scoped delegation, and tamper-evident audit. Apache 2.0. Self-hostable on AWS, GCP, Azure, or air-gapped. Built in Australia. Deployable globally.</p>

[![CI](https://github.com/techblaze-au/idprova/actions/workflows/ci.yml/badge.svg)](https://github.com/techblaze-au/idprova/actions)
[![Crates.io](https://img.shields.io/crates/v/idprova-core.svg)](https://crates.io/crates/idprova-core)
[![PyPI](https://img.shields.io/pypi/v/idprova.svg)](https://pypi.org/project/idprova/)
[![npm](https://img.shields.io/npm/v/@idprova/core.svg)](https://www.npmjs.com/package/@idprova/core)
[![Docs.rs](https://img.shields.io/docsrs/idprova-core)](https://docs.rs/idprova-core)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1--draft-orange.svg)](docs/protocol-spec-v0.1.md)
[![NIST](https://img.shields.io/badge/NIST-CAISI--filed-success)](docs/compliance.md)

[Documentation](https://idprova.dev) | [Getting Started](docs/getting-started.md) | [Protocol Spec](docs/protocol-spec-v0.1.md) | [Compliance](docs/compliance.md) | [Cloud Product](https://idprova.com)

</div>

---

## Why IDProva?

You've already invested in identity infrastructure. Okta, Entra ID, Auth0, your custom CIAM — these handle humans well. Now AI agents are calling your APIs, delegating to sub-agents, and accessing sensitive systems on behalf of users.

**The gap:** every line of your existing identity stack was designed for humans who type passwords, click "allow", and authenticate dozens of times per day. None of it answers the questions that matter for AI agents:

- **Who** is this agent — cryptographically, not just by API key?
- **What** is it allowed to do, and **who** granted that permission?
- **What did it do** — and can you prove the audit trail wasn't tampered with?

OAuth tokens don't chain. JWTs don't carry delegation provenance. API keys can't scope to specific actions. SPIFFE was built for workloads, not delegation chains. None of them produce tamper-evident audit logs you can take to a compliance auditor.

**IDProva is the layer that fits alongside your existing IdP** — three cryptographic primitives designed specifically for AI agents:

| Primitive | Purpose |
|---|---|
| **Agent Identity Documents (AIDs)** | W3C DID-based identity bound to Ed25519 + ML-DSA-65 hybrid keys |
| **Delegation Attestation Tokens (DATs)** | Signed, scoped, time-bounded, chainable permission tokens |
| **Action Receipts** | Hash-chained, tamper-evident audit log of every agent action, mapped to compliance controls |

You keep Okta. You keep Entra ID. You keep Auth0. You add IDProva for the agents.

## Where this fits

Three deployment stories — pick whichever fits your environment:

### 1. Global Cloud
Hosted IDProva on AWS, GCP, or Azure in your region of choice. AU (live), US East (v1.0), EU Frankfurt (v1.0 stretch), Singapore + UAE (v1.1). Web dashboard, SSO, RBAC, compliance report generator, SIEM integration, anomaly detection. Starting at $149/mo. → [idprova.com](https://idprova.com)

### 2. Self-hosted Enterprise
Run the full stack inside your VPC. Apache 2.0 source. No licence fees for the protocol. Commercial Enterprise Edition available with SLA, support, and additional management features.

### 3. Sovereign / air-gapped
Deploy in PROTECTED, classified, or otherwise isolated environments. Offline issuance and verification. Epoch-based revocation list distribution. No phone-home requirement. Designed for defence, intelligence, and critical infrastructure.

## Works alongside your existing identity stack

| Existing IdP | Integration pattern | Effort |
|---|---|---|
| **Okta** | OIDC ID token → RFC 8693 token exchange → IDProva DAT | ~50 lines of code |
| **Microsoft Entra ID** | Entra Agent ID provisions → IDProva wraps actions in DATs + signs receipts (complementary) | Configurable; existing Entra deployment unchanged |
| **Auth0** | Auth0 Action calls IDProva `/v1/dat/issue` after user authentication | ~30 lines of JavaScript |
| **Custom / SAML** | Generic OIDC bridge or direct DAT issuance from your auth callback | Varies; ~1 day for typical integrations |

See `docs/integrations/` for full integration walkthroughs (LangChain, MCP, CrewAI, AutoGen).

## Quick Install

### From package registries

```bash
# Rust (CLI + core library)
cargo install idprova-cli

# Python SDK (PyO3 bindings)
pip install idprova

# TypeScript SDK (napi-rs bindings)
npm install @idprova/core
```

### Build from source

```bash
git clone https://github.com/techblaze-au/idprova.git
cd idprova
cargo build --release
# Binaries at: target/release/idprova and target/release/idprova-registry
```

### Docker

```bash
docker pull techblazeau/idprova:latest
docker run -p 8080:8080 techblazeau/idprova:latest
```

## 60-Second Quickstart

### CLI: generate keys, create identity, issue delegation

```bash
# 1. Generate an Ed25519 keypair
idprova keygen --output operator.key

# 2. Create an Agent Identity Document
idprova aid create \
  --id "did:aid:example.com:my-agent" \
  --name "My Agent" \
  --controller "did:aid:example.com:operator" \
  --key operator.key

# 3. Issue a scoped delegation token (read-only, 24h expiry)
idprova dat issue \
  --issuer "did:aid:example.com:operator" \
  --subject "did:aid:example.com:my-agent" \
  --scope "mcp:tool:filesystem:read" \
  --expires-in 24h \
  --key operator.key

# 4. Verify the token
idprova dat verify <TOKEN> --key operator.key.pub --scope "mcp:tool:filesystem:read"
```

### Python: LangChain integration in 30 lines _(v1.0 target API — preview)_

> The `idprova_langchain` callback handler lands as part of the v1.0 launch (target 2026-08-25; sandbox in flight Wk 2 of the launch plan, May 13–19). The snippet below is the shape it will take. Today's working Python integration uses `from idprova_http import IDProvaClient` — see [`examples/python/`](examples/python/) and [`docs/integrations/`](docs/integrations/).

```python
from langchain.agents import AgentExecutor, create_react_agent
from idprova_langchain import IDProvaAuditCallbackHandler
from idprova import AgentIdentity

# 1. Identify your agent
agent_identity = AgentIdentity.create(
    name="customer-support-agent",
    domain="example.com",
)

# 2. Get a delegation token (in production, this comes from your IdP)
dat = agent_identity.issue_dat(
    subject_did=agent_identity.did,
    scope="mcp:tool:knowledge-base:read",
    expires_in_seconds=3600,
)

# 3. Attach IDProva audit to your LangChain agent
audit = IDProvaAuditCallbackHandler(
    agent_did=agent_identity.did,
    dat_token=dat.to_compact(),
    receipts_path="/var/lib/idprova/receipts/",
    registry_url="https://registry.idprova.com",
)

# 4. Use your agent normally — every tool call now produces a signed receipt
executor = AgentExecutor(agent=your_agent, tools=your_tools, callbacks=[audit])
executor.invoke({"input": "Help me find that order"})
```

The receipt log is now an audit-grade record of every action your agent took, signed and chained.

### Rust: programmatic usage

```rust
use idprova_core::crypto::KeyPair;
use idprova_core::aid::AidBuilder;
use idprova_core::dat::Dat;
use chrono::{Utc, Duration};

// Generate keys
let keypair = KeyPair::generate();

// Create an Agent Identity Document
let aid = AidBuilder::new()
    .id("did:aid:example.com:my-agent")
    .controller("did:aid:example.com:operator")
    .name("My Agent")
    .add_ed25519_key(&keypair)
    .build()?;

// Issue a Delegation Attestation Token
let dat = Dat::issue(
    "did:aid:example.com:operator",   // issuer
    "did:aid:example.com:my-agent",   // subject
    vec!["mcp:tool:filesystem:read".into()],
    Utc::now() + Duration::hours(24), // expiry
    None,                              // constraints
    None,                              // config attestation
    &keypair,
)?;

// Receipts produced by `idprova-verify` middleware automatically
```

## Standards alignment

IDProva is designed to fit into existing standards rather than invent new ones where it doesn't have to:

| Standard | Role | Status |
|---|---|---|
| **W3C DID Core 1.0** | Identifier model (`did:aid:` method) | Aligned; submitted to DID Method Registry |
| **NIST SP 800-53 Rev 5** | Compliance control mapping (US Federal + global enterprise) | [docs/controls.md](docs/controls.md) |
| **NIST SP 800-207 Zero Trust** | Architectural alignment | [docs/compliance.md](docs/compliance.md) |
| **NIST CAISI submission** | AI standards body engagement | Filed (NIST-2025-0035) |
| **GDPR (EU 2016/679)** | EU privacy compliance mapping | [docs/gdpr.md](docs/gdpr.md) |
| **EU AI Act (2024/1689)** | Logging + transparency obligations | [docs/gdpr.md](docs/gdpr.md) §EU AI Act |
| **ISO 27001:2022** | Annex A control mapping | (planned v1.0) |
| **Australian ISM** | Defence-aligned controls | [docs/compliance.md](docs/compliance.md) |
| **Singapore MAS TRM** | SG financial services | (planned v1.0) |
| **UAE NESA** | UAE government + financial | (planned v1.0) |
| **HIPAA Security Rule** | US healthcare | (planned v1.0) |
| **SOC 2 Type II readiness** | US enterprise procurement | (planned v1.0 mapping pack; certification v1.1) |
| **JOSE / JWS** | DAT token format | RFC 7515-compliant |
| **RFC 8693** | OAuth token exchange (IdP integration) | Supported in `idprova-bridge` |
| **FIPS 204 (ML-DSA-65)** | Post-quantum signatures (hybrid mode) | Supported in `idprova-core` |
| **BLAKE3** | Receipt hash chain | Native |
| **Ed25519 (RFC 8032)** | Classical signatures | Native |

## Cryptographic foundations

- **Ed25519** for classical signatures (RFC 8032). Constant-time, 128-bit security level, 64-byte signatures.
- **ML-DSA-65** for post-quantum signatures (FIPS 204). Hybrid signing supported — operators choose classical-only, hybrid, or PQ-only per identity.
- **BLAKE3** for content hashing in the receipt chain. Parallelisable, faster than SHA-256 on modern CPUs.

See [docs/security.md](docs/security.md) for cryptographic rationale and [docs/STRIDE-THREAT-MODEL.md](docs/STRIDE-THREAT-MODEL.md) for the formal threat analysis.

## Documentation

- [Getting Started](docs/getting-started.md) — install, configure, issue your first DAT
- [Protocol Specification](docs/protocol-spec-v0.1.md) — the full spec, normative
- [Concepts](docs/concepts.md) — AIDs, DATs, scopes, trust levels, receipts
- [Core API](docs/core-api.md) — Rust core library reference
- [Python SDK](docs/sdk-python.md) — PyO3 bindings reference
- [TypeScript SDK](docs/sdk-typescript.md) — napi-rs bindings reference
- [API Reference](docs/api-reference.md) — registry HTTP API
- [Adoption Guide](docs/ADOPTION-GUIDE.md) — for engineering leaders considering IDProva
- [Technical Requirements](docs/TRD.md) — detailed technical requirements
- [Threat Model](docs/STRIDE-THREAT-MODEL.md) — STRIDE analysis
- [Security Model](docs/security.md) — cryptographic foundations
- [Key Rotation](docs/key-rotation.md) — operator playbook
- [NIST 800-53 Mapping](docs/controls.md) — compliance control mapping
- [GDPR Mapping](docs/gdpr.md) — EU privacy + AI Act alignment
- [Compliance Overview](docs/compliance.md) — ISM + Zero Trust mapping

## Status

IDProva v0.1 was published 2026-03-23. Spec is `v0.1-draft`; v1.0 launch targeted for late August 2026. Track progress at [the public roadmap](https://github.com/techblaze-au/idprova/projects).

## Contributing

We accept contributions via Developer Certificate of Origin (DCO) — sign off your commits with `git commit -s`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

Security disclosures: please email `security@idprova.dev` rather than opening a public issue. See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## Built by

[Tech Blaze](https://techblaze.com.au) — a Canberra-based cybersecurity consultancy. We build IDProva and publish what we learn building it on the [Tech Blaze YouTube channel](https://youtube.com/@techblaze).

For commercial support, IDProva Cloud, or implementation consulting, see [idprova.com](https://idprova.com) or contact [hello@techblaze.com.au](mailto:hello@techblaze.com.au).

## Licence

Protocol spec, core library, SDKs, and registry: Apache License 2.0. See [LICENSE](LICENSE).

The Cloud product (idprova.com) and the commercial Self-hosted Enterprise Edition are separately licensed; see [idprova.com/terms](https://idprova.com/terms) for details.
