# IDProva — Project Plan & Status

> **Last Updated:** 2026-03-02
> **Version:** 0.1.0-draft
> **Owner:** Tech Blaze Consulting Pty Ltd (Pratyush Sood)

---

## 1. Project Overview

**IDProva** is an open protocol for establishing cryptographically verifiable identity, scoped delegation, and tamper-evident audit trails for autonomous AI agents. Positioned as **"the OAuth of the agent era"**.

**Tagline:** *Verifiable identity for the agent era*

| Item | Value |
|------|-------|
| License | Apache 2.0 |
| Spec Version | v0.1-draft |
| NIST Submission | NIST-2025-0035 (CAISI) |
| GitHub | github.com/techblaze-au/idprova |
| Documentation | idprova.dev |
| Landing Page | techblaze.com.au/idprova |
| Protocol DID | `did:idprova:` |

### Why IDProva Exists

- 92% of organizations lack visibility into AI agent identities
- Existing identity systems (OAuth, API keys, SPIFFE) were designed for humans or workloads, not agents
- No standard for agent delegation chains or scoped permissions
- No tamper-evident audit trail standard for agent actions
- Quantum computing threatens current cryptographic identities

### Three Pillars

1. **Identity (AIDs)** — W3C DID-based Agent Identity Documents with cryptographic keys, metadata, trust levels
2. **Delegation (DATs)** — Signed, scoped, time-bounded, chainable permission tokens (JWS format)
3. **Audit (Action Receipts)** — Hash-chained, signed audit trails mapped to compliance frameworks

---

## 2. Project Locations

| Project | Path | Purpose |
|---------|------|---------|
| **IDProva** (Rust) | `C:\Users\praty\toon_conversations\IDProva\` | Core library, CLI, registry server |
| **idprova-website** | `C:\Users\praty\toon_conversations\idprova-website\` | Documentation site (idprova.dev) |
| **tech-blaze-web** | `C:\Users\praty\toon_conversations\Tech Blaze website\tech-blaze-web\` | Landing page at /idprova |

---

## 3. Architecture

### Protocol Flow

```
HUMAN OPERATOR (key holder, delegator)
    │ issues DAT (scoped, time-bounded)
    ▼
AGENT RUNTIME                    IDProva Registry
  ┌───────────────┐              ┌──────────────────────┐
  │ IDProva SDK   │              │  GET /v1/aid/{id}    │
  │ - AID Store   │──────────►   │  PUT /v1/aid/{id}    │
  │ - DAT Wallet  │              │  DELETE /v1/aid/{id} │
  │ - Receipt Log │              └──────────────────────┘
  │ - MCP Auth    │
  └───────┬───────┘
          │ presents AID + DAT
          ▼
MCP SERVER / A2A SERVICE
  ┌──────────────────────────────────┐
  │  IDProva Verification Middleware │
  │  1. Extract AID + DAT           │
  │  2. Resolve AID → public key    │
  │  3. Verify DAT signature chain  │
  │  4. Check scope vs operation    │
  │  5. Check expiry + constraints  │
  │  6. Log Action Receipt          │
  │  7. Allow / Deny                │
  └──────────────────────────────────┘
```

### DID Method Format

```
did:idprova:techblaze.com.au:kai
│   │       │                 │
│   │       │                 └─ local name
│   │       └─ domain (namespace + L1 verification anchor)
│   └─ method name
└─ DID scheme
```

### Scope Grammar

```
scope     = namespace ":" resource ":" action
namespace = "mcp" | "a2a" | "idprova" | "http" | custom
resource  = name | "*"
action    = "read" | "write" | "execute" | "delegate" | "*"

Examples:
  mcp:tool:filesystem:read       — read-only filesystem tool
  mcp:tool:*:*                   — all MCP tools, all actions
  a2a:agent:billing:execute      — execute on A2A billing agent
  idprova:delegate:L0            — can sub-delegate at L0 trust
```

### Trust Levels

| Level | Name | Verification |
|-------|------|-------------|
| L0 | Self-declared | Unverified |
| L1 | Domain-verified | DNS TXT record |
| L2 | Organization-verified | CA-like |
| L3 | Third-party audited | External audit |
| L4 | Continuously monitored | Runtime monitoring |

### Cryptography

| Purpose | Algorithm | Library | Status |
|---------|-----------|---------|--------|
| Signatures | Ed25519 | ed25519-dalek v2 (audited) | Active |
| Hashing | BLAKE3 | blake3 crate | Active |
| Interop hashing | SHA-256 | sha2 crate | Active |
| Key encoding | Multibase (base58btc) | multibase crate | Active |
| Post-Quantum | ML-DSA-65 (FIPS 204) | fips204 crate | Planned |

**PQC Roadmap:**
- Phase 0 (Current): Ed25519 only, PQC agile design
- Phase 1: Hybrid Ed25519 + ML-DSA-65 support
- Phase 2: PQC-preferred, classical fallback
- Phase 3 (2029+): PQC-only option

---

## 4. Rust Implementation Status (IDProva)

### Workspace Structure

```
idprova/
├── Cargo.toml                 # Rust workspace (resolver v2)
├── crates/
│   ├── idprova-core/          # Core library
│   ├── idprova-registry/      # Registry server (Axum + SQLite)
│   └── idprova-cli/           # CLI tool
├── sdks/
│   ├── python/                # Python SDK (PyO3) — placeholder
│   └── typescript/            # TypeScript SDK (napi-rs) — planned
├── test-vectors/              # Published test vectors
├── docs/                      # Protocol specification
└── examples/                  # Integration examples
```

### Core Library (idprova-core) — 100% Complete

| Module | Files | Status | Details |
|--------|-------|--------|---------|
| **crypto** | keys.rs, hash.rs | 100% | Ed25519 keygen, sign, verify; BLAKE3/SHA-256 hashing; multibase encoding. 5 tests. |
| **aid** | document.rs, builder.rs | 100% | DID parsing/validation, AidDocument with W3C DID structure, fluent builder, proof generation. 14 tests. |
| **dat** | token.rs, scope.rs, chain.rs | 100% | JWS token issue/verify, scope parsing with wildcards, delegation chain validation with scope narrowing. 11 tests. |
| **receipt** | entry.rs, log.rs | 100% | ActionDetails, hash-chained receipts, append-only log with integrity verification. |
| **trust** | level.rs | 100% | L0-L4 enum with ordering, parsing, minimum-check. 4 tests. |
| **error** | error.rs | 100% | Comprehensive error enum covering crypto, AID, DAT, receipt, trust, serialization. |

**Key Implementation Details:**
- DatClaims include: iss, sub, iat, exp, nbf, jti, scope, constraints, config_attestation, delegation_chain
- DatConstraints support: max_actions, allowed_servers, require_receipt
- Chain validation enforces: parent-child issuer linkage, scope narrowing, expiry inheritance
- Receipt ChainLink: previous_hash (or "genesis") + sequence_number
- ReceiptLog: verify_integrity() checks hash chain continuity

### CLI (idprova-cli) — 95% Complete

| Command | Status | Notes |
|---------|--------|-------|
| `idprova keygen` | 100% | Generate Ed25519 keypair, hex-encoded secret, multibase public |
| `idprova aid create` | 100% | Build + sign AID document, save JSON |
| `idprova aid resolve` | STUB | "Registry client not yet implemented — coming in v0.1" |
| `idprova aid verify` | 100% | Load + validate AID from JSON file |
| `idprova dat issue` | 100% | Issue DAT with scopes, expiry, constraints |
| `idprova dat verify` | 80% | Validates timing, prints claims; signature verify needs registry |
| `idprova dat inspect` | 100% | Decode + pretty-print DAT without verification |
| `idprova receipt verify` | 100% | Load JSONL receipt log, verify hash chain integrity |
| `idprova receipt stats` | 100% | Action type counts, timestamps, entry totals |

### Registry Server (idprova-registry) — 100% Complete

| Endpoint | Method | Status |
|----------|--------|--------|
| `/health` | GET | 100% — Returns status, version, protocol |
| `/v1/meta` | GET | 100% — Protocol metadata, algorithms |
| `/v1/aid/:id` | PUT | 100% — Register/update AID (validates, stores) |
| `/v1/aid/:id` | GET | 100% — Resolve AID (returns document or 404) |
| `/v1/aid/:id` | DELETE | 100% — Soft-delete AID |
| `/v1/aid/:id/key` | GET | 100% — Return verification methods |

**Stack:** Axum 0.7 + SQLite (rusqlite bundled) + tokio async

### Build Configuration

- Rust edition: 2021, MSRV: 1.75
- Release profile: LTO enabled, stripped binaries, single codegen unit
- No git commits yet (bootstrap state)
- PQC dependency (fips204) commented out, ready to enable

---

## 5. Documentation Site Status (idprova-website)

**Stack:** Astro 5.6.1 + Starlight 0.37.6 + Tailwind CSS 4.2.1
**Fonts:** Inter (body), Plus Jakarta Sans (headings), JetBrains Mono (code)
**Brand:** Indigo accent (#4F46E5), dark mode supported (Slate)

### Content Completeness

| Section | Pages | Complete | Stubs | % Done |
|---------|-------|----------|-------|--------|
| Getting Started | 2 | 2 | 0 | **100%** |
| Concepts | 4 | 4 | 0 | **100%** |
| Protocol Spec | 5 | 5 | 0 | **100%** |
| Guides | 4 | 0 | 4 | **0%** |
| Reference | 3 | 0 | 3 | **0%** |
| Compliance | 3 | 0 | 3 | **0%** |
| Blog | 5 | 5 | 0 | **100%** |
| FAQ + Home | 2 | 2 | 0 | **100%** |
| **TOTAL** | **28** | **18** | **10** | **64%** |

### Completed Pages (18)

**Getting Started:**
- Introduction — Full explanation of purpose, design principles, three pillars
- Quick Start — Step-by-step CLI + Rust SDK walkthrough

**Concepts (all ~5-6K words each):**
- Agent Identity (AIDs) — DID syntax, document structure, metadata, CRUD
- Delegation (DATs) — Token format, scope grammar, constraints, chains, revocation
- Audit (Receipts) — Receipt structure, hash chaining, verification, compliance mapping
- Trust Levels — L0-L4 progressive model, temporal/contextual/directional properties

**Protocol Specification (8-11K words each):**
- AID Format & DID Method — Full technical reference
- DAT Structure & Scopes — JWS format, claims, scope grammar, validation algorithm
- Action Receipts — Receipt structure, hash chaining, compliance mapping
- Cryptography — Hybrid Ed25519+ML-DSA-65, hashing, key encoding, PQC roadmap
- Protocol Bindings — MCP, A2A, HTTP integration specs

**Blog (5 articles, 6-8.5K words each):**
- Introducing IDProva
- The Identity Gap in Agentic AI
- Post-Quantum Agent Identity
- IDProva & NIST 800-53
- IDProva vs OAuth

**Other:**
- FAQ — 30+ questions covering general, technical, compliance
- Homepage — Full splash with hero, pillars, quick start tabs, comparison table

### Stub Pages (10) — Need Content

**Guides (4 pages):**
- [ ] CLI Usage — Advanced CLI workflows beyond quick start
- [ ] MCP Authentication — Step-by-step MCP server/client integration
- [ ] Rust SDK — API patterns, error handling, advanced usage
- [ ] Running a Registry — Deployment, configuration, federation

**Reference (3 pages):**
- [ ] Core API — idprova-core crate documentation
- [ ] CLI Commands — Complete command reference with all flags
- [ ] Registry API — REST API reference with examples

**Compliance (3 pages):**
- [ ] NIST 800-53 Mapping — Detailed control-by-control mapping
- [ ] Australian ISM — ISM control mapping
- [ ] SOC 2 Mapping — TSC criteria mapping

---

## 6. Tech Blaze Website Integration

### Landing Page (`/idprova`)
- **File:** `src/pages/idprova.astro` (untracked in git)
- **Status:** Complete, uses BaseLayout with proper SEO
- **Sections:** Hero (navy), Three Pillars (white), Why IDProva (gray), CTA (dark)
- **Links to:** idprova.dev (docs), GitHub, /contact

### Navigation
- **Header:** IDProva Protocol link in Services dropdown (indigo text)
- **Footer:** IDProva Protocol link in Resources section

### Action Needed
- [ ] Commit `idprova.astro` to git (currently untracked)
- [ ] Verify CSP headers in vercel.json allow idprova.dev links

---

## 7. SDK Roadmap

| SDK | Package | Status | Technology |
|-----|---------|--------|------------|
| Rust | `idprova-core` | **95% complete** | Native |
| Python | `idprova` (PyPI) | Placeholder exists | PyO3 bindings |
| TypeScript | `@idprova/core` (npm) | Planned | napi-rs |
| Go | `github.com/techblaze-au/idprova-go` | Planned (v0.2) | Native |

---

## 8. Compliance Positioning

### Framework Mappings

| Framework | Key Controls | IDProva Component |
|-----------|-------------|-------------------|
| **NIST 800-53** | AU-2, AU-3, AU-8, AU-9, AU-10, AU-12, IA-2, AC-6 | Receipts (AU-*), AIDs (IA-2), DATs (AC-6) |
| **Australian ISM** | Agent identity, access control, audit logging | All three pillars |
| **SOC 2** | CC6.1, CC6.3, CC7.2 | DATs (CC6.1/6.3), Receipts (CC7.2) |

### NIST CAISI Submission
- Submission ID: NIST-2025-0035
- Participating in NCCoE AI Agent Identity project

---

## 9. Open Tasks & Next Steps

### Priority 1 — Ship v0.1.0

- [ ] **Initialize git repos** for IDProva and idprova-website (both have no commits)
- [ ] **Build & test** Rust workspace (`cargo build`, `cargo test`)
- [ ] **Implement CLI `aid resolve`** — HTTP client to query registry
- [ ] **Implement CLI `dat verify` signature** — Resolve AID for public key, verify JWS sig
- [ ] **Enable PQC** — Uncomment fips204 dependency, add hybrid signing support
- [ ] **Publish to crates.io** — idprova-core, idprova-cli
- [ ] **Create GitHub repo** — github.com/techblaze-au/idprova
- [ ] **Commit idprova.astro** to tech-blaze-web repo

### Priority 2 — Documentation Completeness

- [ ] Write **CLI Usage** guide
- [ ] Write **MCP Authentication** guide
- [ ] Write **Rust SDK** guide
- [ ] Write **Running a Registry** guide
- [ ] Write **Core API** reference (from Rust doc comments)
- [ ] Write **CLI Commands** reference
- [ ] Write **Registry API** reference (OpenAPI spec)
- [ ] Write **NIST 800-53** detailed control mapping
- [ ] Write **Australian ISM** control mapping
- [ ] Write **SOC 2** criteria mapping

### Priority 3 — Ecosystem & Growth

- [ ] **Python SDK** — PyO3 bindings for idprova-core
- [ ] **TypeScript SDK** — napi-rs bindings
- [ ] **Docker image** for registry server
- [ ] **MCP middleware** — Drop-in IDProva verification for MCP servers
- [ ] **A2A extension** — IDProva integration for Agent-to-Agent protocol
- [ ] **Real-world examples** — Multi-agent delegation, compliance audit workflow
- [ ] **Test vectors** — Published test vectors for interop testing
- [ ] **CI/CD** — GitHub Actions for build, test, publish
- [ ] **Deploy idprova.dev** — Starlight docs to Vercel/Netlify

### Priority 4 — Business & Positioning

- [ ] **Register for NIST NCCoE** collaboration activities
- [ ] **Conference talks** — AISA, BSides, government security conferences
- [ ] **Compliance templates** — IDProva-based audit report templates
- [ ] **Partner integrations** — Approach MCP framework maintainers
- [ ] **Blog: "How to Secure Your AI Agents in 15 Minutes"** — Practical walkthrough
- [ ] **Video demo** — CLI + registry + MCP integration flow

---

## 10. Technical Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| DID method | Custom `did:idprova:` | W3C compatible, domain-anchored, agent-native |
| Signature algorithm | Ed25519 (hybrid PQC planned) | Audited library, small signatures, PQC-agile |
| Hashing | BLAKE3 (SHA-256 for interop) | Fast, secure, modern |
| Token format | JWS (compact serialization) | JWT/JWS ecosystem compatibility |
| Audit format | Hash-chained JSONL | Tamper-evident, streamable, verifiable |
| Registry database | SQLite (bundled) | Zero-dependency, embedded, sufficient for v0.1 |
| Web framework | Axum | Async, tower middleware, Rust ecosystem standard |
| Key encoding | Multibase (base58btc) | DID spec alignment, human-readable |
| Scope format | namespace:resource:action | Simple, extensible, MCP-native |
| Trust model | L0-L4 progressive | Maps to real-world verification ceremonies |

---

## 11. Competitive Landscape

| Solution | Type | Limitation |
|----------|------|-----------|
| OAuth 2.0/OIDC | Human identity | No delegation chains, no agent metadata, no audit |
| SPIFFE/SPIRE | Workload identity | No delegation, no scope narrowing, no receipts |
| API Keys | Shared secrets | No identity, no delegation, no rotation, no audit |
| Verifiable Credentials | Credential format | No agent-specific semantics, no receipt chain |
| **IDProva** | **Agent-native protocol** | **All three pillars: identity + delegation + audit** |

---

## 12. Key Files Quick Reference

### IDProva (Rust)
```
Cargo.toml                              # Workspace config
crates/idprova-core/src/lib.rs           # Core library entry
crates/idprova-core/src/crypto/keys.rs   # Ed25519 key management
crates/idprova-core/src/aid/document.rs  # AID document structure
crates/idprova-core/src/aid/builder.rs   # AID builder pattern
crates/idprova-core/src/dat/token.rs     # DAT issue/verify
crates/idprova-core/src/dat/scope.rs     # Scope parsing & matching
crates/idprova-core/src/dat/chain.rs     # Delegation chain validation
crates/idprova-core/src/receipt/entry.rs # Action receipt structure
crates/idprova-core/src/receipt/log.rs   # Hash-chained receipt log
crates/idprova-core/src/trust/level.rs   # Trust level definitions
crates/idprova-cli/src/main.rs           # CLI entry point
crates/idprova-registry/src/main.rs      # Registry HTTP server
crates/idprova-registry/src/store.rs     # SQLite persistence
README.md                                # Project README
SECURITY.md                              # Security policy
```

### idprova-website
```
astro.config.mjs                         # Site config + sidebar structure
src/content/docs/index.mdx               # Homepage
src/content/docs/docs/getting-started.mdx
src/content/docs/docs/quick-start.mdx
src/content/docs/docs/concepts/*.mdx     # 4 concept pages (complete)
src/content/docs/docs/protocol/*.mdx     # 5 spec pages (complete)
src/content/docs/docs/guides/*.mdx       # 4 guides (STUBS)
src/content/docs/docs/reference/*.mdx    # 3 references (STUBS)
src/content/docs/docs/compliance/*.mdx   # 3 compliance (STUBS)
src/content/docs/blog/*.mdx              # 5 blog articles (complete)
src/content/docs/docs/faq.mdx            # FAQ (complete)
src/styles/custom.css                    # Brand styling
```

### tech-blaze-web
```
src/pages/idprova.astro                  # Landing page (UNTRACKED)
src/components/common/Header.astro       # Nav link (line 82-86)
src/components/common/Footer.astro       # Footer link (line 150-155)
```

---

## 13. Session Resumption Checklist

When resuming work on IDProva, check:

1. **Which repo?** — IDProva (Rust), idprova-website (docs), or tech-blaze-web (landing page)?
2. **Git status?** — Neither IDProva nor idprova-website have initial commits yet
3. **What's next?** — See Priority 1-4 in Section 9
4. **Build check:** `cargo build --workspace` and `cargo test --workspace` in IDProva
5. **Docs build:** `npm run build` in idprova-website
6. **Landing page:** `npm run build` in tech-blaze-web (idprova.astro is untracked)

---

*This document captures the complete state of the IDProva project as of 2026-03-02. Use it to plan next sessions and track progress.*