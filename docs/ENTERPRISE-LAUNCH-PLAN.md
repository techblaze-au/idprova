# IDProva — Enterprise Launch Readiness Plan

## Context

IDProva v0.1 is **feature-complete** (CI green, 221 tests). Before going public, we need to operate like a full enterprise with every C-suite seat filled. This plan covers:

1. **C-Suite Gap Analysis** — What each role needs before launch
2. **Enterprise Deliverables** — Documents to create
3. **Customer-Facing Demo Playbook** — Manual test procedures for live presentations

---

## Part 1: C-Suite Gap Analysis

### CEO — Strategy & Vision
**What exists:** Strong technical foundation, Apache 2.0 license, NIST RFI submission (credibility)
**What's missing:**
- No public GitHub repo (URGENT — push to `techblaze-au/idprova`)
- No public roadmap (`ROADMAP.md`)
- No partnership strategy (Target: Anthropic MCP auth, LangChain, CrewAI, Vercel)
- No standards body engagement (W3C DID WG, IETF draft)
- No advisory board

### CFO — Revenue & Financial Model
**What exists:** Nothing financial documented
**What's missing:**
- No pricing model (HIGH — 3-tier: Open Source / Managed Registry / Enterprise)
- No revenue projections (Year 1-3 freemium → SaaS → enterprise)
- No cost analysis (Fly.io, domain, CI/CD infra costs)
- No ROI calculator for customers
- R&D tax already logging via rd-tax-logger

**Pricing skeleton:**
- **Free:** Self-hosted registry, CLI, core library (Apache 2.0)
- **Pro ($99/mo):** Managed registry SaaS, dashboard, 10K verifications/mo
- **Enterprise ($999/mo):** SLA, dedicated registry, compliance reports, support

### CTO — Technical Architecture
**What exists:** Complete — 5 crates, 221 tests, CI green, Docker, Fly.io
**What's missing:**
- No load testing results (benchmark: verifications/sec, registry throughput)
- No external security audit (document self-assessment at minimum)
- Python/TS SDK bindings need completing
- No TLS/mTLS guidance for production
- No horizontal scaling plan

### CPO — Product Management
**What exists:** Feature-complete v0.1, WALKTHROUGH.md, demo scripts
**What's missing:**
- No customer journey map (where IDProva fits in agent dev lifecycle)
- No user personas (Agent Dev, Platform Eng, Security Architect, CISO)
- No public feature prioritization (v0.2, v0.3, v1.0)
- No competitive analysis doc (vs SPIFFE, OAuth2, API keys, custom JWT)
- No feedback mechanism

### CMO — Marketing & Brand
**What exists:** README positioning, NIST RFI (thought leadership asset)
**What's missing:**
- No marketing website (URGENT — deploy idprova.dev)
- No pitch deck (10-slide investor/customer deck)
- No LinkedIn content plan (12-week calendar)
- No brand guidelines (logo, colors, voice)
- No blog/thought leadership (3 launch posts)
- No demo video (2-min screen recording)

**LinkedIn content angles:**
1. "We submitted to NIST on AI agent security — here's what we built"
2. "Why OAuth doesn't work for AI agents"
3. "BLAKE3 hash-chained receipts: tamper-proof agent audit trails"
4. "The 4-part scope grammar every MCP server needs"
5. Architecture diagrams (DID → AID → DAT → Receipt flow)

### COO — Operations & Support
**What exists:** DEPLOY.md, Docker, Fly.io config
**What's missing:**
- No SLA definitions (uptime, response time, support tiers)
- No incident response playbook
- No monitoring/alerting setup
- No customer onboarding process (30-60-90 day guide)
- No support channel (GitHub Issues initially)

### CLO / Legal & Compliance
**What exists:** Apache 2.0, SECURITY.md, compliance.md (NIST/ISM/SOC2), STRIDE threat model
**What's missing:**
- No terms of service (for managed registry SaaS)
- No privacy policy (data handling for registry entries)
- No security questionnaire template (enterprise RFP responses)
- No DPA (Data Processing Agreement)
- No export control analysis (cryptography)

### VP Sales — Go-to-Market
**What exists:** demo.ps1, demo-a2a.ps1, demo-mcp.ps1 (excellent demo scripts)
**What's missing:**
- No sales playbook (objection handling, qualification)
- No customer presentation deck
- No case study templates
- No trial/POC process
- No channel partner program

### Business Analyst — Market Intelligence
**What exists:** NIST RFI response (demonstrates market understanding)
**What's missing:**
- No TAM/SAM/SOM analysis (AI agent identity market sizing)
- No competitor feature matrix
- No industry trend report (AI agent governance regulatory landscape)
- No customer interview framework

---

## Part 2: Enterprise Deliverables (Priority Order)

### Batch 1 — Create Now (This Sprint)

| # | Deliverable | File | Owner Role |
|---|------------|------|------------|
| 1 | CMO Brief | `docs/CMO-BRIEF.md` | CMO |
| 2 | Customer Demo Playbook | `docs/CUSTOMER-DEMO-PLAYBOOK.md` | VP Sales + CTO |
| 3 | E2E Test Playbook | `docs/E2E-TEST-PLAYBOOK.md` | CTO + QA |
| 4 | Competitive Analysis | `docs/COMPETITIVE-ANALYSIS.md` | BA + CPO |

### Batch 2 — Next Sprint

| # | Deliverable | File | Owner Role |
|---|------------|------|------------|
| 5 | Pricing & Revenue Model | `docs/PRICING-MODEL.md` | CFO |
| 6 | Public Roadmap | `ROADMAP.md` | CEO + CPO |
| 7 | LinkedIn Content Calendar | `docs/LINKEDIN-PLAN.md` | CMO |
| 8 | Customer Personas | `docs/PERSONAS.md` | CPO |

### Batch 3 — Before Public Launch

| # | Deliverable | File | Owner Role |
|---|------------|------|------------|
| 9 | Pitch Deck | `docs/PITCH-DECK.md` | CEO + CMO |
| 10 | Sales Playbook | `docs/SALES-PLAYBOOK.md` | VP Sales |
| 11 | SLA & Support Tiers | `docs/SLA.md` | COO |
| 12 | Terms of Service | `docs/TERMS.md` | CLO |
| 13 | Privacy Policy | `docs/PRIVACY.md` | CLO |

---

## Part 3: Customer Demo Playbook (20-min Presentation)

### Act 1: The Problem (3 min) — Slides
- "Your AI agents act without verifiable identity"
- "Who authorized this agent? What can it do? Who's accountable?"
- "OAuth was built for humans. Agents need something purpose-built."

### Act 2: The Protocol (2 min) — Architecture Diagram
- DID → AID → DAT → Receipt Chain
- 4-layer stack: Identity → Delegation → Execution → Audit

### Act 3: Live Demo (12 min) — Terminal + Dashboard

**Step 1: Generate Keys (30s)**
```bash
idprova keygen --output /tmp/demo/alice.key
idprova keygen --output /tmp/demo/bob.key
```

**Step 2: Create Agent Identities (1 min)**
```bash
idprova aid create --id "did:aid:demo:alice" --name "Alice (Orchestrator)" \
  --controller "did:aid:demo:alice" --key /tmp/demo/alice.key
```
Talking point: "Each agent gets a W3C DID — a globally unique, cryptographic identity"

**Step 3: Start Registry + Publish (1 min)**
```bash
cargo run -p idprova-registry &
idprova aid publish did_idprova_demo_alice.json --registry http://localhost:4242
```

**Step 4: Issue Delegation Token (1 min)**
```bash
idprova dat issue --issuer "did:aid:demo:alice" \
  --subject "did:aid:demo:bob" \
  --scope "mcp:tool:filesystem:read" --scope "mcp:tool:echo:invoke" \
  --expires-in "1h" --key /tmp/demo/alice.key
```
Talking point: "Alice delegates read-only filesystem access to Bob, 1-hour expiry"

**Step 5: Inspect Token (1 min)**
```bash
idprova dat inspect <token>
```
Shows beautiful box-drawn output with issuer, subject, scopes, constraints, expiry
Talking point: "Every claim cryptographically signed. No one can forge or modify."

**Step 6: Verify — Happy Path (30s)**
```bash
idprova dat verify <token> --key /tmp/demo/alice.pub --scope "mcp:tool:filesystem:read"
```
Expected: Green checkmarks — Signature VALID, Timing VALID, Scope GRANTED

**Step 7: Verify — Scope Denied (30s)**
```bash
idprova dat verify <token> --key /tmp/demo/alice.pub --scope "mcp:tool:filesystem:write"
```
Expected: Red X — scope NOT GRANTED
Talking point: "Bob tried to write. Denied. Scope grammar enforced cryptographically."

**Step 8: Registry-Assisted Verification (30s)**
```bash
idprova dat verify <token> --registry http://localhost:4242 --scope "mcp:tool:filesystem:read"
```
Expected: "VALID (verified via registry)" — resolves issuer key automatically

**Step 9: Show Dashboard (2 min)**
- Open `http://localhost:4242/dashboard`
- Show agents table, paste DAT into verifier, resolve AID
- Talking point: "Your security team gets real-time visibility. No black-box agents."

**Step 10: Revocation (1 min)**
```bash
curl -X POST http://localhost:4242/v1/dat/revoke -H "Content-Type: application/json" \
  -d '{"jti":"<token-jti>","reason":"compromised","revoked_by":"did:aid:demo:alice"}'
```
Then verify again → fails. Talking point: "One API call kills compromised agent access."

**Step 11: Receipt Chain (1 min)**
- Show MCP demo receipt log, explain BLAKE3 hash chain
- Talking point: "Tamper with one entry, entire chain breaks. This is your audit trail."

### Act 4: Where It Fits (3 min)
- Customer's agent architecture diagram
- "IDProva slots in at the delegation layer"
- Integration points: MCP servers, LangChain, custom agents
- "Start with CLI today, graduate to managed registry"

### Pre-Demo Checklist
- [ ] Rust toolchain installed, `cargo build` succeeds
- [ ] Registry starts on expected port
- [ ] Dashboard loads in browser
- [ ] Key generation works
- [ ] Demo scripts tested in last 24 hours
- [ ] Clean `/tmp/demo/` directory
- [ ] Works fully offline

---

## Part 4: E2E Test Playbook (Internal QA)

### 25 Tests — Run Before Every Release/Demo

| ID | Test | Pass Criteria |
|----|------|---------------|
| T1 | `cargo build --workspace --exclude idprova-python --exclude idprova-typescript` | Exit 0 |
| T2 | `cargo test --workspace --exclude ...` | 221+ tests pass |
| T3 | `cargo clippy --workspace --exclude ... -- -D warnings` | Exit 0 |
| T4 | `cargo fmt --all -- --check` | Exit 0 |
| T5 | CLI keygen | 2 key files, correct sizes |
| T6 | CLI aid create | Valid AID JSON, correct DID format |
| T7 | CLI dat issue | Compact JWS (3 dot-separated segments) |
| T8 | CLI dat verify (correct key) | "VALID" |
| T9 | CLI dat verify (wrong key) | Error, non-zero exit |
| T10 | CLI dat verify (expired) | "expired" in error |
| T11 | CLI dat verify (wrong scope) | "scope" in error |
| T12 | Registry `/health` | 200, `{"status":"ok"}` |
| T13 | Registry `PUT /v1/aid/{id}` | 201 |
| T14 | Registry `GET /v1/aid/{id}` | 200, correct JSON |
| T15 | Registry `POST /v1/dat/verify` | 200, `{"valid":true}` |
| T16 | Registry `POST /v1/dat/revoke` | 200, `{"status":"revoked"}` |
| T17 | Registry `GET /v1/dat/revoked/{jti}` | 200, `{"revoked":true}` |
| T18 | Dashboard loads at `/dashboard` | HTML renders, no JS errors |
| T19 | Dashboard verify DAT | Green result box |
| T20 | MCP demo echo tool | Receipt generated |
| T21 | `docker build .` | Image built |
| T22 | Docker container `/health` | 200 |
| T23 | demo.ps1 end-to-end | All steps pass |
| T24 | demo-a2a.ps1 end-to-end | Delegation chain works |
| T25 | demo-mcp.ps1 end-to-end | MCP + receipts work |

### Cross-Platform Matrix

| Test | Windows | macOS | Linux |
|------|---------|-------|-------|
| T1-T4 | MSVC toolchain | Xcode CLT | gcc + libssl-dev |
| T5-T11 | PowerShell | zsh/bash | bash |
| T12-T17 | curl / Invoke-WebRequest | curl | curl |
| T18-T19 | Edge/Chrome | Safari/Chrome | Firefox/Chrome |
| T21-T22 | Docker Desktop | Docker Desktop | docker-ce |
| T23-T25 | PowerShell scripts | Bash port needed | Bash port needed |

---

## Part 5: Competitive Analysis

| Feature | IDProva | OAuth2/OIDC | SPIFFE | API Keys | Custom JWT |
|---------|---------|-------------|--------|----------|------------|
| Built for agents | Yes | No (human-first) | Partial | No | No |
| Delegation chains | Yes (depth control) | No | No | No | Manual |
| Scope grammar | 4-part structured | Freeform | N/A | N/A | Freeform |
| Receipt audit trail | BLAKE3 hash chain | No | No | No | No |
| Constraint engine | 8 policy types | Claims only | SVID | None | Manual |
| Revocation | Instant API | Introspection | CRL/OCSP | Rotate | Manual |
| Tamper detection | Built-in | No | No | No | No |
| License | Apache 2.0 | RFC 6749 | CNCF | N/A | N/A |
| Compliance maps | NIST ZTA, ISM | Varies | Partial | None | None |

---

## Status

**Plan written:** 2026-03-09, Session 11
**Next action:** Execute Batch 1 — create the 4 documents (CMO Brief, Customer Demo Playbook, E2E Test Playbook, Competitive Analysis)
**Blocked on:** Nothing — ready to execute
