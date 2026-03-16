# 10 — Launch Content Drafts

Ready-to-post content for IDProva launch across platforms.

---

## 1. Show HN Post

**Title:** Show HN: IDProva – Cryptographic identity for AI agents (Rust)

**URL:** https://github.com/techblaze-au/idprova

**Body:**

I'm an IRAP Assessor (ASD-endorsed security assessor in Australia) with 20+ years in cybersecurity. While assessing AI systems for Australian government, I kept hitting the same problem: there's no proper identity layer for AI agents.

OAuth assumes a human in the loop. API keys can't scope, expire, or delegate properly. SPIFFE was designed for services, not autonomous agents that need to act on behalf of other agents with bounded authority.

IDProva is a cryptographic identity protocol built specifically for AI agents. Three primitives:

- **Agent Identity Documents (AIDs)** — W3C DID-based identity bound to Ed25519 keypairs. Each agent gets a verifiable identity, not just credentials.
- **Delegation Attestation Tokens (DATs)** — Scoped, time-bounded, chainable delegation. Agent A can authorize Agent B to perform specific actions, and B can sub-delegate with reduced scope. Every link in the chain is cryptographically verifiable.
- **Action Receipts** — Hash-chained audit log. Every action an agent takes is signed and chained to the previous receipt. Tamper-evident by construction.

Crypto: Ed25519 signatures, BLAKE3 hashing, post-quantum migration path planned (ML-DSA-65). 247 tests. Compliance mapped to NIST 800-53, Australian ISM, and SOC 2.

Available as:
- `cargo install idprova-cli`
- `pip install idprova` (PyO3 bindings)
- `npm install @idprova/core` (napi-rs bindings)
- Docker image

This is v0.1.0 — early but functional. The core protocol works and the test suite is solid. What's missing: production registry (currently in-memory or file-backed), formal security audit, and real-world battle testing.

I built this because the gap exists and nobody was filling it. The AI agent ecosystem is moving fast, and identity/authorization is being bolted on as an afterthought. It shouldn't be.

Feedback welcome, especially from anyone building multi-agent systems or dealing with agent-to-agent delegation.

GitHub: https://github.com/techblaze-au/idprova
Docs: https://idprova.dev

---

## 2. X/Twitter Launch Thread (7 tweets)

**Tweet 1 (Hook):**
AI agents are getting API keys and running autonomously.

None of them have proper identity.

I built IDProva — a cryptographic identity protocol for AI agents. Open source, written in Rust.

Here's why this matters. (thread)

**Tweet 2 (Problem):**
The current state of AI agent auth:
- OAuth tokens designed for humans clicking "Allow"
- API keys with god-mode access and no expiry
- No way to verify which agent did what
- No delegation chains — agent A can't safely authorize agent B

We're building autonomous systems on authentication designed for web apps.

**Tweet 3 (Solution):**
IDProva has three primitives:

1. Agent Identity Documents (AIDs) — W3C DID-based, Ed25519-bound
2. Delegation Attestation Tokens (DATs) — scoped, time-bounded, chainable
3. Action Receipts — hash-chained, tamper-evident audit trail

Every agent action is cryptographically signed and traceable.

**Tweet 4 (Delegation):**
The killer feature: delegation chains.

Agent A delegates to Agent B with scope ["read:files", "write:reports"].
Agent B sub-delegates to Agent C with scope ["read:files"] only.

Each link is signed. Scope can only narrow, never widen. Time bounds enforced at every level.

**Tweet 5 (Technical):**
Built in Rust. 247 tests.

Ed25519 + BLAKE3 crypto. Post-quantum ready (ML-DSA-65 migration planned).

SDKs:
- Rust (native)
- Python (PyO3)
- TypeScript (napi-rs)
- Python HTTP + LangChain integration

`cargo install idprova-cli` to try it now.

**Tweet 6 (Credibility):**
Why me: I'm an IRAP Assessor (ASD-endorsed) with 20+ years in cybersecurity. I assess systems for Australian government security compliance.

I built IDProva because I kept seeing AI systems with no proper identity model. The gap is real.

Compliance mapped to NIST 800-53, Australian ISM, SOC 2.

**Tweet 7 (CTA):**
IDProva is v0.1.0 — early, open source (Apache 2.0), and looking for feedback.

If you're building multi-agent systems, MCP servers, or anything where AI agents act autonomously — this is for you.

GitHub: github.com/techblaze-au/idprova
Docs: idprova.dev

#AIAgents #CyberSecurity #RustLang #OpenSource

---

## 3. LinkedIn Announcement

**Title:** Introducing IDProva: Cryptographic Identity for AI Agents

As AI agents become autonomous participants in enterprise systems, we face a fundamental security gap: these agents have no proper identity layer.

OAuth was designed for humans clicking consent screens. API keys provide static, unscoped access. SPIFFE addresses service-to-service mesh identity, not autonomous agents that need to delegate authority to other agents with bounded scope and time limits.

Today I'm open-sourcing **IDProva**, a cryptographic identity protocol purpose-built for AI agents.

**The problem is real.** In my work as an IRAP Assessor (ASD-endorsed security assessor), I assess AI systems against Australian government security standards. The pattern I see repeatedly: organisations deploying AI agents with over-privileged credentials, no delegation model, and no tamper-evident audit trail. This is a compliance gap that will only grow as agent autonomy increases.

**IDProva provides three cryptographic primitives:**

- **Agent Identity Documents (AIDs):** W3C DID-based identity bound to Ed25519 keypairs. Every agent gets a verifiable, unique identity.
- **Delegation Attestation Tokens (DATs):** Scoped, time-bounded, cryptographically chainable delegation. An agent can authorize another agent to perform specific actions, with scope that can only narrow through the chain — never widen.
- **Action Receipts:** Hash-chained, signed audit log. Every agent action is linked to the previous, creating a tamper-evident record that satisfies compliance requirements.

**Compliance is built in, not bolted on.** IDProva's controls map directly to NIST 800-53, the Australian ISM, and SOC 2. I designed it with assessment in mind because I'm the person who performs those assessments.

The protocol is implemented in Rust with 247 tests, Ed25519 and BLAKE3 cryptography, and a post-quantum migration path (ML-DSA-65). SDKs are available for Rust, Python, TypeScript, and there's a LangChain integration for immediate use in AI pipelines.

This is v0.1.0 — the protocol works, the test suite is comprehensive, and the documentation is solid. What comes next depends on community feedback and real-world usage.

If you're a CISO evaluating AI agent deployments, a security architect designing multi-agent systems, or a developer building autonomous AI tools — I'd welcome your feedback.

Open source under Apache 2.0.

GitHub: https://github.com/techblaze-au/idprova
Documentation: https://idprova.dev

#CyberSecurity #AIAgents #IdentityManagement #ZeroTrust #OpenSource #IRAP #SecurityArchitecture

---

## 4. Reddit Posts

### r/rust

**Title:** IDProva — cryptographic identity protocol for AI agents, built as a Rust workspace

**Body:**

I've been building an identity protocol for AI agents and wanted to share the Rust implementation.

**Workspace structure:**
- `idprova-core` — protocol primitives (AIDs, delegation tokens, action receipts)
- `idprova-crypto` — Ed25519 signing (ring), BLAKE3 hashing, key management
- `idprova-cli` — command-line tool for identity management
- `idprova-registry` — agent registry with in-memory and file-backed stores
- `idprova-python` — PyO3 bindings
- `idprova-node` — napi-rs TypeScript bindings

**Crypto choices and rationale:**
- **Ed25519 via `ring`** — fast, well-audited, deterministic signatures. Considered `ed25519-dalek` but went with `ring` for its FIPS-validated lineage and constant-time guarantees.
- **BLAKE3** — used for content hashing in action receipts and delegation token binding. Faster than SHA-256, tree-hashable, and the API is cleaner than most hash crate interfaces.
- **Post-quantum:** ML-DSA-65 (FIPS 204) is planned. The protocol abstracts over crypto algorithms, so swapping signature schemes is a crate-level change, not a protocol-level one.

**Design decisions I'm happy with:**
- Delegation tokens use scope intersection for chain narrowing — no custom policy language, just set operations on capability strings.
- Action receipts are a hash chain (each receipt includes the hash of the previous). Simple and tamper-evident without needing a blockchain.
- The CLI uses `clap` with derive macros. Nothing exotic.

**Things I'd do differently:**
- Registry trait could be more ergonomic. The async story isn't great yet.
- Error types are functional but not as refined as I'd like.

247 tests, all passing. `cargo install idprova-cli` to try it.

Apache 2.0. Feedback on the architecture welcome.

https://github.com/techblaze-au/idprova

---

### r/netsec

**Title:** IDProva: A cryptographic identity protocol for AI agents — security model and compliance mapping

**Body:**

I'm an IRAP Assessor (Australian government security assessor, ASD-endorsed) with 20+ years in cybersecurity. I built IDProva because the AI agent ecosystem has a fundamental identity gap.

**The threat model IDProva addresses:**

1. **Agent impersonation** — Without cryptographic identity, any process can claim to be any agent. AIDs (Agent Identity Documents) bind identity to Ed25519 keypairs with W3C DID-compatible structure.

2. **Over-privileged delegation** — API keys and OAuth tokens can't express "Agent A authorizes Agent B to read files in /data but nothing else, for the next 2 hours." Delegation Attestation Tokens (DATs) provide scoped, time-bounded, cryptographically chainable delegation where scope can only narrow through the chain.

3. **Non-repudiation / audit trail** — Action Receipts create a hash-chained, signed log. Each receipt includes: agent DID, action performed, timestamp, result hash, and hash of the previous receipt. Tamper with any entry and the chain breaks.

4. **Delegation chain attacks** — A compromised agent in a delegation chain can't escalate scope. DATs enforce that each delegatee's permissions are a subset of the delegator's. Cryptographic verification at each link.

**What IDProva is NOT:**

- Not a network security tool. It's an application-layer identity protocol.
- Not a replacement for mTLS or SPIFFE for service mesh identity. It's complementary.
- Not formally verified (yet). 247 tests, but no Coq/Lean proofs.
- Not audited by a third party. It's v0.1.0.

**Compliance mapping:**

I mapped IDProva's controls to NIST 800-53 (IA, AU, AC families), Australian ISM (agent authentication, audit logging, key management controls), and SOC 2 (CC6, CC7, CC8). The mappings are in the docs, not just marketing claims.

**Crypto:** Ed25519 (ring), BLAKE3, ML-DSA-65 post-quantum path planned.

Would welcome review from anyone doing threat modeling for multi-agent AI systems.

https://github.com/techblaze-au/idprova

---

### r/MachineLearning

**Title:** The identity problem in multi-agent AI systems — and an open-source protocol to fix it

**Body:**

If you're building multi-agent systems (AutoGen, CrewAI, LangGraph, or custom), you've probably hit this: how do you control what each agent can do, verify which agent did what, and safely delegate between agents?

Current approaches are inadequate:

- **Shared API keys** — every agent has the same access. One compromised agent, everything's exposed.
- **OAuth tokens** — designed for humans. No concept of agent-to-agent delegation chains.
- **Trust by convention** — "Agent A is supposed to only read files." Nothing enforces it.

I built **IDProva**, a cryptographic identity protocol for AI agents. Three primitives:

1. **Agent Identity Documents** — Each agent gets a unique, cryptographically-bound identity (W3C DID-based).
2. **Delegation Attestation Tokens** — Agent A can delegate specific capabilities to Agent B, time-bounded and scope-limited. B can sub-delegate with further restrictions. The chain is cryptographically verifiable.
3. **Action Receipts** — Hash-chained audit log. Every agent action is signed. You can reconstruct exactly what happened, in order, and verify nothing was tampered with.

**MCP integration:** If you're using Anthropic's Model Context Protocol, IDProva can provide the identity layer that MCP currently lacks. An MCP server can verify agent identity before granting tool access, and scope what tools each agent can use based on delegation tokens.

**Practical example:** Your orchestrator agent creates a research agent with delegation to read web content and write summaries. The research agent creates a sub-agent for specific searches, delegated only to read — it can't write. Every action is logged with cryptographic proof of which agent did it.

Python SDK available (`pip install idprova`), with a LangChain integration for tool-use patterns.

v0.1.0, open source (Apache 2.0). Built in Rust with Python/TypeScript bindings.

https://github.com/techblaze-au/idprova

---

### r/LocalLLaMA

**Title:** Open-source identity protocol for local AI agents — because your self-hosted agents need security too

**Body:**

Running local LLMs with tool use? Function calling with agents that can access your filesystem, execute code, or call APIs?

Here's the thing: those agents are running with your permissions. If you're building multi-agent setups (multiple local agents coordinating), there's no standard way to:

- Limit what each agent can actually do
- Delegate specific capabilities from one agent to another
- Know which agent performed which action
- Revoke access without restarting everything

I built **IDProva** to solve this. It's a cryptographic identity protocol — each agent gets a unique identity, delegation is scoped and time-bounded, and every action is logged in a tamper-evident chain.

**Why this matters for local/self-hosted setups:**

- **Self-hosted registry** — The identity registry runs locally. No external service, no cloud dependency. Your agent identities stay on your hardware.
- **File-backed storage** — Registry data persists to local files. No database required.
- **Offline-capable** — Identity verification is cryptographic, not network-dependent. Agents can verify each other's identity and delegation tokens without calling home.
- **CLI-first** — `idprova-cli` lets you create identities, issue delegation tokens, and inspect audit logs from the terminal.

**Quick start:**
```bash
cargo install idprova-cli
# or
pip install idprova
# or
docker pull techblaze/idprova
```

If you're running something like a local agent swarm with Ollama + function calling, IDProva gives you the access control layer that's currently missing.

v0.1.0, Apache 2.0, written in Rust. 247 tests.

https://github.com/techblaze-au/idprova

---

## 5. Dev.to Cross-Post

```
---
title: "The AI Agent Identity Crisis: Why OAuth Can't Save Us"
published: false
description: "AI agents need identity, not just authentication. A deep dive into why existing protocols fail and what a purpose-built solution looks like."
tags: security, ai, rust, opensource
series: "AI Agent Security"
cover_image: # TODO: Add cover image URL
canonical_url: https://idprova.dev/blog/ai-agent-identity-crisis
---
```

# The AI Agent Identity Crisis: Why OAuth Can't Save Us

There are roughly 750 million OAuth tokens active on the internet right now. OAuth solved web authentication. It lets humans click "Allow" and grant applications access to their data.

But AI agents aren't humans. They don't click buttons. They don't read consent screens. And the assumptions OAuth makes about how identity and delegation work simply don't apply to autonomous software agents.

I'm an IRAP Assessor — an ASD-endorsed security assessor in Australia. I've spent 20+ years in cybersecurity, and the last several assessing AI systems against government security standards. The pattern I keep seeing is troubling: AI agents deployed with static API keys, over-privileged OAuth tokens, and zero audit trail for autonomous actions.

This is the AI agent identity crisis, and it's getting worse as agents get more capable.

## The Problem, Concretely

Consider a typical multi-agent system. An orchestrator agent coordinates specialist agents: one for research, one for code generation, one for deployment. Each agent needs access to different resources with different permissions.

**How this works today:**

- The orchestrator has an API key. It passes that key (or a copy) to sub-agents. Every agent has the same access level.
- Or: each agent gets its own API key. But there's no way to express "this agent can only use these specific capabilities, and only until 5pm."
- Or: OAuth tokens everywhere. But OAuth's delegation model (scopes granted by a human) doesn't map to agent-to-agent delegation.

**What's missing:**

1. **Agent-native identity** — Not "user pratyush's token being used by an agent," but "this specific agent, with this specific role, created at this time."
2. **Delegation chains** — Agent A authorizes Agent B to do X. Agent B authorizes Agent C to do a subset of X. Each link is verifiable. Scope only narrows.
3. **Non-repudiation** — A tamper-evident record of what each agent did, signed by that agent's key, linked in an ordered chain.

## Why Existing Solutions Don't Fit

### OAuth 2.0

OAuth assumes a human in the authorization loop. The "resource owner" grants access. But in a multi-agent system, the "resource owner" is often another agent. OAuth's token exchange extensions (RFC 8693) get closer, but they still don't support:

- Cryptographic delegation chains with scope narrowing
- Agent-to-agent delegation without a central authorization server making real-time decisions
- Tamper-evident action logging tied to identity

### API Keys

API keys are static, unscoped secrets. They can't express:

- "Valid for the next 2 hours"
- "Only for reading files in /data"
- "Delegated from Agent A with these restrictions"

When an API key leaks, everything it has access to is compromised, with no way to audit what happened.

### SPIFFE/SPIRE

SPIFFE provides identity for services in a mesh. It's excellent at what it does. But it was designed for infrastructure workloads, not autonomous agents that need to:

- Delegate authority to dynamically created sub-agents
- Maintain hash-chained audit trails
- Operate with capabilities that narrow through delegation chains

### mTLS

Mutual TLS authenticates connections between services. It doesn't address authorization, delegation, or audit at the application layer.

## What Agent Identity Actually Needs

After assessing dozens of systems and thinking about this problem for over a year, I identified the requirements:

**1. Cryptographic binding.** An agent's identity must be bound to a keypair it controls. Not a token issued by someone else — a key the agent holds and uses to sign its actions.

**2. Scoped, time-bounded delegation.** When Agent A delegates to Agent B, the delegation must specify exactly what B can do, for how long, and B must be able to sub-delegate with strictly equal or reduced scope.

**3. Verifiable chains.** Anyone holding a delegation token must be able to verify the entire chain back to the root authority, without calling a central server.

**4. Tamper-evident audit.** Every action an agent takes should be signed and chained. Modify any entry and the chain integrity breaks.

**5. Protocol-level compliance.** The protocol should map to recognized security frameworks (NIST 800-53, SOC 2) so that organizations can assess it against their existing compliance requirements.

## IDProva: A Purpose-Built Protocol

I built IDProva to address these requirements. It's a cryptographic identity protocol implemented in Rust, with three core primitives.

### Agent Identity Documents (AIDs)

Based on W3C Decentralized Identifiers (DIDs), an AID binds an agent's identity to an Ed25519 keypair. The document includes:

- A unique DID (e.g., `did:aid:agent:a1b2c3d4`)
- The agent's public key
- Metadata: creation time, purpose, organizational context
- The agent's signature over the document

AIDs are self-certifying — the document is signed by the key it contains. No certificate authority needed for basic identity verification.

### Delegation Attestation Tokens (DATs)

DATs express scoped, time-bounded delegation from one agent to another:

```
Delegator: did:aid:agent:orchestrator
Delegatee: did:aid:agent:researcher
Scope: ["read:web", "write:summaries"]
Not Before: 2025-01-15T09:00:00Z
Expires: 2025-01-15T17:00:00Z
```

Key properties:

- **Chainable:** Agent B can create a new DAT delegating a subset of its received scope to Agent C.
- **Scope narrowing:** Each delegation in the chain can only reduce scope, never expand it. This is enforced by set intersection at verification time.
- **Cryptographically signed:** Each DAT is signed by the delegator. Verification walks the chain, checking each signature and scope reduction.

### Action Receipts

Every agent action produces a signed receipt:

```
Agent: did:aid:agent:researcher
Action: web_search
Input Hash: blake3("query=rust cryptography libraries")
Output Hash: blake3(<search results>)
Previous Receipt: blake3(<previous receipt>)
Timestamp: 2025-01-15T09:15:22Z
Signature: <Ed25519 signature over all fields>
```

The `previous_receipt` field creates a hash chain. Tamper with any receipt and every subsequent hash is invalid. This provides an ordered, tamper-evident log of everything an agent did.

## Honest Limitations

IDProva is v0.1.0. Here's what it doesn't do yet:

- **No production-grade registry.** The current registry is in-memory or file-backed. A distributed registry with consensus is on the roadmap, not shipped.
- **No formal verification.** 247 tests, not Coq proofs. The protocol hasn't been formally analyzed.
- **No third-party audit.** I designed it with security assessment in mind (it's literally my day job), but it hasn't been independently audited.
- **Post-quantum is planned, not shipped.** ML-DSA-65 (FIPS 204) is the target, but Ed25519 is current.
- **Performance at scale is unproven.** It works well in testing. Production workloads with thousands of agents and deep delegation chains need real-world validation.

## Getting Started

```bash
# Rust
cargo install idprova-cli

# Python
pip install idprova

# TypeScript
npm install @idprova/core

# Docker
docker pull techblaze/idprova
```

The Python SDK includes a LangChain integration for immediate use in AI agent pipelines.

## Why I Built This

I assess AI systems for a living. I'm one of the people who sits across the table from organizations and asks, "How do you know which agent did this? How do you limit what this agent can access? What happens if this agent is compromised?"

The answers are almost always inadequate. Not because the teams are incompetent, but because the tools don't exist. You can't properly scope an API key. You can't build a delegation chain with OAuth. You can't get a tamper-evident audit trail without building it yourself.

IDProva exists because this gap needed filling. It's open source (Apache 2.0), it's early, and it needs feedback from people building real agent systems.

**GitHub:** [github.com/techblaze-au/idprova](https://github.com/techblaze-au/idprova)
**Docs:** [idprova.dev](https://idprova.dev)

---

*Pratyush Sood is an IRAP Assessor and founder of Tech Blaze Consulting. He builds security tools and assesses systems for Australian government compliance.*
