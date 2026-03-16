# PyCon AU 2026 — Talk Proposal Draft

> **Submit at:** https://pretalx.com/pycon-au-2026/cfp
> **Deadline:** March 29, 2026 (anywhere on earth)
> **Format:** 30 minutes (25 min talk + 5 min Q&A)
> **Tracks:** Submit to Cybersecurity (primary) + Data & AI (secondary)

---

## Title

Cryptographic Passports for AI Agents: Building Trust in Agentic Python

## Abstract

AI agents are everywhere — LangChain pipelines, CrewAI teams, MCP tool servers — but none of them can prove who they are. When your agent calls another agent, there's no identity, no delegation chain, no audit trail. Just vibes and API keys.

IDProva is an open-source protocol (Apache 2.0, Rust core with Python bindings) that gives AI agents verifiable cryptographic identity using W3C Decentralized Identifiers, scoped delegation tokens, and hash-chained audit trails. Think of it as passports for AI agents.

In this talk, you'll see:

- **Why AI agents need their own identity** — not human identity retrofitted, not service accounts, not API keys. A new principal class with purpose-built semantics.
- **Live demo:** Create an agent identity, delegate scoped authority to a sub-agent, execute a tool call through MCP, and verify the tamper-evident audit trail — all from Python.
- **How delegation chains prevent privilege escalation** — each sub-delegation must be a strict subset of the parent's scope. Cryptographically enforced, not prompt-based.
- **Post-quantum readiness** — IDProva uses hybrid Ed25519 + ML-DSA-65 signatures, aligning with NIST FIPS 204 before the 2035 mandatory transition deadline.
- **Real compliance mapping** — how hash-chained receipts map directly to NIST 800-53 audit controls (AU-2 through AU-12) and can satisfy assessor requirements today.

You'll walk away understanding why "who is this agent and what can it do?" is the security question of 2026, and how to answer it in your own Python applications.

## Description

This talk bridges the gap between the AI agent explosion and the security infrastructure that hasn't caught up. It's relevant to anyone building or deploying AI agents in Python — whether you're a security practitioner wondering how to govern agent systems, or a developer building multi-agent workflows who wants proper identity and authorization.

The talk is structured in three parts:

**Part 1: The Problem (5 min)**
The AI agent identity crisis in numbers: 78% of enterprises don't give agents their own identity. 44% still use static API keys. ~2,000 MCP servers scanned — all lacked authentication. NIST has launched an AI Agent Standards Initiative specifically because this gap is critical.

**Part 2: The Protocol (10 min)**
How IDProva's three primitives work together:
- Agent Identity Documents (AIDs) — W3C DID-based, carrying agent metadata, trust levels, and configuration attestation
- Delegation Attestation Tokens (DATs) — JWS-encoded, time-bounded, scope-narrowing delegation chains
- Action Receipts — hash-chained, signed audit records that trace any action back to the authorising human

Live demo using the Python SDK: create an identity, issue a delegation, call a tool, verify the receipt chain.

**Part 3: Why This Matters Now (10 min)**
- NIST NCCoE is running a project on AI Agent Identity and Authorization (we submitted feedback)
- EU AI Act becomes fully applicable August 2, 2026 — audit trail requirements are real
- Post-quantum transition is mandatory by 2035 — start now or retrofit later
- How to integrate IDProva into existing LangChain/CrewAI/MCP workflows

**Target audience:** Python developers building AI agent systems, security practitioners governing AI deployments, anyone curious about the intersection of cryptographic identity and autonomous AI.

**Prerequisites:** Basic Python. No cryptography or identity background needed — the talk builds intuition from first principles.

## Notes for Reviewers

I'm Pratyush Sood, an ASD-endorsed IRAP Assessor (Australia's equivalent of FedRAMP assessors) with 20+ years in cybersecurity. I'm the author of IDProva, which I built because I couldn't find an adequate answer to "how do you assess the identity controls of an AI agent system?" during my assessment work.

I recently submitted feedback to NIST's NCCoE concept paper on AI Agent Identity and Authorization, and a response to the NIST AI Agent Standards Initiative RFI (NIST-2025-0035). IDProva is referenced in both submissions.

The protocol is feature-complete (205 tests, zero failures) with Rust core and Python/TypeScript SDKs. The Python SDK uses PyO3 bindings — so this talk also touches on the practical experience of shipping a Rust+Python hybrid library.

I haven't spoken at PyCon AU before, but I regularly present to government and enterprise audiences on security architecture and compliance. This talk has a live demo component that I've tested end-to-end.

Contact: pratyush@techblaze.com.au
Website: https://idprova.dev
