# IDProva Market Research & Competitive Landscape

> Research completed: March 14, 2026
> Purpose: Validate the idea, understand competition, identify gaps, inform roadmap

---

## VERDICT: IDProva is exceptionally well-timed

The market has exploded since you started building:
- Non-human identity startups raised **$400M+ in 2025**
- Palo Alto acquired CyberArk for **$25B** — identity security is a platform pillar
- Machine identities outnumber humans **82-500:1** in enterprises
- **Only 24%** of orgs have visibility into agent-to-agent interactions
- **44% still use static API keys** for agent auth
- Gartner: **30% of enterprises** will rely on AI agents by 2026
- AI agent market: $5.25B (2024) -> projected $52.62B by 2030

---

## Competitive Landscape

### Tier 1 — Direct Threats

| Competitor | Backing | Approach | Threat to IDProva |
|-----------|---------|----------|------------------|
| **AGNTCY** | Cisco, Linux Foundation, 75+ companies | DID/VC (same as IDProva) | **HIGH** — same DID approach, massive backing |
| **Microsoft Entra Agent ID** | Microsoft | Managed identities, Entra | **MEDIUM-HIGH** in MS shops, LOW elsewhere |
| **Astrix Security** | $85M funding (Menlo + Anthropic) | NHI discovery & governance | **MEDIUM** — governance, not protocol |

### Tier 2 — Complementary (potential integration targets)

| Protocol/Product | Focus | Relationship to IDProva |
|-----------------|-------|----------------------|
| **Google A2A** | Agent-to-agent communication | IDProva could be identity layer UNDER A2A |
| **Anthropic MCP** | Agent-to-tool access | IDProva could authenticate MCP agents |
| **SPIFFE/SPIRE** | Workload identity | Infrastructure-level; IDProva is agent-level |
| **OpenAI** | Consumer of standards | Integration target, not competitor |

### Tier 3 — Emerging Standards

| Body | Draft/Initiative | Status |
|------|-----------------|--------|
| **NIST CAISI** | AI Agent Standards Initiative | Launched Feb 2026, listening sessions Apr 2026+ |
| **IETF WIMSE** | AI Agent Identity drafts | Active drafts, expires Sept 2026 |
| **W3C** | DIDs v1.1 + AI Agent Protocol CG | Candidate Rec (Mar 2026), comments due Apr 5 |
| **OpenID Foundation** | AI Identity Management CG | Whitepaper published Oct 2025 |
| **OWASP** | Top 10 Agentic Applications | Published Dec 2025 |

### Commercial NHI Vendors

| Vendor | Focus | Funding |
|--------|-------|---------|
| Astrix Security | NHI discovery & governance | $85M Series B |
| Defakto | NHI lifecycle management | $30.75M Series B |
| Trulioo | Know Your Agent (KYA) | Public |
| Visa | Trusted Agent Protocol (TAP) | N/A |
| Strata Identity | Agentic identity orchestration | Private |

---

## IDProva's Unique Differentiators (vs ALL competitors)

1. **Post-quantum readiness (ML-DSA-65)** — NO other agent identity protocol has this
2. **Three-primitive completeness** (AID + DAT + Action Receipt) — competitors do 1-2 of these
3. **Compliance mapping** (NIST 800-53 + ISM) — unique in this space
4. **Hash-chained legally auditable delegation chains** — nobody else has this
5. **Open-source Rust implementation** — performance + safety + auditability
6. **Built by IRAP assessor** — government credibility no startup can match

---

## What IDProva Hasn't Addressed (Gaps)

### Must Address (before or shortly after launch)

1. **MCP Integration** — MCP is de facto standard. Need IDProva as identity provider for MCP servers.
2. **OAuth/OIDC Bridge** — 44% of enterprises use API keys. Migration path from legacy to IDProva is critical.
3. **Agent Lifecycle Management** — Provisioning, rotation, revocation at scale. Enterprise expectation.

### Should Address (roadmap items)

4. **Agent Discovery** — A2A has "Agent Cards", AGNTCY has OASF. IDProva needs discovery story.
5. **A2A Compatibility** — IDProva AIDs as backing for A2A Agent Cards.
6. **AGNTCY Interop** — Both use DIDs/VCs. Ensure credential-layer compatibility.
7. **Dynamic Agent Spawning** — How AIDs work when agents create sub-agents at runtime.
8. **Real-Time Anomaly Detection** — Action Receipts provide audit but lack real-time detection.

### Consider (future)

9. **Cross-Organizational Federations** — Agent authenticating across company boundaries.
10. **Pseudonymous Agents** — Privacy-preserving identity (auditable but not identifying).
11. **Legal Admissibility** — Get legal opinion on hash-chained receipts as court evidence.
12. **EU AI Act Article 50** — Transparency obligations for AI-generated content.

---

## Recommended Positioning

**"The compliance-ready, post-quantum agent identity protocol for government and regulated industries."**

- Don't compete with AGNTCY/Microsoft on breadth
- Compete on: **depth + compliance + post-quantum + open-source independence**
- Position as the identity layer that works UNDERNEATH A2A and MCP, and ALONGSIDE AGNTCY and Entra

---

## Key Stats for Content Marketing

- **44%** authenticate agents with static API keys (CSA)
- **Only 28%** can trace agent actions back to a human sponsor (CSA)
- **100:1** ratio of machine identities to humans (CSA 2026)
- **Only 21.9%** treat agents as identity-bearing entities (Gravitee)
- **45.6%** use shared API keys for agent-to-agent auth (Gravitee)
- **Only 6%** have advanced AI security strategies (Gravitee)
- **80%** of IT pros have seen agents act unexpectedly (SailPoint)
- **~2,000 MCP servers** scanned, ALL lacked authentication (Pillar Security)
- Multi-agent papers grew from **890 (2019) to 18,500 (2024)** on arXiv

---

## Sources

- Strata, Dark Reading, WSO2, CyberArk, Microsoft Security Blog (market validation)
- AGNTCY/Cisco Outshift, Linux Foundation (AGNTCY)
- IBM, Google Developers Blog, Auth0 (A2A)
- Microsoft Learn/Entra docs (Entra Agent ID)
- Aembit, Stack Overflow Blog, AWS Blog (MCP)
- HashiCorp, Solo.io (SPIFFE/SPIRE)
- NIST CAISI, NCCoE Concept Paper (government)
- IETF Datatracker (WIMSE, OAuth extensions)
- Menlo Ventures, CyberArk, Defakto (startups/funding)
- Gravitee State of AI Agent Security 2026 (industry stats)
