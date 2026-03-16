# Platform & Audience Strategy

> Where your audience lives, what to say, and how to reach them.

---

## Two Narratives — Use the Right One for Each Platform

### Developer Narrative (HN, GitHub, X, Reddit, Dev.to)
- **Problem:** "AI agents can't prove who they are"
- **Emotion:** Curiosity, craft, elegance
- **Proof:** Working code, speed, 205 tests, Rust performance
- **CTA:** `cargo install idprova-cli`
- **Tone:** Senior engineer talking to peers. Never: "revolutionary," "game-changing"
- **Tagline:** "The OAuth of the agent era" / "Cryptographic identity for AI agents"

### Enterprise/CISO Narrative (LinkedIn, AISA, conferences, direct outreach)
- **Problem:** "You have zero governance over AI agents"
- **Emotion:** Fear, compliance pressure, accountability
- **Proof:** NIST 800-53 mapping, IRAP assessor credibility, audit trails
- **CTA:** "Book a governance assessment" / "Read the compliance mapping"
- **Tone:** Trusted advisor. Reference standards, not features.
- **Tagline:** "Verifiable identity for the agent era"

---

## Platform Priorities

### P0 — Launch Week (must do)

| Platform | Audience | What to Post | Best Time |
|----------|----------|-------------|-----------|
| **Hacker News** | Devs, founders, tech leaders | "Show HN" post | Mon/Tue 10am US ET |
| **GitHub** | OSS developers | Polished README, enable Discussions | Before HN |
| **LinkedIn** | CISOs, IRAP community, govt | Professional post, compliance angle | Mon-Fri morning AEST |

### P1 — Launch Week + Week 2 (should do)

| Platform | Audience | What to Post | Notes |
|----------|----------|-------------|-------|
| **X/Twitter** | AI/ML community, devs, VCs | Launch thread (5-7 tweets) | Same day as HN |
| **Reddit r/rust** | Rust developers | Technical post, code focus | Strong community, be genuine |
| **Reddit r/netsec** | Security professionals | Security angle, threat model | Day after HN |
| **Reddit r/MachineLearning** | AI researchers, engineers | AI governance angle | Different day |
| **Dev.to** | Web/fullstack developers | Cross-post blog article | After Reddit |

### P2 — Month 2+ (nice to have)

| Platform | Audience | What to Post | When |
|----------|----------|-------------|------|
| **AISA / AusCERT** | Australian security pros | Conference talks, whitepapers | After CFP acceptance |
| **YouTube** | Developers wanting demos | 5-10 min walkthroughs | After 100+ stars |
| **Substack/Newsletter** | Engaged followers | Weekly "AI Agent Security" digest | After 500+ stars |
| **Podcasts** | Broader tech audience | Guest on Latent Space, Changelog | After traction |
| **Discord** | Support community | Support channel (NOT community hub) | When needed |

---

## People Who Do the Same Work (Your Network)

### IRAP / Security Assessment Community
- **Where they are:** LinkedIn, AISA conferences (CyberCon), AusCERT, BSides
- **What they care about:** Compliance frameworks, ISM, NIST, audit evidence
- **How to reach them:** LinkedIn posts, AISA membership lists, conference networking
- **Your edge:** You ARE one of them (IRAP assessor, TSPV cleared)

### AI Agent / MCP Developers
- **Where they are:** GitHub (MCP repos), X/Twitter, Hacker News, Discord servers
- **What they care about:** Tool interop, agent frameworks, security concerns
- **How to reach them:** Engage in MCP discussions, build integrations, write tutorials
- **Your edge:** You've built the solution they don't know they need yet

### Government / Defence Tech
- **Where they are:** LinkedIn, closed conferences (ACSC, ASPI), direct relationships
- **What they care about:** Sovereign capability, compliance, DISP, ISM controls
- **How to reach them:** Warm intros from ASD contacts, DISP consulting leads
- **Your edge:** TSPV clearance + IRAP + technical depth = rare combination

### Rust / Open Source Community
- **Where they are:** r/rust, crates.io, GitHub, This Week in Rust newsletter
- **What they care about:** Code quality, performance, correctness, memory safety
- **How to reach them:** Ship quality crate, engage genuinely, submit to TWIR
- **Your edge:** Clean Rust implementation with 205 tests, real-world protocol

### Enterprise Security / Compliance (Global)
- **Where they are:** LinkedIn, RSA Conference, Gartner, industry analyst reports
- **What they care about:** SOC 2, NIST, agent governance, risk management
- **How to reach them:** Whitepapers, conference talks, analyst briefings (later)
- **Your edge:** Built by assessor, compliance-mapped from day one

---

## Content Repurposing Strategy

Every piece of content should be repurposed 3-5 ways:

```
Blog post
  → X/Twitter thread (key points as tweets)
  → LinkedIn post (professional summary)
  → Reddit post (discussion-oriented)
  → Dev.to cross-post (tutorial angle)
  → Newsletter section (digest format)
```

Every conference talk should become:
```
Talk
  → YouTube video (full recording)
  → Blog post (written version)
  → X thread (key insights)
  → LinkedIn post (professional recap)
  → 3-5 short clips (social media)
```

---

## Key Messaging Do's and Don'ts

### DO
- "Verifiable identity for the agent era"
- "What TLS did for web traffic, IDProva does for agent communication"
- "Built by an IRAP assessor — compliance-mapped from day one"
- "205 tests. Zero failures. Production-ready."
- Show working code, not slides

### DON'T
- "Revolutionary" / "game-changing" / "cutting-edge" / "disruptive"
- Overstate adoption (be honest about early stage)
- Bash competitors (position as complementary)
- Lead with features (lead with the problem)
- Claim government endorsement you don't have
