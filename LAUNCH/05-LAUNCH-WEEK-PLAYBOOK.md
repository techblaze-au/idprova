# Launch Week Playbook — Mar 24-28, 2026

> Hour-by-hour plan for launch week. Print this out.

---

## Pre-Launch (Sunday Mar 23, evening)

- [ ] Final check: all install paths work (cargo, pip, npm, docker)
- [ ] Final check: idprova.dev — all links work, mobile looks good
- [ ] Final check: GitHub README renders correctly
- [ ] Enable GitHub Discussions (Settings > Features > Discussions)
- [ ] All draft posts open in browser tabs, ready to paste
- [ ] Set alarm for 7 AM AEDT Monday

---

## Monday Mar 24 — HN Launch Day

### 7:00 AM AEDT (1:00 PM PT Sunday / 10:00 AM ET Monday)
- [ ] Post "Show HN" on Hacker News

**Show HN post format:**
```
Title: Show HN: IDProva – Cryptographic identity for AI agents (Rust, open source)

URL: https://github.com/techblaze-au/idprova

Text (optional, keep SHORT):
IDProva is an open protocol that gives AI agents verifiable identity,
scoped delegation, and tamper-evident audit trails.

Three primitives:
- Agent Identity Documents (AIDs) — W3C DID-based, Ed25519
- Delegation Attestation Tokens (DATs) — signed, scoped, time-bounded
- Action Receipts — hash-chained audit log

Built in Rust. 205 tests. Python + TypeScript SDKs.
Compliance-mapped to NIST 800-53 and Australian ISM.

Docs: https://idprova.dev
```

### 7:15 AM AEDT
- [ ] Post X/Twitter launch thread
- [ ] Post LinkedIn announcement

### 7:30 AM — 12:00 PM AEDT
- [ ] Monitor HN comments — respond to EVERY comment within 30 min
- [ ] Be technical, honest, humble. Acknowledge limitations.
- [ ] If someone asks about competitors, be respectful: "We're complementary to X"
- [ ] If someone asks about adoption: "Early stage — we're looking for feedback"

### 12:00 PM — 5:30 PM AEDT
- [ ] Continue monitoring HN (check every 30 min)
- [ ] Respond to any X/Twitter engagement
- [ ] Respond to any LinkedIn comments

### 6:00 PM — 8:30 PM AEDT
- **FAMILY TIME — DO NOT TOUCH**

### 8:30 PM — 10:30 PM AEDT
- [ ] Final HN comment sweep
- [ ] Check GitHub for new stars, issues, discussions
- [ ] Check Google Sheet for waitlist signups
- [ ] Screenshot analytics (stars, page views, signups) for records

---

## Tuesday Mar 25

### Morning
- [ ] Post to r/rust — technical angle, Rust code quality focus
- [ ] Check and respond to overnight HN comments
- [ ] Check GitHub issues/stars

### Evening (after family time)
- [ ] Post LinkedIn follow-up if first post got traction
- [ ] Respond to Reddit comments
- [ ] Check analytics

---

## Wednesday Mar 26

### Morning
- [ ] Post to r/netsec — security angle
- [ ] Cross-post "The AI Agent Identity Crisis" to Dev.to
- [ ] Engage with any MCP community discussions

### Evening
- [ ] Respond to all platform comments
- [ ] Check GitHub stars/issues

---

## Thursday Mar 27

### Morning
- [ ] Post to r/MachineLearning — AI governance angle
- [ ] Engage with any discussions from earlier posts

### Evening
- [ ] Respond to everything
- [ ] Start planning Stage 2 content

---

## Friday Mar 28 — Week 1 Retrospective

### Morning
- [ ] Compile Week 1 metrics:
  - GitHub stars count
  - Waitlist signups
  - Page views (Google Analytics)
  - crates.io / PyPI / npm download counts
  - Social engagement (likes, comments, shares)
- [ ] Identify what resonated most (which platform, which angle)
- [ ] Note recurring questions → add to FAQ or blog ideas

### Evening
- [ ] Write brief retrospective (what worked, what didn't)
- [ ] Plan next week's content based on what resonated
- [ ] Submit to "This Week in Rust" newsletter if applicable

---

## Emergency Responses

**If HN commenters find a bug:**
→ Acknowledge immediately: "Great catch — fixing now"
→ Fix it, push, reply with commit link

**If someone claims "this already exists":**
→ "You're right that [X] covers [Y aspect]. IDProva focuses specifically on [Z]. We see them as complementary — here's the comparison: idprova.dev/blog/idprova-vs-oauth-agent-auth"

**If someone asks about traction/adoption:**
→ "We just launched. Built by an IRAP assessor in Canberra. Looking for feedback from the community on the protocol design."

**If a security researcher finds an issue:**
→ Take it seriously. Thank them publicly. Fix immediately. This is your credibility.

---

## Success Metrics for Week 1

| Metric | Stretch | Good | Minimum |
|--------|---------|------|---------|
| GitHub stars | 500+ | 200+ | 50+ |
| HN upvotes | 200+ | 100+ | 30+ |
| Waitlist signups | 100+ | 30+ | 10+ |
| crates.io downloads | 500+ | 100+ | 20+ |
| Blog page views | 5000+ | 1000+ | 200+ |
