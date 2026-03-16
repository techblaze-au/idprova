# IDProva: Complete Status Map & Staged Launch Plan
**Last Updated:** 2026-03-14

## Current State (March 14, 2026)

### Codebase — Feature Complete ✅
| Component | Tests | Status |
|-----------|-------|--------|
| idprova-core | 182 | ✅ Done — crypto pinned, policy engine, RBAC |
| idprova-verify | 17 | ✅ Done |
| idprova-middleware | 9 | ✅ Done — Tower/Axum middleware |
| idprova-registry | 7 | ✅ Done — CORS, rate limits, CSP, mutex recovery |
| idprova-cli | 10 | ✅ Done — persistence + config |
| idprova-mcp-demo | 5 | ✅ Done — standalone demo |
| Python SDK (PyO3) | — | ✅ Ready for PyPI |
| TypeScript SDK (napi-rs) | — | ✅ Ready for npm |
| Python HTTP + LangChain | — | ✅ Done |
| **Total** | **247** | **All passing, zero failures** |

### GitHub — github.com/techblaze-au/idprova
- ✅ Code pushed (latest: ade6c9e + 11 local commits)
- ✅ CI workflow (fmt, clippy, test, build with MSRV matrix)
- ✅ Security audit workflow (weekly cargo audit)
- ✅ Release workflow (cross-platform binaries + Docker to GHCR)
- ✅ README polished (hero, quickstart, comparison table)
- 🔴 Repo is PRIVATE — must go public
- 🔴 No git tags — need v0.1.0

### Website — idprova.dev (Astro Starlight on Vercel)
- ✅ 31 pages deployed
- ✅ Google Analytics (G-N7TNLGLWVR)
- ✅ SEO/OG/Schema.org
- ✅ Cloudflare Turnstile on early access form
- ✅ 6 blog posts
- ⚠️ Launch dates being updated from April 7 to March 2026

### Infrastructure
- ✅ Docker multi-stage build ready
- ✅ Docker Compose + Caddy ready
- ✅ Fly.io config (Sydney) ready
- ✅ Proxmox LXC (201-204) running
- ✅ Publishing metadata ready (crates.io/PyPI/npm)

## Pre-Launch Checklist

### Gate 1: Technical — "Can someone use it?"
- [ ] Push 11 local commits to origin/main
- [ ] Make GitHub repo public
- [ ] Create v0.1.0 git tag → triggers release workflow
- [ ] Publish to crates.io: idprova-core → idprova-verify → idprova-middleware → idprova-registry → idprova-cli
- [ ] Publish Python SDK to PyPI (maturin publish)
- [ ] Publish TypeScript SDK to npm (npm publish --access public)
- [ ] Verify: cargo install idprova-cli
- [ ] Verify: pip install idprova
- [ ] Verify: docker pull ghcr.io/techblaze-au/idprova-registry

### Gate 2: Marketing — "Does the website work?"
- [ ] All 31 pages load correctly, no broken links
- [ ] Early access form submits to Google Sheet
- [ ] Install instructions point to published packages (not just git clone)
- [ ] Quick-start examples match published API

### Gate 3: Distribution — "Can I announce it?"
- [ ] HN "Show HN" post drafted
- [ ] X/Twitter thread drafted (7 tweets)
- [ ] LinkedIn announcement drafted
- [ ] Reddit posts drafted (r/rust, r/netsec, r/MachineLearning, r/LocalLLaMA)
- [ ] Dev.to cross-post prepared

## Staged Launch Roadmap

### Stage 0: Go Live (Mar 14-21) — 3 evenings
Evening 1: Publish everything
Evening 2: Website verification
Evening 3: Draft launch content

### Stage 1: Soft Launch (Mar 24-28)
Target: 500-1000 developers
- HN Show HN (be online 4+ hours)
- X/Twitter thread
- Reddit r/rust + r/netsec
- Dev.to cross-post
- LinkedIn professional announcement

### Stage 2: Build Credibility (April 2026)
- LangChain integration tutorial
- MCP integration guide
- Conference CFPs (BSides Canberra, PyCon AU)
- MCP community engagement

### Stage 3: Enterprise Signal (May-June 2026)
- Brief ASD/ACSC contacts
- BSides Canberra presentation
- DISP consulting leads
- Australian trademark filing
- NIST NCCoE follow-up

### Stage 4: First Revenue (July-Sept 2026)
- Agent identity governance assessments ($2-3.5K/day)
- 3-5 defence prime / APS agency targets
- Government PoC ($20-50K)
- IDProva Cloud scoping

## Decision Gates
| Gate | When | Success | If Not |
|------|------|---------|--------|
| 1 | June 2026 | 500+ stars, 1 framework integration, HN front page | Adjust messaging |
| 2 | Sept 2026 | 200+ stars, 1 enterprise PoC, 1 paid gig | Reduce to maintenance |
| 3 | Mar 2027 | $10K+ MRR or 3+ enterprise contracts | Raise/bootstrap/sunset |

## Publishing Order (Reference)
```
# Rust crates (dependency order)
cargo publish -p idprova-core
cargo publish -p idprova-verify
cargo publish -p idprova-middleware
cargo publish -p idprova-registry
cargo publish -p idprova-cli

# Python SDK
cd sdks/python && maturin publish

# TypeScript SDK
cd sdks/typescript/packages/core && npm publish --access public
```

## Content Strategy
See: 04-PLATFORM-STRATEGY.md, 09-SEO-AND-CONTENT.md, 10-LAUNCH-CONTENT-DRAFTS.md
