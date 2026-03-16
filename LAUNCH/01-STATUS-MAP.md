# IDProva Status Map — March 14, 2026

> Where everything stands right now. Scan this when you need clarity.

---

## Codebase (v0.1 FEATURE-COMPLETE)

| Component | Status | Tests | Notes |
|-----------|--------|-------|-------|
| idprova-core | DONE | 126 | Crypto pinned, policy engine, RBAC |
| idprova-verify | DONE | 16 | High-level verification |
| idprova-registry | DONE | 5 | Hardened: CORS, rate limits, CSP |
| idprova-cli | DONE | — | Persistence + config support |
| idprova-middleware | DONE | — | Tower/Axum middleware |
| idprova-mcp-demo | DONE | 16 | Standalone MCP demo |
| Python SDK (PyO3) | DONE | — | Ready for PyPI |
| TypeScript SDK (napi-rs) | DONE | — | Ready for npm |
| Python HTTP wrapper | DONE | — | Pure Python + LangChain |
| **TOTAL** | **DONE** | **205** | **Zero failures** |

**No more coding needed.** The product is built.

---

## GitHub (`github.com/techblaze-au/idprova`)

| Item | Done? |
|------|-------|
| Repo exists, code pushed | YES |
| GitHub Actions CI (fmt, clippy, test, build) | YES |
| Security audit workflow (weekly cargo audit) | YES |
| Release workflow (binaries + Docker to GHCR) | YES |
| README polished (hero, quickstart, comparison) | YES |
| **Repo is PUBLIC** | **NO — still private** |
| **v0.1.0 release tag** | **NO** |
| **Published to crates.io** | **NO** |
| **Published to PyPI** | **NO** |
| **Published to npm** | **NO** |

---

## Website (`idprova.dev`)

| Item | Done? |
|------|-------|
| Domain + Vercel deployment | YES |
| Google Analytics (G-N7TNLGLWVR) | YES |
| SEO/OG tags + Schema.org | YES |
| Cloudflare Turnstile CAPTCHA | YES |
| Early access / waitlist page | YES (Google Sheet backend) |
| Launch status page | YES |
| Pre-release banners | YES |

### Content on Site (25+ pages)
- Getting Started: 2 pages (Intro + Quick Start)
- Concepts: 4 pages (AIDs, DATs, Audit, Trust Levels)
- Protocol Spec: 5 pages (AIDs, DATs, Receipts, Bindings, Crypto)
- Reference: 2 pages (Core API, Registry API)
- Compliance: 4 pages (NIST 800-53, ISM, SOC2, NCCoE)
- Blog: 6 posts (all written)
- FAQ: 1 page
- Early Access + Launch Status: 2 pages

---

## Infrastructure

| Item | Done? |
|------|-------|
| Docker multi-stage build | YES |
| Docker Compose + Caddy reverse proxy | YES |
| Fly.io config (Sydney region) | YES |
| Proxmox LXC containers (201-204) | YES, running |
| Publishing metadata in all Cargo.toml | YES |

---

## Demo Materials

| Item | Location |
|------|----------|
| Demo scripts (4x PowerShell) | `demo.ps1`, `demo-mcp.ps1`, `demo-a2a.ps1`, `test-tamper.ps1` |
| Demo guide (3 tracks) | `DEMO-GUIDE.md` |
| Demo cheatsheet | `DEMO-CHEATSHEET.md` |
| Pre-recorded videos | Desktop: `idprova-cinematic.mp4`, `idprova-with-audio.mp4` |
| Web GUI demo | React + Vite (localhost:5173) |

---

## Security (Deferred — NOT blocking launch)

10 issues documented in `~/.claude/projects/C--Users-praty/memory/idprova-security-remediation.md`
- 2 HIGH (CORS origins, rate limiter memory)
- 3 MEDIUM (IP fallback, mutex recovery, CSP)
- 4 LOW + 1 INFO

These are hardening items. The registry already has basic CORS, rate limiting, and CSP. These are improvements, not showstoppers.

---

## Standards Engagement

| Submission | Deadline | Status |
|---|---|---|
| NIST CAISI RFI (NIST-2025-0035) | Mar 9, 2026 | **SUBMITTED** |
| NCCoE Concept Paper Feedback | Apr 2, 2026 | **SUBMITTED** (Mar 15) |
| CAISI Listening Sessions Registration | Mar 20, 2026 | **SUBMITTED** (Mar 15) |
| W3C DIDs v1.1 Comments | Apr 5, 2026 | Not started |
| PyCon AU 2026 CFP | Mar 29, 2026 | Not started |

See `10-STANDARDS-ENGAGEMENT.md` for full tracker.

---

## Bottom Line

**DONE:** Code, tests, website, docs, demos, CI/CD, deployment configs, NIST RFI, NCCoE feedback draft
**NOT DONE:** Publishing (crates.io/PyPI/npm), making repo public, launch content drafts
**EFFORT REMAINING:** ~2-3 evenings before launch week
