# Track D — Handover

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Progress:** Task 3 of 7 complete (session 1 — stopped after 3 tasks per CLAUDE.md rule)

## Completed

| Task | Commit | Notes |
|------|--------|-------|
| Task 1: README Overhaul | 4733677 | 185 lines, mermaid diagram, register step, docs links |
| Task 2: Getting Started Guide | 5f23d0f | `docs/getting-started.md` — full CLI workflow, 8 steps |
| Task 3: API Reference | 5b83c57 | `docs/api-reference.md` — all 9 registry endpoints with curl examples |

## Next Task

**Task 4: Core Library API Guide** — Create `docs/core-api.md`

Document idprova-core public API: KeyPair, Aid, Dat, ReceiptLog, PolicyEngine with Rust usage examples.

Reference files:
- `crates/idprova-core/src/lib.rs`
- `crates/idprova-core/src/crypto/keys.rs`
- `crates/idprova-core/src/aid/builder.rs`
- `crates/idprova-core/src/dat/token.rs`
- `crates/idprova-core/src/receipt/log.rs`
- `crates/idprova-core/src/policy/evaluator.rs`

## Key Decisions

- README kept to 185 lines (limit 200)
- Used mermaid for architecture diagram
- Quick-start includes curl-based AID registration step (matches actual registry PUT endpoint)
- DAT verify shows both offline (--key) and registry modes
- API reference includes all 9 routes, auth requirements, rate limits, env vars
- `aid create` saves to `{did_with_underscores}.json` (e.g. `did_idprova_example.com_my-agent.json`)
- Scope format: `namespace:resource:action` (colon-separated, 3 parts)

## Session Notes

- Branch: `idprova/track-d-docs-website`
- All commits: `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT modify `crates/`, `sdks/`, `.github/`, `Dockerfile`, `Cargo.*`
- Registry routes in `crates/idprova-registry/src/main.rs` — all 9 routes fully verified
