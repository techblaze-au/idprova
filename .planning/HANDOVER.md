# Track D — Handover

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Progress:** Task 6 of 7 complete (session 2 — stopped after 3 tasks per CLAUDE.md rule)

## Completed

| Task | Commit | Notes |
|------|--------|-------|
| Task 1: README Overhaul | 4733677 | 185 lines, mermaid diagram, register step, docs links |
| Task 2: Getting Started Guide | 5f23d0f | `docs/getting-started.md` — full CLI workflow, 8 steps |
| Task 3: API Reference | 5b83c57 | `docs/api-reference.md` — all 9 registry endpoints with curl examples |
| Task 4: Core Library API Guide | 69f51fa | `docs/core-api.md` — KeyPair, AidBuilder, Dat, ReceiptLog, PolicyEvaluator |
| Task 5: Protocol Concepts Guide | 902be4a | `docs/concepts.md` — mermaid diagrams for AID lifecycle, DAT flow, trust levels, receipt chains |
| Task 6: Security Model | ccfcd39 | `docs/security.md` — threat summary, crypto rationale, key mgmt best practices, security checklist |

## Next Task

**Task 7: SDK Quick-Start Guides** — Create `docs/sdk-python.md` and `docs/sdk-typescript.md`

Brief guides showing PyO3/napi-rs bindings usage — create identity, issue DAT, verify, log receipt.
Note: SDKs may not be fully built yet — document the planned API surface.

Reference files:
- `sdks/python/`
- `sdks/typescript/`

## Key Decisions

- README kept to 185 lines (limit 200)
- Used mermaid for architecture diagram
- Quick-start includes curl-based AID registration step (matches actual registry PUT endpoint)
- DAT verify shows both offline (--key) and registry modes
- API reference includes all 9 routes, auth requirements, rate limits, env vars
- `aid create` saves to `{did_with_underscores}.json` (e.g. `did_idprova_example.com_my-agent.json`)
- Scope format: `namespace:resource:action` (colon-separated, 3 parts)
- core-api.md cross-references both `dat::constraints::EvaluationContext` (simple) and `policy::context::EvaluationContext` (full builder) — both exist in codebase
- concepts.md uses mermaid stateDiagram for AID lifecycle, sequenceDiagram for DAT flow, flowchart for policy engine
- security.md includes STRIDE summary table with severity ratings from STRIDE-THREAT-MODEL.md

## Session Notes

- Branch: `idprova/track-d-docs-website`
- All commits: `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT modify `crates/`, `sdks/`, `.github/`, `Dockerfile`, `Cargo.*`
- Task 7 is the final task — after completion, touch `.planning/TRACK_COMPLETE` and update HANDOVER to COMPLETE
