# Track D — Handover

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Status:** COMPLETE — all 7 tasks done

## Completed

| Task | Commit | Notes |
|------|--------|-------|
| Task 1: README Overhaul | 4733677 | 185 lines, mermaid diagram, register step, docs links |
| Task 2: Getting Started Guide | 5f23d0f | `docs/getting-started.md` — full CLI workflow, 8 steps |
| Task 3: API Reference | 5b83c57 | `docs/api-reference.md` — all 9 registry endpoints with curl examples |
| Task 4: Core Library API Guide | 69f51fa | `docs/core-api.md` — KeyPair, AidBuilder, Dat, ReceiptLog, PolicyEvaluator |
| Task 5: Protocol Concepts Guide | 902be4a | `docs/concepts.md` — mermaid diagrams for AID lifecycle, DAT flow, trust levels, receipt chains |
| Task 6: Security Model | ccfcd39 | `docs/security.md` — threat summary, crypto rationale, key mgmt best practices, security checklist |
| Task 7: SDK Quick-Start Guides | 06945ce | `docs/sdk-python.md` + `docs/sdk-typescript.md` — installation, AgentIdentity, DAT, Scope, complete examples |

## Next Task

None — track is complete.

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
- sdk-python.md and sdk-typescript.md document the actual API surface from `.pyi` stubs and `.d.ts` types, cross-validated against test files
- AgentIdentity is the recommended high-level entry point in both SDKs
- TypeScript exports `AID`/`AIDBuilder` as aliases for `Aid`/`AidBuilder` — noted in docs

## Session Notes

- Branch: `idprova/track-d-docs-website`
- All commits: `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT modify `crates/`, `sdks/`, `.github/`, `Dockerfile`, `Cargo.*`
- Track complete — `.planning/TRACK_COMPLETE` touched
