# This week — IDProva devlog

> Public-facing weekly devlog. Plain prose, no PR/issue cross-links unless they explain something. Updated weekly on Fridays (or Monday if a release lands on a Friday).
> Old entries roll into `docs/devlog/YYYY-MM.md` at the end of each month.

---

## Week of 2026-05-12 (Day 5–11 of the 16-week launch run; v1.0 target Aug 25)

### Shipped

- **v0.1.2 release on crates.io / PyPI / npm** (last Saturday, 2026-05-09). Bug-fix release; the npm-publish workflow finally stopped flaking after four iterations on the macOS-arm64 runner path. The full set of CI work landed across PRs #34–#42.

### In flight this week

- **Doc-vs-reality cleanup.** `docs/integrations/README.md` claimed the OIDC bridge was shipped — it isn't yet; the routes are specified in RFC 0001 §7.2 but not wired into `build_app()`. Fix in flight ([fix/IDP-014-IDP-127-honest-docs-and-devlog](#)).
- **Honest pricing copy on idprova.com.** Enterprise tier was marketing SSO/SAML; we ship SSO via OIDC in v0.2, SAML inbound in v0.3. Fix landed today on idprova-com PR #5.
- **W3C DID Methods Registry PR #693.** Open 38+ days, no W3C reviewer engagement. Drafted a polite WG-contact email; following up via public-credentials@w3.org this week. cheqd team has engaged publicly on the PR with their ObligationSchema work (PR #694) — we're treating that as net-positive convergence and proposing a joint arXiv preprint.
- **NIST CAISI follow-up technical contribution.** Drafted. Pending ACIC-lite legal review before submission. Deadline 30 days from 2026-05-11.
- **RUSTSEC backlog.** Lockfile bumps (rand 0.8.6 / 0.9.4 / 0.10.1; rustls-webpki 0.103.13) landed pre-v0.1.2 and `cargo audit` runs are green on main. Six tracking GitHub issues (#25–#30) are stale; closing them with patch-commit references this week.

### Decisions made

- **v0.2 ships OIDC inbound only.** SAML inbound is deferred to v0.3 per RFC 0001 §11. Rationale: every Tier-1 IdP we care about (Okta, Entra, Auth0, Keycloak) speaks OIDC; SAML support is a "we'll get to it" not a "we're stuck without it."
- **`idprova-identity-adapters` traits crate.** Headline architectural move for v0.2. Lets us plug Okta / Entra / Auth0 / Keycloak adapters in without touching `idprova-core`. Scaffolds Night 2 of the autonomous-execution sprint.
- **Partner positioning shift.** The "first-mover" framing in our v1 marketing is no longer accurate — Auth0, Ping, Okta, and Entra all went GA with agent-identity SKUs between Nov 2025 and May 2026. New differentiator: portable cryptographic receipts + sovereign / air-gapped deployment. Battle Cards rewritten to v2 (2026-05-12).

### Blocked / waiting

- **W3C PR #693** — waiting on WG reviewer.
- **Partner outreach** (Strata, cheqd, Aembit) — drafted; pending Pratyush's send.
- **NIST CAISI submission** — drafted; pending legal review.

### Not yet covered

We don't have a working LangChain integration in this repo today — the `idprova_langchain` Python package is in flight (sandbox standup is the Asana task due 2026-05-16). The Python HTTP client (`idprova_http.IDProvaClient`) works as a manual integration in the meantime; see `examples/python/issue_verify.py`.

We also don't have CrewAI or AutoGen first-party adapters. Both are v1.1 (post-v1.0) work.

### Next week (Week of 2026-05-19)

- Night 2 of the autonomous-execution sprint: scaffold `idprova-identity-adapters` traits crate; split `idprova-registry/src/lib.rs` (712-line monolith) into module folders.
- LangChain sandbox standup on CT 261.
- Reply on W3C PR #693 to @spiceoogway and the cheqd team; send direct outreach email to cheqd if the public reply lands well.

---

## Older weeks

- *2026-05-05 to 2026-05-11* — strategy reset (Decision Memo + 2 RFCs + 5 agent reports + battle cards v2). Decided to ship sovereign-residency Government tier as the load-bearing commercial differentiator. Repointed v1.0 launch from "open protocol, first mover" to "open protocol, complementary to your existing IdP."
- *2026-04-28 to 2026-05-04* — npm-publish CI saga (mostly macOS-arm64). Resolved.
- *2026-03-23 to 2026-03-29* — v0.1.0 launch and ASD contract kickoff.

---

*This file lives at the repo root and is human-edited. CI does not modify it. If you're an agent reading this — your work belongs in `IDProva_Execution_Handover_2026-05-12.md` §saga-state, not here.*
