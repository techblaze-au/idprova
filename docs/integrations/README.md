# Integrations

Where IDProva fits in your AI agent stack. The protocol layer (AID + DAT + receipts, see [`../protocol-spec-v0.1.md`](../protocol-spec-v0.1.md)) is identity-system-agnostic; this directory documents the surface that connects it to specific runtimes and identity providers.

Status reflects what exists in the repo today (2026-05-09). The launch-target API for v1.0 is **2026-08-25** — track week-by-week progress at the [public roadmap](https://github.com/techblaze-au/idprova/projects).

## Status by integration

| Integration | Today | Where to look |
|---|---|---|
| **MCP (Model Context Protocol)** | **Shipped.** Auth middleware, scope evaluation, signed-receipt logging for every tool call. | [`crates/idprova-mcp/`](../../crates/idprova-mcp/), runnable examples in [`crates/idprova-mcp/examples/`](../../crates/idprova-mcp/examples/) (`filesystem_mcp.rs`, `multi_agent.rs`). |
| **OIDC bridge** (Okta, Microsoft Entra ID, Auth0, generic OIDC) | **Shipped.** Registry endpoints accept an OIDC ID token via RFC 8693 token exchange and return a scoped DAT. | Registry routes `/v1/auth/oidc/bridge`, `/v1/auth/challenge`, `/v1/auth/verify`. See [`../api-reference.md`](../api-reference.md). |
| **Python (`idprova` package, HTTP client)** | **Shipped.** PyO3 bindings on PyPI; HTTP client for registry interactions. | [`sdks/python/`](../../sdks/python/), examples in [`examples/python/`](../../examples/python/). |
| **TypeScript (`@idprova/core`, napi-rs)** | **Shipped.** Native bindings on npm. | [`sdks/typescript/`](../../sdks/typescript/), examples in [`examples/typescript/`](../../examples/typescript/). |
| **LangChain (`idprova_langchain` Python package)** | **In flight — Wk 2 of v1.0 launch plan (May 13–19).** Sandbox under construction; package not yet published to PyPI. README's LangChain code block shows the target API. | Tracked in Asana: "Stand up CT 261 LangChain sandbox" (due 2026-05-16). Working Python integration today uses `IDProvaClient` from `idprova_http` — see [`examples/python/issue_verify.py`](../../examples/python/issue_verify.py). |
| **Agent-to-Agent (A2A) patterns** | **Protocol foundation shipped; reference patterns documented.** A DID-identified agent can issue a scoped DAT to another agent and chain delegations. Concrete walkthroughs ship post-v1.0. | Protocol-level treatment in [`../concepts.md`](../concepts.md). Multi-agent example: [`crates/idprova-mcp/examples/multi_agent.rs`](../../crates/idprova-mcp/examples/multi_agent.rs). |
| **CrewAI** | **Planned (post-v1.0, v1.1 target).** | Not started. |
| **AutoGen** | **Planned (post-v1.0, v1.1 target).** | Not started. |

## Picking an integration path

If you are…

- **Wrapping an MCP server** — start with [`crates/idprova-mcp/examples/filesystem_mcp.rs`](../../crates/idprova-mcp/examples/filesystem_mcp.rs). It is the shortest end-to-end path: keypair → DAT → tool call → signed receipt.
- **Already on Okta / Entra / Auth0** — use the OIDC bridge. Your existing user authentication stays in place; IDProva only mints scoped DATs for the agent identity. See the standards-alignment table in the [root README](../../README.md#works-alongside-your-existing-identity-stack).
- **Building with LangChain today** — use the `idprova_http.IDProvaClient` Python class directly (see `examples/python/`). The `idprova_langchain` callback handler is in flight and lands as part of the v1.0 launch.
- **Building with CrewAI / AutoGen** — there is no first-party adapter yet. The Python HTTP client is generic enough to wire into either framework's tool-call hook; first-party adapters land post-v1.0.

## Conventions

- Every "Shipped" row above is backed by code paths in this repo or by package versions on the public registries (PyPI, crates.io, npm).
- Every "In flight" row is backed by a dated Asana task in the [v3 16-Week Launch Plan](https://github.com/techblaze-au/idprova/projects).
- "Planned" means scoped but not started; promised post-v1.0.

If a row's status looks wrong against current reality, please open an issue rather than amending this file directly — the intent is for this page to track repo state, not aspirational state.
