# v0.1.2 — cross-platform TypeScript SDK (5 platforms)

This release fixes a long-standing install issue: `@idprova/core@0.1.1` was published with a Windows-only native binary, which broke `npm install @idprova/core` on macOS and Linux. From v0.1.2 onward, five pre-built native binaries ship from a single tag — no more host-restricted installs.

## What's new

**Cross-platform `@idprova/core@0.1.2` on npm**

The metapackage is now backed by five platform-specific packages, each containing a pre-built native binary. npm picks the right one automatically via `optionalDependencies`:

| Package | Platform |
|---|---|
| `@idprova/core-win32-x64-msvc` | Windows x64 (MSVC) |
| `@idprova/core-darwin-arm64` | macOS Apple Silicon |
| `@idprova/core-linux-x64-gnu` | Linux x64 (glibc) |
| `@idprova/core-linux-arm64-gnu` | Linux ARM64 (glibc) — AWS Graviton, Azure Ampere |
| `@idprova/core-linux-x64-musl` | Linux x64 (musl) — Alpine, smaller Docker images |

```bash
npm install @idprova/core
```

now succeeds on every supported platform.

> **Intel Mac users**: macOS x86_64 is **not** in v0.1.2. GitHub's `macos-13` runners have been persistently unavailable on this account (queued >1.5h across 4 dry-runs, never picking up; macOS-13 was deprecated in late 2024). Tracked for v0.1.3 follow-up via cross-compile from Apple Silicon. Apple stopped Intel Mac sales in 2022; if you're on Intel Mac and need IDProva sooner, please open an issue. All packages are published with [npm provenance attestation](https://docs.npmjs.com/generating-provenance-statements) so consumers can verify they were built by GitHub Actions from this repo.

**New runnable TypeScript examples**

`examples/typescript/` now ships two runnable demos:

- [`quickstart.ts`](examples/typescript/quickstart.ts) — generate keys, build an Agent Identity, issue and verify a Delegation Attestation Token (DAT), append to a Receipt Log
- [`mcp-protected.ts`](examples/typescript/mcp-protected.ts) — wrap an MCP-style request handler so every call requires a valid IDProva delegation chain (signature + scope + timing + audit-log)

```bash
cd examples/typescript
npm install
npm run quickstart
npm run mcp
```

**New compliance documentation (no protocol changes)**

Three new operator-facing docs land in this release; framed as factual cryptographic-evidence mappings, not legal opinions:

- [`docs/key-rotation.md`](docs/key-rotation.md) — operator playbook (~1900 words) consolidating rotation/revocation references previously scattered across the protocol spec. Covers scheduled vs emergency rotation, compromise recovery runbook, air-gapped operations, threat-model integration.
- [`docs/controls.md`](docs/controls.md) — NIST SP 800-53 Rev 5 mapping. 25 controls across AU (9), IA (5), AC (4), SC (6), SI (2). Includes Australian baseline mapping (OFFICIAL→Moderate, PROTECTED→Moderate+High, SECRET→High).
- [`docs/gdpr.md`](docs/gdpr.md) — GDPR Article-by-article mapping (Art 5/6/25/30/32/33/35/12-22/44-50) + DPA template references + EU AI Act considerations.

[`docs/compliance.md`](docs/compliance.md) now cross-references all three.

## Infrastructure

A new GitHub Actions workflow (`.github/workflows/npm-publish.yml`) builds + tests + publishes all six platform binaries from a single `v*` tag push. It supports `workflow_dispatch` with a `dry_run` input for verification without publishing — useful before any future release. See [`PUBLISHING.md`](PUBLISHING.md) for the operator procedure.

## Upgrade

For consumers:

```bash
npm install @idprova/core@0.1.2
```

No code changes required. The TypeScript surface is byte-compatible with v0.1.1.

For maintainers releasing future versions: follow `PUBLISHING.md` — bump version, push a `v*` tag, the workflow handles the rest. Always run a dry-run first via `gh workflow run npm-publish.yml -f dry_run=true`.

## Verification

```bash
npm view @idprova/core@0.1.2
# Should show all 6 optionalDependencies entries

npm install @idprova/core@0.1.2
# Should succeed on Windows / macOS Intel / macOS Apple Silicon / Linux glibc x64 / Linux glibc arm64 / Linux musl x64

node -e "const { KeyPair } = require('@idprova/core'); console.log(KeyPair.generate().publicKeyMultibase);"
# Should print a multibase-encoded Ed25519 public key, e.g. z6MkN...
```

Provenance attestation can be verified via `npm audit signatures @idprova/core@0.1.2`.

## Acknowledgements

Thanks to early contributors who flagged the Windows-only install issue. The fix path required two CI-side hotfixes ([PR #34](https://github.com/techblaze-au/idprova/pull/34), [PR #35](https://github.com/techblaze-au/idprova/pull/35)) discovered through dry-run iterations — see those PRs for the gory details.

— *Built and maintained by [Tech Blaze](https://techblaze.com.au).*
