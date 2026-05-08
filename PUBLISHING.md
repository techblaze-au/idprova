# Publishing Guide

Steps to publish each IDProva package to its respective registry.

## Prerequisites

- Rust toolchain >= 1.85
- `cargo login` with a crates.io API token
- Python >= 3.9 with `maturin` installed (for Python SDK)
- npm account (for TypeScript SDK)

## Rust Crates (crates.io)

Crates must be published in dependency order. The workspace uses `Apache-2.0` licensing.

### 1. idprova-core

The foundational crate. No IDProva dependencies.

```bash
cargo publish -p idprova-core --dry-run   # validate first
cargo publish -p idprova-core
```

### 2. idprova-verify

Depends on `idprova-core`.

```bash
cargo publish -p idprova-verify --dry-run
cargo publish -p idprova-verify
```

### 3. idprova-middleware

Depends on `idprova-core` and `idprova-verify`.

```bash
cargo publish -p idprova-middleware --dry-run
cargo publish -p idprova-middleware
```

### 4. idprova-registry

Depends on `idprova-core` and `idprova-verify`.

```bash
cargo publish -p idprova-registry --dry-run
cargo publish -p idprova-registry
```

### 5. idprova-cli

Depends on `idprova-core`.

```bash
cargo publish -p idprova-cli --dry-run
cargo publish -p idprova-cli
```

### Before publishing any crate

1. Ensure each crate has a `README.md` in its directory
2. Update version in `Cargo.toml` workspace (all crates share the workspace version)
3. Update path dependencies to registry dependencies:
   - Change `idprova-core = { path = "../idprova-core" }` to `idprova-core = { version = "0.1.0" }`
   - Do this for all inter-crate references before publishing
4. Run `cargo publish --dry-run -p <crate>` to validate
5. Commit the version bump before publishing

### Not published to crates.io

- `idprova-mcp-demo` — demo/example crate (`publish = false`)
- `idprova-python` — Python SDK native extension (`publish = false`)
- `idprova-typescript` — TypeScript SDK native extension (`publish = false`)

## Python SDK (PyPI)

Published via maturin (PyO3 bindings). Located at `sdks/python/`.

```bash
cd sdks/python

# Build wheel
maturin build --release

# Test locally
pip install target/wheels/idprova-*.whl
python -c "import idprova; print(idprova.__version__)"

# Publish to TestPyPI first
maturin publish --repository testpypi

# Publish to PyPI
maturin publish
```

Requires `~/.pypirc` or `MATURIN_PYPI_TOKEN` environment variable.

## TypeScript SDK (npm) — automated via GitHub Actions

Located at `sdks/typescript/packages/core/`. Uses napi-rs for native bindings.

The TS SDK ships native binaries per platform — Windows, macOS (Intel + Apple Silicon), and Linux (glibc x64, glibc arm64, musl x64). To get all of them on npm in one go, **use the automated workflow** rather than publishing manually from a local host (which only produces the host's binary).

### One-time setup (per-repo)

1. Create an npm Automation token with publish access to the `@idprova` scope:
   - https://www.npmjs.com/settings/<your-user>/tokens → "Generate New Token" → "Automation"
2. Add it as a GitHub Actions secret:
   - GitHub repo → Settings → Secrets and variables → Actions → "New repository secret"
   - Name: `NPM_TOKEN`
   - Value: the token from step 1

### To release a new TS SDK version

1. Bump the version in `sdks/typescript/packages/core/package.json` (and the matching versions inside `optionalDependencies`).
2. Commit and push to `main`.
3. Tag and push: `git tag v0.1.2 && git push origin v0.1.2`.
4. The `.github/workflows/npm-publish.yml` workflow will:
   - Build a native `.node` binary on each of: `windows-latest` (x64-msvc), `macos-13` (Intel), `macos-latest` (Apple Silicon), and three Linux variants in official napi-rs Docker images (glibc x64, glibc arm64, musl x64).
   - Smoke-test each binary on its native host with vitest.
   - Run `napi artifacts` and `napi prepublish` to stage per-platform packages.
   - Publish 6 platform packages (`@idprova/core-win32-x64-msvc`, `@idprova/core-darwin-x64`, `@idprova/core-darwin-arm64`, `@idprova/core-linux-x64-gnu`, `@idprova/core-linux-arm64-gnu`, `@idprova/core-linux-x64-musl`) plus the metapackage `@idprova/core`.
5. Verify: `npm view @idprova/core` should show the new version, and `npm install @idprova/core` should now succeed on macOS and Linux (not just Windows).

### Dry-run before a real release

To verify a release would succeed *without* actually publishing:

- GitHub repo → Actions tab → "npm publish (TS SDK)" → "Run workflow"
- Set `dry_run` to `true`
- The build + test jobs run; the publish job is skipped
- If all 6 platforms build and all 4 host tests pass, the next tagged release is safe to ship

### Manual publish (legacy / single-platform, NOT recommended)

Only use this if the GitHub Actions workflow is broken or for emergency patches. It will produce a metapackage with **only your host's binary**, breaking `npm install` for users on other platforms.

```bash
cd sdks/typescript/packages/core

# Build native module for the current host only
npm run build -- --target $(rustc -vV | sed -n 's/host: //p')

# Test
npm test

# Publish (single-platform — broken on other OSes)
npm publish --access public
```

This is how `@idprova/core@0.1.1` ended up Windows-only. Do not repeat. Use the workflow.

## Version Bumping

All Rust crates share the workspace version in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.0"
```

To bump the version:
1. Update `version` in root `Cargo.toml` under `[workspace.package]`
2. Update `version` in `sdks/python/pyproject.toml`
3. Update `version` in `sdks/typescript/packages/core/package.json` (if exists)
4. Commit: `git commit -m "chore: bump version to X.Y.Z"`
5. Tag: `git tag vX.Y.Z`

## CI/CD

Consider adding GitHub Actions workflows for automated publishing:
- On tag push `v*`: publish all crates, build Python wheels, publish npm package
- Use `cargo-release` for orchestrating Rust crate publishing in order
