# Publishing Guide

Steps to publish each IDProva package to its respective registry.

## Prerequisites

- Rust toolchain >= 1.82
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

## TypeScript SDK (npm)

Located at `sdks/typescript/packages/core/`. Uses napi-rs for native bindings.

```bash
cd sdks/typescript/packages/core

# Build native module
npm run build

# Test
npm test

# Publish
npm publish --access public
```

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
