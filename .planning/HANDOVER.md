# Track E Handover

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-e-infra`
**Status: COMPLETE — all 6 tasks done**
**Progress:** 6 of 6 tasks complete

---

## All Tasks Completed

### Task 1: CI Pipeline — Build & Test (826ce41)
- `.github/workflows/ci.yml` updated
- Matrix: `stable` + `1.75` (MSRV), ubuntu-latest
- Excludes: `--exclude idprova-python --exclude idprova-typescript`
- Separate lint job; improved cache paths

### Task 2: Security Audit (8a8369a)
- `.github/workflows/audit.yml` created
- Weekly schedule + triggers on Cargo.lock/Cargo.toml changes
- Uses `rustsec/audit-check@v2`

### Task 3: Dockerfile Optimization (b4e57d0)
- 4-stage cargo-chef build: chef → planner → builder → runtime
- `debian:bookworm-slim` runtime, non-root `idprova` user
- HEALTHCHECK via curl against `/health` endpoint

### Task 4: Docker Compose Stack (2ea471f)
- `docker-compose.yml`: registry service with SQLite volume
- `Caddyfile`: reverse proxy with automatic HTTPS, security headers, gzip
- Caddy activated via `--profile proxy`; all config via env vars

### Task 5: Release Workflow (7647b3b)
- `.github/workflows/release.yml`: triggered on `v*` tag push
- Builds 5 targets: Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64
- Uses `cross` for Linux aarch64 cross-compilation
- Multi-arch Docker image (amd64+arm64) pushed to GHCR
- GitHub Release created with archives + SHA256 checksums
- Pre-release auto-detected from tag (e.g. `v1.0.0-rc1`)

### Task 6: Developer Scripts (5464af9)
- `scripts/dev-setup.sh`: install tooling, build, lint, test; `--skip-tests` flag
- `scripts/run-registry.sh`: build + launch registry; `--release` flag
- Both scripts are executable and idempotent

---

## Key Decisions

- CI runs ubuntu-latest only; MSRV 1.75 tested alongside stable
- SDK crates excluded from all workspace cargo commands
- Dockerfile uses `debian:bookworm-slim` (not distroless) — curl needed for healthcheck
- Caddy optional via Docker Compose profiles — zero overhead when not needed
- `cross` used for Linux aarch64 (avoids maintaining separate runners)

---

## Blockers / Issues

None.

---

## Next Steps

Track E is complete. No further execution required on this branch.
