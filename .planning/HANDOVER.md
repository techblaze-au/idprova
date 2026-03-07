# Track E Handover

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-e-infra`
**Session ended after 3 tasks (session rotation rule)**
**Progress:** 3 of 6 tasks complete

---

## Tasks Completed This Session

### Task 1: CI Pipeline — Build & Test (826ce41)
- Updated `.github/workflows/ci.yml`
- Matrix: `stable` + `1.75` (MSRV) — both on ubuntu-latest
- Excludes: `--exclude idprova-python --exclude idprova-typescript`
- Improved cache paths: `registry/index/`, `registry/cache/`, `git/db/`, `target/`
- Split lint into separate job

### Task 2: Security Audit (8a8369a)
- Created `.github/workflows/audit.yml`
- Schedule: weekly Monday 08:00 UTC
- Triggers on Cargo.lock/Cargo.toml changes and manual dispatch
- Uses `rustsec/audit-check@v2`

### Task 3: Dockerfile Optimization (b4e57d0)
- Rewrote `Dockerfile` with 4-stage cargo-chef build
- Stages: chef → planner → builder → runtime
- Dependency layer cached independently of source changes
- Added `curl` to runtime for HEALTHCHECK; hardened user setup

---

## Next Task to Execute

**Task 4: Docker Compose Stack**
- Create `docker-compose.yml`
- Registry service with SQLite volume mount
- Optional Caddy reverse proxy with automatic HTTPS
- Environment variable configuration

---

## Remaining Tasks (4, 5, 6)

4. `docker-compose.yml` — registry + Caddy reverse proxy
5. `.github/workflows/release.yml` — cross-platform release binaries + GHCR Docker push
6. `scripts/dev-setup.sh` + `scripts/run-registry.sh` — developer helper scripts

---

## Key Decisions

- CI runs on ubuntu-latest only (not matrix across OS) to keep costs down; MSRV tested on same platform
- SDK crates (`idprova-python`, `idprova-typescript`) excluded from all workspace commands in CI
- Dockerfile uses `debian:bookworm-slim` runtime (not distroless) — curl needed for HEALTHCHECK
- `cargo-chef cook` scoped to `--package idprova-registry` to avoid building SDK plumbing

---

## Blockers / Issues

None.
