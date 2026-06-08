# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Changes since `v0.1.2`. The next version number is not yet decided._

### Added

- Sigstore Rekor transparency-log anchoring for receipts, per ADR 0011 (opt-in, default-OFF). (#53)
- Privacy-preserving batched anchoring (salted HMAC leaf + Merkle root), per ADR 0012. (#56)
- `ChainCheckpoint` discriminator on `Receipt` (IDP-002). (#49)
- `idprova-identity-adapters` traits crate — decouples identity-provider adapters from core (IDP-020). (#51)
- Golden-path end-to-end test with independent offline verification. (#54)
- Receipt-anchor round-trip assertion in the MCP golden-path test, per ADR 0011. (#55)

### Changed

- Registry: split the 711-line `lib.rs` into focused modules (IDP-010). (#50)
- README rewritten for launch positioning. (#33)

### Fixed

- Emit BLAKE3 receipt hashes with an explicit `blake3:` algorithm prefix (IDP-030). (#45)
- Correct the OIDC-bridge capability claim (IDP-014, IDP-127). (#43)
- CI: npm-publish pipeline — `napi create-npm-dir` invocation and package name. (#40, #41, #42)

### Docs

- ADR 0003: the tenant boundary lives in the registry + adapters, not in core (IDP-005). (#48)
- Reconcile the L2 trust definition — SAML inbound deferred to v0.3. (#46)
- Reserve `riskScoreUpperBound` and `error:exec` / `error:net` for v0.3 (IDP-004). (#47)

[Unreleased]: https://github.com/techblaze-au/idprova/compare/v0.1.2...HEAD
