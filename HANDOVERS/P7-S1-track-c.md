# Track C — Phase 7, Session 1 (SDK/CLI Persistence & Config)

**Date:** 2026-03-05
**Track:** C (SDK/CLI)
**Status:** ✅ ALL TASKS COMPLETE

---

## What Was Done

### 1. Python SDK — `AgentIdentity.save()` / `AgentIdentity.load()`
- **File:** `sdks/python/src/lib.rs`
- Added `save(path=None)` — saves keypair + AID + metadata to `~/.idprova/identities/{name}/`
- Added `load(path)` — static method, reads hex key + AID JSON, validates AID
- Added `expand_home()` + `default_identity_dir()` helpers
- Private key saved as hex-encoded 32 bytes, chmod 0600 on Unix

### 2. Python SDK — `ReceiptLog.append()`
- **File:** `sdks/python/src/lib.rs`
- Added `append(agent_did, dat_jti, action_type, input_data, signing_key, ...)`
- Generates ULID receipt ID, computes BLAKE3 input/output hashes
- Builds Receipt with chain linking (previous_hash, sequence_number)
- Signs canonical JSON with empty signature field, fills hex signature
- All optional params: server, tool, output_data, status, duration_ms, session_id

### 3. CLI — `~/.idprova/config.toml` support
- **New file:** `crates/idprova-cli/src/config.rs`
- **Modified:** `crates/idprova-cli/src/main.rs`
- Config schema: `registry_url`, `default_key`, `output_format`
- Loads from `~/.idprova/config.toml`, falls back to defaults
- CLI `--registry` args changed from `default_value` to `Option<String>` — config value used when arg not provided

### 4. TypeScript SDK — `AgentIdentity.save()` / `AgentIdentity.load()`
- **File:** `sdks/typescript/packages/core/src/native.rs`
- Identical API surface to Python: `save(path?)`, `load(path)`
- Same on-disk format (directory with secret.key + aid.json + identity.json)

### 5. TypeScript SDK — `ReceiptLog.append()`
- **File:** `sdks/typescript/packages/core/src/native.rs`
- Identical API to Python, adapted for napi-rs types (Buffer instead of &[u8])

---

## Files Changed

| File | Change |
|------|--------|
| `Cargo.toml` | Added `toml = "0.8"` to workspace deps |
| `sdks/python/Cargo.toml` | Added `hex`, `ulid` workspace deps |
| `sdks/python/src/lib.rs` | +save/load on AgentIdentity, +append on ReceiptLog, +path helpers, +imports |
| `sdks/typescript/packages/core/Cargo.toml` | Added `hex`, `ulid` workspace deps |
| `sdks/typescript/packages/core/src/native.rs` | +save/load on AgentIdentity, +append on ReceiptLog, +path helpers, +imports |
| `crates/idprova-cli/Cargo.toml` | Added `toml` workspace dep |
| `crates/idprova-cli/src/config.rs` | **NEW** — Config struct + loader |
| `crates/idprova-cli/src/main.rs` | Added `mod config`, config loading, registry URL resolution from config |

---

## Build Status

- `cargo build --workspace` (excluding SDKs for PyO3 path issue): ✅
- `cargo test --workspace` (81 tests): ✅ ALL PASS
- `cargo build -p idprova-python` (with PYO3_PYTHON): ✅
- `cargo build -p idprova-typescript`: ✅

---

## On-Disk Identity Format

```
~/.idprova/identities/{name}/
  secret.key       # hex-encoded 32-byte Ed25519 secret (0600 on Unix)
  aid.json         # AidDocument JSON
  identity.json    # {"version": 1, "did": "...", "created": "..."}
```

---

## Known Issues / Warnings

1. **CLI config warnings:** `default_key` and `output_format` fields are parsed but not yet consumed by commands — warnings expected until commands use them
2. **PyO3 Python path:** Build requires `PYO3_PYTHON` env var pointing to correct Python 3.13 on this machine
3. **Receipt signing:** Uses canonical JSON with empty signature field. Verifier must zero signature before re-verifying.

---

## What's Next

- **Track C Session 2 (optional):** TypeScript SDK config file support (low priority — config is CLI-focused)
- **Track A Session A-2:** Fix Quick Start API mismatch, scope grammar decision
- **Track D:** Doc stubs, website deploy
- **Testing:** Add pytest + vitest integration tests for save/load/append roundtrips
