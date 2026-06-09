# idprova_agents — implementation notes

## Status (2026-06-08)

| Component | State |
|---|---|
| `guard.py` (ToolGuard + receipt serializer + scope check) | **Built and VERIFIED on R710** |
| `__init__.py` | Built |
| `GUARD_CONTRACT.md` | Locked spec |
| `idprova_langchain.py` audit→enforce+audit upgrade | **Pending** (delegated to MiMo) |
| `examples/langchain/quickstart.py` | **Pending** |
| `tests/test_langchain_quickstart.py` | **Pending** |

## The honesty gate is PASSED (proven, not asserted)

The contract's definition-of-done is that emitted receipts pass `idprova receipt verify`.
The pre-existing `idprova_langchain.py` receipts did **not** (flat/unsigned vs the nested
camelCase Rust `Receipt`). The new `guard.py` serializer was tested against the real Rust
verifier and passes.

### How it was verified (R710 CT204 `idprova-worker-e`)

Local disk (97% full) cannot run Rust builds, so verification ran on R710:

1. Shipped this worktree (schema = `d313da4`, `anchor` field present) to CT204.
2. Built a minimal verifier (`rcheck`) depending **only** on `idprova-core` (no clap/reqwest/
   tokio) — compiles in ~7–37 s, disk-frugal — that runs `ReceiptLog::verify_integrity()`.
3. Generated receipts with `guard.py` (1 Ed25519 key; two in-scope `kb_search` ALLOWED, one
   out-of-scope `send_email` BLOCKED).
4. Ran the verifier over the receipts.

Result:

```
RESULT=VALID entries=3
```

Sample emitted receipt (chain-verified):

```json
{"id":"a3064363-…","timestamp":"2026-06-07T23:33:39.205540Z","agent":"did:aid:co:researcher","dat":"dat-demo-123","action":{"type":"tool_call","tool":"kb_search","inputHash":"blake3:b82d61eb…","status":"success"},"chain":{"previousHash":"genesis","sequenceNumber":0},"signature":"f04df85d…"}
```

### What this confirms (the risky assumptions, now verified)

- **Timestamp format:** Python `…%H:%M:%S.<6-digit µs>Z` (and bare `…SSZ` when µs == 0)
  round-trips identically through chrono's `DateTime<Utc>` serde. This was the highest interop
  risk in the contract — **confirmed**, not assumed.
- **Signing-payload byte-exactness:** field order `id,timestamp,agent,dat,[kind],action,
  [context],chain`, camelCase renames, compact separators, `ensure_ascii=False`, and the
  `kind`/`context` skip-when-default behaviour all match `serde_json::to_vec`.
- **Chain semantics:** `previousHash="genesis"` + `sequenceNumber` from 0; each link recomputes.
- **Scope enforcement:** in-scope ALLOWED, out-of-scope BLOCKED, both recorded.

## Reproduce / run the full §6 gate

The §6 gate (against the real `idprova` CLI, not just `rcheck`) still needs `cargo build
-p idprova-cli` for `idprova receipt verify` — equivalent logic, confirmed here via `rcheck`.
Run on a host with disk headroom (R710 CT204 used here; local Windows box is at 97%).

## Not yet earned

The `docs/integrations` LangChain row stays **"In flight"** until the full quickstart + CI test
land and run green. `guard.py`'s core claim ("receipts that pass the Rust verifier") **is** now
earned and evidenced above.
