# IDProva Agents — Guard Contract (Conversation A spec)

**Author:** Claude (orchestrator) · **Status:** contract locked; implementation delegated to MiMo.
This is the framework-agnostic heart of the agent adapters. LangChain/CrewAI/AutoGen are thin
shims over it. **The non-negotiable acceptance test is that emitted receipts pass
`idprova receipt verify`.** Do not claim "verifiable receipts" until that test is green.

## 0. Honesty-gate finding (resolved 2026-06-08)

The pre-existing `sdks/python/idprova_langchain.py` writes a **flat 6-field** receipt
(`timestamp, agent_did, tool, outcome, payload_hash, prev_hash`), unsigned, hashing the whole
dict in insertion order, chain starting at `None`. The Rust `idprova receipt verify`
(`crates/idprova-cli/src/commands/receipt.rs` → `ReceiptLog::verify_integrity`) deserializes a
**nested, camelCase** `Receipt` and recomputes a BLAKE3 chain. **The two are cross-incompatible
— today's Python receipts DO NOT pass `idprova receipt verify`.** The docstring claiming parity
is false. This contract replaces that schema with the real one.

## 1. The receipt schema MiMo MUST emit (matches Rust `Receipt`)

Source of truth: `crates/idprova-core/src/receipt/entry.rs` + `…/receipt/log.rs`.

JSON object per line (JSONL), keys in **camelCase**, optional fields omitted when absent:

```jsonc
{
  "id": "<uuid-v4 string>",
  "timestamp": "<RFC3339 UTC, e.g. 2026-06-07T22:54:50.690357Z>",
  "agent": "<AID, e.g. did:aid:co:researcher>",
  "dat": "<DAT id or token string the action was authorized under>",
  // "kind": omitted when the default/"data" kind (serde skips it)
  "action": {
    "type": "<action type, e.g. \"tool_call\">",   // serde rename: action_type -> "type"
    "tool": "<tool name>",                           // optional
    "inputHash": "blake3:<64-hex>",                  // blake3 of the canonical tool input
    "status": "<allowed|denied|success|error>"       // outcome of the call
    // "outputHash","durationMs","server" optional — omit when absent
  },
  // "context": {...} optional — omit when absent
  "chain": { "previousHash": "<genesis|blake3:...>", "sequenceNumber": <u64> },
  "signature": "<base64 Ed25519 signature over the signing-payload bytes>"
  // "anchor": omitted (anchoring is a later/optional step)
}
```

## 2. Hash chain (must match `verify_integrity`)

- Entry 0: `chain.previousHash = "genesis"`, `chain.sequenceNumber = 0`.
- Entry i>0: `chain.previousHash = compute_hash(entry[i-1])`, `chain.sequenceNumber = i`.
- `compute_hash(entry)` = `"blake3:" + blake3_hex(signing_payload_bytes(entry))`.
- `signing_payload_bytes` = `serde_json::to_vec` of a struct with fields **in this exact order**:
  `id, timestamp, agent, dat, kind, action, context, chain` — **excluding** `signature` and
  `anchor`. `kind` and `context` follow the same skip-when-absent rules as the wire form.

### Byte-exactness is the whole game (CRITICAL)
`verify_integrity` recomputes `compute_hash`, so the Python JSON bytes fed to BLAKE3 must be
**byte-identical** to what serde_json produces. Requirements:
- Compact separators: `json.dumps(obj, separators=(",", ":"))`.
- **`ensure_ascii=False`** (serde_json emits raw UTF-8; Python's default escapes non-ASCII).
- Preserve field order via an ordered dict built in the order above (do **not** sort keys).
- `timestamp` must serialize the way chrono's `DateTime<Utc>` does (RFC3339, `Z` suffix). This is
  the highest interop risk — confirm against a real round-trip, do not assume.
- `inputHash` / hashes use lowercase hex with the `blake3:` prefix (see
  `crates/idprova-core/src/crypto/hash.rs::prefixed_blake3`).

## 3. ToolGuard API (framework-agnostic)

```python
class Decision:
    allowed: bool
    reason: str          # human-readable; e.g. "scope 'mcp:tool:x:write' not granted"

class ToolGuard:
    def __init__(self, aid: str, dat: str, signing_key,  # Ed25519 private key (agent's)
                 scope_for_tool: Callable[[str], str],    # tool name -> required scope
                 granted_scopes: list[str],               # parsed from the DAT
                 receipts_path: str): ...

    def check(self, tool_name: str, tool_input) -> Decision:
        """Map tool -> required scope; allow iff required scope is covered by granted_scopes
        using the 4-part grammar (namespace:protocol:resource:action), honoring the same
        subset/wildcard semantics as Rust ScopeSet (crates/idprova-core/src/dat/scope.rs)."""

    def record(self, tool_name: str, tool_input, status: str) -> None:
        """Append ONE receipt (schema §1, chain §2) for this call — whether allowed or denied."""
```

- **Both allow and deny are recorded** (accountability covers refusals too).
- Reuse the existing pure-Python `idprova_http.IDProvaClient`
  (`create_aid/get_aid/issue_dat/verify_dat/list_aids`) for anything needing the registry; the
  guard itself is offline (scope check + receipt append).

## 4. LangChain adapter (upgrade `idprova_langchain.py`: audit-only → enforce+audit)

- `BaseCallbackHandler.on_tool_start`: call `guard.check(tool, input)`; if `not allowed`,
  `guard.record(..., "denied")` then **raise** to abort the tool call; else proceed.
- `on_tool_end` / `on_tool_error`: `guard.record(..., "success"|"error")`.
- Also provide a tool-wrapper (`guarded_tool(tool, guard)`) for hard enforcement where a
  callback raise alone isn't sufficient to prevent execution.
- Keep an `audit_only=True` switch for users who want logging without blocking, but the default
  is **enforce**.

## 5. Runnable example — `examples/langchain/quickstart.py`

A research agent with two tools:
- `knowledge_base_search` → required scope `mcp:tool:knowledge-base:read` (**granted** → ALLOWED).
- `send_email` → required scope `mcp:tool:email:send` (**not granted** → BLOCKED before it runs).

Flow: create/lookup AID → issue a scoped DAT (`mcp:tool:knowledge-base:read`, short expiry) →
run the agent → show the in-scope call succeeding, the out-of-scope call blocked, then run
`idprova receipt verify receipts.jsonl` and print `VALID`.

## 6. The acceptance test (CI-runnable) — DEFINITION OF DONE

`tests/test_langchain_quickstart.py`:
1. Start a local registry (`cargo run -p idprova-registry`) OR run fully offline if the example
   doesn't need resolution.
2. Run the quickstart.
3. Assert: in-scope tool ran; out-of-scope tool was blocked (raised/denied + a `"denied"` receipt
   exists); and **`idprova receipt verify receipts.jsonl` prints `VALID`** (shell out to the
   built CLI). This last assertion is the honesty gate — iterate the serializer until it passes.

> **Do not flip the `docs/integrations` LangChain row to "Shipped"** until this test is green in
> CI. Until then it stays "In flight".

## 7. Known environment constraint (carry to whoever runs it)

This was authored on a host at **97% disk (≈19 GB free)**; the prior session deliberately avoided
Rust builds (ENOSPC + Windows thin-LTO LNK1120 flake). The §6 cargo step needs disk headroom —
run the verification on a machine with space, or after freeing the drive. **Code may be drafted
and reviewed without it, but the "verifiable" claim is NOT earned until §6 passes.**
