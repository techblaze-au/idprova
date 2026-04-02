# L3 MCP Auth Middleware — Summary

## Crate: `idprova-mcp`

Drop-in identity verification middleware for MCP (Model Context Protocol) servers.
Provides DAT-based authentication, scope enforcement, and hash-chained audit receipts.

## Architecture

```
idprova-mcp
  ├── src/
  │   ├── lib.rs       — Public API re-exports
  │   ├── auth.rs      — McpAuth + VerifiedAgent (core verification)
  │   ├── error.rs     — McpAuthError enum with IdprovaError conversion
  │   ├── scope.rs     — scope_covers() delegating to idprova-core
  │   └── receipt.rs   — McpReceiptLog wrapping idprova-core ReceiptLog
  └── examples/
      ├── filesystem_mcp.rs  — Single-agent read/write scope demo
      └── multi_agent.rs     — 4-agent delegation chain with scope narrowing
```

## Key Types

| Type | Purpose |
|------|---------|
| `McpAuth` | Verifies DAT tokens against required scopes (offline or registry mode) |
| `VerifiedAgent` | Result of successful verification: aid, scope, trust_level, delegator, jti |
| `McpAuthError` | Error enum: MissingToken, InvalidDat, InsufficientScope, VerificationFailed |
| `McpReceiptLog` | MCP-specific receipt log with log_tool_call() and log_denial() |
| `scope_covers()` | Convenience function for 4-part scope matching |

## Dependencies

- `idprova-core` — Scope, Dat, ReceiptLog, TrustLevel, KeyPair types
- `idprova-verify` — verify_dat() full pipeline (signature + timing + scope + constraints)
- `serde`, `serde_json`, `thiserror`, `tracing`, `chrono`, `ulid`

## Test Coverage

- 29 unit tests across all 4 modules
- 2 doc-tests (lib.rs compile check, scope_covers example)
- All workspace tests pass (cargo test --workspace)
- Clippy clean (cargo clippy -p idprova-mcp)

## Examples

### filesystem_mcp
- Operator issues DAT scoped to `mcp:tool:filesystem:read`
- Worker succeeds on read, gets blocked on write
- Receipt chain printed and integrity verified

### multi_agent
- 4-agent delegation: Operator -> A -> B -> C
- Progressive scope narrowing: `mcp:tool:*:*` -> `mcp:tool:filesystem:*` -> `mcp:tool:filesystem:read`
- Agent C blocked on write and search (scope enforcement)
- 5-entry receipt chain with integrity verification

## Design Decisions

1. **Delegates to idprova-core** — No reinvention of scope matching or DAT verification
2. **Offline-first** — McpAuth::offline() for direct key verification without registry
3. **Receipt logging** — Every tool call (success or denial) produces a hash-chained receipt
4. **Error conversion** — IdprovaError maps cleanly to MCP-specific error variants
5. **No async required** — All operations are synchronous (DAT verification is CPU-only)
