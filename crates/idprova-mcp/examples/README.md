# `idprova-mcp` examples

Runnable Rust examples that show how to use IDProva to authorize and audit Model Context Protocol (MCP) tool calls. Each file is a `cargo run --example <name>` target.

## Files

- `filesystem_mcp.rs` — minimal happy path. An operator issues a DAT scoped to `mcp:tool:filesystem:read`. A worker agent calls a read tool (allowed), then tries a write tool (blocked). The example prints the full receipt chain so you can see what gets recorded for each call. Use this as the first example to read.

- `multi_agent.rs` — four-step delegation chain showing progressive scope narrowing. The operator delegates `mcp:tool:*:*` to agent A, A re-delegates `mcp:tool:filesystem:*` to B, B re-delegates `mcp:tool:filesystem:read` to C. Agent C's read succeeds; its write is blocked even though the operator's original scope would have allowed it. Use this to understand chain verification and `dat verify` against re-delegated tokens.

## Run them

```bash
# From the repo root
cargo run --example filesystem_mcp -p idprova-mcp
cargo run --example multi_agent   -p idprova-mcp
```

Both examples print to stdout. They do not start a server, talk to a registry, or write any files — verification is offline using the public keys constructed in-memory.

## Adapting these to your own MCP server

The examples build the same `McpAuth` and `McpReceiptLog` types that real integrations use (re-exported from the `idprova_mcp` crate). The pattern is:

1. Generate or load Ed25519 keypairs for each principal.
2. Issue a DAT (`Dat::issue` or `dat issue` from the CLI) with the narrowest scope the agent actually needs.
3. On every tool call: verify the DAT, check the requested scope is covered, append a signed receipt to your log.

The CLI does the same thing for ad-hoc operations — see [`../README.md`](../README.md) and the top-level [`docs/concepts.md`](../../../docs/concepts.md).
