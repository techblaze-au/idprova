# idprova-mcp

Drop-in identity verification for MCP (Model Context Protocol) servers.

Add cryptographic agent identity to any MCP server in 3 lines:

```rust
use idprova_mcp::McpAuth;

let auth = McpAuth::offline();
let agent = auth.verify_request(&dat_token, "mcp:tool:filesystem:read")?;
```

## Features

- **McpAuth** — online (registry lookup) and offline (air-gapped) verification
- **Scope matching** — hierarchical `mcp:tool:filesystem:read` with wildcard support
- **Receipt logging** — BLAKE3 hash-chained audit trail for tool calls and denials
- **VerifiedAgent** — agent identity, scope, trust level, delegator info

## Examples

- `filesystem_mcp` — read succeeds, write blocked by scope, receipt chain shown
- `multi_agent` — 4-agent delegation chain with progressive scope narrowing

```bash
cargo run --example filesystem_mcp
cargo run --example multi_agent
```

## Installation

```toml
[dependencies]
idprova-mcp = "0.1"
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE) for details.

Part of the [IDProva](https://github.com/techblaze-au/idprova) protocol.
