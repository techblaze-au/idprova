# IDProva MCP Demo — Public Files

This directory contains files readable via the `read_file` tool.

## About IDProva

IDProva is an open protocol for AI agent identity and delegation.

Every tool call through this MCP server is:
1. Authenticated via a DAT (Delegation Attestation Token)
2. Scope-checked against the requested tool
3. Logged in a BLAKE3-chained receipt

## Example Receipt

```json
{
  "id": "01JXXXXXXXXXXXXXXXXXXXXXXX",
  "timestamp": "2026-01-01T00:00:00Z",
  "tool": "echo",
  "subject_did": "did:idprova:example:agent1",
  "scope": "mcp:tool:echo:call",
  "request_hash": "...",
  "prev_receipt_hash": "genesis"
}
```

## Available Tools

- `echo` — echoes a message with IDProva verification stamp
- `calculate` — evaluates a math expression (max 200 chars)
- `read_file` — reads files from this public/ directory

## Links

- Protocol: https://idprova.dev
- Repository: https://github.com/techblaze-au/idprova
