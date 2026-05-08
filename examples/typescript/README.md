# IDProva — TypeScript Quickstart

Two examples demonstrating the IDProva primitives:

| File | What it shows |
|---|---|
| [`quickstart.ts`](./quickstart.ts) | Generate keys, build an Agent Identity, issue and verify a Delegation Token, append to a Receipt Log |
| [`mcp-protected.ts`](./mcp-protected.ts) | Wrap an MCP-style request handler so every call requires a valid IDProva delegation chain |

## Run it

```bash
cd examples/typescript
npm install
npm run quickstart      # runs quickstart.ts
npm run mcp             # runs mcp-protected.ts
```

`@idprova/core` is a native module via napi-rs. Supported platforms (from v0.1.2 onwards):

- Windows x64 (msvc)
- macOS x64 (Intel) and arm64 (Apple Silicon)
- Linux x64 and arm64 (glibc), x64 (musl/Alpine)

If `npm install` fails to download the platform binary, your platform is not yet supported — please open an issue at https://github.com/techblaze-au/idprova/issues with your `process.platform` and `process.arch`.

## What you should see

After running `quickstart.ts` you'll see something like:

```
1. Generated KeyPair
   public key (multibase): z7Td57yuv6GHD3nWPkkg8YhBCfusinYVLBvbMN47S44tW

2. Built Agent Identity
   DID: did:idprova:example.com:my-agent
   Trust Level: L0

3. Issued Delegation Token (DAT)
   Issuer:  did:idprova:example.com:my-agent
   Subject: did:idprova:example.com:sub-agent
   Scope:   [ 'mcp:tool:read', 'mcp:tool:list' ]
   TTL:     3600s

4. DAT signature verifies: true
5. Receipt log started — entries: 0
```

## Next steps

- [Protocol spec](../../docs/protocol-spec-v0.1.md) — the full wire format
- [API reference](../../docs/api-reference.md)
- [Concepts: AID, DAT, Receipt](../../docs/concepts.md)
- [MCP integration deep-dive](../../docs/sdk-typescript.md)
