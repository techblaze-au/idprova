# IDProva v0.1 Demo Scripts

End-to-end demos showing the full IDProva protocol: key generation, AID registration, DAT issuance/verification, MCP tool calls with bearer auth, BLAKE3 receipt chains, scope enforcement, token expiry, and revocation.

## Interactive Demo (bash)

Run directly on a machine with the IDProva source:

```bash
bash scripts/demo-interactive.sh
```

Requires: `cargo`, `curl`, `python3` (for JSON formatting), `bash`

Each step pauses with an explanation before executing.

## Remote Demo (PowerShell)

Run from Windows, executing commands on a remote Linux server via SSH:

```powershell
.\scripts\demo-remote.ps1 -RemoteHost "root@198.51.100.12" -ProjectDir "/root/idprova"
```

Parameters:
- `-RemoteHost` — SSH target (default: `root@198.51.100.12`)
- `-ProjectDir` — IDProva source directory on remote (default: `/root/idprova`)
- `-RegistryPort` — Registry port (default: `4242`)
- `-McpPort` — MCP demo server port (default: `3001`)

Requires: SSH access to the remote host, `cargo` on remote

## What the demo covers

| Step | Feature | Expected |
|------|---------|----------|
| 1 | Build | Release binaries compile |
| 2 | Registry | Health check returns 200 |
| 3 | Keygen | Ed25519 keypair created |
| 4 | AID | Document registered + resolved |
| 5 | DAT issue | Scoped token created |
| 6 | DAT verify | Signature + timing + scope pass |
| 7 | MCP server | Health check returns 200 |
| 8 | Tool call | Echo + calculate with bearer auth |
| 9 | Receipts | BLAKE3-chained audit trail |
| 10 | Wrong scope | HTTP 403 Forbidden |
| 11 | Expired token | HTTP 401 Unauthorized |
| 12 | Revocation | Token rejected after revoke |
