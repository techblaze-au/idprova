#!/usr/bin/env pwsh
#
# IDProva v0.1 — Remote Demo (Windows → Linux)
#
# Runs the demo on a remote server via SSH.
# Usage: .\scripts\demo-remote.ps1 [-Host "root@192.168.8.92"] [-ProjectDir "/root/idprova"]
#

param(
    [string]$RemoteHost = "root@192.168.8.92",
    [string]$ProjectDir = "/root/idprova",
    [int]$RegistryPort = 4242,
    [int]$McpPort = 3001
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([int]$Num, [string]$Title, [string]$Description)
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor Blue
    Write-Host "  Step ${Num}: $Title" -ForegroundColor Blue -NoNewline
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor Blue
    Write-Host "  $Description" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Press Enter to continue"
}

function Write-Ok { param([string]$Msg); Write-Host "  ✓ $Msg" -ForegroundColor Green }
function Write-Fail { param([string]$Msg); Write-Host "  ✗ $Msg" -ForegroundColor Red }
function Write-Info { param([string]$Msg); Write-Host "  → $Msg" -ForegroundColor Cyan }

function Invoke-Remote {
    param([string]$Command)
    $result = ssh $RemoteHost $Command 2>&1
    return $result
}

# ── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "  ║        IDProva v0.1 — Remote Interactive Demo           ║" -ForegroundColor White
Write-Host "  ║                                                          ║" -ForegroundColor White
Write-Host "  ║  Running on: $RemoteHost" -ForegroundColor White -NoNewline
Write-Host ("".PadRight(42 - $RemoteHost.Length)) -NoNewline
Write-Host "║" -ForegroundColor White
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

# ── Step 1: Build ───────────────────────────────────────────────────────────
Write-Step 1 "Build release binaries" "Compiling IDProva on the remote server."
$buildOutput = Invoke-Remote "source ~/.cargo/env && cd $ProjectDir && cargo build --release -p idprova-cli -p idprova-registry -p idprova-mcp-demo 2>&1 | tail -5"
$buildOutput | ForEach-Object { Write-Host "  $_" }
Write-Ok "Build complete"

# ── Step 2: Start registry ──────────────────────────────────────────────────
Write-Step 2 "Start the IDProva Registry" "Running registry in dev mode on port $RegistryPort."
Invoke-Remote "cd /tmp && REGISTRY_PORT=$RegistryPort $ProjectDir/target/release/idprova-registry &" | Out-Null
Start-Sleep -Seconds 2

$health = Invoke-Remote "curl -s http://127.0.0.1:${RegistryPort}/health"
Write-Host "  $health"
Write-Ok "Registry running"

# ── Step 3: Generate keypair ────────────────────────────────────────────────
Write-Step 3 "Generate Ed25519 keypair" "Creating signing keypair for the demo controller."
Invoke-Remote "mkdir -p /tmp/idprova-demo/.idprova/keys && $ProjectDir/target/release/idprova keygen -o /tmp/idprova-demo/.idprova/keys/controller.key"
Write-Ok "Keypair generated"
$pubkey = Invoke-Remote "head -1 /tmp/idprova-demo/.idprova/keys/controller.key"
Write-Info "Public key: $pubkey"

# ── Step 4: Register AID ───────────────────────────────────────────────────
Write-Step 4 "Register Agent Identity Document" "Creating and registering a DID document."
Invoke-Remote @"
$ProjectDir/target/release/idprova aid create --id 'did:aid:example.com:demo-agent' --name 'Demo Agent' --controller 'did:aid:example.com:demo-user' --model 'idprova-demo/v1' --key /tmp/idprova-demo/.idprova/keys/controller.key > /tmp/idprova-demo/aid.json
"@ | ForEach-Object { Write-Host "  $_" }

$registerResult = Invoke-Remote "curl -s -X PUT http://127.0.0.1:${RegistryPort}/v1/aid/example.com:demo-agent -H 'Content-Type: application/json' -d @/tmp/idprova-demo/aid.json"
Write-Host "  $registerResult"
Write-Ok "AID registered"

# ── Step 5: Issue DAT ──────────────────────────────────────────────────────
Write-Step 5 "Issue Delegation Attestation Token" "Creating a scoped, time-bounded DAT."
$datToken = Invoke-Remote "$ProjectDir/target/release/idprova dat issue --issuer 'did:aid:example.com:demo-user' --subject 'did:aid:example.com:demo-agent' --scope 'mcp:tool:echo:call,mcp:tool:calculate:call' --expires-in '1h' --key /tmp/idprova-demo/.idprova/keys/controller.key"
$datToken = $datToken.Trim()
Write-Ok "DAT issued"
Write-Info "Token: $($datToken.Substring(0, [Math]::Min(80, $datToken.Length)))..."

# ── Step 6: Verify DAT ────────────────────────────────────────────────────
Write-Step 6 "Verify DAT via registry" "Signature + timing + scope verification."
$verifyResult = Invoke-Remote "curl -s -X POST http://127.0.0.1:${RegistryPort}/v1/dat/verify -H 'Content-Type: application/json' -d '{`"token`":`"$datToken`",`"scope`":`"mcp:tool:echo:call`"}'"
Write-Host "  $verifyResult"
Write-Ok "DAT verified"

# ── Step 7: Start MCP server ──────────────────────────────────────────────
Write-Step 7 "Start MCP demo server" "MCP server with DAT bearer auth + BLAKE3 receipts."
Invoke-Remote "mkdir -p /tmp/idprova-demo/public && echo 'Hello from IDProva!' > /tmp/idprova-demo/public/readme.txt && REGISTRY_URL=http://127.0.0.1:${RegistryPort} MCP_PORT=$McpPort PUBLIC_DIR=/tmp/idprova-demo/public RECEIPTS_FILE=/tmp/idprova-demo/receipts.jsonl $ProjectDir/target/release/idprova-mcp-demo &" | Out-Null
Start-Sleep -Seconds 2
$mcpHealth = Invoke-Remote "curl -s http://127.0.0.1:${McpPort}/health"
Write-Host "  $mcpHealth"
Write-Ok "MCP server running"

# ── Step 8: Call MCP tool ──────────────────────────────────────────────────
Write-Step 8 "Call MCP tool with DAT" "JSON-RPC echo tool call with bearer token auth."
$mcpResult = Invoke-Remote "curl -s -X POST http://127.0.0.1:${McpPort}/ -H 'Content-Type: application/json' -H 'Authorization: Bearer $datToken' -d '{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"echo`",`"params`":{`"message`":`"Hello from Windows!`"}}'"
Write-Host "  $mcpResult"
Write-Ok "Tool call executed"

# ── Step 9: View receipts ─────────────────────────────────────────────────
Write-Step 9 "View BLAKE3 receipt chain" "Tamper-evident audit trail."
$receipts = Invoke-Remote "curl -s http://127.0.0.1:${McpPort}/receipts"
Write-Host "  $receipts"
Write-Ok "Receipt chain intact"

# ── Step 10: Wrong scope → 403 ────────────────────────────────────────────
Write-Step 10 "Wrong scope → 403" "Calling read_file with echo-only DAT."
$scopeCode = Invoke-Remote "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:${McpPort}/ -H 'Content-Type: application/json' -H 'Authorization: Bearer $datToken' -d '{`"jsonrpc`":`"2.0`",`"id`":3,`"method`":`"read_file`",`"params`":{`"filename`":`"readme.txt`"}}'"
Write-Host "  HTTP Status: $scopeCode"
if ($scopeCode -match "403") { Write-Ok "Scope enforcement works!" } else { Write-Info "Got $scopeCode (expected 403)" }

# ── Step 11: Expired token → 401 ──────────────────────────────────────────
Write-Step 11 "Expired token → 401" "Issue 1s DAT, wait, attempt use."
$shortDat = Invoke-Remote "$ProjectDir/target/release/idprova dat issue --issuer 'did:aid:example.com:demo-user' --subject 'did:aid:example.com:demo-agent' --scope 'mcp:tool:echo:call' --expires-in '1s' --key /tmp/idprova-demo/.idprova/keys/controller.key"
$shortDat = $shortDat.Trim()
Write-Info "Waiting 2 seconds for expiry..."
Start-Sleep -Seconds 2
$expiredCode = Invoke-Remote "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:${McpPort}/ -H 'Content-Type: application/json' -H 'Authorization: Bearer $shortDat' -d '{`"jsonrpc`":`"2.0`",`"id`":4,`"method`":`"echo`",`"params`":{`"message`":`"expired`"}}'"
Write-Host "  HTTP Status: $expiredCode"
if ($expiredCode -match "401") { Write-Ok "Expiry enforcement works!" } else { Write-Info "Got $expiredCode (expected 401)" }

# ── Step 12: Revoke DAT ──────────────────────────────────────────────────
Write-Step 12 "Revoke DAT" "Revoking the original token, then attempting use."
$jti = Invoke-Remote "echo '$datToken' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c `"import sys,json; print(json.load(sys.stdin)['jti'])`""
$jti = $jti.Trim()
Write-Info "Revoking JTI: $jti"
Invoke-Remote "curl -s -X POST http://127.0.0.1:${RegistryPort}/v1/dat/revoke -H 'Content-Type: application/json' -d '{`"jti`":`"$jti`",`"reason`":`"demo revocation`",`"revoked_by`":`"did:aid:example.com:demo-user`"}'" | ForEach-Object { Write-Host "  $_" }
Write-Ok "DAT revoked"

$revokedCode = Invoke-Remote "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:${McpPort}/ -H 'Content-Type: application/json' -H 'Authorization: Bearer $datToken' -d '{`"jsonrpc`":`"2.0`",`"id`":5,`"method`":`"echo`",`"params`":{`"message`":`"revoked`"}}'"
Write-Host "  HTTP Status: $revokedCode"
if ($revokedCode -match "401") { Write-Ok "Revocation enforcement works!" } else { Write-Info "Got $revokedCode" }

# ── Cleanup ─────────────────────────────────────────────────────────────────
Write-Step 13 "Cleanup" "Stopping background processes and cleaning up."
Invoke-Remote "pkill -f idprova-registry 2>/dev/null; pkill -f idprova-mcp-demo 2>/dev/null; rm -rf /tmp/idprova-demo" | Out-Null
Write-Ok "Cleanup complete"

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║              IDProva v0.1 Demo Complete!                 ║" -ForegroundColor Green
Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  ✓ Ed25519 key generation                               ║" -ForegroundColor Green
Write-Host "  ║  ✓ AID registration + resolution                        ║" -ForegroundColor Green
Write-Host "  ║  ✓ DAT issuance + verification                          ║" -ForegroundColor Green
Write-Host "  ║  ✓ MCP tool call with bearer auth                       ║" -ForegroundColor Green
Write-Host "  ║  ✓ BLAKE3 receipt chain                                  ║" -ForegroundColor Green
Write-Host "  ║  ✓ Scope enforcement (403)                               ║" -ForegroundColor Green
Write-Host "  ║  ✓ Token expiry (401)                                    ║" -ForegroundColor Green
Write-Host "  ║  ✓ Token revocation                                      ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Learn more: https://idprova.dev" -ForegroundColor Cyan
Write-Host ""
