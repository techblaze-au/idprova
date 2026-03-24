# 04-issue-machine-dats.ps1
# Run on Windows dev machine.
# Issues 7-day machine DATs for R710 and Kai, deploys them to each machine.
# Re-run weekly before DATs expire (check expiry in app.html My Agents screen).
#
# Usage: .\scripts\production\04-issue-machine-dats.ps1
# Prerequisites: 03-register-agents.ps1 completed.

param(
    [string]$R710       = "198.51.100.12",
    [string]$Kai        = "198.51.100.94",
    [string]$RepoRoot   = $PSScriptRoot + "\..\..\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot    = (Resolve-Path $RepoRoot).Path
$idprova     = Join-Path $RepoRoot "target\release\idprova.exe"
$keysDir     = Join-Path $RepoRoot "demo-keys\production"
$registryUrl = "http://${R710}:4242"

Write-Host "=== IDProva Machine DAT Issuance ===" -ForegroundColor Cyan
Write-Host "Registry: $registryUrl"
Write-Host "Expiry:   7 days (168h)"
Write-Host ""

# ── Verify prerequisites ──────────────────────────────────────────────────────
if (-not (Test-Path $idprova)) {
    Write-Error "Binary not found: $idprova`nRun: cargo build --release -p idprova-cli"
}

$r710KeyPath = Join-Path $keysDir "r710-agent.key"
$kaiKeyPath  = Join-Path $keysDir "kai-agent.key"

foreach ($f in @($r710KeyPath, $kaiKeyPath)) {
    if (-not (Test-Path $f)) {
        Write-Error "Key not found: $f`nRun 03-register-agents.ps1 first."
    }
}

# ── Issue R710 machine DAT ────────────────────────────────────────────────────
Write-Host "[1/3] Issuing DAT for Dell R710 (did:aid:techblaze.com.au:r710)..."

$r710Dat = & $idprova dat issue `
    --issuer  "did:aid:techblaze.com.au:r710" `
    --subject "did:aid:techblaze.com.au:r710" `
    --scope   "mcp:tool:*:call" `
    --expires-in "168h" `
    --key $r710KeyPath 2>&1

if ($LASTEXITCODE -ne 0) { Write-Error "DAT issuance failed for R710: $r710Dat" }
$r710Dat = $r710Dat.Trim()
Write-Host "      DAT issued ($($r710Dat.Length) chars)"

# Deploy to R710
$tmpR710 = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tmpR710 -Value $r710Dat -NoNewline
scp $tmpR710 "root@${R710}:/opt/idprova/keys/machine-dat.txt"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP r710 DAT failed" }
ssh "root@$R710" "chmod 600 /opt/idprova/keys/machine-dat.txt && chown idprova:idprova /opt/idprova/keys/machine-dat.txt"
Remove-Item $tmpR710
Write-Host "      Deployed to R710:/opt/idprova/keys/machine-dat.txt"

# ── Issue Kai machine DAT ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/3] Issuing DAT for Kai Server (did:aid:techblaze.com.au:kai-server)..."

# Kai gets limited scope — only the tools it needs
$kaiScope = "mcp:tool:echo:call,mcp:tool:calculate:call,mcp:tool:read_file:call"

$kaiDat = & $idprova dat issue `
    --issuer  "did:aid:techblaze.com.au:kai-server" `
    --subject "did:aid:techblaze.com.au:kai-server" `
    --scope   $kaiScope `
    --expires-in "168h" `
    --key $kaiKeyPath 2>&1

if ($LASTEXITCODE -ne 0) { Write-Error "DAT issuance failed for Kai: $kaiDat" }
$kaiDat = $kaiDat.Trim()
Write-Host "      DAT issued ($($kaiDat.Length) chars)"
Write-Host "      Scope: $kaiScope"

# Deploy to Kai
$tmpKai = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tmpKai -Value $kaiDat -NoNewline
scp $tmpKai "root@${Kai}:/root/.idprova/current-dat.txt"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP Kai DAT failed" }
ssh "root@$Kai" "chmod 600 /root/.idprova/current-dat.txt"
Remove-Item $tmpKai
Write-Host "      Deployed to Kai:~/.idprova/current-dat.txt"

# ── Verify Kai can call MCP ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/3] Verifying Kai can call MCP echo tool..."

$testCmd = @"
curl -s -X POST http://${R710}:3001/ \
  -H "Authorization: Bearer `$(cat ~/.idprova/current-dat.txt)" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"DAT test from Kai"}}}'
"@

$result = ssh "root@$Kai" $testCmd
Write-Host "      Response: $result"

if ($result -match "DAT test from Kai") {
    Write-Host "      Kai MCP call: OK" -ForegroundColor Green
} else {
    Write-Warning "Kai MCP call returned unexpected response. Check:"
    Write-Host "  ssh root@$Kai 'curl -v ... (same command)'"
    Write-Host "  ssh root@$R710 'journalctl -u idprova-mcp -n 20 --no-pager'"
}

Write-Host ""
Write-Host "=== DAT issuance complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "DAT expiry: 7 days from now"
Write-Host "Renewal:    Re-run this script weekly, or when app.html shows expiry < 24h"
Write-Host ""
Write-Host "To verify in browser:"
Write-Host "  1. Open dashboard/app.html"
Write-Host "  2. Load Session → demo-keys/production/session-production.json"
Write-Host "  3. My Agents → check expiry countdowns"
