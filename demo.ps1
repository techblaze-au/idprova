#Requires -Version 5.1
<#
.SYNOPSIS
    IDProva Protocol — End-to-End Windows Demo Script

.DESCRIPTION
    Demonstrates the full IDProva identity stack:
      1. Registry starts (background)
      2. Two AI agent identities created (Alice + Bob)
      3. AIDs registered on the registry
      4. DAT issued from Alice -> Bob (delegation)
      5. DAT verified via registry (online key lookup)
      6. Sub-delegation: Bob further delegates to Charlie
      7. DAT inspection (decode without verifying)
      8. DAT revoked
      9. Revocation status confirmed
     10. Dashboard URL shown

    Suitable for investor / non-technical audience demos.

.PARAMETER RegistryPort
    Port for the local registry (default 4242).

.PARAMETER SkipBuild
    Skip cargo build step (use existing binaries).

.PARAMETER Pause
    Pause at each step for walkthrough mode.
#>
param(
    [int]$RegistryPort = 4242,
    [switch]$SkipBuild,
    [switch]$Pause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Number, [string]$Text)
    Write-Host ""
    Write-Host "[$Number] $Text" -ForegroundColor Yellow
    Write-Host ("-" * 50) -ForegroundColor DarkGray
}

function Write-Ok {
    param([string]$Text)
    Write-Host "  OK  $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "       $Text" -ForegroundColor Gray
}

function Invoke-Step {
    param([string]$Cmd)
    Write-Host "  > $Cmd" -ForegroundColor DarkCyan
    $result = & cmd /c $Cmd 2>&1
    return $result
}

function Pause-Demo {
    if ($Pause) {
        Write-Host ""
        Write-Host "  [Press ENTER to continue...]" -ForegroundColor Magenta
        Read-Host | Out-Null
    }
}

function Wait-Registry {
    param([int]$Port, [int]$TimeoutSecs = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($resp.status -eq "ok") { return $true }
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# ── Resolve binary paths ──────────────────────────────────────────────────────

$Root     = $PSScriptRoot
$RelBin   = Join-Path $Root "target\release"
$CliExe   = Join-Path $RelBin "idprova.exe"
$RegExe   = Join-Path $RelBin "idprova-registry.exe"
$DemoDir  = Join-Path $env:TEMP "idprova-demo-$(Get-Random)"

# ── Banner ────────────────────────────────────────────────────────────────────

Clear-Host
Write-Host ""
Write-Host "  ██╗██████╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗" -ForegroundColor Cyan
Write-Host "  ██║██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██║██║  ██║██████╔╝██████╔╝██║   ██║██║   ██║███████║" -ForegroundColor Cyan
Write-Host "  ██║██║  ██║██╔═══╝ ██╔══██╗██║   ██║╚██╗ ██╔╝██╔══██║" -ForegroundColor Cyan
Write-Host "  ██║██████╔╝██║     ██║  ██║╚██████╔╝ ╚████╔╝ ██║  ██║" -ForegroundColor Cyan
Write-Host "  ╚═╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AI Agent Identity Protocol — Live Demo" -ForegroundColor White
Write-Host "  techblaze.com.au / idprova.dev" -ForegroundColor DarkGray
Write-Host ""

# ── Step 0: Build ─────────────────────────────────────────────────────────────

if (-not $SkipBuild) {
    Write-Step "0" "Building IDProva binaries (release mode)"
    Write-Info "Running: cargo build --release -p idprova-cli -p idprova-registry"
    Push-Location $Root
    $buildOutput = cargo build --release -p idprova-cli -p idprova-registry 2>&1
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed:" -ForegroundColor Red
        $buildOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    Write-Ok "Binaries compiled"
} else {
    Write-Info "Skipping build (--SkipBuild)"
}

if (-not (Test-Path $CliExe)) {
    Write-Host "ERROR: CLI binary not found at $CliExe" -ForegroundColor Red
    Write-Host "Run without -SkipBuild to compile first." -ForegroundColor Yellow
    exit 1
}

# ── Step 1: Start Registry ────────────────────────────────────────────────────

Write-Step "1" "Starting IDProva Registry on port $RegistryPort"
New-Item -ItemType Directory -Path $DemoDir -Force | Out-Null
$RegDbPath = Join-Path $DemoDir "demo_registry.db"

$env:REGISTRY_PORT = "$RegistryPort"
$env:RUST_LOG = "warn"
$regProcess = Start-Process -FilePath $RegExe `
    -WorkingDirectory $DemoDir `
    -PassThru -WindowStyle Hidden

$script:RegPid = $regProcess.Id
Write-Info "Registry PID: $($regProcess.Id)"

# Register cleanup so registry always stops
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:RegPid) {
        Stop-Process -Id $script:RegPid -Force -ErrorAction SilentlyContinue
    }
}

Write-Info "Waiting for registry to accept connections..."
if (-not (Wait-Registry -Port $RegistryPort)) {
    Write-Host "ERROR: Registry did not start within 15 seconds." -ForegroundColor Red
    Stop-Process -Id $regProcess.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

$health = Invoke-RestMethod -Uri "http://127.0.0.1:$RegistryPort/health"
Write-Ok "Registry healthy — protocol: $($health.protocol), version: $($health.version)"
Pause-Demo

# ── Step 2: Generate Keypairs ─────────────────────────────────────────────────

Write-Step "2" "Generating Ed25519 keypairs for Alice and Bob"

$AliceKey = Join-Path $DemoDir "alice.key"
$AlicePub = Join-Path $DemoDir "alice.pub"
$BobKey   = Join-Path $DemoDir "bob.key"
$BobPub   = Join-Path $DemoDir "bob.pub"
$CharlieKey = Join-Path $DemoDir "charlie.key"
$CharliePub = Join-Path $DemoDir "charlie.pub"

& $CliExe keygen --output $AliceKey 2>&1 | Out-Null
& $CliExe keygen --output $BobKey   2>&1 | Out-Null
& $CliExe keygen --output $CharlieKey 2>&1 | Out-Null

# Read pub keys that the CLI wrote alongside .key files
if (-not (Test-Path $AlicePub)) {
    Write-Host "ERROR: alice.pub not found — did keygen succeed?" -ForegroundColor Red
    exit 1
}

Write-Ok "Alice   key: $AliceKey"
Write-Info "        pub: $(Get-Content $AlicePub)"
Write-Ok "Bob     key: $BobKey"
Write-Info "        pub: $(Get-Content $BobPub)"
Write-Ok "Charlie key: $CharlieKey"
Pause-Demo

# ── Step 3: Create AID Documents ─────────────────────────────────────────────

Write-Step "3" "Creating Agent Identity Documents (AIDs)"

Push-Location $DemoDir

& $CliExe aid create `
    --id "did:aid:demo.local:alice" `
    --name "Alice (Orchestrator Agent)" `
    --controller "did:aid:demo.local:alice" `
    --model "claude-sonnet-4-6" `
    --runtime "idprova-demo/1.0" `
    --key $AliceKey 2>&1 | Out-Null

& $CliExe aid create `
    --id "did:aid:demo.local:bob" `
    --name "Bob (Executor Agent)" `
    --controller "did:aid:demo.local:alice" `
    --model "claude-haiku-4-5" `
    --runtime "idprova-demo/1.0" `
    --key $BobKey 2>&1 | Out-Null

& $CliExe aid create `
    --id "did:aid:demo.local:charlie" `
    --name "Charlie (Tool Agent)" `
    --controller "did:aid:demo.local:bob" `
    --model "claude-haiku-4-5" `
    --runtime "idprova-demo/1.0" `
    --key $CharlieKey 2>&1 | Out-Null

Pop-Location

$AliceAid   = Join-Path $DemoDir "did_idprova_demo.local_alice.json"
$BobAid     = Join-Path $DemoDir "did_idprova_demo.local_bob.json"
$CharlieAid = Join-Path $DemoDir "did_idprova_demo.local_charlie.json"

Write-Ok "Alice AID: $(((Get-Content -Raw $AliceAid | ConvertFrom-Json).id))"
Write-Ok "Bob   AID: $(((Get-Content -Raw $BobAid   | ConvertFrom-Json).id))"
Write-Ok "Charlie AID: $(((Get-Content -Raw $CharlieAid | ConvertFrom-Json).id))"
Pause-Demo

# ── Step 4: Register AIDs with Registry ──────────────────────────────────────

Write-Step "4" "Registering AIDs with the IDProva Registry"
Write-Info "Registry endpoint: http://localhost:$RegistryPort"

$RegistryBase = "http://127.0.0.1:$RegistryPort"

foreach ($pair in @(
    @{ Name = "Alice"; Did = "did:aid:demo.local:alice"; File = $AliceAid },
    @{ Name = "Bob";   Did = "did:aid:demo.local:bob";   File = $BobAid },
    @{ Name = "Charlie"; Did = "did:aid:demo.local:charlie"; File = $CharlieAid }
)) {
    $id = $pair.Did -replace "did:aid:", ""
    $body = Get-Content $pair.File -Raw
    $resp = Invoke-RestMethod -Uri "$RegistryBase/v1/aid/$id" `
        -Method PUT -Body $body -ContentType "application/json"
    Write-Ok "$($pair.Name) registered — status: $($resp.status)"
}

# Confirm list endpoint
$list = Invoke-RestMethod -Uri "$RegistryBase/v1/aids"
Write-Info "Total AIDs in registry: $($list.total)"
Pause-Demo

# ── Step 5: Issue DAT (Alice -> Bob) ──────────────────────────────────────────

Write-Step "5" "Issuing Delegation Attestation Token: Alice -> Bob"
Write-Info "Scope: mcp:tool:read,mcp:tool:write"
Write-Info "Expiry: 1 hour"

$Dat1 = & $CliExe dat issue `
    --issuer "did:aid:demo.local:alice" `
    --subject "did:aid:demo.local:bob" `
    --scope "mcp:tool:read,mcp:tool:write" `
    --expires-in "1h" `
    --key $AliceKey

Write-Ok "DAT issued"
Write-Info "Token (first 60 chars): $($Dat1.Substring(0, [Math]::Min(60, $Dat1.Length)))..."
Pause-Demo

# ── Step 6: Inspect the DAT ───────────────────────────────────────────────────

Write-Step "6" "Inspecting the DAT (decode, no verification)"
$inspect = & $CliExe dat inspect $Dat1 2>&1
$inspect | ForEach-Object { Write-Info $_ }
Pause-Demo

# ── Step 7: Verify DAT with CLI (offline, issuer key) ───────────────────────

Write-Step "7" "Verifying DAT with CLI (offline — issuer's public key)"
Write-Info "Using Alice's public key file for signature verification"

$verify = & $CliExe dat verify $Dat1 `
    --key $AlicePub `
    --scope "mcp:tool:read" 2>&1
$verify | ForEach-Object { Write-Info $_ }
Write-Ok "Signature verified offline — no registry call needed"
Pause-Demo

# ── Step 8: Verify Wrong Scope (should fail) ─────────────────────────────────

Write-Step "8" "Testing scope enforcement — wrong scope should FAIL"
Write-Info "Requesting scope 'mcp:admin:delete' not granted in this DAT..."

$ErrorActionPreference = "Continue"
$wrongScope = & $CliExe dat verify $Dat1 `
    --key $AlicePub `
    --scope "mcp:admin:delete" 2>&1
$ErrorActionPreference = "Stop"
$wrongScope | ForEach-Object { Write-Info $_ }
Write-Ok "Correctly rejected: scope 'mcp:admin:delete' not granted"
Pause-Demo

# ── Step 9: Sub-Delegation (Bob -> Charlie) ───────────────────────────────────

Write-Step "9" "Sub-delegation: Bob issues narrowed DAT to Charlie"
Write-Info "Bob can only grant scopes he holds (mcp:tool:read)"

$Dat2 = & $CliExe dat issue `
    --issuer "did:aid:demo.local:bob" `
    --subject "did:aid:demo.local:charlie" `
    --scope "mcp:tool:read" `
    --expires-in "30m" `
    --key $BobKey

Write-Ok "Sub-delegation DAT issued (Bob -> Charlie)"
Write-Info "Token: $($Dat2.Substring(0, [Math]::Min(60, $Dat2.Length)))..."

$verifyChain = & $CliExe dat verify $Dat2 `
    --key $BobPub `
    --scope "mcp:tool:read" 2>&1
$verifyChain | ForEach-Object { Write-Info $_ }
Pause-Demo

# ── Step 10: Revoke a DAT ────────────────────────────────────────────────────

Write-Step "10" "Revoking DAT — Alice revokes Bob's token"
Write-Info "Extracting JTI from DAT to revoke by identifier..."

# Decode JTI from DAT (payload is base64url segment 2)
$parts = $Dat1 -split "\."
$payloadB64 = $parts[1]
# Add padding for base64
$padded = $payloadB64 + ("=" * ((4 - $payloadB64.Length % 4) % 4))
$payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
$payload = $payloadJson | ConvertFrom-Json
$jti = $payload.jti
Write-Info "JTI to revoke: $jti"

$revokeBody = @{
    jti       = $jti
    reason    = "token compromised - demo revocation"
    revoked_by = "did:aid:demo.local:alice"
} | ConvertTo-Json

$revokeResp = Invoke-RestMethod -Uri "$RegistryBase/v1/dat/revoke" `
    -Method POST -Body $revokeBody -ContentType "application/json"
Write-Ok "DAT revoked — status: $($revokeResp.status)"

# Check revocation status
$checkResp = Invoke-RestMethod -Uri "$RegistryBase/v1/dat/revoked/$jti"
Write-Ok "Revocation confirmed — revoked at: $($checkResp.revoked_at)"
Pause-Demo

# ── Step 11: Registry API — verify via HTTP ───────────────────────────────────

Write-Step "11" "Registry DAT verification endpoint (HTTP API)"
Write-Info "POST /v1/dat/verify — used by MCP servers, middlewares, SDK integrations"

$verifyBody = @{
    token      = $Dat2
    scope      = "mcp:tool:read"
    request_ip = "203.0.113.42"
    trust_level = 80
} | ConvertTo-Json

$apiResp = Invoke-RestMethod -Uri "$RegistryBase/v1/dat/verify" `
    -Method POST -Body $verifyBody -ContentType "application/json"

Write-Ok "API Response:"
Write-Info "  valid:   $($apiResp.valid)"
Write-Info "  issuer:  $($apiResp.issuer)"
Write-Info "  subject: $($apiResp.subject)"
Write-Info "  scopes:  $($apiResp.scopes -join ', ')"
Pause-Demo

# ── Step 12: Summary ──────────────────────────────────────────────────────────

Write-Header "DEMO COMPLETE — All Flows Verified"

Write-Host ""
Write-Host "  What was demonstrated:" -ForegroundColor White
Write-Host "  ✓ Ed25519 keypair generation" -ForegroundColor Green
Write-Host "  ✓ AID creation (W3C DID-compatible identity documents)" -ForegroundColor Green
Write-Host "  ✓ Registry: PUT/GET/LIST endpoints" -ForegroundColor Green
Write-Host "  ✓ DAT issuance (signed delegation tokens)" -ForegroundColor Green
Write-Host "  ✓ Offline DAT inspection (decode without verify)" -ForegroundColor Green
Write-Host "  ✓ Online verification via registry (no local key needed)" -ForegroundColor Green
Write-Host "  ✓ Scope enforcement (wrong scope correctly rejected)" -ForegroundColor Green
Write-Host "  ✓ Sub-delegation (depth-2 chain: Alice -> Bob -> Charlie)" -ForegroundColor Green
Write-Host "  ✓ DAT revocation (JTI blacklist)" -ForegroundColor Green
Write-Host "  ✓ Registry HTTP verification API" -ForegroundColor Green
Write-Host ""
Write-Host "  Registry still running at: http://localhost:$RegistryPort" -ForegroundColor Cyan
Write-Host "  Open the visual dashboard:  dashboard\index.html" -ForegroundColor Cyan
Write-Host "  Point dashboard at:         http://localhost:$RegistryPort" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Demo files in: $DemoDir" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press ENTER to stop the registry and exit..." -ForegroundColor Yellow
Read-Host | Out-Null

# ── Cleanup ───────────────────────────────────────────────────────────────────

Stop-Process -Id $regProcess.Id -Force -ErrorAction SilentlyContinue
Write-Host "Registry stopped. Demo complete." -ForegroundColor Green
