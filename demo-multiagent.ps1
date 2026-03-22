#Requires -Version 5.1
<#
.SYNOPSIS
    IDProva Multi-Agent Demo — sets up 4 agents and opens the Control Panel.

.DESCRIPTION
    1. Generates Ed25519 keypairs for 4 agents (kai, reader, writer, admin)
    2. Starts the IDProva registry with admin auth
    3. Registers all 4 agents as AIDs
    4. Writes demo-keys/session.json for the browser dashboard
    5. Starts the MCP demo server
    6. Opens the Control Panel (dashboard/index.html) in the browser

    Agents:
      kai          did:aid:techblaze.com.au:kai   L3 — issuer, all scopes
      reader-agent did:aid:r17.local:reader        L1 — echo only
      writer-agent did:aid:r17.local:writer        L2 — echo + calculate
      admin-agent  did:aid:r17.local:admin         L3 — all tools

.PARAMETER SkipBuild
    Skip cargo build (use existing binaries).

.PARAMETER RegistryPort
    Port for the registry (default 4242).

.PARAMETER McpPort
    Port for the MCP demo server (default 3001).

.PARAMETER R17
    Use R17 Tailscale IP for the dashboard URLs (prompts for IP).

.PARAMETER TailscaleIp
    Tailscale IP to use with -R17 (skips prompt).

.EXAMPLE
    .\demo-multiagent.ps1 -SkipBuild
    .\demo-multiagent.ps1 -R17 -TailscaleIp 100.64.0.1
#>
param(
    [switch]$SkipBuild,
    [int]$RegistryPort = 4242,
    [int]$McpPort = 3001,
    [switch]$R17,
    [string]$TailscaleIp = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$N, [string]$Text)
    Write-Host ''
    Write-Host "[$N] $Text" -ForegroundColor Yellow
    Write-Host ('-' * 50) -ForegroundColor DarkGray
}

function Write-Ok   { param([string]$T); Write-Host "  OK  $T" -ForegroundColor Green }
function Write-Info { param([string]$T); Write-Host "       $T" -ForegroundColor Gray }
function Write-Warn { param([string]$T); Write-Host "  !!  $T" -ForegroundColor Yellow }

function Wait-Registry {
    param([int]$Port, [int]$TimeoutSecs = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($r.status -eq 'ok') { return $true }
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# Convert hex pubkey to multibase (base58btc, prefix 'z')
function ConvertTo-Multibase {
    param([string]$Hex)
    $bytes = [byte[]]@(for ($i = 0; $i -lt $Hex.Length; $i += 2) { [Convert]::ToByte($Hex.Substring($i, 2), 16) })
    $B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    $n = [System.Numerics.BigInteger]::new($bytes + @([byte]0), $true, $true)
    $out = ''
    $fifty8 = [System.Numerics.BigInteger]58
    while ($n -gt 0) {
        $rem = [System.Numerics.BigInteger]::Remainder($n, $fifty8)
        $out = $B58[[int]$rem] + $out
        $n = [System.Numerics.BigInteger]::Divide($n, $fifty8)
    }
    foreach ($b in $bytes) { if ($b -ne 0) { break }; $out = '1' + $out }
    return 'z' + $out
}

# ── Paths ─────────────────────────────────────────────────────────────────────

$Root     = $PSScriptRoot
$RelBin   = Join-Path $Root 'target\release'
$CliExe   = Join-Path $RelBin 'idprova.exe'
$RegExe   = Join-Path $RelBin 'idprova-registry.exe'
$McpExe   = Join-Path $RelBin 'idprova-mcp-demo.exe'
$KeysDir  = Join-Path $Root 'demo-keys'
$DashHtml = Join-Path $Root 'dashboard\app.html'

# ── Banner ────────────────────────────────────────────────────────────────────

Clear-Host
Write-Host ''
Write-Host '  IDProva — Multi-Agent Control Panel Demo' -ForegroundColor Cyan
Write-Host '  4 agents  |  live DAT issuance  |  scenario runner' -ForegroundColor DarkGray
Write-Host ''

# ── Resolve R17 IP ─────────────────────────────────────────────────────────────

$DisplayHost = 'localhost'
if ($R17) {
    if (-not $TailscaleIp) {
        $TailscaleIp = Read-Host 'Enter R17 Tailscale IP (e.g. 100.x.x.x)'
    }
    if (-not $TailscaleIp) { Write-Host 'No IP provided — using localhost' -ForegroundColor Yellow; $R17 = $false }
    else { $DisplayHost = $TailscaleIp }
}

$RegistryBase = "http://127.0.0.1:$RegistryPort"
$RegistryDisplay = "http://${DisplayHost}:${RegistryPort}"
$McpDisplay      = "http://${DisplayHost}:${McpPort}"

# ── Step 0: Build ─────────────────────────────────────────────────────────────

if (-not $SkipBuild) {
    Write-Step '0' 'Building release binaries'
    Push-Location $Root
    $out = cargo build --release -p idprova-cli -p idprova-registry -p idprova-mcp-demo 2>&1
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Build failed:' -ForegroundColor Red
        $out | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    Write-Ok 'Binaries compiled'
} else {
    Write-Info 'Skipping build (-SkipBuild)'
}

foreach ($bin in @($CliExe, $RegExe, $McpExe)) {
    if (-not (Test-Path $bin)) {
        Write-Host "ERROR: binary not found: $bin" -ForegroundColor Red
        Write-Host 'Run without -SkipBuild to compile.' -ForegroundColor Yellow
        exit 1
    }
}

# ── Step 1: Generate keypairs ─────────────────────────────────────────────────

Write-Step '1' 'Generating Ed25519 keypairs'
New-Item -ItemType Directory -Path $KeysDir -Force | Out-Null

$Agents = @(
    @{ Name = 'kai';          Did = 'did:aid:techblaze.com.au:kai';  Trust = 'L3' },
    @{ Name = 'reader-agent'; Did = 'did:aid:r17.local:reader';      Trust = 'L1' },
    @{ Name = 'writer-agent'; Did = 'did:aid:r17.local:writer';      Trust = 'L2' },
    @{ Name = 'admin-agent';  Did = 'did:aid:r17.local:admin';       Trust = 'L3' }
)

# Also generate admin root keypair (for registry write auth)
$AdminKeyFile = Join-Path $KeysDir 'admin-root.key'
$AdminPubFile = Join-Path $KeysDir 'admin-root.pub'
& $CliExe keygen --output $AdminKeyFile 2>&1 | Out-Null
$AdminPrivHex = Get-Content $AdminKeyFile -Raw | ForEach-Object { $_.Trim() }
$AdminPubMb   = Get-Content $AdminPubFile -Raw | ForEach-Object { $_.Trim() }

# Convert multibase to hex (strip 'z', base58 decode)
function ConvertFrom-Multibase {
    param([string]$Mb)
    if (-not $Mb.StartsWith('z')) { throw "Expected multibase with 'z' prefix" }
    $B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    $n = [System.Numerics.BigInteger]::Zero
    foreach ($c in $Mb.Substring(1).ToCharArray()) {
        $idx = $B58.IndexOf($c)
        if ($idx -lt 0) { throw "Invalid base58 character: $c" }
        $n = $n * 58 + $idx
    }
    $hex = $n.ToString('x64')
    return $hex.Substring($hex.Length - 64)
}

$AdminPubHex = ConvertFrom-Multibase -Mb $AdminPubMb
Write-Ok "Admin root keypair — pub: $($AdminPubMb.Substring(0,16))…"

# Generate keypairs for each agent
foreach ($a in $Agents) {
    $keyFile = Join-Path $KeysDir "$($a.Name).key"
    $pubFile = Join-Path $KeysDir "$($a.Name).pub"
    & $CliExe keygen --output $keyFile 2>&1 | Out-Null
    $priv = Get-Content $keyFile -Raw | ForEach-Object { $_.Trim() }
    $pubMb = Get-Content $pubFile -Raw | ForEach-Object { $_.Trim() }
    $pubHex = ConvertFrom-Multibase -Mb $pubMb
    $a['PrivHex'] = $priv
    $a['PubHex']  = $pubHex
    $a['PubMb']   = $pubMb
    Write-Ok "$($a.Name.PadRight(15)) $($a.Did)"
    Write-Info "pub: $($pubMb.Substring(0,20))…"
}

# ── Step 2: Start Registry ────────────────────────────────────────────────────

Write-Step '2' "Starting registry on port $RegistryPort (with admin auth)"

$env:REGISTRY_PORT      = "$RegistryPort"
$env:REGISTRY_ADMIN_PUBKEY = $AdminPubHex
$env:RUST_LOG           = 'warn'

$RegTempDir = Join-Path $env:TEMP "idprova-demo-$(Get-Random)"
New-Item -ItemType Directory -Path $RegTempDir -Force | Out-Null

$regProcess = Start-Process -FilePath $RegExe `
    -WorkingDirectory $RegTempDir `
    -PassThru -WindowStyle Hidden

$script:RegPid = $regProcess.Id
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:RegPid) { Stop-Process -Id $script:RegPid -Force -ErrorAction SilentlyContinue }
}

Write-Info "Registry PID: $($regProcess.Id)"
Write-Info 'Waiting for registry…'

if (-not (Wait-Registry -Port $RegistryPort)) {
    Write-Host 'ERROR: Registry did not start in 20 seconds.' -ForegroundColor Red
    Stop-Process -Id $regProcess.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

$health = Invoke-RestMethod -Uri "$RegistryBase/health"
Write-Ok "Registry healthy — protocol: $($health.protocol) v$($health.version)"

# ── Step 3: Issue admin DAT for write auth ────────────────────────────────────

Write-Step '3' 'Issuing admin DAT for write operations'

# Use CLI to issue an admin DAT signed with admin-root key
$AdminDid = 'did:aid:admin-root'
$AdminDat = & $CliExe dat issue `
    --issuer $AdminDid `
    --subject $AdminDid `
    --scope '*:*:*:*' `
    --expires-in '24h' `
    --key $AdminKeyFile 2>&1

# The CLI outputs the compact JWS on stdout
$AdminToken = $AdminDat | Where-Object { $_ -match '^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$' } | Select-Object -Last 1

if (-not $AdminToken) {
    Write-Warn "Could not extract admin DAT from CLI output — registry write auth may fail"
    Write-Info "CLI output: $AdminDat"
    $AdminToken = ''
}
Write-Ok "Admin DAT issued (JTI embedded)"

# ── Step 4: Create and register AIDs ─────────────────────────────────────────

Write-Step '4' 'Registering agent AIDs with the registry'

Push-Location $RegTempDir

foreach ($a in $Agents) {
    # Create AID document via CLI
    & $CliExe aid create `
        --id $a.Did `
        --name "$($a.Name)" `
        --controller $a.Did `
        --model 'idprova-demo/1.0' `
        --runtime 'idprova-demo/1.0' `
        --key (Join-Path $KeysDir "$($a.Name).key") 2>&1 | Out-Null

    # Find generated AID file (CLI saves as did_..._name.json)
    $aidFileName = ($a.Did -replace 'did:aid:', '' -replace ':', '_') + '.json'
    # CLI actually names it with the full path format: "did_aid_..." let's glob it
    $aidFile = Get-ChildItem -Path $RegTempDir -Filter '*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $aidFile) {
        Write-Warn "AID file not found for $($a.Name) — trying to build document manually"
        # Build AID document manually
        $aidDoc = @{
            '@context' = @('https://www.w3.org/ns/did/v1', 'https://idprova.dev/ns/v1')
            'id' = $a.Did
            'controller' = $a.Did
            'verificationMethod' = @(@{
                'id' = '#key-ed25519'
                'type' = 'Ed25519VerificationKey2020'
                'controller' = $a.Did
                'publicKeyMultibase' = $a.PubMb
            })
            'authentication' = @('#key-ed25519')
            'trustLevel' = $a.Trust
        }
        $aidJson = $aidDoc | ConvertTo-Json -Depth 5
    } else {
        $aidJson = Get-Content $aidFile.FullName -Raw
    }

    $id = $a.Did -replace 'did:aid:', ''
    $headers = @{ 'Content-Type' = 'application/json' }
    if ($AdminToken) { $headers['Authorization'] = "Bearer $AdminToken" }

    try {
        $resp = Invoke-RestMethod -Uri "$RegistryBase/v1/aid/$([Uri]::EscapeDataString($id))" `
            -Method PUT -Body $aidJson -Headers $headers
        Write-Ok "$($a.Name.PadRight(15)) registered — $($resp.status)"
    } catch {
        Write-Warn "$($a.Name) registration error: $_"
    }
}

Pop-Location

$list = Invoke-RestMethod -Uri "$RegistryBase/v1/aids"
Write-Info "Total AIDs in registry: $($list.total)"

# ── Step 5: Write session.json ─────────────────────────────────────────────────

Write-Step '5' 'Writing demo-keys/session.json'

$sessionObj = @{
    registry = $RegistryDisplay
    mcp      = $McpDisplay
    admin    = @{
        did     = 'did:aid:admin-root'
        pubkey  = $AdminPubHex
        privkey = $AdminPrivHex
    }
    agents = @(
        foreach ($a in $Agents) {
            @{
                did        = $a.Did
                name       = $a.Name
                trustLevel = $a.Trust
                pubkey     = $a.PubHex
                privkey    = $a.PrivHex
            }
        }
    )
}

$sessionJson = $sessionObj | ConvertTo-Json -Depth 5
$sessionFile = Join-Path $KeysDir 'session.json'
Set-Content -Path $sessionFile -Value $sessionJson -Encoding UTF8

Write-Ok "Written: $sessionFile"
Write-Info "Agents: $(($Agents | ForEach-Object { $_.Name }) -join ', ')"

# ── Step 6: Start MCP demo server ─────────────────────────────────────────────

Write-Step '6' "Starting MCP demo server on port $McpPort"

$env:MCP_PORT     = "$McpPort"
$env:REGISTRY_URL = $RegistryBase
$env:RUST_LOG     = 'warn'

$McpTempDir = Join-Path $env:TEMP "idprova-mcp-$(Get-Random)"
New-Item -ItemType Directory -Path $McpTempDir -Force | Out-Null

$mcpProcess = Start-Process -FilePath $McpExe `
    -WorkingDirectory $McpTempDir `
    -PassThru -WindowStyle Hidden

$script:McpPid = $mcpProcess.Id
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:McpPid) { Stop-Process -Id $script:McpPid -Force -ErrorAction SilentlyContinue }
}

Write-Info "MCP PID: $($mcpProcess.Id)"
Start-Sleep -Milliseconds 1500

try {
    $mcpHealth = Invoke-RestMethod -Uri "http://127.0.0.1:$McpPort/health" -TimeoutSec 5
    Write-Ok "MCP server healthy — $($mcpHealth.service) v$($mcpHealth.version)"
} catch {
    Write-Warn 'MCP server health check failed — it may still be starting'
}

# ── Step 7: Open Dashboard ─────────────────────────────────────────────────────

Write-Step '7' 'Opening Control Panel'

# Build dashboard URL with session param
$SessionUrl  = "file:///$($sessionFile -replace '\\','/')"
$DashUrl     = "file:///$($DashHtml -replace '\\','/')?session=$([Uri]::EscapeDataString($SessionUrl))"

# Prefer running with --disable-web-security so MCP fetch() calls work
$TmpProfile = Join-Path $env:TEMP 'idprova-demo-browser'
New-Item -ItemType Directory -Path $TmpProfile -Force | Out-Null

$browserArgs = "--disable-web-security --user-data-dir=`"$TmpProfile`" `"$DashUrl`""

$opened = $false
foreach ($browser in @('msedge.exe','chrome.exe')) {
    try {
        $path = (Get-Command $browser -ErrorAction SilentlyContinue).Source
        if ($path) {
            Start-Process -FilePath $path -ArgumentList $browserArgs
            Write-Ok "Opened in $browser (--disable-web-security for MCP calls)"
            $opened = $true
            break
        }
    } catch { }
}

if (-not $opened) {
    # Fallback: open with default browser (MCP calls may fail due to CORS)
    Start-Process $DashUrl
    Write-Warn "Opened with default browser — MCP fetch() calls may fail (CORS)."
    Write-Info "For full functionality, run manually:"
    Write-Info "  msedge.exe --disable-web-security --user-data-dir=`"$TmpProfile`" `"$DashUrl`""
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host ('=' * 64) -ForegroundColor Cyan
Write-Host '  DEMO READY' -ForegroundColor Green
Write-Host ('=' * 64) -ForegroundColor Cyan
Write-Host ''
Write-Host "  Registry : $RegistryDisplay" -ForegroundColor White
Write-Host "  MCP      : $McpDisplay" -ForegroundColor White
Write-Host "  Dashboard: $DashHtml" -ForegroundColor White
Write-Host "  Session  : $sessionFile" -ForegroundColor White
Write-Host ''
Write-Host '  Agents:' -ForegroundColor White
foreach ($a in $Agents) {
    Write-Host "    $($a.Name.PadRight(15)) $($a.Did)  [$($a.Trust)]" -ForegroundColor Gray
}
Write-Host ''
Write-Host '  Press Ctrl+C to stop both servers.' -ForegroundColor DarkGray
Write-Host ''

# Keep script alive so cleanup handlers work
try {
    while ($true) { Start-Sleep -Seconds 5 }
} finally {
    Write-Host 'Stopping servers...' -ForegroundColor Yellow
    Stop-Process -Id $script:RegPid -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $script:McpPid -Force -ErrorAction SilentlyContinue
}
