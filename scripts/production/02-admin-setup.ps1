# 02-admin-setup.ps1
# Run on Windows dev machine.
# Generates admin keypair, pushes admin.env to R710, starts idprova-registry.
#
# Usage: .\scripts\production\02-admin-setup.ps1
# Prerequisites: cargo build --release already done, 01-deploy-r710.sh already run on R710.

param(
    [string]$R710 = "198.51.100.12",
    [string]$RepoRoot = $PSScriptRoot + "\..\..\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path $RepoRoot).Path
$idprova  = Join-Path $RepoRoot "target\release\idprova.exe"
$keysDir  = Join-Path $RepoRoot "demo-keys\production"

Write-Host "=== IDProva Admin Setup ===" -ForegroundColor Cyan
Write-Host "R710: $R710"
Write-Host "Repo: $RepoRoot"
Write-Host ""

# ── Verify binary exists ──────────────────────────────────────────────────────
if (-not (Test-Path $idprova)) {
    Write-Error "Binary not found: $idprova`nRun: cargo build --release -p idprova-cli"
}

# ── Create keys directory ─────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $keysDir | Out-Null
$keyPath = Join-Path $keysDir "admin-root.key"
$pubPath = Join-Path $keysDir "admin-root.pub"

# ── Generate admin keypair ────────────────────────────────────────────────────
if (Test-Path $keyPath) {
    Write-Host "WARN: admin-root.key already exists. Using existing key." -ForegroundColor Yellow
    Write-Host "      Delete it first if you want to rotate the admin key."
} else {
    Write-Host "[1/4] Generating admin keypair..."
    & $idprova keygen --output $keyPath
    if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed" }
    Write-Host "      Written: $keyPath"
    Write-Host "      Written: $pubPath"
}

# ── Read public key (multibase format: z...) ──────────────────────────────────
$multibasePub = (Get-Content $pubPath -Raw).Trim()
Write-Host ""
Write-Host "[2/4] Admin public key (multibase): $multibasePub"

# Convert multibase (z = base58btc) to hex for REGISTRY_ADMIN_PUBKEY env var.
# The idprova keygen output is multibase-encoded. We need the raw hex bytes.
# Use: idprova pubkey-hex --key <path> (if that subcommand exists)
# Fallback: decode base58 manually via PowerShell.

$hexPub = $null

# Try CLI subcommand first
$cliOut = & $idprova pubkey-hex --key $keyPath 2>&1
if ($LASTEXITCODE -eq 0) {
    $hexPub = $cliOut.Trim()
    Write-Host "      Hex (via CLI): $hexPub"
} else {
    # Manual base58 decode of multibase key (z prefix = base58btc)
    Write-Host "      pubkey-hex subcommand not available, decoding base58 manually..."

    $b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    $encoded = $multibasePub.TrimStart('z')

    [System.Numerics.BigInteger]$num = 0
    foreach ($c in $encoded.ToCharArray()) {
        $idx = $b58chars.IndexOf($c)
        if ($idx -lt 0) { Write-Error "Invalid base58 character: $c" }
        $num = $num * 58 + $idx
    }

    # Convert BigInteger to byte array (little-endian → reverse)
    $bytes = $num.ToByteArray()
    [Array]::Reverse($bytes)
    # Remove leading zero byte added by BigInteger for sign
    if ($bytes[0] -eq 0) { $bytes = $bytes[1..($bytes.Length-1)] }
    # Take last 32 bytes (Ed25519 pubkey)
    if ($bytes.Length -gt 32) { $bytes = $bytes[($bytes.Length-32)..($bytes.Length-1)] }

    $hexPub = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    Write-Host "      Hex (decoded): $hexPub"
}

if ($hexPub.Length -ne 64) {
    Write-Error "Expected 32-byte (64 hex char) pubkey, got $($hexPub.Length) chars: $hexPub"
}

# ── Write admin.env and push to R710 ─────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Writing admin.env and pushing to R710..."

$adminEnvContent = "REGISTRY_ADMIN_PUBKEY=$hexPub"
$tmpEnvPath = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tmpEnvPath -Value $adminEnvContent -NoNewline

# SCP to R710
scp $tmpEnvPath "root@${R710}:/opt/idprova/keys/admin.env"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP of admin.env failed" }
Remove-Item $tmpEnvPath

# Set correct permissions on R710
$cmd = "chmod 600 /opt/idprova/keys/admin.env && chown idprova:idprova /opt/idprova/keys/admin.env"
ssh "root@$R710" $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "chmod/chown of admin.env failed" }

Write-Host "      admin.env written to R710: REGISTRY_ADMIN_PUBKEY=$($hexPub.Substring(0,8))...[truncated]"

# ── Start registry service ────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Starting idprova-registry on R710..."

ssh "root@$R710" "systemctl start idprova-registry && sleep 2 && systemctl is-active idprova-registry"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to start idprova-registry" }

# Verify health
Write-Host "      Checking health endpoint..."
Start-Sleep -Seconds 1
try {
    $health = Invoke-RestMethod "http://${R710}:4242/health" -TimeoutSec 10
    Write-Host "      Health: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Warning "Health check failed: $_"
    Write-Host "Check: ssh root@$R710 'journalctl -u idprova-registry -n 20 --no-pager'"
}

Write-Host ""
Write-Host "=== Admin setup complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Admin keypair location:"
Write-Host "  Private: $keyPath"
Write-Host "  Public:  $pubPath"
Write-Host "  Hex pub: $hexPub"
Write-Host ""
Write-Host "Next: run 03-register-agents.ps1"
