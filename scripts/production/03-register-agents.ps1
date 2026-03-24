# 03-register-agents.ps1
# Run on Windows dev machine.
# Generates keypairs for R710 and Kai, creates AID documents, registers them with the
# production registry, and deploys key files to their respective machines.
#
# Usage: .\scripts\production\03-register-agents.ps1
# Prerequisites: 02-admin-setup.ps1 completed, registry is running on R710.

param(
    [string]$R710     = "198.51.100.12",
    [string]$Kai      = "198.51.100.94",
    [string]$RepoRoot = $PSScriptRoot + "\..\..\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot    = (Resolve-Path $RepoRoot).Path
$idprova     = Join-Path $RepoRoot "target\release\idprova.exe"
$keysDir     = Join-Path $RepoRoot "demo-keys\production"
$registryUrl = "http://${R710}:4242"

Write-Host "=== IDProva Agent Registration ===" -ForegroundColor Cyan
Write-Host "Registry: $registryUrl"
Write-Host ""

# ── Verify prerequisites ──────────────────────────────────────────────────────
if (-not (Test-Path $idprova)) {
    Write-Error "Binary not found: $idprova`nRun: cargo build --release -p idprova-cli"
}

$adminKeyPath = Join-Path $keysDir "admin-root.key"
if (-not (Test-Path $adminKeyPath)) {
    Write-Error "Admin key not found: $adminKeyPath`nRun 02-admin-setup.ps1 first."
}

New-Item -ItemType Directory -Force -Path $keysDir | Out-Null

# ── Helper: multibase to hex ──────────────────────────────────────────────────
function ConvertFrom-Multibase {
    param([string]$multibase)

    $b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    $encoded  = $multibase.TrimStart('z')

    [System.Numerics.BigInteger]$num = 0
    foreach ($c in $encoded.ToCharArray()) {
        $idx = $b58chars.IndexOf($c)
        if ($idx -lt 0) { throw "Invalid base58 character: $c" }
        $num = $num * 58 + $idx
    }

    $bytes = $num.ToByteArray()
    [Array]::Reverse($bytes)
    if ($bytes[0] -eq 0) { $bytes = $bytes[1..($bytes.Length-1)] }
    if ($bytes.Length -gt 32) { $bytes = $bytes[($bytes.Length-32)..($bytes.Length-1)] }

    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

# ── Helper: get hex privkey from .key file ────────────────────────────────────
function Get-HexKey {
    param([string]$path)
    return (Get-Content $path -Raw).Trim()
}

# ── Step 1: Issue admin DAT for write access ──────────────────────────────────
Write-Host "[1/5] Issuing admin DAT for write operations..."

$adminDat = & $idprova dat issue `
    --issuer "did:aid:admin-root" `
    --subject "did:aid:admin-root" `
    --scope "registry:admin:*:write" `
    --expires-in "2h" `
    --key $adminKeyPath 2>&1

if ($LASTEXITCODE -ne 0) { Write-Error "Failed to issue admin DAT: $adminDat" }
$adminDat = $adminDat.Trim()
Write-Host "      Admin DAT issued (2h expiry)"

# ── Step 2: Generate R710 agent keypair ───────────────────────────────────────
Write-Host ""
Write-Host "[2/5] Generating R710 agent keypair..."

$r710KeyPath = Join-Path $keysDir "r710-agent.key"
$r710PubPath = Join-Path $keysDir "r710-agent.pub"

if (Test-Path $r710KeyPath) {
    Write-Host "      WARN: r710-agent.key exists, using existing key." -ForegroundColor Yellow
} else {
    & $idprova keygen --output $r710KeyPath
    if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed for R710" }
}

$r710PubMultibase = (Get-Content $r710PubPath -Raw).Trim()
$r710PubHex = ConvertFrom-Multibase $r710PubMultibase
Write-Host "      R710 pubkey hex: $($r710PubHex.Substring(0,8))..."

# ── Step 3: Generate Kai agent keypair ────────────────────────────────────────
Write-Host ""
Write-Host "[3/5] Generating Kai agent keypair..."

$kaiKeyPath = Join-Path $keysDir "kai-agent.key"
$kaiPubPath = Join-Path $keysDir "kai-agent.pub"

if (Test-Path $kaiKeyPath) {
    Write-Host "      WARN: kai-agent.key exists, using existing key." -ForegroundColor Yellow
} else {
    & $idprova keygen --output $kaiKeyPath
    if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed for Kai" }
}

$kaiPubMultibase = (Get-Content $kaiPubPath -Raw).Trim()
$kaiPubHex = ConvertFrom-Multibase $kaiPubMultibase
Write-Host "      Kai pubkey hex: $($kaiPubHex.Substring(0,8))..."

# ── Step 4: Create and register AIDs ─────────────────────────────────────────
Write-Host ""
Write-Host "[4/5] Creating and registering AID documents..."

$origDir = Get-Location
Set-Location $RepoRoot

# R710 AID
Write-Host "      Creating AID: did:aid:techblaze.com.au:r710"
& $idprova aid create `
    --id "did:aid:techblaze.com.au:r710" `
    --name "Dell R710 Server" `
    --controller "did:aid:techblaze.com.au:r710" `
    --key $r710KeyPath
if ($LASTEXITCODE -ne 0) { Write-Error "AID create failed for R710" }

$r710AidFile = Get-ChildItem "did_aid_techblaze.com.au_r710*.json" | Select-Object -First 1
if (-not $r710AidFile) {
    # Try alternate naming
    $r710AidFile = Get-ChildItem "*.json" | Where-Object { $_.Name -match "r710" } | Select-Object -First 1
}
if (-not $r710AidFile) { Write-Error "Could not find generated R710 AID JSON file" }

$r710AidJson = Get-Content $r710AidFile.FullName -Raw
$r710AidId   = ($r710AidJson | ConvertFrom-Json).id

# PUT R710 AID to registry
Write-Host "      Registering: $r710AidId"
$resp = Invoke-RestMethod `
    -Uri "$registryUrl/v1/aid/$([System.Uri]::EscapeDataString($r710AidId))" `
    -Method PUT `
    -Body $r710AidJson `
    -ContentType "application/json" `
    -Headers @{ Authorization = "Bearer $adminDat" }
Write-Host "      R710 registered: $($resp | ConvertTo-Json -Compress)"
Remove-Item $r710AidFile.FullName

# Kai AID
Write-Host ""
Write-Host "      Creating AID: did:aid:techblaze.com.au:kai-server"
& $idprova aid create `
    --id "did:aid:techblaze.com.au:kai-server" `
    --name "Kai Server" `
    --controller "did:aid:techblaze.com.au:kai-server" `
    --key $kaiKeyPath
if ($LASTEXITCODE -ne 0) { Write-Error "AID create failed for Kai" }

$kaiAidFile = Get-ChildItem "did_aid_techblaze.com.au_kai-server*.json" | Select-Object -First 1
if (-not $kaiAidFile) {
    $kaiAidFile = Get-ChildItem "*.json" | Where-Object { $_.Name -match "kai" } | Select-Object -First 1
}
if (-not $kaiAidFile) { Write-Error "Could not find generated Kai AID JSON file" }

$kaiAidJson = Get-Content $kaiAidFile.FullName -Raw
$kaiAidId   = ($kaiAidJson | ConvertFrom-Json).id

Write-Host "      Registering: $kaiAidId"
$resp = Invoke-RestMethod `
    -Uri "$registryUrl/v1/aid/$([System.Uri]::EscapeDataString($kaiAidId))" `
    -Method PUT `
    -Body $kaiAidJson `
    -ContentType "application/json" `
    -Headers @{ Authorization = "Bearer $adminDat" }
Write-Host "      Kai registered: $($resp | ConvertTo-Json -Compress)"
Remove-Item $kaiAidFile.FullName

Set-Location $origDir

# ── Step 5: Deploy key files to machines ──────────────────────────────────────
Write-Host ""
Write-Host "[5/5] Deploying key files to machines..."

# R710 — its own key
Write-Host "      Deploying r710-agent.key to R710..."
scp $r710KeyPath "root@${R710}:/opt/idprova/keys/machine.key"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP r710 key failed" }
ssh "root@$R710" "chmod 600 /opt/idprova/keys/machine.key && chown idprova:idprova /opt/idprova/keys/machine.key"
Write-Host "      R710 key deployed and secured (chmod 600)"

# Kai — idprova binary + its own key
Write-Host "      Deploying idprova binary to Kai..."
scp (Join-Path $RepoRoot "target\release\idprova") "root@${Kai}:/usr/local/bin/idprova"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP idprova binary to Kai failed" }
ssh "root@$Kai" "chmod +x /usr/local/bin/idprova"

Write-Host "      Deploying kai-agent.key to Kai..."
ssh "root@$Kai" "mkdir -p ~/.idprova/keys"
scp $kaiKeyPath "root@${Kai}:/root/.idprova/keys/machine.key"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP kai key failed" }
ssh "root@$Kai" "chmod 600 /root/.idprova/keys/machine.key"
Write-Host "      Kai key deployed and secured (chmod 600)"

# ── Verification ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Verifying registrations..."

$r710Aid = Invoke-RestMethod "$registryUrl/v1/aid/techblaze.com.au:r710"
Write-Host "  R710 AID: $($r710Aid.id) [OK]" -ForegroundColor Green

$kaiAid = Invoke-RestMethod "$registryUrl/v1/aid/techblaze.com.au:kai-server"
Write-Host "  Kai AID:  $($kaiAid.id) [OK]" -ForegroundColor Green

Write-Host ""
Write-Host "=== Agent registration complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Key files:"
Write-Host "  $r710KeyPath  (DO NOT COMMIT)"
Write-Host "  $kaiKeyPath   (DO NOT COMMIT)"
Write-Host ""
Write-Host "Next: run 04-issue-machine-dats.ps1"
