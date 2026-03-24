# break-glass/setup.ps1
# Run on Windows dev machine — ONCE during initial setup.
# Generates BG-A and BG-B break-glass keypairs, uploads public keys to R710,
# and prints instructions for storing private keys offline.
#
# IMPORTANT: Run in a terminal session that is not being logged to any cloud service.
# After running, private keys must be stored offline (Bitwarden + physical safe).
# Delete the .key files from disk after storing them.
#
# Usage: .\scripts\production\break-glass\setup.ps1

param(
    [string]$R710     = "198.51.100.12",
    [string]$RepoRoot = $PSScriptRoot + "\..\..\..\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot  = (Resolve-Path $RepoRoot).Path
$idprova   = Join-Path $RepoRoot "target\release\idprova.exe"
$bgDir     = Join-Path $RepoRoot "demo-keys\production\break-glass"

Write-Host ""
Write-Host "=== IDProva Break-Glass Key Generation ===" -ForegroundColor Red
Write-Host "IMPORTANT: This terminal session output contains private keys."
Write-Host "           Store them immediately and delete the .key files."
Write-Host ""

if (-not (Test-Path $idprova)) {
    Write-Error "Binary not found: $idprova`nRun: cargo build --release -p idprova-cli"
}

New-Item -ItemType Directory -Force -Path $bgDir | Out-Null

# ── Generate BG-A (Bitwarden) ─────────────────────────────────────────────────
$bgAKey = Join-Path $bgDir "bg-a.key"
$bgAPub = Join-Path $bgDir "bg-a.pub"

Write-Host "[1/4] Generating Break-Glass A keypair..."
if (Test-Path $bgAKey) {
    Write-Host "      WARN: bg-a.key exists. Using existing key." -ForegroundColor Yellow
} else {
    & $idprova keygen --output $bgAKey
    if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed for BG-A" }
}

$bgAPrivHex = (Get-Content $bgAKey -Raw).Trim()
$bgAPubMultibase = (Get-Content $bgAPub -Raw).Trim()
Write-Host "      BG-A keypair generated."

# ── Generate BG-B (Physical safe) ────────────────────────────────────────────
$bgBKey = Join-Path $bgDir "bg-b.key"
$bgBPub = Join-Path $bgDir "bg-b.pub"

Write-Host ""
Write-Host "[2/4] Generating Break-Glass B keypair..."
if (Test-Path $bgBKey) {
    Write-Host "      WARN: bg-b.key exists. Using existing key." -ForegroundColor Yellow
} else {
    & $idprova keygen --output $bgBKey
    if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed for BG-B" }
}

$bgBPrivHex = (Get-Content $bgBKey -Raw).Trim()
$bgBPubMultibase = (Get-Content $bgBPub -Raw).Trim()
Write-Host "      BG-B keypair generated."

# ── Upload public keys to R710 ────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Uploading public keys to R710..."

scp $bgAPub "root@${R710}:/opt/idprova/keys/bg-a.pub"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP bg-a.pub failed" }
scp $bgBPub "root@${R710}:/opt/idprova/keys/bg-b.pub"
if ($LASTEXITCODE -ne 0) { Write-Error "SCP bg-b.pub failed" }
Write-Host "      Public keys deployed to R710."

# Write BREAK-GLASS.txt on R710
$breakGlassText = @"
IDProva Break-Glass Recovery Procedure
=======================================
Written: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

If you are locked out (admin key lost, compromised, or service failing):

OPTION A — Use Break-Glass Key A (Bitwarden):
  1. SSH to 198.51.100.12 as root
  2. Retrieve BG-A private key hex from Bitwarden entry "IDProva Break-Glass A"
  3. Stop registry: systemctl stop idprova-registry
  4. Swap admin.env:
       echo "REGISTRY_ADMIN_PUBKEY=$(cat /opt/idprova/keys/bg-a.pub)" > /opt/idprova/keys/admin.env
       chmod 600 /opt/idprova/keys/admin.env
  5. Start registry: systemctl start idprova-registry
  6. Verify: curl http://localhost:4242/health
  7. From Windows: issue admin DAT with BG-A private key
  8. Use DAT to re-register agents and issue new main admin keypair
  9. Once recovered, restore original admin.env and delete temp key files

OPTION B — Nuclear (BG-A also lost):
  1. Retrieve sealed envelope labeled "IDProva Emergency Key B" from physical safe
  2. Scan QR code → BG-B private key hex
  3. Same procedure as Option A but replace bg-a.pub with bg-b.pub

RECOVERY SCRIPT (from Windows dev machine):
  Edit scripts/production/break-glass/recover.sh to set BG_PUBKEY_FILE
  Then: ssh root@198.51.100.12 'bash -s' < scripts/production/break-glass/recover.sh

BREAK-GLASS PUBLIC KEYS (safe to store here — only private keys need protection):
BG-A pubkey (multibase): $bgAPubMultibase
BG-B pubkey (multibase): $bgBPubMultibase
"@

$tmpBGFile = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tmpBGFile -Value $breakGlassText
scp $tmpBGFile "root@${R710}:/opt/idprova/keys/BREAK-GLASS.txt"
ssh "root@$R710" "chmod 640 /opt/idprova/keys/BREAK-GLASS.txt && chown root:idprova /opt/idprova/keys/BREAK-GLASS.txt"
Remove-Item $tmpBGFile
Write-Host "      BREAK-GLASS.txt written to R710."

# ── Print private keys for offline storage ────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  PRIVATE KEYS — COPY THESE NOW — STORE OFFLINE IMMEDIATELY   " -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "BREAK-GLASS A (→ Save in Bitwarden as 'IDProva Break-Glass A'):" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Private key (hex): $bgAPrivHex" -ForegroundColor White
Write-Host "  Public key:        $bgAPubMultibase" -ForegroundColor Gray
Write-Host ""
Write-Host "BREAK-GLASS B (→ Print as QR, seal in envelope, store in safe):" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Private key (hex): $bgBPrivHex" -ForegroundColor White
Write-Host "  Public key:        $bgBPubMultibase" -ForegroundColor Gray
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""

Write-Host "[4/4] ACTIONS REQUIRED NOW:" -ForegroundColor Red
Write-Host ""
Write-Host "  1. Open Bitwarden and create a Secure Note:"
Write-Host "       Title: IDProva Break-Glass A"
Write-Host "       Paste the BG-A private key hex above"
Write-Host "       Also save the public key"
Write-Host "       SAVE IT NOW before closing this terminal."
Write-Host ""
Write-Host "  2. Print BG-B private key as QR code:"
Write-Host "       Use a local tool (qrencode, etc.) — NOT an online service"
Write-Host "       Write label: 'IDProva Emergency Key B - $(Get-Date -Format yyyy-MM-dd)'"
Write-Host "       Seal in envelope, store in physical filing cabinet or safe"
Write-Host ""
Write-Host "  3. After storing, delete the private key files:"
Write-Host "       Remove-Item $bgAKey"
Write-Host "       Remove-Item $bgBKey"
Write-Host ""
Write-Host "  Public key files (safe to keep in repo):"
Write-Host "       $bgAPub  (KEEP)"
Write-Host "       $bgBPub  (KEEP)"
Write-Host ""
Write-Host "=== Break-glass setup complete ===" -ForegroundColor Green
Write-Host "REMINDER: Delete .key files after storing private keys offline!" -ForegroundColor Red
