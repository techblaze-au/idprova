#!/usr/bin/env bash
# 01-deploy-r710.sh
# Run ON R710 via: ssh root@198.51.100.12 'bash -s' < scripts/production/01-deploy-r710.sh
#
# Creates directory structure, idprova system user, systemd units, and firewall rules.
# Does NOT start services — that happens in 02-admin-setup.ps1 after admin.env is written.

set -euo pipefail

echo "=== IDProva R710 Deployment ==="
echo "Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "Date: $(date)"
echo ""

# ── 1. System user ────────────────────────────────────────────────────────────
echo "[1/5] Creating idprova system user..."
id idprova &>/dev/null || useradd -r -s /bin/false -d /opt/idprova -c "IDProva service user" idprova
echo "      OK"

# ── 2. Directory structure ────────────────────────────────────────────────────
echo "[2/5] Creating /opt/idprova directory structure..."
mkdir -p /opt/idprova/{data,keys,receipts,logs,public}
chown -R idprova:idprova /opt/idprova
chmod 750 /opt/idprova
chmod 750 /opt/idprova/data
chmod 700 /opt/idprova/keys     # keys directory: idprova user only
chmod 750 /opt/idprova/receipts
chmod 750 /opt/idprova/logs
chmod 755 /opt/idprova/public
echo "      OK"

# ── 3. Verify binaries exist ──────────────────────────────────────────────────
echo "[3/5] Checking binaries..."
for bin in idprova-registry idprova-mcp-demo idprova; do
    if [[ ! -x /usr/local/bin/$bin ]]; then
        echo "ERROR: /usr/local/bin/$bin not found or not executable."
        echo "       Run: scp target/release/$bin root@198.51.100.12:/usr/local/bin/"
        exit 1
    fi
    echo "      /usr/local/bin/$bin OK"
done

# ── 4. Systemd unit files ─────────────────────────────────────────────────────
echo "[4/5] Writing systemd unit files..."

cat > /etc/systemd/system/idprova-registry.service << 'UNIT'
[Unit]
Description=IDProva Registry
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=idprova
Group=idprova
WorkingDirectory=/opt/idprova
ExecStart=/usr/local/bin/idprova-registry
Restart=on-failure
RestartSec=5
Environment=REGISTRY_PORT=4242
Environment=REGISTRY_DB_PATH=/opt/idprova/data/registry.db
Environment=RUST_LOG=warn
EnvironmentFile=/opt/idprova/keys/admin.env

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/idprova-mcp.service << 'UNIT'
[Unit]
Description=IDProva MCP Demo Server
After=idprova-registry.service
Requires=idprova-registry.service

[Service]
Type=simple
User=idprova
Group=idprova
WorkingDirectory=/opt/idprova
ExecStart=/usr/local/bin/idprova-mcp-demo
Restart=on-failure
RestartSec=5
Environment=MCP_PORT=3001
Environment=REGISTRY_URL=http://127.0.0.1:4242
Environment=RECEIPTS_FILE=/opt/idprova/receipts/receipts.jsonl
Environment=PUBLIC_DIR=/opt/idprova/public
Environment=RUST_LOG=warn

[Install]
WantedBy=multi-user.target
UNIT

chmod 644 /etc/systemd/system/idprova-registry.service
chmod 644 /etc/systemd/system/idprova-mcp.service
systemctl daemon-reload
systemctl enable idprova-registry idprova-mcp
echo "      Systemd units written and enabled."
echo "      Registry will start after admin.env is written by 02-admin-setup.ps1"

# ── 5. Firewall ───────────────────────────────────────────────────────────────
echo "[5/5] Configuring UFW firewall rules..."

if command -v ufw &>/dev/null; then
    # LAN-only access — never expose to internet without TLS
    ufw allow from 198.51.100.0/24 to any port 4242 comment "idprova-registry LAN" 2>/dev/null || true
    ufw allow from 198.51.100.0/24 to any port 3001 comment "idprova-mcp LAN" 2>/dev/null || true
    echo "      UFW rules added."
elif command -v iptables &>/dev/null; then
    # Fallback: iptables
    iptables -C INPUT -s 198.51.100.0/24 -p tcp --dport 4242 -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -s 198.51.100.0/24 -p tcp --dport 4242 -j ACCEPT
    iptables -C INPUT -s 198.51.100.0/24 -p tcp --dport 3001 -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -s 198.51.100.0/24 -p tcp --dport 3001 -j ACCEPT
    echo "      iptables rules added (not persistent — save with iptables-save if needed)."
else
    echo "      WARNING: Neither ufw nor iptables found. Configure firewall manually:"
    echo "        Allow 198.51.100.0/24 → port 4242 (registry)"
    echo "        Allow 198.51.100.0/24 → port 3001 (mcp)"
fi

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Next step: run 02-admin-setup.ps1 on Windows to:"
echo "  1. Generate admin keypair"
echo "  2. Write /opt/idprova/keys/admin.env"
echo "  3. Start idprova-registry"
echo ""
echo "Directories created:"
ls -la /opt/idprova/
