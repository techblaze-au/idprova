#!/usr/bin/env bash
# 03-setup-registry.sh
# Run ON Proxmox host (192.168.8.90) — executes inside CT 401 (idp-registry) via pct exec.
# Creates directory structure, idprova system user, and systemd units.
# Does NOT start services — needs admin.env first (from 04-admin-setup.sh).
#
# Usage: bash scripts/testlab/03-setup-registry.sh
# Prerequisites: 02-push-binaries.sh completed.

set -euo pipefail

CT_REGISTRY=401
REGISTRY_IP="192.168.8.141"

echo "=== IDProva Test Lab: Registry Setup (CT $CT_REGISTRY) ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""

# ── Verify container is running ─────────────────────────────────────────────
status=$(pct status "$CT_REGISTRY" 2>/dev/null | awk '{print $2}')
if [[ "$status" != "running" ]]; then
    echo "ERROR: CT $CT_REGISTRY is not running (status: ${status:-unknown})."
    exit 1
fi

# ── Execute setup inside the container ──────────────────────────────────────
pct exec "$CT_REGISTRY" -- bash -c '
set -euo pipefail

echo "[1/5] Creating idprova system user..."
id idprova &>/dev/null || useradd -r -s /bin/false -d /opt/idprova -c "IDProva service user" idprova
echo "      OK"

echo "[2/5] Creating /opt/idprova directory structure..."
mkdir -p /opt/idprova/{data,keys,receipts,logs,public}
chown -R idprova:idprova /opt/idprova
chmod 750 /opt/idprova
chmod 750 /opt/idprova/data
chmod 700 /opt/idprova/keys
chmod 750 /opt/idprova/receipts
chmod 750 /opt/idprova/logs
chmod 755 /opt/idprova/public
echo "      OK"

echo "[3/5] Checking binaries..."
for bin in idprova-registry idprova-mcp-demo idprova; do
    if [[ ! -x /usr/local/bin/$bin ]]; then
        echo "ERROR: /usr/local/bin/$bin not found or not executable."
        exit 1
    fi
    echo "      /usr/local/bin/$bin OK"
done

echo "[4/5] Writing systemd unit files..."

cat > /etc/systemd/system/idprova-registry.service << UNIT
[Unit]
Description=IDProva Registry (Test Lab)
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
Environment=RUST_LOG=info
EnvironmentFile=/opt/idprova/keys/admin.env

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/idprova-mcp.service << UNIT
[Unit]
Description=IDProva MCP Demo Server (Test Lab)
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
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
UNIT

chmod 644 /etc/systemd/system/idprova-registry.service
chmod 644 /etc/systemd/system/idprova-mcp.service
systemctl daemon-reload
systemctl enable idprova-registry idprova-mcp
echo "      Systemd units written and enabled."
echo "      Registry will start after admin.env is written by 04-admin-setup.sh"

echo "[5/5] Directory listing..."
ls -la /opt/idprova/
'

echo ""
echo "=== Registry setup complete on CT $CT_REGISTRY ($REGISTRY_IP) ==="
echo ""
echo "Services created (not yet started):"
echo "  idprova-registry.service (port 4242)"
echo "  idprova-mcp.service      (port 3001)"
echo ""
echo "Next: run 04-admin-setup.sh on CT 402"
