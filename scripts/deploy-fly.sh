#!/usr/bin/env bash
# deploy-fly.sh — Deploy IDProva Registry to Fly.io
# Prerequisites: flyctl installed, authenticated (fly auth login)
set -euo pipefail

APP_NAME="idprova-registry"
REGION="syd"

echo "=== IDProva Registry — Fly.io Deployment ==="

# 1. Create app if it doesn't exist
if ! fly apps list --json | grep -q "\"$APP_NAME\""; then
  echo "Creating Fly app: $APP_NAME in $REGION..."
  fly apps create "$APP_NAME" --org personal
else
  echo "App $APP_NAME already exists."
fi

# 2. Create persistent volume for SQLite (if not exists)
if ! fly volumes list -a "$APP_NAME" --json | grep -q '"name":"registry_data"'; then
  echo "Creating volume: registry_data (1GB) in $REGION..."
  fly volumes create registry_data \
    --app "$APP_NAME" \
    --region "$REGION" \
    --size 1 \
    --yes
else
  echo "Volume registry_data already exists."
fi

# 3. Set secrets (prompt if not already set)
echo "Setting secrets (skip if already configured)..."
if [ -n "${REGISTRY_ADMIN_PUBKEY:-}" ]; then
  fly secrets set REGISTRY_ADMIN_PUBKEY="$REGISTRY_ADMIN_PUBKEY" -a "$APP_NAME"
fi
if [ -n "${STRIPE_SECRET_KEY:-}" ]; then
  fly secrets set STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY" -a "$APP_NAME"
fi
if [ -n "${STRIPE_WEBHOOK_SECRET:-}" ]; then
  fly secrets set STRIPE_WEBHOOK_SECRET="$STRIPE_WEBHOOK_SECRET" -a "$APP_NAME"
fi

# 4. Deploy
echo "Deploying $APP_NAME..."
fly deploy --app "$APP_NAME" --region "$REGION"

# 5. Verify
echo "Checking health..."
fly status -a "$APP_NAME"
curl -sf "https://$APP_NAME.fly.dev/health" && echo " [OK]" || echo " [WAITING]"

echo "=== Deployment complete ==="
