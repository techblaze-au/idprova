# Deployment Guide

## Docker (Local / Self-Hosted)

```bash
# Build and run
docker compose up -d registry

# With TLS reverse proxy (set your domain)
CADDY_DOMAIN=registry.example.com docker compose up -d

# Check health
curl http://localhost:3000/health
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_PORT` | `3000` | TCP port the registry listens on |
| `REGISTRY_ADMIN_PUBKEY` | unset | 64-char hex Ed25519 public key for write auth. Unset = dev mode |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### Production Checklist

1. Set `REGISTRY_ADMIN_PUBKEY` — without it, write endpoints are open
2. Mount a persistent volume at `/app/data` for the SQLite database
3. Place behind a TLS-terminating reverse proxy (Caddy, nginx, Cloudflare Tunnel)
4. Set `RUST_LOG=info` (avoid `debug` in production — verbose)

---

## Fly.io

```bash
# First time
fly launch --copy-config --no-deploy
fly secrets set REGISTRY_ADMIN_PUBKEY=<your-64-char-hex-pubkey>
fly volumes create registry_data --region syd --size 1
fly deploy

# Subsequent deploys
fly deploy

# Check status
fly status
fly logs
```

The `fly.toml` is pre-configured for:
- Sydney region (`syd`)
- Port 8080 internal (Fly maps external 443 → internal 8080)
- Auto-stop/start machines (cost savings)
- 256 MB shared CPU (sufficient for SQLite-backed registry)
- Persistent volume for `/app/data`

### Custom Domain

```bash
fly certs add registry.yourdomain.com
# Then add CNAME: registry.yourdomain.com → idprova-registry.fly.dev
```

---

## Verify Deployment

```bash
# Health check
curl https://your-registry.fly.dev/health

# Protocol metadata
curl https://your-registry.fly.dev/v1/meta

# Register an AID (dev mode)
curl -X PUT https://your-registry.fly.dev/v1/aid/example.com:my-agent \
  -H "Content-Type: application/json" \
  -d @my-agent.aid.json
```
