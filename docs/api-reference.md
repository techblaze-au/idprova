# Registry API Reference

The IDProva Registry is an HTTP server built with Axum. It provides AID document storage and DAT verification services.

**Base URL:** `http://localhost:3000` (default port, configurable via `REGISTRY_PORT`)

**Rate limiting:** 120 requests per 60-second window per IP.

**Request body limit:** 1 MB.

**Security headers:** All responses include `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, and `X-XSS-Protection`.

---

## Authentication

Write endpoints (`PUT`, `DELETE`, `POST /v1/dat/revoke`) require a valid admin DAT when `REGISTRY_ADMIN_PUBKEY` is set.

```
Authorization: Bearer <compact-jws-dat>
```

In development mode (no `REGISTRY_ADMIN_PUBKEY`), write endpoints are open with a warning logged.

---

## Endpoints

### GET /health

Health check. No authentication required.

**Response 200:**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "protocol": "idprova/0.1"
}
```

**curl example:**

```bash
curl http://localhost:3000/health
```

---

### GET /ready

Readiness probe — checks database connectivity. No authentication required.

**Response 200:**

```json
{
  "status": "ready",
  "db": "ok"
}
```

**Response 503 Service Unavailable:**

```json
{
  "status": "not_ready",
  "db": "error"
}
```

**curl example:**

```bash
curl http://localhost:3000/ready
```

---

### GET /v1/meta

Protocol metadata. No authentication required.

**Response 200:**

```json
{
  "protocolVersion": "0.1",
  "registryVersion": "0.1.0",
  "didMethod": "did:aid",
  "supportedAlgorithms": ["EdDSA"],
  "supportedHashAlgorithms": ["blake3", "sha-256"]
}
```

**curl example:**

```bash
curl http://localhost:3000/v1/meta
```

---

### PUT /v1/aid/:id

Register or update an AID document. Requires authentication in production mode.

The `:id` path parameter is the DID suffix after `did:aid:` — e.g. for `did:aid:example.com:my-agent`, use `example.com:my-agent`.

**Request body:** AID document JSON (see [Protocol Specification](protocol-spec-v0.1.md) for schema).

**Response 201 Created** (new AID):

```json
{
  "id": "did:aid:example.com:my-agent",
  "status": "created"
}
```

**Response 200 OK** (updated existing AID):

```json
{
  "id": "did:aid:example.com:my-agent",
  "status": "updated"
}
```

**Response 400 Bad Request:**

```json
{ "error": "invalid AID document: ..." }
```

**Response 401 Unauthorized:**

```json
{ "error": "Authorization header required for write operations" }
```

**curl example:**

```bash
# Development mode
curl -X PUT http://localhost:3000/v1/aid/example.com:my-agent \
  -H "Content-Type: application/json" \
  -d @my-agent.aid.json

# Production mode
curl -X PUT http://localhost:3000/v1/aid/example.com:my-agent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-dat>" \
  -d @my-agent.aid.json
```

---

### GET /v1/aid/:id

Resolve an AID document. No authentication required.

**Response 200:**

```json
{
  "id": "did:aid:example.com:my-agent",
  "controller": "did:aid:example.com:operator",
  "verificationMethod": [
    {
      "id": "did:aid:example.com:my-agent#key-ed25519",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aid:example.com:my-agent",
      "publicKeyMultibase": "z6Mk..."
    }
  ],
  "metadata": {
    "name": "My Agent"
  }
}
```

**Response 404:**

```json
{ "error": "AID not found: did:aid:example.com:my-agent" }
```

**curl example:**

```bash
curl http://localhost:3000/v1/aid/example.com:my-agent
```

---

### DELETE /v1/aid/:id

Deactivate (remove) an AID from the registry. Requires authentication in production mode.

**Response 200:**

```json
{
  "id": "did:aid:example.com:my-agent",
  "status": "deactivated"
}
```

**Response 404:**

```json
{ "error": "AID not found: did:aid:example.com:my-agent" }
```

**curl example:**

```bash
curl -X DELETE http://localhost:3000/v1/aid/example.com:my-agent \
  -H "Authorization: Bearer <admin-dat>"
```

---

### GET /v1/aid/:id/key

Get the verification keys for an AID. No authentication required. Used by services for DAT verification without fetching the full document.

**Response 200:**

```json
{
  "id": "did:aid:example.com:my-agent",
  "keys": [
    {
      "id": "did:aid:example.com:my-agent#key-ed25519",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6Mk..."
    }
  ]
}
```

**Response 404:**

```json
{ "error": "AID not found: did:aid:example.com:my-agent" }
```

**curl example:**

```bash
curl http://localhost:3000/v1/aid/example.com:my-agent/key
```

---

### POST /v1/dat/verify

Verify a DAT token against the issuer's registered public key. No authentication required. The registry looks up the issuer AID, decodes the public key, and runs the full verification pipeline.

**Request body:**

```json
{
  "token": "<compact-jws>",
  "scope": "mcp:tool:filesystem:read",
  "request_ip": "203.0.113.42",
  "trust_level": 1,
  "delegation_depth": 0,
  "actions_in_window": 0,
  "country_code": "AU",
  "agent_config_hash": "<sha256-hex>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | yes | Compact JWS token |
| `scope` | string | no | Required scope (empty = skip scope check) |
| `request_ip` | string | no | Client IP for IP allowlist/denylist constraints |
| `trust_level` | integer (0–100) | no | Agent trust level for `min_trust_level` constraint |
| `delegation_depth` | integer | no | Chain depth for `max_delegation_depth` constraint (default 0) |
| `actions_in_window` | integer | no | Actions in current rate-limit window (default 0) |
| `country_code` | string | no | ISO 3166-1 alpha-2 country code for geofencing |
| `agent_config_hash` | string | no | SHA-256 hex of agent config for `required_config_hash` constraint |

**Response 200 (valid):**

```json
{
  "valid": true,
  "issuer": "did:aid:example.com:operator",
  "subject": "did:aid:example.com:my-agent",
  "scopes": ["mcp:tool:filesystem:read"],
  "jti": "01234567-89ab-cdef-0123-456789abcdef"
}
```

**Response 200 (invalid):**

```json
{
  "valid": false,
  "issuer": "did:aid:example.com:operator",
  "subject": "did:aid:example.com:my-agent",
  "scopes": ["mcp:tool:filesystem:read"],
  "jti": "01234567-89ab-cdef-0123-456789abcdef",
  "error": "DAT has expired"
}
```

**Response 400 (malformed token):**

```json
{
  "valid": false,
  "error": "malformed token: ..."
}
```

The registry checks revocation before any crypto work. If the JTI is revoked, `valid: false` is returned with the revocation details in `error`.

**curl example:**

```bash
curl -X POST http://localhost:3000/v1/dat/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGci...",
    "scope": "mcp:tool:filesystem:read",
    "trust_level": 1,
    "delegation_depth": 0
  }'
```

---

### POST /v1/dat/revoke

Revoke a DAT by JTI. Requires authentication in production mode. Revocation is immediate and permanent — subsequent calls to `POST /v1/dat/verify` with a revoked JTI return `valid: false`.

**Request body:**

```json
{
  "jti": "01234567-89ab-cdef-0123-456789abcdef",
  "reason": "key compromise",
  "revoked_by": "did:aid:example.com:operator"
}
```

| Field | Type | Max Length | Description |
|-------|------|------------|-------------|
| `jti` | string | 128 | Token ID to revoke (required) |
| `reason` | string | 512 | Human-readable revocation reason |
| `revoked_by` | string | 256 | DID or identifier of the revoking party |

**Response 200:**

```json
{
  "jti": "01234567-89ab-cdef-0123-456789abcdef",
  "status": "revoked",
  "reason": "key compromise",
  "revoked_by": "did:aid:example.com:operator"
}
```

**Response 200 (already revoked):**

```json
{
  "jti": "01234567-89ab-cdef-0123-456789abcdef",
  "status": "already_revoked"
}
```

**Response 401:** Authentication required.

**curl example:**

```bash
curl -X POST http://localhost:3000/v1/dat/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-dat>" \
  -d '{
    "jti": "01234567-89ab-cdef-0123-456789abcdef",
    "reason": "key compromise",
    "revoked_by": "did:aid:example.com:operator"
  }'
```

---

### GET /v1/dat/revocations

List DAT revocations with pagination. No authentication required.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 50 | Max records to return (capped at 200) |
| `offset` | integer | 0 | Number of records to skip |

**Response 200:**

```json
{
  "revocations": [
    {
      "jti": "01234567-89ab-cdef-0123-456789abcdef",
      "reason": "key compromise",
      "revoked_by": "did:aid:example.com:operator",
      "revoked_at": "2026-03-07T12:00:00Z"
    }
  ],
  "count": 1,
  "limit": 50,
  "offset": 0
}
```

**curl example:**

```bash
curl "http://localhost:3000/v1/dat/revocations?limit=10&offset=0"
```

---

### GET /v1/dat/revoked/:jti

Check whether a specific JTI has been revoked. No authentication required.

**Response 200 (revoked):**

```json
{
  "revoked": true,
  "jti": "01234567-89ab-cdef-0123-456789abcdef",
  "reason": "key compromise",
  "revoked_by": "did:aid:example.com:operator",
  "revoked_at": "2026-03-07T12:00:00Z"
}
```

**Response 200 (not revoked):**

```json
{
  "revoked": false,
  "jti": "01234567-89ab-cdef-0123-456789abcdef"
}
```

**curl example:**

```bash
curl http://localhost:3000/v1/dat/revoked/01234567-89ab-cdef-0123-456789abcdef
```

---

## Error Responses

All error responses use JSON with an `error` field:

```json
{ "error": "description of what went wrong" }
```

| Status | Meaning |
|--------|---------|
| 400 | Invalid request body or parameters |
| 401 | Missing or invalid authorization token |
| 404 | AID or JTI not found |
| 429 | Rate limit exceeded (max 120 req/min/IP); retry after 60s |
| 500 | Internal storage or verification error |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_PORT` | `3000` | TCP port to listen on |
| `REGISTRY_ADMIN_PUBKEY` | unset | 64-char hex Ed25519 public key for write auth. Unset = dev mode (open writes) |

---

## Route Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Health check |
| GET | `/ready` | — | Readiness probe (DB check) |
| GET | `/v1/meta` | — | Protocol metadata |
| PUT | `/v1/aid/:id` | write | Register or update AID |
| GET | `/v1/aid/:id` | — | Resolve AID |
| DELETE | `/v1/aid/:id` | write | Deactivate AID |
| GET | `/v1/aid/:id/key` | — | Get AID public keys |
| POST | `/v1/dat/verify` | — | Verify a DAT |
| POST | `/v1/dat/revoke` | write | Revoke a DAT by JTI |
| GET | `/v1/dat/revocations` | — | List revocations (paginated) |
| GET | `/v1/dat/revoked/:jti` | — | Check revocation status |
