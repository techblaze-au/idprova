# IDProva Security Model

This document covers the threat model, cryptographic design, key management practices, and security properties of the IDProva protocol. For the complete formal threat analysis see [STRIDE-THREAT-MODEL.md](STRIDE-THREAT-MODEL.md).

---

## Cryptographic Foundations

### Algorithm selection

IDProva uses Ed25519 for classical signatures with post-quantum hybrid support planned:

| Algorithm | Role | Standard | Status |
|-----------|------|---------|--------|
| **Ed25519** | Signatures (signing/verification) | RFC 8032 | Implemented |
| **BLAKE3** | Content hashing (receipts, config attestation) | BLAKE3 spec | Implemented |
| **SHA-256** | Interoperability hashing | FIPS 180-4 | Implemented |
| **ML-DSA-65** | Post-quantum hybrid signatures | FIPS 204 | Planned |

When ML-DSA-65 hybrid support is added, identities created today will gain post-quantum resistance via dual signatures — securing them against both classical and quantum adversaries.

### Why Ed25519?

- **Constant-time operations** — the `ed25519-dalek` crate implements all operations in constant time, preventing timing side-channel attacks
- **Small key and signature sizes** — 32-byte public keys, 64-byte signatures; ideal for embedded in JWS tokens and DID Documents
- **Zeroize on drop** — `SigningKey` implements `ZeroizeOnDrop`, clearing key material from memory when the `KeyPair` struct is dropped
- **Strong security** — ~128-bit security level under classical adversaries

### Why BLAKE3?

- Faster than SHA-256 on modern CPUs
- Native parallelism — can use SIMD and multithreading
- Designed for use as a PRF, MAC, KDF, and hash function
- All receipt hashes use the `blake3:` prefix to signal algorithm in the hash string

---

## Trust Boundaries

The IDProva system has four trust boundaries:

```
┌──────────────────────────────────────┐
│ TB-1: Agent Runtime (untrusted)      │
│   - AI agent process                 │
│   - Agent configuration              │
│   - Local key storage                │
│   ┌──────────────────────────────┐   │
│   │ TB-2: IDProva SDK (trusted)  │   │
│   │   - KeyPair (Ed25519)        │   │
│   │   - DAT issue/verify         │   │
│   │   - Receipt generation       │   │
│   └──────────────────────────────┘   │
└────────────────┬─────────────────────┘
                 │ Network (TLS 1.3+)
                 ▼
┌──────────────────────────────────────┐
│ TB-3: IDProva Registry (semi-trusted)│
│   - AID storage (SQLite/Postgres)    │
│   - DID resolution endpoint          │
└──────────────┬───────────────────────┘
               ▼
┌──────────────────────────────────────┐
│ TB-4: External Services              │
│   - MCP servers, A2A peers           │
│   - DNS (DID resolution)             │
└──────────────────────────────────────┘
```

The SDK is the only fully trusted component. The agent runtime, registry, and all external services are treated as potentially hostile.

---

## Key Management

### Generating keys

```bash
# Generate a keypair — private key stored in ./keys/my-agent.key
idprova keygen --output ./keys/my-agent.key

# Public key is printed to stdout in multibase format
```

### Storage best practices

| Environment | Recommended storage |
|------------|---------------------|
| Development | Plaintext file, never committed to source control |
| Production | Hardware Security Module (HSM) or cloud KMS (AWS KMS, GCP Cloud HSM) |
| Containers | Kubernetes Secrets with encryption at rest; mount as volume, not env var |
| Embedded | Secure enclave / TrustZone; encrypt with device-bound key |

**Rules:**
- Never log, print, or return private key bytes
- Never pass private key bytes across FFI boundaries (Python, TypeScript SDKs)
- Rotate keys when: agent is decommissioned, key compromise is suspected, or periodically per policy
- Use short-lived keys (rotate every 30–90 days) for high-privilege agents

### Key rotation

Key rotation requires a new AID version:
1. Generate new keypair
2. Build a new AID with incremented `version` and the new `verificationMethod`
3. Sign the new AID with the **old** key (proof of continuous control)
4. Register the new AID via `PUT /aids/{did}`
5. Re-issue all active DATs with the new key

### Memory safety

`ed25519-dalek`'s `SigningKey` implements `ZeroizeOnDrop` — the secret bytes are overwritten with zeros when the `KeyPair` is dropped:

```rust
{
    let kp = KeyPair::generate();
    // kp.signing_key is in memory
} // kp dropped → signing_key bytes zeroed
```

For FFI bindings (Python/TypeScript), the SDK wrappers must **never** expose raw secret bytes. The Rust layer handles all signing internally.

---

## DAT Security Properties

### Algorithm enforcement

The DAT verifier hard-rejects any `alg` value other than `"EdDSA"` — protecting against algorithm confusion attacks (SEC-3 mitigation):

```rust
if header.alg != "EdDSA" {
    return Err(IdprovaError::InvalidDat(
        format!("unsupported algorithm '{}': only 'EdDSA' is permitted", header.alg)
    ));
}
```

Attempting to present a DAT with `"alg": "none"` or `"alg": "HS256"` is rejected immediately during parsing, before any cryptographic check.

### Header injection prevention

`DatHeader` uses `#[serde(deny_unknown_fields)]` — any JWS header containing extra fields (`jwk`, `jku`, `x5u`, `x5c`) is rejected outright (SEC-4 mitigation). This prevents key injection attacks where an attacker embeds their own key material in the token header.

### Replay attack prevention

DATs are time-bounded via `exp` (expiry) and `nbf` (not-before). Verifiers **must** check both:

```rust
dat.validate_timing()?;
// or via the full policy pipeline:
let pe = PolicyEvaluator::new();
let decision = pe.evaluate(&dat, &ctx);
```

For high-security scenarios, combine short expiry windows (minutes, not hours) with a JTI blocklist of recently seen tokens to prevent within-window replay.

### Scope containment

Wildcard scopes (`mcp:*:*`) are powerful and should be granted sparingly:

| Pattern | Grants |
|---------|--------|
| `mcp:tool:filesystem:read` | Single specific action |
| `mcp:tool:filesystem:*` | All actions on one tool |
| `mcp:tool:*:*` | All MCP tools and all actions |
| `mcp:*:*:*` | All MCP resources and all actions |
| `*:*:*:*` | Unrestricted — avoid entirely in production |

When re-delegating, child DAT scopes must be a **strict subset** of the parent's scope set. The delegation chain enforces this — a verifier should reject any delegation where the child claims broader scope than the parent.

### Delegation depth

Unbounded delegation chains create uncontrollable privilege escalation. Limit depth via `DatConstraints`:

```rust
DatConstraints {
    max_delegation_depth: Some(2), // allow at most 2 levels of re-delegation
    ..Default::default()
}
```

The protocol recommends a **hard cap of 5** delegation levels. Set this in your verification middleware.

---

## Receipt Chain Integrity

### Tamper evidence

The BLAKE3 hash chain makes any receipt log modification detectable. Deleting, inserting, or modifying any receipt breaks the `previousHash` linkage for all subsequent entries.

Always call `verify_integrity()` after loading a receipt log from storage:

```rust
let log = ReceiptLog::from_entries(entries);
log.verify_integrity()?; // fail fast on tampered log
```

### Atomic receipt generation

To prevent unaccounted actions, generate receipts **before** returning the action result to the caller:

```
1. Receive action request
2. Verify DAT (authorization)
3. Execute action
4. Generate and store receipt     ← must complete before returning
5. Return result to caller
```

If the agent crashes between steps 4 and 5, the receipt exists and the action is accounted for. If it crashes between 3 and 4, the action is unrecorded — this is the primary audit gap to mitigate at the infrastructure level (e.g., WAL-mode SQLite, distributed log with acknowledgement before response).

### Input/output hashing

The `inputHash` and `outputHash` fields use BLAKE3 with a `blake3:` prefix. For common or predictable inputs, add a per-agent or per-session nonce to the hash input to prevent rainbow table correlation:

```rust
// Recommended: hash nonce || input rather than raw input
let nonce = session_id.as_bytes();
let hash_input = [nonce, input_bytes].concat();
let input_hash = format!("blake3:{}", hex::encode(blake3::hash(&hash_input)));
```

---

## Registry Security

### Transport

All communication with the registry must use **TLS 1.3+**. The registry does not support plain HTTP in production mode.

### Authentication

Registry write endpoints (`PUT /aids/{did}`, `DELETE /aids/{did}`) require an `Authorization: Bearer <DAT>` header. The DAT must be issued by the DID's controller and scoped to `idprova:registry:aid:write`.

Read endpoints (`GET /aids/{did}`, `GET /health`) are unauthenticated.

### Rate limiting

The registry enforces rate limiting on write endpoints. Configure via the `RATE_LIMIT_*` environment variables (see [API Reference](api-reference.md)).

### AID trust level transitions

Trust level cannot be self-declared above L0. Elevation to L1+ requires the registry to validate the DNS TXT record for the domain in the DID's authority component. Elevation to L2+ requires additional out-of-band attestation by the registry operator.

---

## STRIDE Threat Summary

The following table summarises the highest-severity threats and their primary mitigations:

| ID | STRIDE | Threat | Severity | Mitigation |
|----|--------|--------|----------|-----------|
| KEY-S1 | Spoofing | Private key theft → forge any DAT | Critical | Encrypt at rest; HSM; zeroize on drop |
| KEY-I1 | Info Disclosure | Key bytes leaked via FFI memory dump | Critical | Never expose secret bytes across FFI |
| DAT-S1 | Spoofing | Algorithm confusion (`"alg": "none"`) | Critical | Hard-reject non-EdDSA alg in `from_compact()` |
| DAT-S2 | Spoofing | JWS header key injection via `jwk`/`jku` | Critical | `deny_unknown_fields` on `DatHeader` |
| AID-S1 | Spoofing | Claim unowned domain in DID authority | Critical | L1+ requires DNS TXT verification |
| DAT-T2 | Tampering | Replay of expired/revoked DAT | High | Check `exp`/`nbf`; JTI blocklist for sensitive ops |
| DAT-E1 | Elevation | Wildcard scope grants unintended perms | High | Restrict wildcards; audit scope grants |
| REC-T1 | Tampering | Receipt log truncation/modification | High | `verify_integrity()` on every load; external timestamp anchors |
| REC-R1 | Repudiation | No receipt generated if agent crashes | High | Atomic: store receipt before returning result |
| AID-E1 | Elevation | Self-declare elevated trust level | High | Registry validates trust level transitions |
| DAT-D1 | DoS | Unbounded delegation chain depth | Medium | `max_delegation_depth` constraint; hard cap at 5 |
| AID-D1 | DoS | Registry storage exhaustion | Medium | Rate limiting; storage quotas per namespace |

For the complete STRIDE analysis with all threats and mitigations, see [STRIDE-THREAT-MODEL.md](STRIDE-THREAT-MODEL.md).

---

## Security Checklist

Use this checklist when deploying IDProva in production:

**Key management**
- [ ] Private keys encrypted at rest (AES-256-GCM or hardware-backed)
- [ ] Private keys never logged, printed, or exported via API
- [ ] Key rotation policy defined and documented
- [ ] SDK FFI bindings verified to zeroize key memory

**DAT issuance**
- [ ] Minimum required expiry enforced (no "never expires" tokens)
- [ ] Wildcard scopes audited and restricted
- [ ] `max_delegation_depth` set on all production DATs
- [ ] JTI blocklist for sensitive operations

**Registry**
- [ ] TLS 1.3+ on all registry endpoints
- [ ] Write endpoints require DAT authentication
- [ ] Rate limiting configured
- [ ] AID signatures verified on every resolution

**Receipt chain**
- [ ] `verify_integrity()` called on every receipt log load
- [ ] Receipt generation atomic with action execution
- [ ] Receipt storage durable (WAL mode / replication)

**Network**
- [ ] DNSSEC enabled for domain-verified (L1+) agents
- [ ] Registry TLS certificates pinned where possible
- [ ] All inter-service communication over TLS

---

## See also

- [STRIDE-THREAT-MODEL.md](STRIDE-THREAT-MODEL.md) — complete threat analysis
- [GAP-ANALYSIS.md](GAP-ANALYSIS.md) — implementation gaps and security roadmap
- [Concepts Guide](concepts.md) — protocol concepts including trust levels
- [Core Library API](core-api.md) — `KeyPair`, `Dat`, `ReceiptLog` API with examples
