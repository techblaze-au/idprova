# IDProva Core Library API Reference

`idprova-core` is the foundational Rust crate providing all cryptographic primitives, identity documents, delegation tokens, audit receipts, and the RBAC policy engine.

Add it to your `Cargo.toml`:

```toml
[dependencies]
idprova-core = { path = "../idprova-core" }
```

---

## Modules

| Module | Purpose |
|--------|---------|
| `crypto` | Ed25519 key generation, signing, verification, BLAKE3 hashing |
| `aid` | Agent Identity Documents (W3C DID compatible) |
| `dat` | Delegation Attestation Tokens (JWS-based) |
| `receipt` | Hash-chained action receipts for audit |
| `trust` | Trust level definitions (L0–L4) |
| `policy` | RBAC policy engine with pluggable evaluators |

---

## `crypto::KeyPair`

An Ed25519 keypair. The signing key is zeroized on drop.

### Construction

```rust
use idprova_core::crypto::KeyPair;

// Generate a fresh random keypair
let kp = KeyPair::generate();

// Reconstruct from stored secret bytes
let secret: [u8; 32] = /* loaded from secure storage */;
let kp = KeyPair::from_secret_bytes(&secret);
```

### Public key access

```rust
// Raw 32-byte public key
let pub_bytes: [u8; 32] = kp.public_key_bytes();

// Multibase-encoded (base58btc, 'z' prefix) — used in AID documents
let multibase: String = kp.public_key_multibase();

// Serializable struct (for JSON embedding)
let pk: PublicKey = kp.public_key();
// pk.key_type == "Ed25519VerificationKey2020"
// pk.public_key_multibase == "z..."
```

### Signing and verification

```rust
// Sign arbitrary bytes
let signature: Vec<u8> = kp.sign(b"my message");

// Verify a signature (static method — takes raw public key bytes)
KeyPair::verify(&pub_bytes, b"my message", &signature)?;

// Decode a multibase public key string back to raw bytes
let raw: [u8; 32] = KeyPair::decode_multibase_pubkey("z...")?;
```

### Errors

| Error | When |
|-------|------|
| `IdprovaError::InvalidKey` | Bad multibase encoding or wrong key length |
| `IdprovaError::VerificationFailed` | Signature mismatch or invalid signature bytes |

---

## `aid::AidBuilder` / `AidDocument`

Agent Identity Documents follow the W3C DID specification under the `did:idprova` method.

### Building an AID

```rust
use idprova_core::aid::AidBuilder;
use idprova_core::crypto::KeyPair;

let kp = KeyPair::generate();

let doc = AidBuilder::new()
    .id("did:idprova:example.com:my-agent")       // required
    .controller("did:idprova:example.com:alice")   // required
    .name("My Agent")                              // required
    .description("An example agent")
    .model("acme-ai/agent-v2")
    .runtime("myruntime/v1.0")
    .config_attestation("blake3:abcdef1234567890")
    .trust_level("L1")
    .add_ed25519_key(&kp)                          // required (at least one)
    .build()?;
```

Required fields: `id`, `controller`, `name`, and at least one verification method via `add_ed25519_key`.

### AidDocument fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | The agent's DID (`did:idprova:<domain>:<name>`) |
| `controller` | `String` | DID of the controlling entity |
| `verification_method` | `Vec<VerificationMethod>` | Ed25519 keys |
| `authentication` | `Vec<String>` | Key ID references |
| `service` | `Option<Vec<AidService>>` | Service endpoints (metadata) |
| `trust_level` | `Option<String>` | Trust level string ("L0"–"L4") |
| `version` | `Option<u32>` | Document version |
| `created` / `updated` | `Option<DateTime<Utc>>` | Timestamps (auto-set on build) |
| `proof` | `Option<serde_json::Value>` | Detached proof (populated by registry) |

### Serialization

`AidDocument` implements `serde::Serialize` / `serde::Deserialize`:

```rust
let json = serde_json::to_string_pretty(&doc)?;
let parsed: AidDocument = serde_json::from_str(&json)?;
```

### Errors

| Error | When |
|-------|------|
| `IdprovaError::AidValidation` | Missing required field or empty verification methods |

---

## `dat::Dat`

Delegation Attestation Tokens are compact JWS (JSON Web Signature) tokens that grant scoped permissions from an issuer to a subject agent.

### Issuing a DAT

```rust
use idprova_core::dat::{Dat, constraints::DatConstraints};
use chrono::{Utc, Duration};

let kp = KeyPair::generate(); // issuer's keypair
let expires = Utc::now() + Duration::hours(24);

let dat = Dat::issue(
    "did:idprova:example.com:alice",    // issuer DID
    "did:idprova:example.com:my-agent", // subject DID
    vec!["mcp:tool:read".to_string()],  // granted scopes
    expires,
    None,   // constraints (see below)
    None,   // config_attestation
    &kp,
)?;

// Serialize to compact JWS: header.payload.signature
let token_string: String = dat.to_compact()?;
```

### Scope format

Scopes follow the `namespace:resource:action` grammar (3 colon-separated parts). Wildcards are supported at any segment:

```
mcp:tool:read          # specific tool read access
mcp:tool:*             # all actions on mcp tools
mcp:*:*                # all mcp resources and actions
```

### Parsing a received DAT

```rust
// Parse without verifying (call verify() separately)
let dat = Dat::from_compact(&token_string)?;

println!("Issuer: {}", dat.claims.iss);
println!("Subject: {}", dat.claims.sub);
println!("Scopes: {:?}", dat.claims.scope);
println!("Expires: {}", dat.claims.exp);
```

### Verifying a DAT

```rust
use idprova_core::dat::constraints::EvaluationContext;

let pub_bytes = issuer_kp.public_key_bytes();

// Simple verify — checks signature, timing, and a required scope
let ctx = EvaluationContext::default();
dat.verify(&pub_bytes, "mcp:tool:read", &ctx)?;

// Pass "" for required_scope to skip the scope check (e.g. introspection)
dat.verify(&pub_bytes, "", &ctx)?;
```

`verify()` runs in order:
1. Signature verification
2. Timing (expiry + not-before)
3. Scope coverage check
4. Constraint evaluators (rate limit, IP, trust, depth, geofence, time windows)
5. Config attestation (if constraint present)

### DAT claims reference

```rust
pub struct DatClaims {
    pub iss: String,                            // issuer DID
    pub sub: String,                            // subject DID
    pub iat: i64,                               // issued-at Unix timestamp
    pub exp: i64,                               // expiry Unix timestamp
    pub nbf: i64,                               // not-before Unix timestamp
    pub jti: String,                            // unique token ID ("dat_<ULID>")
    pub scope: Vec<String>,                     // granted scope strings
    pub constraints: Option<DatConstraints>,    // usage constraints
    pub config_attestation: Option<String>,     // required config hash
    pub delegation_chain: Option<Vec<String>>,  // parent DAT JTIs
}
```

### DatConstraints

Embed constraints into a DAT at issuance time:

```rust
use idprova_core::dat::constraints::{DatConstraints, RateLimit, TimeWindow};

let constraints = DatConstraints {
    // Rate limiting
    rate_limit: Some(RateLimit {
        max_actions: 100,
        window_secs: 3600,  // per hour
    }),

    // IP access control
    ip_allowlist: Some(vec!["10.0.0.0/8".to_string()]),
    ip_denylist:  Some(vec!["10.0.0.0/24".to_string()]),

    // Trust level requirement (0–100)
    min_trust_level: Some(50),

    // Delegation chain depth cap (0 = no re-delegation)
    max_delegation_depth: Some(2),

    // Geofence (ISO 3166-1 alpha-2)
    allowed_countries: Some(vec!["AU".to_string(), "NZ".to_string()]),

    // Time windows (UTC hours, inclusive)
    time_windows: Some(vec![TimeWindow {
        start_hour: 9,
        end_hour: 17,
        days_of_week: Some(vec![0, 1, 2, 3, 4]), // Mon–Fri (0=Mon, 6=Sun)
    }]),

    // Config attestation (BLAKE3/SHA-256 hex of agent config)
    required_config_hash: Some("abcdef1234...".to_string()),

    // Require a receipt for every action
    require_receipt: Some(true),

    ..Default::default()
};

let dat = Dat::issue(
    issuer_did, subject_did, scopes, expires,
    Some(constraints), None, &kp,
)?;
```

### Timing helpers

```rust
dat.is_expired()       // true if now >= exp
dat.is_not_yet_valid() // true if now < nbf
dat.validate_timing()  // returns Err if expired or not-yet-valid
```

### Errors

| Error | When |
|-------|------|
| `IdprovaError::InvalidDat` | Malformed compact JWS or unsupported algorithm |
| `IdprovaError::VerificationFailed` | Bad signature |
| `IdprovaError::DatExpired` | Token past expiry |
| `IdprovaError::DatNotYetValid` | Token before `nbf` |
| `IdprovaError::ScopeNotPermitted` | Requested scope not covered |
| `IdprovaError::ConstraintViolated` | Constraint evaluator denied |

---

## `receipt::ReceiptLog` / `Receipt`

An append-only, hash-chained audit log. Each entry is a `Receipt` whose `chain` field links it to the previous receipt via a BLAKE3 hash.

### Creating receipts and appending to a log

```rust
use idprova_core::receipt::{ReceiptLog, entry::{Receipt, ActionDetails, ChainLink, ReceiptContext}};
use chrono::Utc;

let mut log = ReceiptLog::new();

// Build a receipt — link it to the current chain tip
let receipt = Receipt {
    id: "rcpt_01J...".to_string(),
    timestamp: Utc::now(),
    agent: "did:idprova:example.com:my-agent".to_string(),
    dat: "dat_01J...".to_string(),           // jti from the authorizing DAT
    action: ActionDetails {
        action_type: "mcp:tool-call".to_string(),
        server: Some("tools.example.com".to_string()),
        tool: Some("read_file".to_string()),
        input_hash: "blake3:aabb...".to_string(),
        output_hash: Some("blake3:ccdd...".to_string()),
        status: "success".to_string(),
        duration_ms: Some(42),
    },
    context: Some(ReceiptContext {
        session_id: Some("sess_xyz".to_string()),
        parent_receipt_id: None,
        request_id: Some("req_abc".to_string()),
    }),
    chain: ChainLink {
        previous_hash: log.last_hash(),         // "genesis" for first
        sequence_number: log.next_sequence(),   // 0, 1, 2, ...
    },
    signature: "base64url...".to_string(),       // agent's Ed25519 signature
};

log.append(receipt);
```

### Verifying chain integrity

```rust
// Checks sequence numbers and hash linkage for the entire chain
log.verify_integrity()?;
```

### Accessing entries

```rust
let entries: &[Receipt] = log.entries();
let count: usize = log.len();
let empty: bool = log.is_empty();
let tip_hash: String = log.last_hash();   // hash of the last receipt
let next_seq: u64 = log.next_sequence();  // sequence number for next entry
```

### Loading from storage

```rust
// Reconstruct a log from persisted entries (e.g., from SQLite)
let entries: Vec<Receipt> = /* load from db */;
let log = ReceiptLog::from_entries(entries);
log.verify_integrity()?; // always verify after loading
```

### Receipt hashing

Each `Receipt` can be hashed for chain linking:

```rust
let hash: String = receipt.compute_hash(); // "blake3:<hex>"
```

### Errors

| Error | When |
|-------|------|
| `IdprovaError::ReceiptChainBroken(seq)` | Sequence mismatch or broken hash link at `seq` |

---

## `policy::PolicyEvaluator`

The `PolicyEvaluator` combines timing, scope, and constraint checks into a single `evaluate()` call. It uses pluggable `ConstraintEvaluator` implementations and short-circuits on first denial.

### Basic usage

```rust
use idprova_core::policy::{PolicyEvaluator, context::EvaluationContext, decision::PolicyDecision};

let pe = PolicyEvaluator::new(); // loads all 7 built-in evaluators

let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
    .caller_trust_level(TrustLevel::L2)
    .actions_this_hour(42)
    .source_country("AU")
    .delegation_depth(1)
    .build();

match pe.evaluate(&dat, &ctx) {
    PolicyDecision::Allow => { /* proceed */ }
    PolicyDecision::Deny(reason) => {
        eprintln!("Denied: {:?}", reason);
    }
}
```

### Evaluation order

1. **Timing** — token expired or not yet valid → `DenialReason::Expired` / `NotYetValid`
2. **Scope** — requested scope not covered → `DenialReason::ScopeNotCovered`
3. **Constraints** — iterates all registered evaluators in order, short-circuits on first denial

### `EvaluationContext` builder

```rust
use idprova_core::policy::context::EvaluationContext;
use idprova_core::trust::level::TrustLevel;
use std::net::IpAddr;

let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
    .source_ip("10.1.2.3".parse::<IpAddr>().unwrap())
    .source_country("AU")
    .caller_trust_level(TrustLevel::L2)
    .actions_this_hour(42)
    .actions_this_day(200)
    .active_concurrent(3)
    .delegation_depth(1)
    .caller_config_attestation("blake3:abcdef...")
    .extension("custom_key", serde_json::json!("custom_value"))
    .build();
```

All fields except `requested_scope` are optional. Evaluators that require a missing field fail-open (skip) rather than fail-closed — except for allowlist/required constraints, which fail-closed when the context value is absent.

### `DenialReason` variants

| Variant | Cause |
|---------|-------|
| `Expired` | Token past `exp` |
| `NotYetValid` | Token before `nbf` |
| `ScopeNotCovered` | Requested scope not in DAT's scope set |
| `RateLimitExceeded { limit_type, current, limit }` | Rate limit breach |
| `IpNotAllowed` | IP not in allowlist or in denylist |
| `TrustLevelInsufficient` | Agent trust level too low |
| `DelegationDepthExceeded` | Chain depth beyond `max_delegation_depth` |
| `GeofenceViolation` | Country not in `allowed_countries` |
| `TimeWindowViolation` | Outside all permitted time windows |
| `ConfigAttestationMismatch` | Config hash mismatch |
| `Custom(String)` | From a custom evaluator |

### Custom evaluators

```rust
use idprova_core::policy::constraints::{ConstraintEvaluator, DatConstraints};
use idprova_core::policy::context::EvaluationContext;
use idprova_core::policy::decision::PolicyDecision;

struct MyEvaluator;

impl ConstraintEvaluator for MyEvaluator {
    fn evaluate(&self, constraints: &DatConstraints, ctx: &EvaluationContext) -> PolicyDecision {
        // inspect constraints.extensions or ctx.extensions
        PolicyDecision::Allow
    }
}

let pe = PolicyEvaluator::with_evaluators(vec![
    Box::new(MyEvaluator),
    // add built-ins alongside custom ones as needed
]);
```

---

## Error types

All fallible operations return `idprova_core::Result<T>` which is `Result<T, IdprovaError>`.

```rust
use idprova_core::{IdprovaError, Result};

pub enum IdprovaError {
    InvalidKey(String),
    VerificationFailed(String),
    AidValidation(String),
    InvalidDat(String),
    DatExpired,
    DatNotYetValid,
    ScopeNotPermitted(String),
    ConstraintViolated(String),
    ReceiptChainBroken(u64),
    Json(serde_json::Error),
    // ... additional variants
}
```

All variants implement `std::error::Error` and `Display`.

---

## Complete example: issue and verify a DAT

```rust
use idprova_core::{
    crypto::KeyPair,
    aid::AidBuilder,
    dat::{Dat, constraints::{DatConstraints, RateLimit}},
    policy::{PolicyEvaluator, context::EvaluationContext},
    trust::level::TrustLevel,
};
use chrono::{Utc, Duration};

fn main() -> idprova_core::Result<()> {
    // 1. Generate issuer and agent keypairs
    let issuer_kp = KeyPair::generate();
    let agent_kp  = KeyPair::generate();

    // 2. Build the agent's AID
    let _aid = AidBuilder::new()
        .id("did:idprova:example.com:my-agent")
        .controller("did:idprova:example.com:alice")
        .name("My Agent")
        .trust_level("L1")
        .add_ed25519_key(&agent_kp)
        .build()?;

    // 3. Issuer creates a DAT for the agent
    let dat = Dat::issue(
        "did:idprova:example.com:alice",
        "did:idprova:example.com:my-agent",
        vec!["mcp:tool:read".to_string(), "mcp:tool:write".to_string()],
        Utc::now() + Duration::hours(8),
        Some(DatConstraints {
            rate_limit: Some(RateLimit { max_actions: 500, window_secs: 3600 }),
            min_trust_level: Some(1),
            max_delegation_depth: Some(0),
            ..Default::default()
        }),
        None,
        &issuer_kp,
    )?;

    // 4. Serialize for transport
    let token = dat.to_compact()?;
    println!("DAT: {}", &token[..40]);

    // 5. Recipient parses the token
    let received = Dat::from_compact(&token)?;

    // 6. Verify using PolicyEvaluator
    let pe = PolicyEvaluator::new();
    let ctx = EvaluationContext::builder("mcp:tool:read")
        .caller_trust_level(TrustLevel::L1)
        .actions_this_hour(42)
        .build();

    let issuer_pub = issuer_kp.public_key_bytes();
    received.verify(&issuer_pub, "mcp:tool:read", &ctx)?;

    let decision = pe.evaluate(&received, &ctx);
    assert!(decision.is_allowed());

    println!("Access granted for scope mcp:tool:read");
    Ok(())
}
```

---

## See also

- [Getting Started Guide](getting-started.md) — CLI workflow
- [API Reference](api-reference.md) — Registry HTTP endpoints
- [Protocol Specification](protocol-spec-v0.1.md) — Full protocol details
- [Concepts Guide](concepts.md) — DID method, AID lifecycle, trust levels
