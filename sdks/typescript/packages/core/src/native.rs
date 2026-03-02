// IDProva TypeScript SDK — napi-rs bindings to idprova-core
//
// Security: Private keys NEVER cross the FFI boundary as raw bytes.
// The KeyPair holds the Rust KeyPair and exposes only sign()/verify()/publicKey.

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;

use chrono::{Duration, Utc};
use idprova_core::aid::builder::AidBuilder;
use idprova_core::aid::document::AidDocument;
use idprova_core::crypto::KeyPair as RustKeyPair;
use idprova_core::dat::scope::Scope as RustScope;
use idprova_core::dat::token::{Dat as RustDat, DatConstraints as RustDatConstraints};
use idprova_core::receipt::log::ReceiptLog as RustReceiptLog;
use idprova_core::trust::level::TrustLevel as RustTrustLevel;
use idprova_core::IdprovaError;

// ---------------------------------------------------------------------------
// Error mapping — IdprovaError → napi::Error
// ---------------------------------------------------------------------------

fn to_napi_err(e: IdprovaError) -> napi::Error {
    match &e {
        IdprovaError::DatExpired => napi::Error::from_reason(format!(
            "DatExpiredError: {}. Fix: Issue a new DAT with a later expiration.",
            e
        )),
        IdprovaError::DatNotYetValid => napi::Error::from_reason(format!(
            "DatNotYetValidError: {}. Fix: Check system clock or wait until the nbf time.",
            e
        )),
        IdprovaError::VerificationFailed(_) => napi::Error::from_reason(format!(
            "VerificationFailedError: {}. Fix: Ensure the correct public key is used.",
            e
        )),
        IdprovaError::InvalidAid(_) | IdprovaError::AidValidation(_) => {
            napi::Error::from_reason(format!("InvalidAidError: {}", e))
        }
        IdprovaError::InvalidDat(_) => {
            napi::Error::from_reason(format!("InvalidDatError: {}", e))
        }
        _ => napi::Error::from_reason(format!("IdprovaError: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// KeyPair — Ed25519 key pair (private key stays in Rust)
// ---------------------------------------------------------------------------

/// An Ed25519 key pair for signing and verification.
///
/// The private key is held securely in Rust memory and never exposed to JavaScript.
/// Use `sign()` to create signatures and `verify()` for verification.
#[napi]
pub struct KeyPair {
    inner: RustKeyPair,
}

#[napi]
impl KeyPair {
    /// Generate a new random Ed25519 key pair.
    #[napi(factory)]
    pub fn generate() -> Self {
        Self {
            inner: RustKeyPair::generate(),
        }
    }

    /// Create a key pair from secret key bytes (32 bytes).
    ///
    /// WARNING: Only use for loading previously saved keys.
    /// Prefer generate() for new keys.
    #[napi(factory)]
    pub fn from_secret_bytes(secret: Buffer) -> Result<Self> {
        let bytes = secret.as_ref();
        if bytes.len() != 32 {
            return Err(napi::Error::from_reason(
                "Secret key must be exactly 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self {
            inner: RustKeyPair::from_secret_bytes(&arr),
        })
    }

    /// Sign a message and return the signature as bytes.
    #[napi]
    pub fn sign(&self, message: Buffer) -> Buffer {
        Buffer::from(self.inner.sign(message.as_ref()))
    }

    /// Verify a signature against a message using this key pair's public key.
    #[napi]
    pub fn verify(&self, message: Buffer, signature: Buffer) -> bool {
        let pub_bytes = self.inner.public_key_bytes();
        RustKeyPair::verify(&pub_bytes, message.as_ref(), signature.as_ref()).is_ok()
    }

    /// Get the public key in multibase encoding (z-prefixed base58btc).
    #[napi(getter)]
    pub fn public_key_multibase(&self) -> String {
        self.inner.public_key_multibase()
    }

    /// Get the raw public key bytes (32 bytes).
    #[napi(getter)]
    pub fn public_key_bytes(&self) -> Buffer {
        Buffer::from(self.inner.public_key_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// AID — Agent Identity Document
// ---------------------------------------------------------------------------

/// An IDProva Agent Identity Document (W3C DID Document).
///
/// Create with AIDBuilder or parse from JSON.
#[napi]
pub struct AID {
    inner: AidDocument,
}

#[napi]
impl AID {
    /// Get the DID identifier (e.g., "did:idprova:example.com:my-agent").
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.id.clone()
    }

    /// Get the controller DID.
    #[napi(getter)]
    pub fn controller(&self) -> String {
        self.inner.controller.clone()
    }

    /// Get the trust level string (e.g., "L0", "L1").
    #[napi(getter)]
    pub fn trust_level(&self) -> Option<String> {
        self.inner.trust_level.clone()
    }

    /// Serialize to JSON string.
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| napi::Error::from_reason(format!("Serialization error: {e}")))
    }

    /// Parse from JSON string.
    #[napi(factory)]
    pub fn from_json(json: String) -> Result<Self> {
        let doc: AidDocument = serde_json::from_str(&json)
            .map_err(|e| napi::Error::from_reason(format!("Invalid AID JSON: {e}")))?;
        doc.validate().map_err(to_napi_err)?;
        Ok(Self { inner: doc })
    }

    /// Validate the document structure.
    #[napi]
    pub fn validate(&self) -> Result<()> {
        self.inner.validate().map_err(to_napi_err)
    }
}

// ---------------------------------------------------------------------------
// AIDBuilder — Builder for AID documents
// ---------------------------------------------------------------------------

/// Builder for creating Agent Identity Documents.
///
/// Usage:
///   const builder = new AIDBuilder();
///   builder.setId("did:idprova:example.com:my-agent");
///   builder.setController("did:idprova:example.com:alice");
///   builder.setName("My Agent");
///   builder.addEd25519Key(keypair);
///   const aid = builder.build();
#[napi]
pub struct AIDBuilder {
    inner: AidBuilder,
}

#[napi]
impl AIDBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: AidBuilder::new(),
        }
    }

    /// Set the DID identifier.
    #[napi]
    pub fn set_id(&mut self, id: String) {
        self.inner = std::mem::take(&mut self.inner).id(&id);
    }

    /// Set the controller DID.
    #[napi]
    pub fn set_controller(&mut self, controller: String) {
        self.inner = std::mem::take(&mut self.inner).controller(&controller);
    }

    /// Set the human-readable agent name.
    #[napi]
    pub fn set_name(&mut self, name: String) {
        self.inner = std::mem::take(&mut self.inner).name(&name);
    }

    /// Set an optional description.
    #[napi]
    pub fn set_description(&mut self, desc: String) {
        self.inner = std::mem::take(&mut self.inner).description(&desc);
    }

    /// Set the AI model identifier.
    #[napi]
    pub fn set_model(&mut self, model: String) {
        self.inner = std::mem::take(&mut self.inner).model(&model);
    }

    /// Set the runtime environment.
    #[napi]
    pub fn set_runtime(&mut self, runtime: String) {
        self.inner = std::mem::take(&mut self.inner).runtime(&runtime);
    }

    /// Set the trust level (e.g., "L0", "L1").
    #[napi]
    pub fn set_trust_level(&mut self, level: String) {
        self.inner = std::mem::take(&mut self.inner).trust_level(&level);
    }

    /// Add an Ed25519 verification key from a KeyPair.
    #[napi]
    pub fn add_ed25519_key(&mut self, keypair: &KeyPair) {
        self.inner = std::mem::take(&mut self.inner).add_ed25519_key(&keypair.inner);
    }

    /// Build and validate the AID document.
    #[napi]
    pub fn build(&mut self) -> Result<AID> {
        let builder = std::mem::take(&mut self.inner);
        builder
            .build()
            .map(|doc| AID { inner: doc })
            .map_err(to_napi_err)
    }
}

// ---------------------------------------------------------------------------
// DAT — Delegation Attestation Token
// ---------------------------------------------------------------------------

/// A Delegation Attestation Token — signed, scoped, time-bounded permission grant.
///
/// Issue with DAT.issue(), parse with DAT.fromCompact().
#[napi]
pub struct DAT {
    inner: RustDat,
}

#[napi]
impl DAT {
    /// Issue a new DAT signed by the issuer's key pair.
    #[napi(factory)]
    pub fn issue(
        issuer_did: String,
        subject_did: String,
        scope: Vec<String>,
        expires_in_seconds: i64,
        signing_key: &KeyPair,
        max_actions: Option<i64>,
        require_receipt: Option<bool>,
    ) -> Result<Self> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        let constraints = if max_actions.is_some() || require_receipt.is_some() {
            Some(RustDatConstraints {
                max_actions: max_actions.map(|n| n as u64),
                allowed_servers: None,
                require_receipt,
            })
        } else {
            None
        };

        RustDat::issue(
            &issuer_did,
            &subject_did,
            scope,
            expires_at,
            constraints,
            None,
            &signing_key.inner,
        )
        .map(|dat| Self { inner: dat })
        .map_err(to_napi_err)
    }

    /// Serialize to compact JWS format (header.payload.signature).
    #[napi]
    pub fn to_compact(&self) -> Result<String> {
        self.inner.to_compact().map_err(to_napi_err)
    }

    /// Parse from compact JWS string (validates algorithm).
    #[napi(factory)]
    pub fn from_compact(compact: String) -> Result<Self> {
        RustDat::from_compact(&compact)
            .map(|dat| Self { inner: dat })
            .map_err(to_napi_err)
    }

    /// Verify the DAT signature against a public key (Buffer, 32 bytes).
    #[napi]
    pub fn verify_signature(&self, public_key_bytes: Buffer) -> Result<bool> {
        let bytes = public_key_bytes.as_ref();
        if bytes.len() != 32 {
            return Err(napi::Error::from_reason(
                "Public key must be exactly 32 bytes",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        match self.inner.verify_signature(&key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Validate timing constraints (not expired, not before valid).
    #[napi]
    pub fn validate_timing(&self) -> Result<()> {
        self.inner.validate_timing().map_err(to_napi_err)
    }

    /// Check if the DAT is expired.
    #[napi(getter)]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Get the issuer DID.
    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.claims.iss.clone()
    }

    /// Get the subject DID.
    #[napi(getter)]
    pub fn subject(&self) -> String {
        self.inner.claims.sub.clone()
    }

    /// Get the token ID (jti).
    #[napi(getter)]
    pub fn jti(&self) -> String {
        self.inner.claims.jti.clone()
    }

    /// Get the granted scopes as a list of strings.
    #[napi(getter)]
    pub fn scope(&self) -> Vec<String> {
        self.inner.claims.scope.clone()
    }

    /// Get the expiration timestamp (Unix seconds).
    #[napi(getter)]
    pub fn expires_at(&self) -> i64 {
        self.inner.claims.exp
    }
}

// ---------------------------------------------------------------------------
// Scope — Permission scope
// ---------------------------------------------------------------------------

/// A permission scope in namespace:resource:action format.
#[napi]
pub struct Scope {
    inner: RustScope,
}

#[napi]
impl Scope {
    /// Parse a scope string (e.g., "mcp:tool:read").
    #[napi(constructor)]
    pub fn new(scope_str: String) -> Result<Self> {
        RustScope::parse(&scope_str)
            .map(|s| Self { inner: s })
            .map_err(to_napi_err)
    }

    /// Check if this scope covers (permits) the requested scope.
    #[napi]
    pub fn covers(&self, requested: &Scope) -> bool {
        self.inner.covers(&requested.inner)
    }

    /// Get the string representation.
    #[napi]
    pub fn to_string_repr(&self) -> String {
        self.inner.to_string_repr()
    }
}

// ---------------------------------------------------------------------------
// TrustLevel
// ---------------------------------------------------------------------------

/// Trust level for an agent identity (L0 through L4).
#[napi]
pub struct TrustLevel {
    inner: RustTrustLevel,
}

#[napi]
impl TrustLevel {
    /// Parse a trust level string (e.g., "L0", "L1", "L2", "L3", "L4").
    #[napi(constructor)]
    pub fn new(level: String) -> Result<Self> {
        RustTrustLevel::from_str_repr(&level)
            .map(|tl| Self { inner: tl })
            .ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "Invalid trust level '{}'. Must be L0, L1, L2, L3, or L4.",
                    level
                ))
            })
    }

    /// Check if this trust level meets the required minimum.
    #[napi]
    pub fn meets_minimum(&self, required: &TrustLevel) -> bool {
        self.inner.meets_minimum(required.inner)
    }

    /// Get a human-readable description of this trust level.
    #[napi(getter)]
    pub fn description(&self) -> String {
        self.inner.description().to_string()
    }

    /// Get the string representation (e.g., "L0").
    #[napi]
    pub fn to_string_repr(&self) -> String {
        self.inner.as_str().to_string()
    }
}

// ---------------------------------------------------------------------------
// ReceiptLog — Append-only, hash-chained audit log
// ---------------------------------------------------------------------------

/// An append-only, hash-chained audit receipt log.
///
/// Provides tamper-evident logging of agent actions.
#[napi]
pub struct ReceiptLog {
    inner: RustReceiptLog,
}

#[napi]
impl ReceiptLog {
    /// Create a new empty receipt log.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: RustReceiptLog::new(),
        }
    }

    /// Verify the integrity of the entire receipt chain.
    /// Throws an error if any receipt has been tampered with.
    #[napi]
    pub fn verify_integrity(&self) -> Result<()> {
        self.inner.verify_integrity().map_err(to_napi_err)
    }

    /// Get the hash of the last receipt (or "genesis" if empty).
    #[napi(getter)]
    pub fn last_hash(&self) -> String {
        self.inner.last_hash()
    }

    /// Get the next sequence number.
    #[napi(getter)]
    pub fn next_sequence(&self) -> u32 {
        self.inner.next_sequence() as u32
    }

    /// Get the number of entries in the log.
    #[napi(getter)]
    pub fn length(&self) -> u32 {
        self.inner.len() as u32
    }

    /// Serialize the log to JSON string.
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self.inner.entries())
            .map_err(|e| napi::Error::from_reason(format!("Serialization error: {e}")))
    }
}

// ---------------------------------------------------------------------------
// AgentIdentity — High-level convenience class
// ---------------------------------------------------------------------------

/// High-level convenience class for creating agent identities.
///
/// Usage:
///   const identity = AgentIdentity.create("my-agent", "example.com");
///   console.log(identity.did);
#[napi]
pub struct AgentIdentity {
    did_str: String,
    keypair: RustKeyPair,
    aid_doc: AidDocument,
}

#[napi]
impl AgentIdentity {
    /// Create a new agent identity with a generated key pair.
    ///
    /// @param name - Agent name (lowercase alphanumeric + hyphens)
    /// @param domain - Domain namespace (default: "local.dev")
    /// @param controller - Controller DID (default: auto-generated)
    #[napi(factory)]
    pub fn create(
        name: String,
        domain: Option<String>,
        controller: Option<String>,
    ) -> Result<Self> {
        let domain = domain.unwrap_or_else(|| "local.dev".to_string());
        let keypair = RustKeyPair::generate();
        let did = format!("did:idprova:{domain}:{name}");
        let ctrl = controller.unwrap_or_else(|| format!("did:idprova:{domain}:controller"));

        let aid_doc = AidBuilder::new()
            .id(&did)
            .controller(&ctrl)
            .name(&name)
            .add_ed25519_key(&keypair)
            .trust_level("L0")
            .build()
            .map_err(to_napi_err)?;

        Ok(Self {
            did_str: did,
            keypair,
            aid_doc,
        })
    }

    /// Get the DID identifier.
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.did_str.clone()
    }

    /// Get the AID document.
    #[napi]
    pub fn aid(&self) -> AID {
        AID {
            inner: self.aid_doc.clone(),
        }
    }

    /// Get the key pair (for signing operations).
    #[napi]
    pub fn keypair(&self) -> KeyPair {
        KeyPair {
            inner: RustKeyPair::from_secret_bytes(self.keypair.secret_bytes()),
        }
    }

    /// Issue a delegation token to another agent.
    #[napi]
    pub fn issue_dat(
        &self,
        subject_did: String,
        scope: Vec<String>,
        expires_in_seconds: Option<i64>,
    ) -> Result<DAT> {
        let expires_in = expires_in_seconds.unwrap_or(3600);
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        RustDat::issue(
            &self.did_str,
            &subject_did,
            scope,
            expires_at,
            None,
            None,
            &self.keypair,
        )
        .map(|dat| DAT { inner: dat })
        .map_err(to_napi_err)
    }

    /// Get the public key bytes (32 bytes).
    #[napi(getter)]
    pub fn public_key_bytes(&self) -> Buffer {
        Buffer::from(self.keypair.public_key_bytes().to_vec())
    }
}
