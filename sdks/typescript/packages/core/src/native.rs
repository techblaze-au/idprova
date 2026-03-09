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
use idprova_core::crypto::hash::prefixed_blake3;
use idprova_core::crypto::KeyPair as RustKeyPair;
use idprova_core::dat::scope::Scope as RustScope;
use idprova_core::dat::DatConstraints as RustDatConstraints;
use idprova_core::policy::EvaluationContext as RustEvaluationContext;
use idprova_core::dat::token::Dat as RustDat;
use idprova_core::receipt::entry::{ActionDetails, ChainLink, Receipt, ReceiptContext};
use idprova_core::receipt::log::ReceiptLog as RustReceiptLog;
use idprova_core::trust::level::TrustLevel as RustTrustLevel;
use idprova_core::IdprovaError;
use std::path::PathBuf;

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
        IdprovaError::InvalidDat(_) => napi::Error::from_reason(format!("InvalidDatError: {}", e)),
        IdprovaError::DatRevoked(_) => napi::Error::from_reason(format!(
            "DatRevokedError: {}. Fix: The token has been explicitly revoked.",
            e
        )),
        IdprovaError::ConstraintViolated(_) => napi::Error::from_reason(format!(
            "ConstraintViolatedError: {}. Fix: Check the DAT constraints against the request context.",
            e
        )),
        IdprovaError::ScopeNotPermitted(_) => napi::Error::from_reason(format!(
            "ScopeNotPermittedError: {}. Fix: Request a token with the required scope.",
            e
        )),
        _ => napi::Error::from_reason(format!("IdprovaError: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn expand_home(path: &str) -> PathBuf {
    if path.starts_with('~') {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(path.replacen('~', &home, 1))
    } else {
        PathBuf::from(path)
    }
}

fn default_identity_dir(name: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".idprova")
        .join("identities")
        .join(name)
}

// ---------------------------------------------------------------------------
// EvaluationContext — Runtime context for constraint evaluation
// ---------------------------------------------------------------------------

/// Runtime context passed to DAT.verify() for constraint evaluation.
///
/// All fields are optional — only populate what you need for your constraints.
#[napi]
pub struct EvaluationContext {
    /// Number of actions already taken in the current rate-limit window.
    pub actions_in_window: i64,
    /// Request IP address string (IPv4 or IPv6).
    pub request_ip: Option<String>,
    /// Agent trust level (0–100).
    pub agent_trust_level: Option<u8>,
    /// Delegation depth in the current chain.
    pub delegation_depth: u32,
    /// ISO 3166-1 alpha-2 country code of the request origin.
    pub country_code: Option<String>,
    /// SHA-256 hex hash of the agent's current configuration.
    pub agent_config_hash: Option<String>,
}

#[napi]
#[allow(clippy::new_without_default)]
impl EvaluationContext {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            actions_in_window: 0,
            request_ip: None,
            agent_trust_level: None,
            delegation_depth: 0,
            country_code: None,
            agent_config_hash: None,
        }
    }

    fn to_rust(&self, scope: &str) -> RustEvaluationContext {
        let mut builder = RustEvaluationContext::builder(scope)
            .actions_this_hour(self.actions_in_window as u64)
            .delegation_depth(self.delegation_depth);
        if let Some(ref ip_str) = self.request_ip {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                builder = builder.source_ip(ip);
            }
        }
        if let Some(ref cc) = self.country_code {
            builder = builder.source_country(cc.clone());
        }
        if let Some(ref hash) = self.agent_config_hash {
            builder = builder.caller_config_attestation(hash.clone());
        }
        builder.build()
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
#[allow(clippy::new_without_default)]
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
                require_receipt,
                ..Default::default()
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

    /// Full verification pipeline: signature → timing → scope → constraints.
    ///
    /// @param publicKeyBytes - 32-byte Ed25519 public key of the issuer
    /// @param requiredScope - scope string to check (e.g. "mcp:tool:read"), or "" to skip
    /// @param ctx - optional EvaluationContext for constraint evaluation
    #[napi]
    pub fn verify(
        &self,
        public_key_bytes: Buffer,
        required_scope: Option<String>,
        ctx: Option<&EvaluationContext>,
    ) -> Result<()> {
        let bytes = public_key_bytes.as_ref();
        if bytes.len() != 32 {
            return Err(napi::Error::from_reason("Public key must be exactly 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        let scope = required_scope.as_deref().unwrap_or("");
        let default_ctx = EvaluationContext::new();
        let rust_ctx = ctx.unwrap_or(&default_ctx).to_rust(scope);
        {
            self.inner.verify_signature(&key).map_err(to_napi_err)?;
            let evaluator = idprova_core::policy::PolicyEvaluator::new();
            let decision = evaluator.evaluate(&self.inner, &rust_ctx);
            if decision.is_allowed() {
                Ok(())
            } else {
                let reason = decision.denial_reason().map(|r| format!("{:?}", r)).unwrap_or_default();
                Err(napi::Error::from_reason(reason))
            }
        }
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
#[allow(clippy::new_without_default)]
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

    /// Append a new receipt to the log.
    ///
    /// Constructs a signed, hash-chained receipt from the provided action details.
    ///
    /// @param agentDid - DID of the agent performing the action
    /// @param datJti - JTI of the DAT authorizing the action
    /// @param actionType - Action type string (e.g., "mcp:tool-call")
    /// @param inputData - Input data (hashed with BLAKE3, not stored raw)
    /// @param signingKey - Agent's KeyPair for signing
    /// @param server - Optional target server hostname
    /// @param tool - Optional tool/method name
    /// @param outputData - Optional output data (hashed with BLAKE3)
    /// @param status - Action status (default: "success")
    /// @param durationMs - Optional duration in milliseconds
    /// @param sessionId - Optional session identifier
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        agent_did: String,
        dat_jti: String,
        action_type: String,
        input_data: Buffer,
        signing_key: &KeyPair,
        server: Option<String>,
        tool: Option<String>,
        output_data: Option<Buffer>,
        status: Option<String>,
        duration_ms: Option<u32>,
        session_id: Option<String>,
    ) -> Result<()> {
        let receipt_id = ulid::Ulid::new().to_string();
        let prev_hash = self.inner.last_hash();
        let seq = self.inner.next_sequence();

        let action = ActionDetails {
            action_type,
            server,
            tool,
            input_hash: prefixed_blake3(input_data.as_ref()),
            output_hash: output_data.as_ref().map(|d| prefixed_blake3(d.as_ref())),
            status: status.unwrap_or_else(|| "success".to_string()),
            duration_ms: duration_ms.map(|d| d as u64),
        };

        let context = session_id.map(|sid| ReceiptContext {
            session_id: Some(sid),
            parent_receipt_id: None,
            request_id: None,
        });

        let chain = ChainLink {
            previous_hash: prev_hash,
            sequence_number: seq,
        };

        let mut receipt = Receipt {
            id: receipt_id,
            timestamp: Utc::now(),
            agent: agent_did,
            dat: dat_jti,
            action,
            context,
            chain,
            signature: String::new(),
        };

        let canonical = serde_json::to_vec(&receipt)
            .map_err(|e| napi::Error::from_reason(format!("Serialization error: {e}")))?;
        let sig_bytes = signing_key.inner.sign(&canonical);
        receipt.signature = hex::encode(sig_bytes);

        self.inner.append(receipt);
        Ok(())
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

    /// Save this identity to disk.
    ///
    /// Creates a directory containing the private key, AID document, and metadata.
    /// The private key file has restrictive permissions (0600 on Unix).
    ///
    /// @param path - Directory path. Defaults to ~/.idprova/identities/{name}/
    #[napi]
    pub fn save(&self, path: Option<String>) -> Result<()> {
        let dir = match path {
            Some(p) => expand_home(&p),
            None => {
                let name = self.did_str.rsplit(':').next().unwrap_or("agent");
                default_identity_dir(name)
            }
        };

        std::fs::create_dir_all(&dir)
            .map_err(|e| napi::Error::from_reason(format!("Failed to create directory: {e}")))?;

        // Save secret key (hex-encoded)
        let key_path = dir.join("secret.key");
        let secret_hex = hex::encode(self.keypair.secret_bytes());
        std::fs::write(&key_path, &secret_hex)
            .map_err(|e| napi::Error::from_reason(format!("Failed to write key: {e}")))?;

        // Restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| napi::Error::from_reason(format!("Failed to set permissions: {e}")))?;
        }

        // Save AID document
        let aid_json = serde_json::to_string_pretty(&self.aid_doc)
            .map_err(|e| napi::Error::from_reason(format!("Serialization error: {e}")))?;
        std::fs::write(dir.join("aid.json"), &aid_json)
            .map_err(|e| napi::Error::from_reason(format!("Failed to write AID: {e}")))?;

        // Save metadata
        let metadata = serde_json::json!({
            "version": 1,
            "did": self.did_str,
            "created": Utc::now().to_rfc3339(),
        });
        std::fs::write(
            dir.join("identity.json"),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .map_err(|e| napi::Error::from_reason(format!("Failed to write metadata: {e}")))?;

        Ok(())
    }

    /// Load an identity from disk.
    ///
    /// @param path - Directory containing secret.key and aid.json
    #[napi(factory)]
    pub fn load(path: String) -> Result<Self> {
        let dir = expand_home(&path);

        // Read secret key
        let secret_hex = std::fs::read_to_string(dir.join("secret.key"))
            .map_err(|e| napi::Error::from_reason(format!("Failed to read key: {e}")))?;
        let secret_bytes = hex::decode(secret_hex.trim())
            .map_err(|e| napi::Error::from_reason(format!("Invalid key hex: {e}")))?;
        if secret_bytes.len() != 32 {
            return Err(napi::Error::from_reason("Secret key must be 32 bytes"));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&secret_bytes);
        let keypair = RustKeyPair::from_secret_bytes(&key_arr);

        // Read AID document
        let aid_json = std::fs::read_to_string(dir.join("aid.json"))
            .map_err(|e| napi::Error::from_reason(format!("Failed to read AID: {e}")))?;
        let aid_doc: AidDocument = serde_json::from_str(&aid_json)
            .map_err(|e| napi::Error::from_reason(format!("Invalid AID JSON: {e}")))?;
        aid_doc.validate().map_err(to_napi_err)?;

        let did_str = aid_doc.id.clone();
        Ok(Self {
            did_str,
            keypair,
            aid_doc,
        })
    }

    /// Get the public key bytes (32 bytes).
    #[napi(getter)]
    pub fn public_key_bytes(&self) -> Buffer {
        Buffer::from(self.keypair.public_key_bytes().to_vec())
    }
}
