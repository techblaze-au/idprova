// IDProva Python SDK — PyO3 bindings to idprova-core
//
// Security: Private keys NEVER cross the FFI boundary as raw bytes.
// The PyKeyPair holds the Rust KeyPair and exposes only sign()/verify()/public_key().

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

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
// Error mapping — IdprovaError → Python exceptions
// ---------------------------------------------------------------------------

fn to_py_err(e: IdprovaError) -> PyErr {
    match &e {
        IdprovaError::DatExpired => PyValueError::new_err(format!(
            "DatExpiredError: {}. Fix: Issue a new DAT with a later expiration.",
            e
        )),
        IdprovaError::DatNotYetValid => PyValueError::new_err(format!(
            "DatNotYetValidError: {}. Fix: Check system clock or wait until the nbf time.",
            e
        )),
        IdprovaError::VerificationFailed(_) => PyValueError::new_err(format!(
            "VerificationFailedError: {}. Fix: Ensure the correct public key is used.",
            e
        )),
        IdprovaError::InvalidAid(_) | IdprovaError::AidValidation(_) => {
            PyValueError::new_err(format!("InvalidAidError: {}", e))
        }
        IdprovaError::InvalidDat(_) => {
            PyValueError::new_err(format!("InvalidDatError: {}", e))
        }
        _ => PyRuntimeError::new_err(format!("IdprovaError: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// KeyPair — Ed25519 key pair (private key stays in Rust)
// ---------------------------------------------------------------------------

/// An Ed25519 key pair for signing and verification.
///
/// The private key is held securely in Rust memory and never exposed to Python.
/// Use `sign()` to create signatures and `verify()` for verification.
#[pyclass]
struct KeyPair {
    inner: RustKeyPair,
}

#[pymethods]
impl KeyPair {
    /// Generate a new random Ed25519 key pair.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        Ok(Self {
            inner: RustKeyPair::generate(),
        })
    }

    /// Create a key pair from secret key bytes (32 bytes).
    ///
    /// WARNING: Only use for loading previously saved keys.
    /// Prefer generate() for new keys.
    #[staticmethod]
    fn from_secret_bytes(secret: &[u8]) -> PyResult<Self> {
        if secret.len() != 32 {
            return Err(PyValueError::new_err(
                "Secret key must be exactly 32 bytes",
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret);
        Ok(Self {
            inner: RustKeyPair::from_secret_bytes(&bytes),
        })
    }

    /// Sign a message and return the signature as bytes.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message)
    }

    /// Verify a signature against a message using this key pair's public key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<bool> {
        let pub_bytes = self.inner.public_key_bytes();
        match RustKeyPair::verify(&pub_bytes, message, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the public key in multibase encoding (z-prefixed base58btc).
    #[getter]
    fn public_key_multibase(&self) -> String {
        self.inner.public_key_multibase()
    }

    /// Get the raw public key bytes (32 bytes).
    #[getter]
    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyPair(public_key='{}')",
            self.inner.public_key_multibase()
        )
    }
}

// ---------------------------------------------------------------------------
// AID — Agent Identity Document
// ---------------------------------------------------------------------------

/// An IDProva Agent Identity Document (W3C DID Document).
///
/// Create with AIDBuilder or parse from JSON.
#[pyclass]
#[allow(clippy::upper_case_acronyms)]
struct AID {
    inner: AidDocument,
}

#[pymethods]
impl AID {
    /// Get the DID identifier (e.g., "did:idprova:example.com:my-agent").
    #[getter]
    fn did(&self) -> &str {
        &self.inner.id
    }

    /// Get the controller DID.
    #[getter]
    fn controller(&self) -> &str {
        &self.inner.controller
    }

    /// Get the trust level string (e.g., "L0", "L1").
    #[getter]
    fn trust_level(&self) -> Option<&str> {
        self.inner.trust_level.as_deref()
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {e}")))
    }

    /// Parse from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let doc: AidDocument = serde_json::from_str(json)
            .map_err(|e| PyValueError::new_err(format!("Invalid AID JSON: {e}")))?;
        doc.validate().map_err(to_py_err)?;
        Ok(Self { inner: doc })
    }

    /// Validate the document structure.
    fn validate(&self) -> PyResult<()> {
        self.inner.validate().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("AID(did='{}')", self.inner.id)
    }
}

// ---------------------------------------------------------------------------
// AIDBuilder — Fluent builder for AID documents
// ---------------------------------------------------------------------------

/// Builder for creating Agent Identity Documents.
///
/// Example:
///     builder = AIDBuilder()
///     builder.id("did:idprova:example.com:my-agent")
///     builder.controller("did:idprova:example.com:alice")
///     builder.name("My Agent")
///     builder.add_ed25519_key(keypair)
///     aid = builder.build()
#[pyclass]
struct AIDBuilder {
    inner: AidBuilder,
}

#[pymethods]
impl AIDBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: AidBuilder::new(),
        }
    }

    /// Set the DID identifier.
    fn id(&mut self, id: &str) {
        self.inner = std::mem::take(&mut self.inner).id(id);
    }

    /// Set the controller DID.
    fn controller(&mut self, controller: &str) {
        self.inner = std::mem::take(&mut self.inner).controller(controller);
    }

    /// Set the human-readable agent name.
    fn name(&mut self, name: &str) {
        self.inner = std::mem::take(&mut self.inner).name(name);
    }

    /// Set an optional description.
    fn description(&mut self, desc: &str) {
        self.inner = std::mem::take(&mut self.inner).description(desc);
    }

    /// Set the AI model identifier.
    fn model(&mut self, model: &str) {
        self.inner = std::mem::take(&mut self.inner).model(model);
    }

    /// Set the runtime environment.
    fn runtime(&mut self, runtime: &str) {
        self.inner = std::mem::take(&mut self.inner).runtime(runtime);
    }

    /// Set the trust level (e.g., "L0", "L1").
    fn trust_level(&mut self, level: &str) {
        self.inner = std::mem::take(&mut self.inner).trust_level(level);
    }

    /// Add an Ed25519 verification key from a KeyPair.
    fn add_ed25519_key(&mut self, keypair: &KeyPair) {
        self.inner = std::mem::take(&mut self.inner).add_ed25519_key(&keypair.inner);
    }

    /// Build and validate the AID document.
    fn build(&mut self) -> PyResult<AID> {
        let builder = std::mem::take(&mut self.inner);
        builder
            .build()
            .map(|doc| AID { inner: doc })
            .map_err(to_py_err)
    }
}

// ---------------------------------------------------------------------------
// DAT — Delegation Attestation Token
// ---------------------------------------------------------------------------

/// A Delegation Attestation Token — signed, scoped, time-bounded permission grant.
///
/// Issue with DAT.issue(), parse with DAT.from_compact().
#[pyclass]
#[allow(clippy::upper_case_acronyms)]
struct DAT {
    inner: RustDat,
}

#[pymethods]
impl DAT {
    /// Issue a new DAT signed by the issuer's key pair.
    ///
    /// Args:
    ///     issuer_did: The DID of the delegator
    ///     subject_did: The DID of the agent receiving delegation
    ///     scope: List of scope strings (e.g., ["mcp:tool:read"])
    ///     expires_in_seconds: Seconds until expiration
    ///     signing_key: The issuer's KeyPair
    ///     max_actions: Optional max number of actions
    ///     require_receipt: Whether action receipts are required
    #[staticmethod]
    #[pyo3(signature = (issuer_did, subject_did, scope, expires_in_seconds, signing_key, max_actions=None, require_receipt=None))]
    fn issue(
        issuer_did: &str,
        subject_did: &str,
        scope: Vec<String>,
        expires_in_seconds: i64,
        signing_key: &KeyPair,
        max_actions: Option<u64>,
        require_receipt: Option<bool>,
    ) -> PyResult<Self> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        let constraints = if max_actions.is_some() || require_receipt.is_some() {
            Some(RustDatConstraints {
                max_actions,
                allowed_servers: None,
                require_receipt,
            })
        } else {
            None
        };

        RustDat::issue(
            issuer_did,
            subject_did,
            scope,
            expires_at,
            constraints,
            None,
            &signing_key.inner,
        )
        .map(|dat| Self { inner: dat })
        .map_err(to_py_err)
    }

    /// Serialize to compact JWS format (header.payload.signature).
    fn to_compact(&self) -> PyResult<String> {
        self.inner.to_compact().map_err(to_py_err)
    }

    /// Parse from compact JWS string (validates algorithm).
    #[staticmethod]
    fn from_compact(compact: &str) -> PyResult<Self> {
        RustDat::from_compact(compact)
            .map(|dat| Self { inner: dat })
            .map_err(to_py_err)
    }

    /// Verify the DAT signature against a public key (32 bytes).
    fn verify_signature(&self, public_key_bytes: &[u8]) -> PyResult<bool> {
        if public_key_bytes.len() != 32 {
            return Err(PyValueError::new_err(
                "Public key must be exactly 32 bytes",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key_bytes);
        match self.inner.verify_signature(&key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Validate timing constraints (not expired, not before valid).
    fn validate_timing(&self) -> PyResult<()> {
        self.inner.validate_timing().map_err(to_py_err)
    }

    /// Check if the DAT is expired.
    #[getter]
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Get the issuer DID.
    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.claims.iss
    }

    /// Get the subject DID.
    #[getter]
    fn subject(&self) -> &str {
        &self.inner.claims.sub
    }

    /// Get the token ID (jti).
    #[getter]
    fn jti(&self) -> &str {
        &self.inner.claims.jti
    }

    /// Get the granted scopes as a list of strings.
    #[getter]
    fn scope(&self) -> Vec<String> {
        self.inner.claims.scope.clone()
    }

    /// Get the expiration timestamp (Unix seconds).
    #[getter]
    fn expires_at(&self) -> i64 {
        self.inner.claims.exp
    }

    fn __repr__(&self) -> String {
        format!(
            "DAT(issuer='{}', subject='{}', jti='{}', expired={})",
            self.inner.claims.iss,
            self.inner.claims.sub,
            self.inner.claims.jti,
            self.inner.is_expired()
        )
    }
}

// ---------------------------------------------------------------------------
// Scope — Permission scope
// ---------------------------------------------------------------------------

/// A permission scope in namespace:resource:action format.
#[pyclass]
struct Scope {
    inner: RustScope,
}

#[pymethods]
impl Scope {
    /// Parse a scope string (e.g., "mcp:tool:read").
    #[new]
    fn new(scope_str: &str) -> PyResult<Self> {
        RustScope::parse(scope_str)
            .map(|s| Self { inner: s })
            .map_err(to_py_err)
    }

    /// Check if this scope covers (permits) the requested scope.
    fn covers(&self, requested: &Scope) -> bool {
        self.inner.covers(&requested.inner)
    }

    fn __str__(&self) -> String {
        self.inner.to_string_repr()
    }

    fn __repr__(&self) -> String {
        format!("Scope('{}')", self.inner.to_string_repr())
    }
}

// ---------------------------------------------------------------------------
// TrustLevel
// ---------------------------------------------------------------------------

/// Trust level for an agent identity (L0 through L4).
#[pyclass]
#[derive(Clone)]
struct TrustLevel {
    inner: RustTrustLevel,
}

#[pymethods]
impl TrustLevel {
    /// Parse a trust level string (e.g., "L0", "L1", "L2", "L3", "L4").
    #[new]
    fn new(level: &str) -> PyResult<Self> {
        RustTrustLevel::from_str_repr(level)
            .map(|tl| Self { inner: tl })
            .ok_or_else(|| {
                PyValueError::new_err(format!(
                    "Invalid trust level '{}'. Must be L0, L1, L2, L3, or L4.",
                    level
                ))
            })
    }

    /// Check if this trust level meets the required minimum.
    fn meets_minimum(&self, required: &TrustLevel) -> bool {
        self.inner.meets_minimum(required.inner)
    }

    /// Get a human-readable description of this trust level.
    #[getter]
    fn description(&self) -> &str {
        self.inner.description()
    }

    fn __str__(&self) -> String {
        self.inner.as_str().to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustLevel('{}' — {})",
            self.inner.as_str(),
            self.inner.description()
        )
    }
}

// ---------------------------------------------------------------------------
// ReceiptLog — Append-only, hash-chained audit log
// ---------------------------------------------------------------------------

/// An append-only, hash-chained audit receipt log.
///
/// Provides tamper-evident logging of agent actions.
#[pyclass]
struct ReceiptLog {
    inner: RustReceiptLog,
}

#[pymethods]
impl ReceiptLog {
    /// Create a new empty receipt log.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustReceiptLog::new(),
        }
    }

    /// Verify the integrity of the entire receipt chain.
    /// Raises an error if any receipt has been tampered with.
    fn verify_integrity(&self) -> PyResult<()> {
        self.inner.verify_integrity().map_err(to_py_err)
    }

    /// Get the hash of the last receipt (or "genesis" if empty).
    #[getter]
    fn last_hash(&self) -> String {
        self.inner.last_hash()
    }

    /// Get the next sequence number.
    #[getter]
    fn next_sequence(&self) -> u64 {
        self.inner.next_sequence()
    }

    /// Get the number of entries in the log.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Serialize the log to JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(self.inner.entries())
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {e}")))
    }

    fn __repr__(&self) -> String {
        format!(
            "ReceiptLog(entries={}, last_hash='{}')",
            self.inner.len(),
            self.inner.last_hash()
        )
    }
}

// ---------------------------------------------------------------------------
// Convenience: AgentIdentity — high-level API
// ---------------------------------------------------------------------------

/// High-level convenience class for creating agent identities.
///
/// Example:
///     identity = AgentIdentity.create("my-agent", domain="example.com")
///     print(identity.did)
#[pyclass]
struct AgentIdentity {
    #[pyo3(get)]
    did: String,
    keypair: RustKeyPair,
    aid: AidDocument,
}

#[pymethods]
impl AgentIdentity {
    /// Create a new agent identity with a generated key pair.
    ///
    /// Args:
    ///     name: Agent name (lowercase alphanumeric + hyphens)
    ///     domain: Domain namespace (default: "local.dev")
    ///     controller: Controller DID (default: auto-generated)
    #[staticmethod]
    #[pyo3(signature = (name, domain="local.dev", controller=None))]
    fn create(
        name: &str,
        domain: &str,
        controller: Option<&str>,
    ) -> PyResult<Self> {
        let keypair = RustKeyPair::generate();
        let did = format!("did:idprova:{domain}:{name}");
        let ctrl = controller
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("did:idprova:{domain}:controller"));

        let aid = AidBuilder::new()
            .id(&did)
            .controller(&ctrl)
            .name(name)
            .add_ed25519_key(&keypair)
            .trust_level("L0")
            .build()
            .map_err(to_py_err)?;

        Ok(Self {
            did,
            keypair,
            aid,
        })
    }

    /// Get the AID document.
    fn aid(&self) -> AID {
        AID {
            inner: self.aid.clone(),
        }
    }

    /// Get the key pair (for signing operations).
    fn keypair(&self) -> KeyPair {
        // Clone the keypair — the original stays in AgentIdentity
        KeyPair {
            inner: RustKeyPair::from_secret_bytes(self.keypair.secret_bytes()),
        }
    }

    /// Issue a delegation token to another agent.
    #[pyo3(signature = (subject_did, scope, expires_in_seconds=3600))]
    fn issue_dat(
        &self,
        subject_did: &str,
        scope: Vec<String>,
        expires_in_seconds: i64,
    ) -> PyResult<DAT> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);
        RustDat::issue(
            &self.did,
            subject_did,
            scope,
            expires_at,
            None,
            None,
            &self.keypair,
        )
        .map(|dat| DAT { inner: dat })
        .map_err(to_py_err)
    }

    /// Get the public key bytes (32 bytes).
    #[getter]
    fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public_key_bytes().to_vec()
    }

    fn __repr__(&self) -> String {
        format!("AgentIdentity(did='{}')", self.did)
    }
}

// ---------------------------------------------------------------------------
// Python module
// ---------------------------------------------------------------------------

/// IDProva — Verifiable identity for the agent era.
///
/// This module provides Ed25519-based agent identity, scoped delegation tokens,
/// and hash-chained audit receipts for AI agent systems.
#[pymodule]
fn idprova(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<KeyPair>()?;
    m.add_class::<AID>()?;
    m.add_class::<AIDBuilder>()?;
    m.add_class::<DAT>()?;
    m.add_class::<Scope>()?;
    m.add_class::<TrustLevel>()?;
    m.add_class::<ReceiptLog>()?;
    m.add_class::<AgentIdentity>()?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
