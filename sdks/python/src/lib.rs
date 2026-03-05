// IDProva Python SDK — PyO3 bindings to idprova-core
//
// Security: Private keys NEVER cross the FFI boundary as raw bytes.
// The PyKeyPair holds the Rust KeyPair and exposes only sign()/verify()/public_key().

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use chrono::{Duration, Utc};
use idprova_core::aid::builder::AidBuilder;
use idprova_core::aid::document::AidDocument;
use idprova_core::crypto::hash::prefixed_blake3;
use idprova_core::crypto::KeyPair as RustKeyPair;
use idprova_core::dat::constraints::{
    DatConstraints as RustDatConstraints, EvaluationContext as RustEvaluationContext,
};
use idprova_core::dat::scope::Scope as RustScope;
use idprova_core::dat::token::Dat as RustDat;
use idprova_core::receipt::entry::{ActionDetails, ChainLink, Receipt, ReceiptContext};
use idprova_core::receipt::log::ReceiptLog as RustReceiptLog;
use idprova_core::trust::level::TrustLevel as RustTrustLevel;
use idprova_core::IdprovaError;
use std::path::PathBuf;

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
        IdprovaError::DatRevoked(_) => PyValueError::new_err(format!(
            "DatRevokedError: {}. Fix: The issuer must issue a new DAT.",
            e
        )),
        IdprovaError::VerificationFailed(_) => PyValueError::new_err(format!(
            "VerificationFailedError: {}. Fix: Ensure the correct public key is used.",
            e
        )),
        IdprovaError::ConstraintViolated(_) => PyValueError::new_err(format!(
            "ConstraintViolatedError: {}",
            e
        )),
        IdprovaError::ScopeNotPermitted(_) => PyValueError::new_err(format!(
            "ScopeNotPermittedError: {}",
            e
        )),
        IdprovaError::InvalidAid(_) | IdprovaError::AidValidation(_) => {
            PyValueError::new_err(format!("InvalidAidError: {}", e))
        }
        IdprovaError::InvalidDat(_) => PyValueError::new_err(format!("InvalidDatError: {}", e)),
        _ => PyRuntimeError::new_err(format!("IdprovaError: {}", e)),
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
    #[staticmethod]
    fn from_secret_bytes(secret: &[u8]) -> PyResult<Self> {
        if secret.len() != 32 {
            return Err(PyValueError::new_err("Secret key must be exactly 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret);
        Ok(Self {
            inner: RustKeyPair::from_secret_bytes(&bytes),
        })
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<bool> {
        let pub_bytes = self.inner.public_key_bytes();
        match RustKeyPair::verify(&pub_bytes, message, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[getter]
    fn public_key_multibase(&self) -> String {
        self.inner.public_key_multibase()
    }

    #[getter]
    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    fn __repr__(&self) -> String {
        format!("KeyPair(public_key='{}')", self.inner.public_key_multibase())
    }
}

// ---------------------------------------------------------------------------
// EvaluationContext — runtime values for constraint evaluation
// ---------------------------------------------------------------------------

/// Runtime context supplied to DAT.verify() for constraint evaluation.
///
/// Example:
///     ctx = EvaluationContext()
///     ctx.request_ip = "10.0.0.5"
///     ctx.agent_trust_level = 75
///     ctx.country_code = "AU"
///     dat.verify(pub_key_bytes, "mcp:tool:read", ctx)
#[pyclass]
#[derive(Clone, Default)]
struct EvaluationContext {
    /// Actions taken in the current rate-limit window.
    #[pyo3(get, set)]
    actions_in_window: u64,

    /// Request IP address string (IPv4 or IPv6).
    #[pyo3(get, set)]
    request_ip: Option<String>,

    /// Agent trust level (0–100).
    #[pyo3(get, set)]
    agent_trust_level: Option<u8>,

    /// Delegation chain depth (0 = root token).
    #[pyo3(get, set)]
    delegation_depth: u32,

    /// ISO 3166-1 alpha-2 country code.
    #[pyo3(get, set)]
    country_code: Option<String>,

    /// SHA-256 hex hash of the agent's current configuration.
    #[pyo3(get, set)]
    agent_config_hash: Option<String>,
}

#[pymethods]
impl EvaluationContext {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __repr__(&self) -> String {
        format!(
            "EvaluationContext(ip={:?}, trust={:?}, depth={}, country={:?})",
            self.request_ip, self.agent_trust_level, self.delegation_depth, self.country_code
        )
    }
}

impl EvaluationContext {
    fn to_rust(&self) -> RustEvaluationContext {
        RustEvaluationContext {
            actions_in_window: self.actions_in_window,
            request_ip: self.request_ip.as_deref().and_then(|s| s.parse().ok()),
            agent_trust_level: self.agent_trust_level,
            delegation_depth: self.delegation_depth,
            country_code: self.country_code.clone(),
            current_timestamp: None,
            agent_config_hash: self.agent_config_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// AID — Agent Identity Document
// ---------------------------------------------------------------------------

#[pyclass]
#[allow(clippy::upper_case_acronyms)]
struct AID {
    inner: AidDocument,
}

#[pymethods]
impl AID {
    #[getter]
    fn did(&self) -> &str {
        &self.inner.id
    }

    #[getter]
    fn controller(&self) -> &str {
        &self.inner.controller
    }

    #[getter]
    fn trust_level(&self) -> Option<&str> {
        self.inner.trust_level.as_deref()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {e}")))
    }

    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let doc: AidDocument = serde_json::from_str(json)
            .map_err(|e| PyValueError::new_err(format!("Invalid AID JSON: {e}")))?;
        doc.validate().map_err(to_py_err)?;
        Ok(Self { inner: doc })
    }

    fn validate(&self) -> PyResult<()> {
        self.inner.validate().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("AID(did='{}')", self.inner.id)
    }
}

// ---------------------------------------------------------------------------
// AIDBuilder
// ---------------------------------------------------------------------------

#[pyclass]
struct AIDBuilder {
    inner: AidBuilder,
}

#[pymethods]
impl AIDBuilder {
    #[new]
    fn new() -> Self {
        Self { inner: AidBuilder::new() }
    }

    fn id(&mut self, id: &str) {
        self.inner = std::mem::take(&mut self.inner).id(id);
    }

    fn controller(&mut self, controller: &str) {
        self.inner = std::mem::take(&mut self.inner).controller(controller);
    }

    fn name(&mut self, name: &str) {
        self.inner = std::mem::take(&mut self.inner).name(name);
    }

    fn description(&mut self, desc: &str) {
        self.inner = std::mem::take(&mut self.inner).description(desc);
    }

    fn model(&mut self, model: &str) {
        self.inner = std::mem::take(&mut self.inner).model(model);
    }

    fn runtime(&mut self, runtime: &str) {
        self.inner = std::mem::take(&mut self.inner).runtime(runtime);
    }

    fn trust_level(&mut self, level: &str) {
        self.inner = std::mem::take(&mut self.inner).trust_level(level);
    }

    fn add_ed25519_key(&mut self, keypair: &KeyPair) {
        self.inner = std::mem::take(&mut self.inner).add_ed25519_key(&keypair.inner);
    }

    fn build(&mut self) -> PyResult<AID> {
        let builder = std::mem::take(&mut self.inner);
        builder.build().map(|doc| AID { inner: doc }).map_err(to_py_err)
    }
}

// ---------------------------------------------------------------------------
// DAT — Delegation Attestation Token
// ---------------------------------------------------------------------------

/// A Delegation Attestation Token — signed, scoped, time-bounded permission grant.
///
/// Issue with DAT.issue(), verify with dat.verify(), parse with DAT.from_compact().
#[pyclass]
#[allow(clippy::upper_case_acronyms)]
struct DAT {
    inner: RustDat,
}

#[pymethods]
impl DAT {
    /// Issue a new DAT.
    ///
    /// Args:
    ///     issuer_did: DID of the delegator
    ///     subject_did: DID of the agent receiving delegation
    ///     scope: List of scope strings, e.g. ["mcp:tool:read"]
    ///     expires_in_seconds: TTL in seconds
    ///     signing_key: Issuer's KeyPair
    ///     max_actions: Optional lifetime action cap
    ///     require_receipt: Whether receipts are required per action
    ///     max_delegation_depth: Max re-delegation depth (0 = no re-delegation)
    ///     min_trust_level: Minimum agent trust level (0-100)
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        issuer_did, subject_did, scope, expires_in_seconds, signing_key,
        max_actions=None, require_receipt=None,
        max_delegation_depth=None, min_trust_level=None
    ))]
    fn issue(
        issuer_did: &str,
        subject_did: &str,
        scope: Vec<String>,
        expires_in_seconds: i64,
        signing_key: &KeyPair,
        max_actions: Option<u64>,
        require_receipt: Option<bool>,
        max_delegation_depth: Option<u32>,
        min_trust_level: Option<u8>,
    ) -> PyResult<Self> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        let has_constraints = max_actions.is_some()
            || require_receipt.is_some()
            || max_delegation_depth.is_some()
            || min_trust_level.is_some();

        let constraints = if has_constraints {
            Some(RustDatConstraints {
                max_actions,
                require_receipt,
                max_delegation_depth,
                min_trust_level,
                ..Default::default()
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

    /// Serialize to compact JWS format.
    fn to_compact(&self) -> PyResult<String> {
        self.inner.to_compact().map_err(to_py_err)
    }

    /// Parse from compact JWS string.
    #[staticmethod]
    fn from_compact(compact: &str) -> PyResult<Self> {
        RustDat::from_compact(compact)
            .map(|dat| Self { inner: dat })
            .map_err(to_py_err)
    }

    /// Full verification pipeline: sig + timing + scope + all constraints.
    ///
    /// Args:
    ///     public_key_bytes: 32-byte Ed25519 public key of the issuer
    ///     required_scope: Scope string to check (e.g. "mcp:tool:read"), or "" to skip
    ///     ctx: EvaluationContext with runtime values (optional, defaults to empty context)
    ///
    /// Raises ValueError on any verification failure.
    #[pyo3(signature = (public_key_bytes, required_scope="", ctx=None))]
    fn verify(
        &self,
        public_key_bytes: &[u8],
        required_scope: &str,
        ctx: Option<&EvaluationContext>,
    ) -> PyResult<()> {
        if public_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Public key must be exactly 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key_bytes);

        let default_ctx = EvaluationContext::default();
        let rust_ctx = ctx.unwrap_or(&default_ctx).to_rust();

        self.inner.verify(&key, required_scope, &rust_ctx).map_err(to_py_err)
    }

    /// Verify signature only (no scope/constraint checks).
    fn verify_signature(&self, public_key_bytes: &[u8]) -> PyResult<bool> {
        if public_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Public key must be exactly 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key_bytes);
        match self.inner.verify_signature(&key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn validate_timing(&self) -> PyResult<()> {
        self.inner.validate_timing().map_err(to_py_err)
    }

    #[getter]
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.claims.iss
    }

    #[getter]
    fn subject(&self) -> &str {
        &self.inner.claims.sub
    }

    #[getter]
    fn jti(&self) -> &str {
        &self.inner.claims.jti
    }

    #[getter]
    fn scope(&self) -> Vec<String> {
        self.inner.claims.scope.clone()
    }

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
// Scope
// ---------------------------------------------------------------------------

#[pyclass]
struct Scope {
    inner: RustScope,
}

#[pymethods]
impl Scope {
    #[new]
    fn new(scope_str: &str) -> PyResult<Self> {
        RustScope::parse(scope_str).map(|s| Self { inner: s }).map_err(to_py_err)
    }

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

#[pyclass]
#[derive(Clone)]
struct TrustLevel {
    inner: RustTrustLevel,
}

#[pymethods]
impl TrustLevel {
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

    fn meets_minimum(&self, required: &TrustLevel) -> bool {
        self.inner.meets_minimum(required.inner)
    }

    #[getter]
    fn description(&self) -> &str {
        self.inner.description()
    }

    fn __str__(&self) -> String {
        self.inner.as_str().to_string()
    }

    fn __repr__(&self) -> String {
        format!("TrustLevel('{}' — {})", self.inner.as_str(), self.inner.description())
    }
}

// ---------------------------------------------------------------------------
// ReceiptLog
// ---------------------------------------------------------------------------

#[pyclass]
struct ReceiptLog {
    inner: RustReceiptLog,
}

#[pymethods]
impl ReceiptLog {
    #[new]
    fn new() -> Self {
        Self { inner: RustReceiptLog::new() }
    }

    fn verify_integrity(&self) -> PyResult<()> {
        self.inner.verify_integrity().map_err(to_py_err)
    }

    #[getter]
    fn last_hash(&self) -> String {
        self.inner.last_hash()
    }

    #[getter]
    fn next_sequence(&self) -> u64 {
        self.inner.next_sequence()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Append a new receipt to the log.
    ///
    /// Constructs a signed, hash-chained receipt from the provided action details.
    /// The receipt is automatically linked to the previous entry in the chain.
    ///
    /// Args:
    ///     agent_did: DID of the agent performing the action
    ///     dat_jti: JTI of the DAT authorizing the action
    ///     action_type: Action type string (e.g., "mcp:tool-call")
    ///     input_data: Input data bytes (hashed with BLAKE3, not stored raw)
    ///     signing_key: Agent's KeyPair for signing the receipt
    ///     server: Optional target server hostname
    ///     tool: Optional tool/method name
    ///     output_data: Optional output data bytes (hashed with BLAKE3)
    ///     status: Action status (default: "success")
    ///     duration_ms: Optional duration in milliseconds
    ///     session_id: Optional session identifier
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        agent_did, dat_jti, action_type, input_data, signing_key,
        server=None, tool=None, output_data=None,
        status="success", duration_ms=None, session_id=None
    ))]
    fn append(
        &mut self,
        agent_did: &str,
        dat_jti: &str,
        action_type: &str,
        input_data: &[u8],
        signing_key: &KeyPair,
        server: Option<String>,
        tool: Option<String>,
        output_data: Option<&[u8]>,
        status: &str,
        duration_ms: Option<u64>,
        session_id: Option<String>,
    ) -> PyResult<()> {
        let receipt_id = ulid::Ulid::new().to_string();
        let prev_hash = self.inner.last_hash();
        let seq = self.inner.next_sequence();

        let action = ActionDetails {
            action_type: action_type.to_string(),
            server,
            tool,
            input_hash: prefixed_blake3(input_data),
            output_hash: output_data.map(prefixed_blake3),
            status: status.to_string(),
            duration_ms,
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

        // Build receipt with empty signature, serialize, sign, then fill signature
        let mut receipt = Receipt {
            id: receipt_id,
            timestamp: Utc::now(),
            agent: agent_did.to_string(),
            dat: dat_jti.to_string(),
            action,
            context,
            chain,
            signature: String::new(),
        };

        let canonical = serde_json::to_vec(&receipt)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {e}")))?;
        let sig_bytes = signing_key.inner.sign(&canonical);
        receipt.signature = hex::encode(sig_bytes);

        self.inner.append(receipt);
        Ok(())
    }

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
// AgentIdentity — high-level convenience API
// ---------------------------------------------------------------------------

#[pyclass]
struct AgentIdentity {
    #[pyo3(get)]
    did: String,
    keypair: RustKeyPair,
    aid: AidDocument,
}

#[pymethods]
impl AgentIdentity {
    #[staticmethod]
    #[pyo3(signature = (name, domain="local.dev", controller=None))]
    fn create(name: &str, domain: &str, controller: Option<&str>) -> PyResult<Self> {
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

        Ok(Self { did, keypair, aid })
    }

    fn aid(&self) -> AID {
        AID { inner: self.aid.clone() }
    }

    fn keypair(&self) -> KeyPair {
        KeyPair { inner: RustKeyPair::from_secret_bytes(self.keypair.secret_bytes()) }
    }

    #[pyo3(signature = (subject_did, scope, expires_in_seconds=3600))]
    fn issue_dat(
        &self,
        subject_did: &str,
        scope: Vec<String>,
        expires_in_seconds: i64,
    ) -> PyResult<DAT> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);
        RustDat::issue(&self.did, subject_did, scope, expires_at, None, None, &self.keypair)
            .map(|dat| DAT { inner: dat })
            .map_err(to_py_err)
    }

    /// Save this identity to disk.
    ///
    /// Creates a directory containing the private key, AID document, and metadata.
    /// The private key file has restrictive permissions (0600 on Unix).
    ///
    /// Args:
    ///     path: Directory path. Defaults to ~/.idprova/identities/{name}/
    #[pyo3(signature = (path=None))]
    fn save(&self, path: Option<String>) -> PyResult<()> {
        let dir = match path {
            Some(p) => expand_home(&p),
            None => {
                let name = self.did.rsplit(':').next().unwrap_or("agent");
                default_identity_dir(name)
            }
        };

        std::fs::create_dir_all(&dir)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create directory: {e}")))?;

        // Save secret key (hex-encoded)
        let key_path = dir.join("secret.key");
        let secret_hex = hex::encode(self.keypair.secret_bytes());
        std::fs::write(&key_path, &secret_hex)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to write key: {e}")))?;

        // Restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to set permissions: {e}")))?;
        }

        // Save AID document
        let aid_json = serde_json::to_string_pretty(&self.aid)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {e}")))?;
        std::fs::write(dir.join("aid.json"), &aid_json)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to write AID: {e}")))?;

        // Save metadata
        let metadata = serde_json::json!({
            "version": 1,
            "did": self.did,
            "created": Utc::now().to_rfc3339(),
        });
        std::fs::write(
            dir.join("identity.json"),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to write metadata: {e}")))?;

        Ok(())
    }

    /// Load an identity from disk.
    ///
    /// Args:
    ///     path: Directory containing secret.key and aid.json
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        let dir = expand_home(path);

        // Read secret key
        let secret_hex = std::fs::read_to_string(dir.join("secret.key"))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to read key: {e}")))?;
        let secret_bytes = hex::decode(secret_hex.trim())
            .map_err(|e| PyValueError::new_err(format!("Invalid key hex: {e}")))?;
        if secret_bytes.len() != 32 {
            return Err(PyValueError::new_err("Secret key must be 32 bytes"));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&secret_bytes);
        let keypair = RustKeyPair::from_secret_bytes(&key_arr);

        // Read AID document
        let aid_json = std::fs::read_to_string(dir.join("aid.json"))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to read AID: {e}")))?;
        let aid: AidDocument = serde_json::from_str(&aid_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid AID JSON: {e}")))?;
        aid.validate().map_err(to_py_err)?;

        let did = aid.id.clone();
        Ok(Self { did, keypair, aid })
    }

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
#[pymodule]
fn idprova(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<KeyPair>()?;
    m.add_class::<EvaluationContext>()?;
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
