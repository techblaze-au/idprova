use thiserror::Error;

/// Result type alias for IDProva operations.
pub type Result<T> = std::result::Result<T, IdprovaError>;

/// Errors that can occur in IDProva operations.
#[derive(Debug, Error)]
pub enum IdprovaError {
    // Crypto errors
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    // AID errors
    #[error("invalid AID identifier: {0}")]
    InvalidAid(String),

    #[error("AID document validation failed: {0}")]
    AidValidation(String),

    #[error("AID not found: {0}")]
    AidNotFound(String),

    // DAT errors
    #[error("invalid DAT: {0}")]
    InvalidDat(String),

    #[error("DAT expired")]
    DatExpired,

    #[error("DAT not yet valid")]
    DatNotYetValid,

    #[error("scope not permitted: {0}")]
    ScopeNotPermitted(String),

    #[error("constraint violated: {0}")]
    ConstraintViolated(String),

    #[error("delegation chain invalid: {0}")]
    InvalidDelegationChain(String),

    // Receipt errors
    #[error("receipt chain integrity violation at sequence {0}")]
    ReceiptChainBroken(u64),

    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),

    // Trust errors
    #[error("trust verification failed for level {0}: {1}")]
    TrustVerification(String, String),

    // Serialization
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // Base64
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    // Generic
    #[error("{0}")]
    Other(String),
}
