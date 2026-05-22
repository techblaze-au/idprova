//! Crate-level error type.
//!
//! Adapter implementations return [`AdapterError`] from any fallible
//! operation. The variants are deliberately coarse-grained — adapters
//! that need vendor-specific error context can wrap the originating
//! error inside [`AdapterError::Other`] (which carries a `String`).

use thiserror::Error;

/// Error variants returned by adapter trait methods.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// The remote IdP refused the request, returned an error response,
    /// or sent a malformed payload.
    #[error("remote IdP error: {0}")]
    Remote(String),

    /// A token, assertion, or signature failed cryptographic verification.
    #[error("verification failed: {0}")]
    Verification(String),

    /// The supplied input could not be parsed (malformed JSON, invalid
    /// JWT structure, unknown SCIM schema URN, etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The requested operation is not implemented by this adapter
    /// (e.g. an `OidcIdpAdapter` that does not support discovery).
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// Catch-all for vendor-specific errors. Use sparingly — prefer a
    /// specific variant when possible.
    #[error("adapter error: {0}")]
    Other(String),
}

/// Adapter-result alias used throughout the crate.
pub type AdapterResult<T> = Result<T, AdapterError>;
