//! Error types for MCP auth operations.

use thiserror::Error;

/// Errors that can occur during MCP authentication and authorization.
#[derive(Debug, Error)]
pub enum McpAuthError {
    /// No DAT token was provided in the request.
    #[error("missing DAT token: {0}")]
    MissingToken(String),

    /// The DAT token is malformed or has an invalid signature.
    #[error("invalid DAT: {0}")]
    InvalidDat(String),

    /// The DAT does not grant the required scope.
    #[error("insufficient scope: {0}")]
    InsufficientScope(String),

    /// DAT verification failed (expired, wrong key, constraint violated, etc.).
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

impl From<idprova_core::IdprovaError> for McpAuthError {
    fn from(e: idprova_core::IdprovaError) -> Self {
        match &e {
            idprova_core::IdprovaError::ScopeNotPermitted(_) => {
                McpAuthError::InsufficientScope(e.to_string())
            }
            idprova_core::IdprovaError::InvalidDat(_) => McpAuthError::InvalidDat(e.to_string()),
            idprova_core::IdprovaError::DatExpired | idprova_core::IdprovaError::DatNotYetValid => {
                McpAuthError::VerificationFailed(e.to_string())
            }
            _ => McpAuthError::VerificationFailed(e.to_string()),
        }
    }
}
