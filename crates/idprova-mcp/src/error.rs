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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_missing_token() {
        let e = McpAuthError::MissingToken("no token".into());
        assert!(e.to_string().contains("missing DAT token"));
    }

    #[test]
    fn test_error_display_invalid_dat() {
        let e = McpAuthError::InvalidDat("bad format".into());
        assert!(e.to_string().contains("invalid DAT"));
    }

    #[test]
    fn test_error_display_insufficient_scope() {
        let e = McpAuthError::InsufficientScope("need write".into());
        assert!(e.to_string().contains("insufficient scope"));
    }

    #[test]
    fn test_error_display_verification_failed() {
        let e = McpAuthError::VerificationFailed("expired".into());
        assert!(e.to_string().contains("verification failed"));
    }

    #[test]
    fn test_from_idprova_scope_error() {
        let core_err = idprova_core::IdprovaError::ScopeNotPermitted("write denied".into());
        let mcp_err: McpAuthError = core_err.into();
        assert!(matches!(mcp_err, McpAuthError::InsufficientScope(_)));
    }

    #[test]
    fn test_from_idprova_invalid_dat() {
        let core_err = idprova_core::IdprovaError::InvalidDat("malformed".into());
        let mcp_err: McpAuthError = core_err.into();
        assert!(matches!(mcp_err, McpAuthError::InvalidDat(_)));
    }

    #[test]
    fn test_from_idprova_expired() {
        let core_err = idprova_core::IdprovaError::DatExpired;
        let mcp_err: McpAuthError = core_err.into();
        assert!(matches!(mcp_err, McpAuthError::VerificationFailed(_)));
    }
}
