//! Core MCP authentication — verify DAT tokens for MCP tool access.

use idprova_core::dat::constraints::EvaluationContext;
use idprova_core::trust::TrustLevel;

use crate::error::McpAuthError;

/// Result type for MCP auth operations.
pub type Result<T> = std::result::Result<T, McpAuthError>;

/// Information about a successfully verified agent.
#[derive(Debug, Clone)]
pub struct VerifiedAgent {
    /// Agent DID (the subject of the DAT).
    pub aid: String,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// Trust level of the agent.
    pub trust_level: TrustLevel,
    /// Delegator DID (the issuer of the DAT).
    pub delegator: String,
    /// DAT JTI (unique token identifier).
    pub jti: String,
}

/// MCP authentication verifier.
///
/// Verifies DAT bearer tokens against required scopes and public keys.
/// Supports both online (registry lookup) and offline (direct key) modes.
#[derive(Debug, Clone)]
pub struct McpAuth {
    /// Registry URL for online key resolution (None = offline mode).
    registry_url: Option<String>,
}

impl McpAuth {
    /// Create an McpAuth instance that resolves keys via the IDProva registry.
    pub fn new(registry_url: &str) -> Self {
        Self {
            registry_url: Some(registry_url.to_string()),
        }
    }

    /// Create an McpAuth instance for offline (direct key) verification.
    ///
    /// In offline mode, the caller must supply the public key directly
    /// to `verify_request()`.
    pub fn offline() -> Self {
        Self { registry_url: None }
    }

    /// Returns the configured registry URL, if any.
    pub fn registry_url(&self) -> Option<&str> {
        self.registry_url.as_deref()
    }

    /// Verify a DAT token against a required scope.
    ///
    /// - `dat_token`: compact JWS DAT string
    /// - `required_scope`: 4-part scope string (e.g., "mcp:tool:filesystem:read")
    /// - `public_key`: Ed25519 public key bytes of the token issuer
    ///
    /// Returns a [`VerifiedAgent`] on success with the agent's identity and permissions.
    pub fn verify_request(
        &self,
        dat_token: &str,
        required_scope: &str,
        public_key: &[u8; 32],
    ) -> Result<VerifiedAgent> {
        if dat_token.is_empty() {
            return Err(McpAuthError::MissingToken("DAT token is empty".to_string()));
        }

        let ctx = EvaluationContext::default();

        let dat = idprova_verify::verify_dat(dat_token, public_key, required_scope, &ctx)?;

        // Determine trust level from constraints (if present)
        let trust_level = dat
            .claims
            .constraints
            .as_ref()
            .and_then(|c| c.min_trust_level)
            .and_then(|level| match level {
                0 => Some(TrustLevel::L0),
                1 => Some(TrustLevel::L1),
                2 => Some(TrustLevel::L2),
                3 => Some(TrustLevel::L3),
                4 => Some(TrustLevel::L4),
                _ => None,
            })
            .unwrap_or(TrustLevel::L0);

        Ok(VerifiedAgent {
            aid: dat.claims.sub,
            scope: dat.claims.scope,
            trust_level,
            delegator: dat.claims.iss,
            jti: dat.claims.jti,
        })
    }
}
