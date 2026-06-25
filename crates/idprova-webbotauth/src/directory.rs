//! Key Directory and Signature Agent Card structures.
//!
//! Defines the JSON format for serving keys and metadata.

use super::Result;
use serde::{Deserialize, Serialize};

/// Media type for the Web Bot Auth directory (JWKS).
pub const MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";

/// A JWKS (JSON Web Key Set) containing Ed25519 public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDirectory {
    /// List of public keys.
    pub keys: Vec<Jwk>,
}

/// An Ed25519 JWK (Octet Key Pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key Type: "OKP".
    pub kty: String,
    /// Curve: "Ed25519".
    pub crv: String,
    /// The public key bytes (Base64URL encoded).
    pub x: String,
    /// Key ID (RFC 7638 thumbprint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl KeyDirectory {
    /// Serialize the directory to JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }

    /// Create a new empty directory.
    pub fn new() -> Self {
        Self { keys: vec![] }
    }

    /// Add a key to the directory.
    pub fn add_key(&mut self, key: Jwk) {
        self.keys.push(key);
    }
}

impl Default for KeyDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// The Signature Agent Card metadata document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureAgentCard {
    /// The canonical ID of the agent (`did:aid:...`).
    pub id: String,
    /// Purpose of the agent (e.g., "payment_processing").
    pub purpose: String,
    /// Contact email or URI.
    pub contact: String,
    /// List of Key IDs available for this agent.
    pub keys: Vec<String>,
    /// Rate limit hint (optional).
    pub rate: Option<String>,
}

impl SignatureAgentCard {
    /// Serialize the card to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_jwks() {
        let dir = KeyDirectory::new();
        let json = dir.to_json().unwrap();
        assert!(json.contains("\"keys\":[]"));
    }
}
