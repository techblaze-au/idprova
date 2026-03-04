use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::KeyPair;
use crate::{IdprovaError, Result};

/// JWS header for a DAT.
///
/// SEC-3 mitigation: `alg` is validated on deserialization — only "EdDSA" is accepted.
/// SEC-4 mitigation: `deny_unknown_fields` rejects `jwk`, `jku`, `x5u`, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatHeader {
    /// Algorithm — always "EdDSA" for Ed25519.
    pub alg: String,
    /// Token type.
    pub typ: String,
    /// Key ID — the DID URL of the signing key.
    pub kid: String,
}

/// Constraints on DAT usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatConstraints {
    /// Maximum number of actions the agent can take under this DAT.
    #[serde(rename = "maxActions", skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u64>,
    /// Allowed server hostnames/patterns.
    #[serde(rename = "allowedServers", skip_serializing_if = "Option::is_none")]
    pub allowed_servers: Option<Vec<String>>,
    /// Whether action receipts are required for each action.
    #[serde(rename = "requireReceipt", skip_serializing_if = "Option::is_none")]
    pub require_receipt: Option<bool>,
}

/// The claims (payload) of a DAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatClaims {
    /// Issuer — the DID of the delegator.
    pub iss: String,
    /// Subject — the DID of the agent receiving delegation.
    pub sub: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Not before (Unix timestamp).
    pub nbf: i64,
    /// JWT ID — unique token identifier.
    pub jti: String,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// Usage constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<DatConstraints>,
    /// Config attestation hash of the agent's configuration.
    #[serde(rename = "configAttestation", skip_serializing_if = "Option::is_none")]
    pub config_attestation: Option<String>,
    /// Delegation chain — list of parent DAT JTIs for multi-level delegation.
    #[serde(rename = "delegationChain", skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<Vec<String>>,
}

/// A complete Delegation Attestation Token.
///
/// # Security: JWS Signing Input Preservation (fix S1)
///
/// Per RFC 7515 §5.2, signature verification MUST use the original base64url-encoded
/// header and payload bytes — NOT a re-serialization. `serde_json` is not guaranteed
/// deterministic across platforms or versions, so re-serializing before verification
/// breaks cross-implementation interoperability.
///
/// `from_compact()` stores the original base64 segments in `raw_header_b64` /
/// `raw_claims_b64` and `verify_signature()` uses those directly.
#[derive(Debug, Clone)]
pub struct Dat {
    pub header: DatHeader,
    pub claims: DatClaims,
    signature: Vec<u8>,
    /// Original header base64url segment (preserved from compact JWS for verification).
    raw_header_b64: Option<String>,
    /// Original claims base64url segment (preserved from compact JWS for verification).
    raw_claims_b64: Option<String>,
}

impl Dat {
    /// Issue a new DAT signed by the issuer's keypair.
    pub fn issue(
        issuer_did: &str,
        subject_did: &str,
        scope: Vec<String>,
        expires_at: DateTime<Utc>,
        constraints: Option<DatConstraints>,
        config_attestation: Option<String>,
        signing_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();

        let header = DatHeader {
            alg: "EdDSA".to_string(),
            typ: "idprova-dat+jwt".to_string(),
            kid: format!("{issuer_did}#key-ed25519"),
        };

        let claims = DatClaims {
            iss: issuer_did.to_string(),
            sub: subject_did.to_string(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            nbf: now.timestamp(),
            jti: format!("dat_{}", ulid::Ulid::new()),
            scope,
            constraints,
            config_attestation,
            delegation_chain: Some(vec![]),
        };

        // Create the signing input: base64url(header).base64url(payload)
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signature = signing_key.sign(signing_input.as_bytes());

        Ok(Self {
            header,
            claims,
            signature,
            raw_header_b64: Some(header_b64),
            raw_claims_b64: Some(claims_b64),
        })
    }

    /// Serialize to compact JWS format: header.payload.signature
    pub fn to_compact(&self) -> Result<String> {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.claims)?);
        let sig_b64 = URL_SAFE_NO_PAD.encode(&self.signature);
        Ok(format!("{header_b64}.{claims_b64}.{sig_b64}"))
    }

    /// Parse a compact JWS string into a DAT (without verifying the signature).
    pub fn from_compact(compact: &str) -> Result<Self> {
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(IdprovaError::InvalidDat(
                "compact JWS must have 3 parts".into(),
            ));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| IdprovaError::InvalidDat(format!("header decode: {e}")))?;
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| IdprovaError::InvalidDat(format!("claims decode: {e}")))?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| IdprovaError::InvalidDat(format!("signature decode: {e}")))?;

        let header: DatHeader = serde_json::from_slice(&header_bytes)?;

        // SEC-3: Hard-reject any algorithm other than EdDSA
        if header.alg != "EdDSA" {
            return Err(IdprovaError::InvalidDat(format!(
                "unsupported algorithm '{}': only 'EdDSA' is permitted",
                header.alg
            )));
        }

        let claims: DatClaims = serde_json::from_slice(&claims_bytes)?;

        // S1 fix: store original base64 segments for use in verify_signature()
        Ok(Self {
            header,
            claims,
            signature,
            raw_header_b64: Some(parts[0].to_string()),
            raw_claims_b64: Some(parts[1].to_string()),
        })
    }

    /// Verify the DAT's signature against a public key.
    ///
    /// Uses the original base64url segments (stored at parse time) per RFC 7515 §5.2.
    /// This avoids the re-serialization non-determinism bug where serde_json field
    /// ordering could differ from the original signing input.
    pub fn verify_signature(&self, public_key_bytes: &[u8; 32]) -> Result<()> {
        let signing_input = match (&self.raw_header_b64, &self.raw_claims_b64) {
            (Some(h), Some(c)) => format!("{h}.{c}"),
            _ => {
                // Fallback for in-memory tokens created via issue() with no raw segments.
                // This path only runs for tokens that were never serialized/parsed.
                let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header)?);
                let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.claims)?);
                format!("{h}.{c}")
            }
        };

        KeyPair::verify(public_key_bytes, signing_input.as_bytes(), &self.signature)
    }

    /// Check if the DAT is expired.
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.claims.exp
    }

    /// Check if the DAT is not yet valid (before nbf).
    pub fn is_not_yet_valid(&self) -> bool {
        let now = Utc::now().timestamp();
        now < self.claims.nbf
    }

    /// Validate timing constraints (not expired, not before valid).
    pub fn validate_timing(&self) -> Result<()> {
        if self.is_expired() {
            return Err(IdprovaError::DatExpired);
        }
        if self.is_not_yet_valid() {
            return Err(IdprovaError::DatNotYetValid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_issue_and_verify() {
        let kp = test_keypair();
        let expires = Utc::now() + Duration::hours(24);

        let dat = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            expires,
            None,
            None,
            &kp,
        )
        .unwrap();

        assert_eq!(dat.claims.iss, "did:idprova:example.com:alice");
        assert_eq!(dat.claims.sub, "did:idprova:example.com:agent");
        assert!(dat.claims.jti.starts_with("dat_"));

        // Verify signature
        let pub_bytes = kp.public_key_bytes();
        assert!(dat.verify_signature(&pub_bytes).is_ok());
    }

    #[test]
    fn test_compact_roundtrip() {
        let kp = test_keypair();
        let expires = Utc::now() + Duration::hours(24);

        let dat = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:*:*".to_string()],
            expires,
            Some(DatConstraints {
                max_actions: Some(1000),
                allowed_servers: None,
                require_receipt: Some(true),
            }),
            None,
            &kp,
        )
        .unwrap();

        let compact = dat.to_compact().unwrap();
        let parsed = Dat::from_compact(&compact).unwrap();

        assert_eq!(parsed.claims.iss, dat.claims.iss);
        assert_eq!(parsed.claims.sub, dat.claims.sub);
        assert_eq!(parsed.claims.scope, dat.claims.scope);

        // Verify the parsed token's signature
        let pub_bytes = kp.public_key_bytes();
        assert!(parsed.verify_signature(&pub_bytes).is_ok());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let expires = Utc::now() + Duration::hours(24);

        let dat = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            expires,
            None,
            None,
            &kp1,
        )
        .unwrap();

        let wrong_pub = kp2.public_key_bytes();
        assert!(dat.verify_signature(&wrong_pub).is_err());
    }

    #[test]
    fn test_timing_validation() {
        let kp = test_keypair();

        // Expired DAT
        let expired = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            Utc::now() - Duration::hours(1),
            None,
            None,
            &kp,
        )
        .unwrap();
        assert!(expired.is_expired());
        assert!(expired.validate_timing().is_err());

        // Valid DAT
        let valid = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            Utc::now() + Duration::hours(24),
            None,
            None,
            &kp,
        )
        .unwrap();
        assert!(!valid.is_expired());
        assert!(valid.validate_timing().is_ok());
    }

    /// S1: JWS re-serialization bug.
    ///
    /// verify_signature() must use the original base64 segments from the compact JWS string,
    /// not re-serialized JSON. This test round-trips through compact form and verifies that
    /// the parsed token passes signature verification using the original bytes.
    #[test]
    fn test_s1_jws_verify_uses_original_segments() {
        let kp = test_keypair();
        let expires = Utc::now() + Duration::hours(1);

        let dat = Dat::issue(
            "did:idprova:example.com:issuer",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:*".to_string()],
            expires,
            None,
            None,
            &kp,
        )
        .unwrap();

        // Round-trip through compact serialization (simulates receiving a token over the wire)
        let compact = dat.to_compact().unwrap();
        let parsed = Dat::from_compact(&compact).unwrap();

        // The parsed token must carry the raw segments
        assert!(
            parsed.raw_header_b64.is_some(),
            "raw_header_b64 must be populated after from_compact"
        );
        assert!(
            parsed.raw_claims_b64.is_some(),
            "raw_claims_b64 must be populated after from_compact"
        );

        // Signature verification MUST pass using original bytes
        let pub_bytes = kp.public_key_bytes();
        assert!(
            parsed.verify_signature(&pub_bytes).is_ok(),
            "verify_signature must pass for a token round-tripped through compact form"
        );

        // A different key must fail
        let kp2 = test_keypair();
        let wrong_pub = kp2.public_key_bytes();
        assert!(
            parsed.verify_signature(&wrong_pub).is_err(),
            "verify_signature must fail with a wrong public key"
        );
    }
}
