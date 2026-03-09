use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::KeyPair;
use crate::{IdprovaError, Result};

use super::constraints::{DatConstraints, EvaluationContext};
use super::scope::{Scope, ScopeSet};

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
#[derive(Debug, Clone)]
pub struct Dat {
    pub header: DatHeader,
    pub claims: DatClaims,
    signature: Vec<u8>,
    /// The original base64url-encoded signing input (header.payload) from the compact JWS.
    /// Preserved to ensure signature verification uses the exact bytes that were signed,
    /// avoiding any JSON re-serialization roundtrip issues.
    raw_signing_input: Option<String>,
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

        let signing_input = format!("{header_b64}.{claims_b64}");

        Ok(Self {
            header,
            claims,
            signature,
            raw_signing_input: Some(signing_input),
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
    ///
    /// Preserves the raw base64url-encoded header.payload as `raw_signing_input`
    /// so that `verify_signature` can verify against the exact original bytes.
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

        // Preserve the original base64url signing input for signature verification
        let raw_signing_input = format!("{}.{}", parts[0], parts[1]);

        Ok(Self {
            header,
            claims,
            signature,
            raw_signing_input: Some(raw_signing_input),
        })
    }

    /// Verify the DAT's signature against a public key.
    ///
    /// Uses the raw signing input from the original compact JWS when available,
    /// falling back to re-serialization for tokens created via `issue()`.
    pub fn verify_signature(&self, public_key_bytes: &[u8; 32]) -> Result<()> {
        let signing_input = match &self.raw_signing_input {
            Some(raw) => raw.clone(),
            None => {
                let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header)?);
                let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.claims)?);
                format!("{header_b64}.{claims_b64}")
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

    /// Full verification pipeline.
    ///
    /// Runs all checks in order:
    /// 1. Signature verification
    /// 2. Timing (exp + nbf)
    /// 3. Scope — `required_scope` must be permitted by the DAT's scope set
    /// 4. Constraint policy engine (rate limit, IP, trust, depth, geofence, time windows)
    /// 5. Config attestation (if constraint requires it)
    ///
    /// Delegation depth is taken as the **maximum** of `ctx.delegation_depth` and the
    /// length of `claims.delegation_chain`, so the stricter value always wins.
    ///
    /// Pass `required_scope = ""` to skip the scope check (e.g. for token introspection).
    pub fn verify(
        &self,
        public_key_bytes: &[u8; 32],
        required_scope: &str,
        ctx: &EvaluationContext,
    ) -> Result<()> {
        // 1. Signature
        self.verify_signature(public_key_bytes)?;

        // 2. Timing
        self.validate_timing()?;

        // 3. Scope
        if !required_scope.is_empty() {
            let requested = Scope::parse(required_scope)?;
            let granted = ScopeSet::parse(&self.claims.scope)?;
            if !granted.permits(&requested) {
                return Err(IdprovaError::ScopeNotPermitted(format!(
                    "scope '{}' is not granted by this DAT",
                    required_scope
                )));
            }
        }

        // 4 & 5. Constraint policy engine (if present)
        if let Some(constraints) = &self.claims.constraints {
            // Derive effective delegation depth — conservative (take max)
            let chain_depth = self
                .claims
                .delegation_chain
                .as_ref()
                .map(|c| c.len() as u32)
                .unwrap_or(0);

            let effective_depth = ctx.delegation_depth.max(chain_depth);

            // Build augmented context with resolved depth
            let augmented = EvaluationContext {
                delegation_depth: effective_depth,
                ..ctx.clone()
            };

            // 4. All constraint evaluators
            constraints.evaluate(&augmented)?;

            // 5. Config attestation (needs the token's own claim)
            constraints.eval_config_attestation(
                &augmented,
                self.claims.config_attestation.as_deref(),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dat::constraints::{RateLimit};
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
                require_receipt: Some(true),
                ..Default::default()
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

    // ── verify() full pipeline ───────────────────────────────────────────────

    fn issue_valid(kp: &KeyPair, scope: &str, constraints: Option<DatConstraints>) -> Dat {
        Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec![scope.to_string()],
            Utc::now() + Duration::hours(24),
            constraints,
            None,
            kp,
        )
        .unwrap()
    }

    #[test]
    fn test_verify_happy_path() {
        let kp = test_keypair();
        let dat = issue_valid(&kp, "mcp:tool:read", None);
        let ctx = EvaluationContext::default();
        assert!(dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp = test_keypair();
        let kp2 = test_keypair();
        let dat = issue_valid(&kp, "mcp:tool:read", None);
        let ctx = EvaluationContext::default();
        assert!(dat.verify(&kp2.public_key_bytes(), "mcp:tool:read", &ctx).is_err());
    }

    #[test]
    fn test_verify_expired_token() {
        let kp = test_keypair();
        let dat = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            Utc::now() - Duration::hours(1),
            None,
            None,
            &kp,
        )
        .unwrap();
        let ctx = EvaluationContext::default();
        let err = dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).unwrap_err();
        assert!(matches!(err, IdprovaError::DatExpired));
    }

    #[test]
    fn test_verify_scope_denied() {
        let kp = test_keypair();
        let dat = issue_valid(&kp, "mcp:tool:read", None);
        let ctx = EvaluationContext::default();
        let err = dat.verify(&kp.public_key_bytes(), "mcp:tool:write", &ctx).unwrap_err();
        assert!(matches!(err, IdprovaError::ScopeNotPermitted(_)));
    }

    #[test]
    fn test_verify_wildcard_scope_passes() {
        let kp = test_keypair();
        let dat = issue_valid(&kp, "mcp:*:*", None);
        let ctx = EvaluationContext::default();
        assert!(dat.verify(&kp.public_key_bytes(), "mcp:tool:write", &ctx).is_ok());
    }

    #[test]
    fn test_verify_empty_scope_skips_check() {
        let kp = test_keypair();
        let dat = issue_valid(&kp, "mcp:tool:read", None);
        let ctx = EvaluationContext::default();
        // "" → skip scope check
        assert!(dat.verify(&kp.public_key_bytes(), "", &ctx).is_ok());
    }

    #[test]
    fn test_verify_constraint_rate_limit_blocks() {
        let kp = test_keypair();
        let dat = issue_valid(
            &kp,
            "mcp:tool:read",
            Some(DatConstraints {
                rate_limit: Some(RateLimit { max_actions: 5, window_secs: 60 }),
                ..Default::default()
            }),
        );
        let mut ctx = EvaluationContext::default();
        ctx.actions_in_window = 10;
        let err = dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).unwrap_err();
        assert!(err.to_string().contains("rate limit exceeded"));
    }

    #[test]
    fn test_verify_delegation_depth_blocked() {
        let kp = test_keypair();
        let dat = issue_valid(
            &kp,
            "mcp:tool:read",
            Some(DatConstraints {
                max_delegation_depth: Some(2),
                ..Default::default()
            }),
        );
        // ctx carries the runtime depth — 3 levels deep exceeds max=2
        let mut ctx = EvaluationContext::default();
        ctx.delegation_depth = 3;
        let err = dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).unwrap_err();
        assert!(err.to_string().contains("delegation depth"));
    }

    #[test]
    fn test_verify_delegation_depth_at_limit_passes() {
        let kp = test_keypair();
        let dat = issue_valid(
            &kp,
            "mcp:tool:read",
            Some(DatConstraints {
                max_delegation_depth: Some(2),
                ..Default::default()
            }),
        );
        let mut ctx = EvaluationContext::default();
        ctx.delegation_depth = 2; // exactly at limit → ok
        assert!(dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).is_ok());
    }

    #[test]
    fn test_verify_config_attestation_pass() {
        let hash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string();
        let kp = test_keypair();
        let dat = Dat::issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:read".to_string()],
            Utc::now() + Duration::hours(24),
            Some(DatConstraints {
                required_config_hash: Some(hash.clone()),
                ..Default::default()
            }),
            Some(hash.clone()), // config_attestation claim in token
            &kp,
        )
        .unwrap();
        let mut ctx = EvaluationContext::default();
        ctx.agent_config_hash = Some(hash);
        assert!(dat.verify(&kp.public_key_bytes(), "mcp:tool:read", &ctx).is_ok());
    }
}
