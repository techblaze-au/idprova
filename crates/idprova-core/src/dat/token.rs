use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::KeyPair;
use crate::{IdprovaError, Result};

/// JWS header for a DAT.
///
/// SR-3: `alg` is validated in `validate()` — only "EdDSA" is accepted.
///   Rejects "none", "RS256", "HS256", "eddsa" (case mismatch), and all other algorithms.
///
/// SR-4: `deny_unknown_fields` rejects header injection attacks via `jwk`, `jku`, `x5u`, `crit`, etc.
///   These fields are used in known JWS confusion attacks and are categorically prohibited.
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

impl DatHeader {
    /// Validate the header fields.
    ///
    /// # SR-3: Algorithm restriction
    ///
    /// Only `"EdDSA"` (exact case) is accepted. Rejects `"none"`, `"RS256"`, `"eddsa"`, etc.
    pub fn validate(&self) -> Result<()> {
        if self.alg != "EdDSA" {
            return Err(IdprovaError::InvalidDat(format!(
                "unsupported algorithm '{}': only 'EdDSA' is permitted",
                self.alg
            )));
        }
        Ok(())
    }
}

/// A time window restriction (day-of-week + hour range, UTC).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeWindow {
    /// Days of the week (0 = Monday, 6 = Sunday).
    pub days: Vec<u8>,
    /// Start hour (0-23, UTC).
    pub start_hour: u8,
    /// End hour (0-23, UTC). If < start_hour, wraps past midnight.
    pub end_hour: u8,
}

/// Constraints on DAT usage.
///
/// All fields use `#[serde(default)]` + `skip_serializing_if` so that:
/// - Old tokens without new fields deserialize cleanly (backward compat)
/// - New tokens omit unset fields (compact serialization)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatConstraints {
    /// Maximum number of actions the agent can take under this DAT.
    #[serde(rename = "maxActions", default, skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u64>,
    /// Allowed server hostnames/patterns.
    #[serde(rename = "allowedServers", default, skip_serializing_if = "Option::is_none")]
    pub allowed_servers: Option<Vec<String>>,
    /// Whether action receipts are required for each action.
    #[serde(rename = "requireReceipt", default, skip_serializing_if = "Option::is_none")]
    pub require_receipt: Option<bool>,

    // --- Phase 2 RBAC constraint fields ---

    /// Maximum API calls per hour.
    #[serde(rename = "maxCallsPerHour", default, skip_serializing_if = "Option::is_none")]
    pub max_calls_per_hour: Option<u64>,
    /// Maximum API calls per day.
    #[serde(rename = "maxCallsPerDay", default, skip_serializing_if = "Option::is_none")]
    pub max_calls_per_day: Option<u64>,
    /// Maximum concurrent operations.
    #[serde(rename = "maxConcurrent", default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u64>,
    /// Allowed source IP addresses/CIDRs (e.g., "10.0.0.0/8", "192.168.1.1").
    #[serde(rename = "allowedIPs", default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// Denied source IP addresses/CIDRs.
    #[serde(rename = "deniedIPs", default, skip_serializing_if = "Option::is_none")]
    pub denied_ips: Option<Vec<String>>,
    /// Minimum trust level required (e.g., "L2").
    #[serde(rename = "requiredTrustLevel", default, skip_serializing_if = "Option::is_none")]
    pub required_trust_level: Option<String>,
    /// Maximum delegation chain depth.
    #[serde(rename = "maxDelegationDepth", default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    /// Allowed country codes (ISO 3166-1 alpha-2) for geofencing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geofence: Option<Vec<String>>,
    /// Allowed time windows for operation.
    #[serde(rename = "timeWindows", default, skip_serializing_if = "Option::is_none")]
    pub time_windows: Option<Vec<TimeWindow>>,
    /// Required config attestation hash (agent must present matching hash).
    #[serde(rename = "requiredConfigAttestation", default, skip_serializing_if = "Option::is_none")]
    pub required_config_attestation: Option<String>,
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

        // SR-3 + SR-4: Validate header (alg whitelist, unknown fields already rejected by serde)
        header.validate()?;

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
            vec!["mcp:tool:*:read".to_string()],
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
            vec!["mcp:*:*:*".to_string()],
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
            vec!["mcp:tool:*:read".to_string()],
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
            vec!["mcp:tool:*:read".to_string()],
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
            vec!["mcp:tool:*:read".to_string()],
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
            vec!["mcp:tool:*:*".to_string()],
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

    /// SR-3: Only "EdDSA" algorithm is permitted.
    ///
    /// Attempts to parse JWS tokens with any other `alg` value must be rejected.
    #[test]
    fn test_sr3_rejects_non_eddsa_algorithms() {
        let kp = test_keypair();
        let expires = Utc::now() + Duration::hours(1);

        // Issue a valid DAT to get a well-formed compact JWS
        let dat = Dat::issue(
            "did:idprova:example.com:issuer",
            "did:idprova:example.com:agent",
            vec!["mcp:tool:*:*".to_string()],
            expires,
            None,
            None,
            &kp,
        )
        .unwrap();

        // Helper: craft a compact JWS with a different alg value
        let make_jws_with_alg = |alg: &str| -> String {
            let header = serde_json::json!({ "alg": alg, "typ": "idprova-dat+jwt", "kid": "did:example#key" });
            let claims = serde_json::json!({
                "iss": dat.claims.iss, "sub": dat.claims.sub,
                "iat": dat.claims.iat, "exp": dat.claims.exp, "nbf": dat.claims.nbf,
                "jti": dat.claims.jti, "scope": dat.claims.scope
            });
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let sig = kp.sign(format!("{h}.{c}").as_bytes());
            format!("{h}.{c}.{}", URL_SAFE_NO_PAD.encode(sig))
        };

        // All of these must be rejected by from_compact()
        for bad_alg in &["none", "RS256", "HS256", "eddsa", "EDDSA", "Ed25519"] {
            let jws = make_jws_with_alg(bad_alg);
            let result = Dat::from_compact(&jws);
            assert!(
                result.is_err(),
                "algorithm '{bad_alg}' must be rejected, but from_compact returned Ok"
            );
        }

        // EdDSA (correct casing) must be accepted
        let valid = make_jws_with_alg("EdDSA");
        assert!(
            Dat::from_compact(&valid).is_ok(),
            "algorithm 'EdDSA' must be accepted"
        );
    }

    /// SR-4: Unknown JWS header fields must be rejected.
    ///
    /// Header injection via `jwk`, `jku`, `x5u`, `crit` etc. are known JWS attacks.
    /// The `deny_unknown_fields` attribute on `DatHeader` prevents deserialization.
    #[test]
    fn test_sr4_rejects_unknown_header_fields() {
        let kp = test_keypair();

        let make_jws_with_header = |header: serde_json::Value| -> String {
            let claims = serde_json::json!({
                "iss": "did:idprova:example.com:iss", "sub": "did:idprova:example.com:sub",
                "iat": 0i64, "exp": 9999999999i64, "nbf": 0i64,
                "jti": "dat_test", "scope": ["mcp:tool:*:*"]
            });
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let sig = kp.sign(format!("{h}.{c}").as_bytes());
            format!("{h}.{c}.{}", URL_SAFE_NO_PAD.encode(sig))
        };

        // Base valid header
        let valid_header = serde_json::json!({
            "alg": "EdDSA", "typ": "idprova-dat+jwt", "kid": "did:example#key"
        });

        // These fields must cause deserialization failure (deny_unknown_fields)
        for injected_field in &["jwk", "jku", "x5u", "crit", "x5c", "x5t"] {
            let mut header = valid_header.clone();
            header[injected_field] = serde_json::json!("injected");
            let jws = make_jws_with_header(header);
            let result = Dat::from_compact(&jws);
            assert!(
                result.is_err(),
                "header with '{injected_field}' field must be rejected"
            );
        }

        // Valid header without injected fields must succeed
        let jws = make_jws_with_header(valid_header);
        assert!(Dat::from_compact(&jws).is_ok(), "clean header must be accepted");
    }

    /// Phase 2: Extended DatConstraints serialize/deserialize roundtrip.
    ///
    /// New RBAC fields must survive JSON roundtrip and old tokens without
    /// them must still deserialize (backward compat via serde defaults).
    #[test]
    fn test_extended_constraints_roundtrip() {
        let constraints = DatConstraints {
            max_actions: Some(500),
            require_receipt: Some(true),
            max_calls_per_hour: Some(100),
            max_calls_per_day: Some(1000),
            max_concurrent: Some(5),
            allowed_ips: Some(vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()]),
            denied_ips: Some(vec!["10.0.0.99".into()]),
            required_trust_level: Some("L2".into()),
            max_delegation_depth: Some(3),
            geofence: Some(vec!["AU".into(), "NZ".into()]),
            time_windows: Some(vec![TimeWindow {
                days: vec![0, 1, 2, 3, 4], // Mon-Fri
                start_hour: 9,
                end_hour: 17,
            }]),
            required_config_attestation: Some("sha256:abc".into()),
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        let parsed: DatConstraints = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.max_calls_per_hour, Some(100));
        assert_eq!(parsed.max_calls_per_day, Some(1000));
        assert_eq!(parsed.max_concurrent, Some(5));
        assert_eq!(parsed.allowed_ips.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.denied_ips.as_ref().unwrap().len(), 1);
        assert_eq!(parsed.required_trust_level.as_deref(), Some("L2"));
        assert_eq!(parsed.max_delegation_depth, Some(3));
        assert_eq!(parsed.geofence.as_ref().unwrap(), &["AU", "NZ"]);
        assert_eq!(parsed.time_windows.as_ref().unwrap().len(), 1);
        assert_eq!(
            parsed.required_config_attestation.as_deref(),
            Some("sha256:abc")
        );
    }

    /// Phase 2: Old tokens without new fields still deserialize.
    #[test]
    fn test_backward_compat_constraints_deserialize() {
        // JSON with only the original 3 fields — no new RBAC fields
        let json = r#"{"maxActions":100,"requireReceipt":true}"#;
        let parsed: DatConstraints = serde_json::from_str(json).unwrap();

        assert_eq!(parsed.max_actions, Some(100));
        assert_eq!(parsed.require_receipt, Some(true));
        // All new fields should be None
        assert!(parsed.max_calls_per_hour.is_none());
        assert!(parsed.max_calls_per_day.is_none());
        assert!(parsed.max_concurrent.is_none());
        assert!(parsed.allowed_ips.is_none());
        assert!(parsed.denied_ips.is_none());
        assert!(parsed.required_trust_level.is_none());
        assert!(parsed.max_delegation_depth.is_none());
        assert!(parsed.geofence.is_none());
        assert!(parsed.time_windows.is_none());
        assert!(parsed.required_config_attestation.is_none());
    }
}
