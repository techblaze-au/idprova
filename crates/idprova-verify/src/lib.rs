//! # idprova-verify
//!
//! High-level verification utilities for the IDProva protocol.
//!
//! Provides three focused functions:
//!
//! - [`verify_dat`] — Full pipeline: signature + timing + scope + constraints
//! - [`verify_dat_from_jws`] — Signature + timing only (no scope/constraint check)
//! - [`verify_receipt_log`] — Hash-chain integrity check for a receipt log
//!
//! ## Example
//!
//! ```rust,no_run
//! use idprova_verify::{verify_dat, verify_dat_from_jws};
//! use idprova_core::dat::constraints::EvaluationContext;
//!
//! let compact_jws = "header.payload.signature"; // compact JWS from token issuer
//! let pub_key = [0u8; 32]; // issuer's Ed25519 public key bytes
//!
//! // Full verification (signature + timing + scope + constraints)
//! let result = verify_dat(compact_jws, &pub_key, "mcp:tool:read", &EvaluationContext::default());
//!
//! // Signature + timing only (no scope/constraint check)
//! let dat = verify_dat_from_jws(compact_jws, &pub_key);
//! ```

use idprova_core::{
    dat::{constraints::EvaluationContext, Dat},
    receipt::Receipt,
    Result,
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify a compact JWS DAT token through the full pipeline.
///
/// Runs in order:
/// 1. Decode and parse the compact JWS
/// 2. Hard-reject non-EdDSA algorithms (SEC-3)
/// 3. Verify Ed25519 signature against `pub_key`
/// 4. Validate timing (`exp` / `nbf`)
/// 5. Check `required_scope` is granted (pass `""` to skip)
/// 6. Evaluate all constraint policies (rate limit, IP, trust level, delegation
///    depth, geofence, time windows, config attestation)
///
/// Returns the decoded [`Dat`] on success so callers can inspect claims.
///
/// # Errors
///
/// Returns [`IdprovaError`](idprova_core::IdprovaError) on any failure.
pub fn verify_dat(
    compact_jws: &str,
    pub_key: &[u8; 32],
    required_scope: &str,
    ctx: &EvaluationContext,
) -> Result<Dat> {
    let dat = Dat::from_compact(compact_jws)?;
    dat.verify(pub_key, required_scope, ctx)?;
    Ok(dat)
}

/// Verify a compact JWS DAT token — signature and timing only.
///
/// Skips scope and constraint checks. Useful for:
/// - Token introspection / admin inspection
/// - Extracting claims before applying custom policy logic
/// - Testing / debugging
///
/// Runs:
/// 1. Decode and parse the compact JWS
/// 2. Hard-reject non-EdDSA algorithms
/// 3. Verify Ed25519 signature
/// 4. Validate timing (`exp` / `nbf`)
///
/// Returns the decoded [`Dat`] on success.
pub fn verify_dat_from_jws(compact_jws: &str, pub_key: &[u8; 32]) -> Result<Dat> {
    let dat = Dat::from_compact(compact_jws)?;
    dat.verify_signature(pub_key)?;
    dat.validate_timing()?;
    Ok(dat)
}

/// Verify the hash-chain integrity of a receipt log.
///
/// Checks that:
/// - Sequence numbers are contiguous starting from 0
/// - Each receipt's `previous_hash` matches the hash of the preceding receipt
/// - The first receipt's `previous_hash` is `"genesis"`
///
/// Does **not** verify individual receipt signatures — this is a structural
/// integrity check only.
///
/// # Errors
///
/// Returns [`IdprovaError::ReceiptChainBroken`](idprova_core::IdprovaError::ReceiptChainBroken)
/// with the index of the first broken link.
pub fn verify_receipt_log(receipts: &[Receipt]) -> Result<()> {
    use idprova_core::receipt::ReceiptLog;
    let log = ReceiptLog::from_entries(receipts.to_vec());
    log.verify_integrity()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use idprova_core::{
        crypto::KeyPair,
        dat::{constraints::DatConstraints, Dat},
        receipt::{ActionDetails, Receipt, ReceiptLog},
    };
    use idprova_core::receipt::entry::ChainLink;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_dat(kp: &KeyPair, scope: &str, valid: bool) -> Dat {
        let expires = if valid {
            Utc::now() + Duration::hours(24)
        } else {
            Utc::now() - Duration::hours(1)
        };
        Dat::issue(
            "did:idprova:test:issuer",
            "did:idprova:test:agent",
            vec![scope.to_string()],
            expires,
            None,
            None,
            kp,
        )
        .unwrap()
    }

    fn make_receipt(log: &ReceiptLog) -> Receipt {
        Receipt {
            id: ulid::Ulid::new().to_string(),
            timestamp: Utc::now(),
            agent: "did:idprova:test:agent".to_string(),
            dat: "dat_test".to_string(),
            action: ActionDetails {
                action_type: "mcp:tool-call".to_string(),
                server: None,
                tool: Some("test_tool".to_string()),
                input_hash: "blake3:abc123".to_string(),
                output_hash: Some("blake3:def456".to_string()),
                status: "success".to_string(),
                duration_ms: None,
            },
            context: None,
            chain: ChainLink {
                previous_hash: log.last_hash(),
                sequence_number: log.next_sequence(),
            },
            signature: "placeholder".to_string(),
        }
    }

    // ── verify_dat ────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_dat_happy_path() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        let result = verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:read", &ctx);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let verified = result.unwrap();
        assert_eq!(verified.claims.iss, "did:idprova:test:issuer");
        assert_eq!(verified.claims.sub, "did:idprova:test:agent");
    }

    #[test]
    fn test_verify_dat_wrong_key_fails() {
        let kp = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        let result = verify_dat(&compact, &kp2.public_key_bytes(), "mcp:tool:read", &ctx);
        assert!(result.is_err(), "wrong key must fail");
    }

    #[test]
    fn test_verify_dat_expired_fails() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", false); // expired
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        let result = verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:read", &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_verify_dat_scope_denied_fails() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        let result = verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:write", &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scope"));
    }

    #[test]
    fn test_verify_dat_wildcard_scope_passes() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:*:*", true);
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:write", &ctx).is_ok());
        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:resource:read", &ctx).is_ok());
    }

    #[test]
    fn test_verify_dat_empty_scope_skips_check() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::default();

        // empty scope = skip scope check
        assert!(verify_dat(&compact, &kp.public_key_bytes(), "", &ctx).is_ok());
    }

    #[test]
    fn test_verify_dat_constraint_rate_limit_blocks() {
        let kp = KeyPair::generate();
        let dat = Dat::issue(
            "did:idprova:test:issuer",
            "did:idprova:test:agent",
            vec!["mcp:tool:read".to_string()],
            Utc::now() + Duration::hours(24),
            Some(DatConstraints {
                rate_limit: Some(idprova_core::dat::constraints::RateLimit {
                    max_actions: 5,
                    window_secs: 60,
                }),
                ..Default::default()
            }),
            None,
            &kp,
        )
        .unwrap();
        let compact = dat.to_compact().unwrap();
        let mut ctx = EvaluationContext::default();
        ctx.actions_in_window = 10; // exceeds limit

        let result = verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:read", &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    #[test]
    fn test_verify_dat_malformed_token_fails() {
        let kp = KeyPair::generate();
        let ctx = EvaluationContext::default();

        assert!(verify_dat("not.a.token", &kp.public_key_bytes(), "", &ctx).is_err());
        assert!(verify_dat("", &kp.public_key_bytes(), "", &ctx).is_err());
        assert!(verify_dat("only.two", &kp.public_key_bytes(), "", &ctx).is_err());
    }

    // ── verify_dat_from_jws ───────────────────────────────────────────────────

    #[test]
    fn test_verify_dat_from_jws_happy_path() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();

        let result = verify_dat_from_jws(&compact, &kp.public_key_bytes());
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims.iss, "did:idprova:test:issuer");
    }

    #[test]
    fn test_verify_dat_from_jws_skips_scope_check() {
        // Token grants mcp:tool:read only — verify_dat would reject mcp:tool:write,
        // but verify_dat_from_jws should succeed because scope is not checked.
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();

        // No scope param — should succeed even though scope is restricted
        assert!(verify_dat_from_jws(&compact, &kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn test_verify_dat_from_jws_wrong_key_fails() {
        let kp = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();

        assert!(verify_dat_from_jws(&compact, &kp2.public_key_bytes()).is_err());
    }

    #[test]
    fn test_verify_dat_from_jws_expired_fails() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", false); // expired
        let compact = dat.to_compact().unwrap();

        assert!(verify_dat_from_jws(&compact, &kp.public_key_bytes()).is_err());
    }

    // ── verify_receipt_log ────────────────────────────────────────────────────

    #[test]
    fn test_verify_receipt_log_empty_passes() {
        assert!(verify_receipt_log(&[]).is_ok());
    }

    #[test]
    fn test_verify_receipt_log_single_receipt_passes() {
        let mut log = ReceiptLog::new();
        let r = make_receipt(&log);
        log.append(r.clone());

        assert!(verify_receipt_log(log.entries()).is_ok());
    }

    #[test]
    fn test_verify_receipt_log_chain_passes() {
        let mut log = ReceiptLog::new();
        for _ in 0..5 {
            let r = make_receipt(&log);
            log.append(r);
        }
        assert_eq!(log.len(), 5);
        assert!(verify_receipt_log(log.entries()).is_ok());
    }

    #[test]
    fn test_verify_receipt_log_broken_chain_fails() {
        let mut log = ReceiptLog::new();
        let r0 = make_receipt(&log);
        log.append(r0);
        let r1 = make_receipt(&log);
        log.append(r1);

        // Build a tampered entry with wrong previous_hash
        let tampered = Receipt {
            id: ulid::Ulid::new().to_string(),
            timestamp: Utc::now(),
            agent: "did:idprova:test:agent".to_string(),
            dat: "dat_test".to_string(),
            action: ActionDetails {
                action_type: "mcp:tool-call".to_string(),
                server: None,
                tool: None,
                input_hash: "blake3:bad".to_string(),
                output_hash: None,
                status: "success".to_string(),
                duration_ms: None,
            },
            context: None,
            chain: ChainLink {
                previous_hash: "wrong_hash_here".to_string(), // broken link
                sequence_number: 2,
            },
            signature: "placeholder".to_string(),
        };

        let mut entries = log.entries().to_vec();
        entries.push(tampered);

        let result = verify_receipt_log(&entries);
        assert!(result.is_err(), "broken chain must be detected");
    }
}
