//! # idprova-verify
//!
//! High-level verification utilities for the IDProva protocol.
//!
//! Provides three focused functions:
//!
//! - [`verify_dat`] — Full pipeline: signature + timing + scope + constraints
//! - [`verify_dat_from_jws`] — Signature + timing only (no scope/constraint check)
//! - [`verify_receipt_log`] — Hash-chain integrity check for a receipt log

use idprova_core::{
    dat::Dat,
    policy::{EvaluationContext, PolicyEvaluator},
    receipt::Receipt,
    Result,
};

// -- Public API ----------------------------------------------------------------

/// Verify a compact JWS DAT token through the full pipeline.
///
/// Runs in order:
/// 1. Decode and parse the compact JWS
/// 2. Verify Ed25519 signature against `pub_key`
/// 3. Validate timing (`exp` / `nbf`)
/// 4. Check `required_scope` is granted (pass `""` to skip)
/// 5. Evaluate all constraint policies via [`PolicyEvaluator`]
///
/// Returns the decoded [`Dat`] on success so callers can inspect claims.
pub fn verify_dat(
    compact_jws: &str,
    pub_key: &[u8; 32],
    required_scope: &str,
    ctx: &EvaluationContext,
) -> Result<Dat> {
    let dat = Dat::from_compact(compact_jws)?;
    dat.verify_signature(pub_key)?;

    if !required_scope.is_empty() {
        // Full policy evaluation: timing + scope + constraints
        let evaluator = PolicyEvaluator::new();
        let mut eval_ctx = ctx.clone();
        eval_ctx.requested_scope = required_scope.to_string();
        let decision = evaluator.evaluate(&dat, &eval_ctx);
        if let Some(reason) = decision.denial_reason() {
            return Err(idprova_core::IdprovaError::ConstraintViolated(
                format!("{:?}", reason),
            ));
        }
    } else {
        dat.validate_timing()?;
    }

    Ok(dat)
}

/// Verify a compact JWS DAT token — signature and timing only.
///
/// Skips scope and constraint checks. Useful for token introspection.
pub fn verify_dat_from_jws(compact_jws: &str, pub_key: &[u8; 32]) -> Result<Dat> {
    let dat = Dat::from_compact(compact_jws)?;
    dat.verify_signature(pub_key)?;
    dat.validate_timing()?;
    Ok(dat)
}

/// Verify the hash-chain integrity of a receipt log.
pub fn verify_receipt_log(receipts: &[Receipt]) -> Result<()> {
    use idprova_core::receipt::ReceiptLog;
    let log = ReceiptLog::from_entries(receipts.to_vec());
    log.verify_integrity()
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use idprova_core::{
        crypto::KeyPair,
        dat::{Dat, DatConstraints},
        receipt::{ActionDetails, Receipt, ReceiptLog},
    };
    use idprova_core::receipt::entry::ChainLink;

    fn make_ctx(scope: &str) -> EvaluationContext {
        EvaluationContext::builder(scope).build()
    }

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

    #[test]
    fn test_verify_dat_happy_path() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = make_ctx("mcp:tool:read");

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
        let ctx = make_ctx("mcp:tool:read");

        assert!(verify_dat(&compact, &kp2.public_key_bytes(), "mcp:tool:read", &ctx).is_err());
    }

    #[test]
    fn test_verify_dat_expired_fails() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", false);
        let compact = dat.to_compact().unwrap();
        let ctx = make_ctx("mcp:tool:read");

        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:read", &ctx).is_err());
    }

    #[test]
    fn test_verify_dat_scope_denied_fails() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = make_ctx("mcp:tool:write");

        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:write", &ctx).is_err());
    }

    #[test]
    fn test_verify_dat_wildcard_scope_passes() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:*:*", true);
        let compact = dat.to_compact().unwrap();

        let ctx1 = make_ctx("mcp:tool:write");
        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:write", &ctx1).is_ok());
        let ctx2 = make_ctx("mcp:resource:read");
        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:resource:read", &ctx2).is_ok());
    }

    #[test]
    fn test_verify_dat_empty_scope_skips_check() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();
        let ctx = make_ctx("");

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
                max_calls_per_hour: Some(5),
                ..Default::default()
            }),
            None,
            &kp,
        )
        .unwrap();
        let compact = dat.to_compact().unwrap();
        let ctx = EvaluationContext::builder("mcp:tool:read")
            .actions_this_hour(10)
            .build();

        assert!(verify_dat(&compact, &kp.public_key_bytes(), "mcp:tool:read", &ctx).is_err());
    }

    #[test]
    fn test_verify_dat_malformed_token_fails() {
        let kp = KeyPair::generate();
        let ctx = make_ctx("");

        assert!(verify_dat("not.a.token", &kp.public_key_bytes(), "", &ctx).is_err());
        assert!(verify_dat("", &kp.public_key_bytes(), "", &ctx).is_err());
        assert!(verify_dat("only.two", &kp.public_key_bytes(), "", &ctx).is_err());
    }

    #[test]
    fn test_verify_dat_from_jws_happy_path() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();

        let result = verify_dat_from_jws(&compact, &kp.public_key_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().claims.iss, "did:idprova:test:issuer");
    }

    #[test]
    fn test_verify_dat_from_jws_skips_scope_check() {
        let kp = KeyPair::generate();
        let dat = make_dat(&kp, "mcp:tool:read", true);
        let compact = dat.to_compact().unwrap();

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
        let dat = make_dat(&kp, "mcp:tool:read", false);
        let compact = dat.to_compact().unwrap();

        assert!(verify_dat_from_jws(&compact, &kp.public_key_bytes()).is_err());
    }

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
                previous_hash: "wrong_hash_here".to_string(),
                sequence_number: 2,
            },
            signature: "placeholder".to_string(),
        };

        let mut entries = log.entries().to_vec();
        entries.push(tampered);

        assert!(verify_receipt_log(&entries).is_err(), "broken chain must be detected");
    }
}
