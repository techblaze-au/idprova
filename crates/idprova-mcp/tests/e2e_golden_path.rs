//! End-to-end golden-path integration test for IDProva.
//!
//! Proves the full lifecycle and an INDEPENDENT offline verification that does
//! not rely on the receipt log's own methods:
//!   1. Operator + agent Ed25519 identities
//!   2. DAT issuance scoped to a tool action (`Dat::issue`)
//!   3. Scoped tool-call authorization via `McpAuth::verify_request`
//!   4. Signed, hash-chained Action Receipts (built via idprova-core)
//!   5. Structural chain integrity (`ReceiptLog::verify_integrity_with_key`)
//!   6. Independent offline verify — reconstructs the canonical signing payload
//!      (`Receipt::signing_payload_bytes`) and verifies the Ed25519 signature
//!      directly with `KeyPair::verify`, never calling a ReceiptLog method.
//!
//! Note on the MCP wrapper: `McpReceiptLog::log_tool_call` produces UNSIGNED
//! receipts (no agent key is threaded through it today), so the signature-
//! bearing golden path is built on `idprova-core` primitives. The wrapper's
//! own chain-integrity path is covered separately below.
//!
//! 7. Offline anchor round-trip (`golden_path_anchor_offline_roundtrip`): the
//!    optional `Receipt::anchor` (ADR 0011) binds the exact SHA-512 of the
//!    signing payload, is excluded from that payload (preserving the S3 fix),
//!    verifies offline via Ed25519ph, and survives serde / wire-skip. The live
//!    Rekor submission round-trip is covered by idprova-core's `#[ignore]` test.

use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::Dat;
use idprova_core::receipt::entry::{ActionDetails, ChainLink, Receipt, ReceiptKind};
use idprova_core::receipt::ReceiptLog;
use idprova_mcp::{McpAuth, McpReceiptLog};

use ed25519_dalek::SigningKey;
use idprova_core::receipt::anchor::{
    ed25519_pubkey_pem_b64, ed25519ph_sign, ed25519ph_verify, sha512_hex, TransparencyAnchor,
};

/// Build a signed receipt with the agent key, chained onto `log`.
fn signed_receipt(
    agent_kp: &KeyPair,
    agent_did: &str,
    dat_jti: &str,
    log: &ReceiptLog,
    tool: &str,
    input_hash: &str,
    output_hash: Option<&str>,
) -> Receipt {
    let action = ActionDetails {
        action_type: "mcp:tool-call".to_string(),
        server: None,
        tool: Some(tool.to_string()),
        input_hash: input_hash.to_string(),
        output_hash: output_hash.map(|s| s.to_string()),
        status: "success".to_string(),
        duration_ms: None,
    };
    let mut r = Receipt {
        id: format!("rcpt_{}", ulid::Ulid::new()),
        timestamp: Utc::now(),
        agent: agent_did.to_string(),
        dat: dat_jti.to_string(),
        kind: ReceiptKind::Data,
        action,
        context: None,
        chain: ChainLink {
            previous_hash: log.last_hash(),
            sequence_number: log.next_sequence(),
        },
        signature: String::new(),
        anchor: None,
    };
    r.signature = hex::encode(agent_kp.sign(&r.signing_payload_bytes()));
    r
}

/// INDEPENDENT offline verification — no ReceiptLog method is used.
/// Reconstructs the canonical signing payload and verifies the Ed25519 sig.
fn independently_verify(receipt: &Receipt, agent_pubkey: &[u8; 32]) -> bool {
    let payload = receipt.signing_payload_bytes();
    let sig = match hex::decode(&receipt.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    KeyPair::verify(agent_pubkey, &payload, &sig).is_ok()
}

#[test]
fn golden_path_signed_receipts_independently_verify() {
    // 1. Identities
    let operator_kp = KeyPair::generate();
    let agent_kp = KeyPair::generate();
    let operator_did = "did:aid:example.com:operator";
    let agent_did = "did:aid:example.com:fs-worker";

    // 2. Issue a scoped DAT (real API, mirrors filesystem_mcp.rs)
    let dat = Dat::issue(
        operator_did,
        agent_did,
        vec!["mcp:tool:filesystem:read".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &operator_kp,
    )
    .expect("failed to issue DAT");
    let dat_token = dat.to_compact().expect("serialize DAT");
    let dat_jti = dat.claims.jti.clone();

    // 3. Authorize the scoped tool call (must succeed); a write must be denied.
    let auth = McpAuth::offline();
    let ctx = auth
        .verify_request(
            &dat_token,
            "mcp:tool:filesystem:read",
            &operator_kp.public_key_bytes(),
        )
        .expect("read within scope must be allowed");
    assert_eq!(ctx.aid, agent_did, "receipt agent must be the DAT subject");
    assert_eq!(ctx.jti, dat_jti);

    assert!(
        auth.verify_request(
            &dat_token,
            "mcp:tool:filesystem:write",
            &operator_kp.public_key_bytes(),
        )
        .is_err(),
        "out-of-scope write must be denied"
    );

    // 4. Two signed, chained receipts under the verified agent context.
    let agent_pub = agent_kp.public_key_bytes();
    let mut log = ReceiptLog::new();
    let r0 = signed_receipt(
        &agent_kp,
        &ctx.aid,
        &ctx.jti,
        &log,
        "filesystem:read",
        "blake3:input_abc",
        Some("blake3:output_def"),
    );
    log.append(r0);
    let r1 = signed_receipt(
        &agent_kp,
        &ctx.aid,
        &ctx.jti,
        &log,
        "filesystem:read",
        "blake3:input_xyz",
        Some("blake3:output_999"),
    );
    log.append(r1);

    // 5. Structural assertions
    let entries = log.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].chain.sequence_number, 0);
    assert_eq!(entries[1].chain.sequence_number, 1);
    assert_eq!(entries[0].chain.previous_hash, "genesis");
    assert_eq!(entries[1].chain.previous_hash, entries[0].compute_hash());
    log.verify_integrity_with_key(&agent_pub)
        .expect("signed chain must verify");

    // 6. INDEPENDENT offline verify (no ReceiptLog method)
    for (i, e) in entries.iter().enumerate() {
        assert!(
            independently_verify(e, &agent_pub),
            "receipt {i} must independently verify"
        );
    }

    // Tamper → must fail
    let mut tampered = entries[1].clone();
    tampered.action.status = "TAMPERED".to_string();
    assert!(!independently_verify(&tampered, &agent_pub));

    // Wrong key → must fail
    let wrong = KeyPair::generate().public_key_bytes();
    assert!(!independently_verify(&entries[0], &wrong));
}

/// The MCP wrapper logs unsigned receipts but still maintains a valid hash
/// chain; assert its structural integrity end-to-end.
#[test]
fn mcp_wrapper_chain_integrity() {
    let operator_kp = KeyPair::generate();
    let operator_did = "did:aid:example.com:operator";
    let agent_did = "did:aid:example.com:fs-worker";

    let dat = Dat::issue(
        operator_did,
        agent_did,
        vec!["mcp:tool:filesystem:read".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &operator_kp,
    )
    .expect("issue DAT");
    let dat_token = dat.to_compact().expect("serialize DAT");

    let auth = McpAuth::offline();
    let mut receipts = McpReceiptLog::new();

    let ctx = auth
        .verify_request(
            &dat_token,
            "mcp:tool:filesystem:read",
            &operator_kp.public_key_bytes(),
        )
        .expect("allowed");
    receipts.log_tool_call(
        &ctx.aid,
        &ctx.jti,
        "filesystem:read",
        "blake3:in1",
        Some("blake3:out1"),
    );
    receipts.log_tool_call(
        &ctx.aid,
        &ctx.jti,
        "filesystem:read",
        "blake3:in2",
        Some("blake3:out2"),
    );

    assert_eq!(receipts.entries().len(), 2);
    receipts
        .verify_integrity()
        .expect("MCP wrapper chain integrity must hold");
}

#[test]
fn golden_path_anchor_offline_roundtrip() {
    // 1. Deterministic agent key, receipt log, one signed receipt
    let agent_kp = KeyPair::from_secret_bytes(&[1u8; 32]);
    let log = ReceiptLog::new();
    let mut receipt = signed_receipt(
        &agent_kp,
        "did:aid:example.com:fs-worker",
        "dat_test",
        &log,
        "filesystem:read",
        "blake3:in",
        Some("blake3:out"),
    );

    // 2. Capture signing payload BEFORE anchoring
    let payload = receipt.signing_payload_bytes();

    // 3. Dedicated anchor key
    let anchor_key = SigningKey::from_bytes(&[0x2a; 32]);

    // 4. Compute anchor crypto artifacts
    let sha = sha512_hex(&payload);
    let sig_b64 = ed25519ph_sign(&anchor_key, &payload).expect("ed25519ph sign must succeed");
    let pem_b64 =
        ed25519_pubkey_pem_b64(&anchor_key.verifying_key()).expect("pem b64 must succeed");
    assert!(!pem_b64.is_empty(), "pem_b64 must be non-empty");

    // 5. Construct offline anchor and attach to receipt
    let anchor = TransparencyAnchor {
        log: "rekor".to_string(),
        instance_url: "https://rekor.sigstore.dev".to_string(),
        log_index: 1687966334,
        entry_uuid: "offline-test-uuid".to_string(),
        integrated_time: 1_700_000_000,
        signed_entry_timestamp: String::new(),
        inclusion_proof: serde_json::json!({}),
        anchored_sha512: sha.clone(),
    };
    receipt.anchor = Some(anchor);

    // 6a. Anchor did NOT change signing payload (S3 exclusion holds)
    assert_eq!(
        receipt.signing_payload_bytes(),
        payload,
        "anchor must not alter signing payload (S3 exclusion)"
    );

    // 6b. Original receipt signature still verifies after anchoring
    assert!(
        independently_verify(&receipt, &agent_kp.public_key_bytes()),
        "agent signature must still verify after anchoring"
    );

    // 6c. Anchor binds exactly the signing-payload SHA-512
    assert_eq!(
        receipt.anchor.as_ref().unwrap().anchored_sha512,
        sha512_hex(&payload),
        "anchor must bind the exact SHA-512 of the signing payload"
    );

    // 6d. Anchor's Ed25519ph signature verifies offline
    assert!(
        ed25519ph_verify(&anchor_key.verifying_key(), &payload, &sig_b64),
        "anchor Ed25519ph signature must verify"
    );

    // 6e. NEGATIVE: wrong key must NOT verify
    let wrong_key = SigningKey::from_bytes(&[0x99; 32]);
    assert!(
        !ed25519ph_verify(&wrong_key.verifying_key(), &payload, &sig_b64),
        "wrong key must not verify anchor signature"
    );

    // 6f. NEGATIVE: tampered payload must fail
    let mut tampered_payload = payload.clone();
    if let Some(b) = tampered_payload.first_mut() {
        *b ^= 0xff;
    }
    assert!(
        !ed25519ph_verify(&anchor_key.verifying_key(), &tampered_payload, &sig_b64),
        "tampered payload must not verify anchor signature"
    );

    // 6g. SERDE round-trip: anchor survives serialization
    let json = serde_json::to_string(&receipt).expect("serialize anchored receipt");
    let deserialized: Receipt = serde_json::from_str(&json).expect("deserialize anchored receipt");
    assert!(
        deserialized.anchor.is_some(),
        "deserialized receipt must have anchor"
    );
    assert_eq!(
        deserialized.anchor.as_ref().unwrap().anchored_sha512,
        sha512_hex(&payload),
        "deserialized anchor must preserve anchored_sha512"
    );
    assert!(
        independently_verify(&deserialized, &agent_kp.public_key_bytes()),
        "deserialized anchored receipt must still verify"
    );

    // 6h. WIRE-SKIP: anchored JSON contains "anchor"; unanchored does NOT
    assert!(
        json.contains("anchor"),
        "anchored receipt JSON must contain anchor field"
    );

    let log2 = ReceiptLog::new();
    let unanchored = signed_receipt(
        &agent_kp,
        "did:aid:example.com:fs-worker",
        "dat_test",
        &log2,
        "filesystem:read",
        "blake3:in",
        Some("blake3:out"),
    );
    let unanchored_json = serde_json::to_string(&unanchored).expect("serialize unanchored receipt");
    assert!(
        !unanchored_json.contains("anchor"),
        "unanchored receipt JSON must NOT contain anchor field (skip_serializing_if)"
    );
}
