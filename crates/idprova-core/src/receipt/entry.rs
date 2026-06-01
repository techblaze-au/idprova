use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::hash::prefixed_blake3;
use crate::crypto::KeyPair;
use crate::receipt::anchor::TransparencyAnchor;
use crate::{IdprovaError, Result};

/// Discriminator marking whether a receipt records a normal action or a
/// periodic chain-checkpoint.
///
/// **Backwards-compatibility (v0.1 → v0.2).** v0.1 receipts have no `kind`
/// field; they deserialise as `ReceiptKind::Data` via `#[serde(default)]`.
/// When serialising a `Data` receipt, the field is omitted from the JSON
/// (see `Receipt::kind`'s `skip_serializing_if`), so the v0.1 wire format
/// is unchanged and verifies bit-for-bit identically.
///
/// **`ChainCheckpoint` semantics.** Agents emit checkpoint receipts
/// periodically (every N data receipts or every T elapsed time, whichever
/// fires first) so a downstream SIEM can independently verify hash-chain
/// integrity without replaying the entire log. A checkpoint carries:
///
/// * `prev_hash` — the BLAKE3 hash of the most-recent data receipt at the
///   moment the checkpoint was minted. Independent SIEMs cross-validate
///   this against their own copy of the chain.
/// * `count` — the total number of data receipts in the chain at
///   checkpoint time (i.e., the sequence number of the most-recent data
///   receipt **plus one**). SIEMs detect gaps when their local data-receipt
///   count is less than `count`.
///
/// The checkpoint receipt is itself chained and signed like a data
/// receipt; the `kind` discriminator is what marks it as a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReceiptKind {
    /// A normal data receipt — an agent took an action.
    #[default]
    Data,
    /// A periodic checkpoint receipt — marks chain state at a moment in
    /// time for independent SIEM verification.
    ChainCheckpoint {
        /// BLAKE3 hash (prefixed `blake3:...`) of the most-recent data
        /// receipt at checkpoint time.
        #[serde(rename = "prevHash")]
        prev_hash: String,
        /// Total number of data receipts in the chain at checkpoint time.
        count: u64,
    },
}

impl ReceiptKind {
    /// `true` if this is the default `Data` kind. Used by
    /// `Receipt::kind`'s `skip_serializing_if` so v0.1 wire-format
    /// compatibility is preserved.
    pub fn is_data(&self) -> bool {
        matches!(self, ReceiptKind::Data)
    }
}

/// Details of the action performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDetails {
    /// Action type (e.g., "mcp:tool-call", "a2a:message").
    #[serde(rename = "type")]
    pub action_type: String,
    /// Target server hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Tool or method name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// BLAKE3 hash of the input data.
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    /// BLAKE3 hash of the output data.
    #[serde(rename = "outputHash", skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    /// Action status.
    pub status: String,
    /// Duration in milliseconds.
    #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Contextual information for the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptContext {
    /// Session identifier.
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent receipt ID (for action chains).
    #[serde(rename = "parentReceiptId", skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Unique request identifier.
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// A single action receipt in the hash chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Unique receipt identifier.
    pub id: String,
    /// Timestamp of the action.
    pub timestamp: DateTime<Utc>,
    /// Agent DID that performed the action.
    pub agent: String,
    /// DAT JTI that authorized the action.
    pub dat: String,
    /// Receipt kind discriminator. Defaults to `Data` for v0.1 wire-format
    /// compatibility; serialised only when not `Data`. See [`ReceiptKind`].
    #[serde(default, skip_serializing_if = "ReceiptKind::is_data")]
    pub kind: ReceiptKind,
    /// Action details.
    pub action: ActionDetails,
    /// Optional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ReceiptContext>,
    /// Hash chain linkage.
    pub chain: ChainLink,
    /// Agent's signature over this receipt.
    pub signature: String,
    /// Optional transparency-log anchor (ADR 0011). Recorded AFTER the receipt
    /// is signed and chained, so it is deliberately excluded from
    /// `ReceiptSigningPayload` / `compute_hash` (preserves the S3 fix). A
    /// `None` anchor is a valid, simply-unanchored receipt; skipped on the
    /// wire when absent so v0.1/v0.2 receipts are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<TransparencyAnchor>,
}

/// Hash chain linkage for tamper-evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    /// BLAKE3 hash of the previous receipt (or "genesis" for first).
    #[serde(rename = "previousHash")]
    pub previous_hash: String,
    /// Sequence number in the chain.
    #[serde(rename = "sequenceNumber")]
    pub sequence_number: u64,
}

/// Signing payload — receipt fields excluding the signature.
///
/// # Security: fix S3 (circular dependency in compute_hash)
///
/// The `signature` field must NOT be included when computing the hash or signing,
/// since the signature is computed over the payload, not over itself.
/// SDK implementers MUST use this struct (or equivalent) as the signing input.
#[derive(Serialize)]
struct ReceiptSigningPayload<'a> {
    pub id: &'a str,
    pub timestamp: &'a DateTime<Utc>,
    pub agent: &'a str,
    pub dat: &'a str,
    /// Mirrors `Receipt::kind`: skipped when `Data` so v0.1 receipts
    /// produce identical signing payloads under v0.2 code.
    #[serde(default, skip_serializing_if = "ReceiptKind::is_data")]
    pub kind: &'a ReceiptKind,
    pub action: &'a ActionDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a ReceiptContext>,
    pub chain: &'a ChainLink,
}

impl Receipt {
    /// Returns the canonical signing payload bytes (excludes signature field).
    ///
    /// This is the data that is (or should be) signed to produce `self.signature`,
    /// and the data used as input to `compute_hash()`.
    ///
    /// **v0.1 / v0.2 wire compatibility:** when `self.kind == ReceiptKind::Data`
    /// (the default), the `kind` field is omitted from the payload so that a
    /// receipt minted under v0.1 produces the exact same signing bytes when
    /// re-hashed by v0.2 code. Only `ChainCheckpoint` receipts include the
    /// discriminator in the signing payload.
    pub fn signing_payload_bytes(&self) -> Vec<u8> {
        let payload = ReceiptSigningPayload {
            id: &self.id,
            timestamp: &self.timestamp,
            agent: &self.agent,
            dat: &self.dat,
            kind: &self.kind,
            action: &self.action,
            context: self.context.as_ref(),
            chain: &self.chain,
        };
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Compute the BLAKE3 hash of this receipt (for chain linking).
    ///
    /// Uses `signing_payload_bytes()` (i.e., excludes the signature field)
    /// so the hash is stable regardless of whether the receipt is signed yet.
    pub fn compute_hash(&self) -> String {
        prefixed_blake3(&self.signing_payload_bytes())
    }

    /// Verify this receipt's signature against the agent's public key.
    ///
    /// # Security: fix S2 (receipt signatures never verified)
    ///
    /// The signature field is hex-encoded Ed25519 signature over `signing_payload_bytes()`.
    pub fn verify_signature(&self, public_key_bytes: &[u8; 32]) -> Result<()> {
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| IdprovaError::InvalidReceipt(format!("signature hex decode: {e}")))?;
        let payload = self.signing_payload_bytes();
        KeyPair::verify(public_key_bytes, &payload, &sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use chrono::Utc;

    fn make_receipt(kp: &KeyPair, seq: u64, prev_hash: &str) -> Receipt {
        let chain = ChainLink {
            previous_hash: prev_hash.to_string(),
            sequence_number: seq,
        };
        let action = ActionDetails {
            action_type: "mcp:tool-call".to_string(),
            server: None,
            tool: Some("read_file".to_string()),
            input_hash: "blake3:abc123".to_string(),
            output_hash: None,
            status: "success".to_string(),
            duration_ms: Some(42),
        };
        let mut r = Receipt {
            id: format!("rcpt_{seq}"),
            timestamp: Utc::now(),
            agent: "did:aid:example.com:kai".to_string(),
            dat: "dat_test".to_string(),
            kind: ReceiptKind::Data,
            action,
            context: None,
            chain,
            signature: String::new(), // placeholder
            anchor: None,
        };
        // Sign the payload
        let payload = r.signing_payload_bytes();
        let sig = kp.sign(&payload);
        r.signature = hex::encode(sig);
        r
    }

    /// S3: compute_hash() must NOT include the signature field.
    ///
    /// The hash must be identical whether computed before or after signing
    /// (i.e., the signature field must be excluded from the hash input).
    #[test]
    fn test_s3_hash_excludes_signature() {
        let kp = KeyPair::generate();
        let r = make_receipt(&kp, 0, "genesis");

        let hash1 = r.compute_hash();

        // Mutate the signature — hash must remain the same
        let mut r2 = r.clone();
        r2.signature = "deadbeef".to_string();
        let hash2 = r2.compute_hash();

        assert_eq!(
            hash1, hash2,
            "compute_hash() must not depend on the signature field"
        );
    }

    /// S2: verify_signature() must reject tampered receipts.
    #[test]
    fn test_s2_receipt_signature_verification() {
        let kp = KeyPair::generate();
        let r = make_receipt(&kp, 0, "genesis");
        let pub_bytes = kp.public_key_bytes();

        // Valid receipt verifies OK
        assert!(r.verify_signature(&pub_bytes).is_ok());

        // Tamper with the action — verification must fail
        let mut tampered = r.clone();
        tampered.action.status = "forged".to_string();
        assert!(
            tampered.verify_signature(&pub_bytes).is_err(),
            "tampered receipt must fail signature verification"
        );

        // Wrong key must fail
        let kp2 = KeyPair::generate();
        let wrong_pub = kp2.public_key_bytes();
        assert!(
            r.verify_signature(&wrong_pub).is_err(),
            "wrong public key must fail verification"
        );
    }

    // ── IDP-002 — ReceiptKind discriminator ───────────────────────────

    /// v0.1 → v0.2 wire-format backwards compatibility: a receipt JSON
    /// missing the `kind` field deserialises as `ReceiptKind::Data`.
    #[test]
    fn test_idp002_v01_receipt_json_without_kind_deserialises_as_data() {
        // Hand-rolled v0.1-shaped JSON (no `kind` field on the receipt).
        let v01_json = r#"{
            "id": "rcpt_v01_0",
            "timestamp": "2026-05-12T00:00:00Z",
            "agent": "did:aid:example.com:legacy",
            "dat": "dat_legacy",
            "action": {
                "type": "mcp:tool-call",
                "tool": "read_file",
                "inputHash": "blake3:legacy",
                "status": "success"
            },
            "chain": {
                "previousHash": "genesis",
                "sequenceNumber": 0
            },
            "signature": "deadbeef"
        }"#;
        let r: Receipt = serde_json::from_str(v01_json).expect("v0.1 receipt must deserialise");
        assert_eq!(
            r.kind,
            ReceiptKind::Data,
            "missing `kind` must default to Data"
        );
    }

    /// `ReceiptKind::Data` is omitted from JSON output for v0.1 wire-format
    /// stability — round-tripping a v0.1 receipt through serde produces an
    /// identical serialised shape.
    #[test]
    fn test_idp002_data_kind_omitted_from_serialised_output() {
        let kp = KeyPair::generate();
        let r = make_receipt(&kp, 0, "genesis");
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(
            !json.contains("\"kind\""),
            "Data receipts must omit `kind` to preserve v0.1 wire format; got: {json}"
        );
    }

    /// A `ChainCheckpoint` receipt round-trips through serde with its
    /// discriminator preserved.
    #[test]
    fn test_idp002_chain_checkpoint_round_trip() {
        let chain = ChainLink {
            previous_hash: "blake3:test".to_string(),
            sequence_number: 100,
        };
        let action = ActionDetails {
            action_type: "idprova:checkpoint".to_string(),
            server: None,
            tool: None,
            input_hash: "blake3:checkpoint".to_string(),
            output_hash: None,
            status: "success".to_string(),
            duration_ms: None,
        };
        let r = Receipt {
            id: "rcpt_checkpoint".to_string(),
            timestamp: Utc::now(),
            agent: "did:aid:example.com:kai".to_string(),
            dat: "dat_checkpoint".to_string(),
            kind: ReceiptKind::ChainCheckpoint {
                prev_hash: "blake3:prev_data_receipt".to_string(),
                count: 100,
            },
            action,
            context: None,
            chain,
            signature: "placeholder".to_string(),
            anchor: None,
        };

        let json = serde_json::to_string(&r).expect("serialise checkpoint");
        assert!(
            json.contains("\"chain_checkpoint\""),
            "ChainCheckpoint discriminator must appear in JSON: {json}"
        );
        assert!(
            json.contains("\"prevHash\":\"blake3:prev_data_receipt\""),
            "prevHash field must be present in JSON: {json}"
        );
        assert!(
            json.contains("\"count\":100"),
            "count field must be present in JSON: {json}"
        );

        let decoded: Receipt = serde_json::from_str(&json).expect("deserialise checkpoint");
        match decoded.kind {
            ReceiptKind::ChainCheckpoint { prev_hash, count } => {
                assert_eq!(prev_hash, "blake3:prev_data_receipt");
                assert_eq!(count, 100);
            }
            other => panic!("expected ChainCheckpoint, got {other:?}"),
        }
    }

    /// `kind` is part of the signing payload for checkpoints (so tampering
    /// the kind invalidates the signature) but is omitted for `Data`
    /// receipts (so v0.1 signatures keep verifying under v0.2 code).
    #[test]
    fn test_idp002_kind_is_part_of_signing_payload_for_checkpoints_only() {
        let kp = KeyPair::generate();
        let r_data = make_receipt(&kp, 0, "genesis");
        let data_payload = r_data.signing_payload_bytes();
        let data_payload_str = String::from_utf8_lossy(&data_payload);
        assert!(
            !data_payload_str.contains("\"kind\""),
            "Data receipts must NOT include `kind` in signing payload \
             (preserves v0.1 signing compatibility); got: {data_payload_str}"
        );

        // Build a ChainCheckpoint receipt with the same other fields and
        // confirm its signing payload includes the discriminator.
        let mut r_ckpt = r_data.clone();
        r_ckpt.kind = ReceiptKind::ChainCheckpoint {
            prev_hash: "blake3:tamper_target".to_string(),
            count: 1,
        };
        let ckpt_payload = r_ckpt.signing_payload_bytes();
        let ckpt_payload_str = String::from_utf8_lossy(&ckpt_payload);
        assert!(
            ckpt_payload_str.contains("\"chain_checkpoint\""),
            "ChainCheckpoint receipts MUST include `kind` in signing payload: {ckpt_payload_str}"
        );

        // Tampering the kind (changing count) must change the signing
        // payload (i.e., the kind is signed, not just serialised).
        let mut r_tampered = r_ckpt.clone();
        r_tampered.kind = ReceiptKind::ChainCheckpoint {
            prev_hash: "blake3:tamper_target".to_string(),
            count: 999, // attacker-flipped value
        };
        assert_ne!(
            r_ckpt.signing_payload_bytes(),
            r_tampered.signing_payload_bytes(),
            "tampering the checkpoint count must change the signing payload"
        );
    }
}
