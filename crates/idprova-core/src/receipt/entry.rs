use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::hash::prefixed_blake3;
use crate::crypto::KeyPair;
use crate::{IdprovaError, Result};

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
    /// Action details.
    pub action: ActionDetails,
    /// Optional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ReceiptContext>,
    /// Hash chain linkage.
    pub chain: ChainLink,
    /// Agent's signature over this receipt.
    pub signature: String,
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
    pub fn signing_payload_bytes(&self) -> Vec<u8> {
        let payload = ReceiptSigningPayload {
            id: &self.id,
            timestamp: &self.timestamp,
            agent: &self.agent,
            dat: &self.dat,
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
            action,
            context: None,
            chain,
            signature: String::new(), // placeholder
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
}
