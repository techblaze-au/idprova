use super::entry::Receipt;
use crate::{IdprovaError, Result};

/// An append-only, hash-chained receipt log.
pub struct ReceiptLog {
    entries: Vec<Receipt>,
}

impl ReceiptLog {
    /// Create a new empty receipt log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create a log from existing entries (e.g., loaded from disk).
    pub fn from_entries(entries: Vec<Receipt>) -> Self {
        Self { entries }
    }

    /// Append a receipt to the log.
    pub fn append(&mut self, receipt: Receipt) {
        self.entries.push(receipt);
    }

    /// Get the hash of the last receipt (for chain linking).
    pub fn last_hash(&self) -> String {
        self.entries
            .last()
            .map(|r| r.compute_hash())
            .unwrap_or_else(|| "genesis".to_string())
    }

    /// Get the next sequence number.
    pub fn next_sequence(&self) -> u64 {
        self.entries
            .last()
            .map(|r| r.chain.sequence_number + 1)
            .unwrap_or(0)
    }

    /// Verify the integrity of the hash chain (sequence numbers + previous_hash linkage).
    ///
    /// This does NOT verify receipt signatures — use `verify_integrity_with_key()` for
    /// full cryptographic verification including signature checks.
    pub fn verify_integrity(&self) -> Result<()> {
        let mut expected_prev = "genesis".to_string();

        for (i, receipt) in self.entries.iter().enumerate() {
            if receipt.chain.sequence_number != i as u64 {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }
            if receipt.chain.previous_hash != expected_prev {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }
            expected_prev = receipt.compute_hash();
        }

        Ok(())
    }

    /// Verify full cryptographic integrity: hash chain linkage AND each receipt's signature.
    ///
    /// # Security: fix S2 (receipt signatures were never verified)
    ///
    /// Without signature verification, an attacker with write access can forge receipts
    /// with correct hash chaining — invalidating the entire compliance audit trail.
    ///
    /// `public_key_bytes` is the Ed25519 public key of the agent that signed the receipts.
    /// For multi-agent logs, use `verify_integrity_with_resolver()` (future).
    pub fn verify_integrity_with_key(&self, public_key_bytes: &[u8; 32]) -> Result<()> {
        let mut expected_prev = "genesis".to_string();

        for (i, receipt) in self.entries.iter().enumerate() {
            if receipt.chain.sequence_number != i as u64 {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }
            if receipt.chain.previous_hash != expected_prev {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }

            // Verify cryptographic signature on this receipt
            receipt.verify_signature(public_key_bytes).map_err(|_| {
                IdprovaError::InvalidReceipt(format!(
                    "receipt {} (seq {i}) has invalid signature",
                    receipt.id
                ))
            })?;

            expected_prev = receipt.compute_hash();
        }

        Ok(())
    }

    /// Get all entries.
    pub fn entries(&self) -> &[Receipt] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::receipt::entry::{ActionDetails, ChainLink};
    use chrono::Utc;

    fn make_signed_receipt(kp: &KeyPair, seq: u64, prev_hash: &str) -> Receipt {
        let chain = ChainLink {
            previous_hash: prev_hash.to_string(),
            sequence_number: seq,
        };
        let action = ActionDetails {
            action_type: "mcp:tool-call".to_string(),
            server: None,
            tool: None,
            input_hash: "blake3:test".to_string(),
            output_hash: None,
            status: "success".to_string(),
            duration_ms: None,
        };
        let mut r = Receipt {
            id: format!("rcpt_{seq}"),
            timestamp: Utc::now(),
            agent: "did:aid:example.com:agent".to_string(),
            dat: "dat_test".to_string(),
            action,
            context: None,
            chain,
            signature: String::new(),
        };
        let sig = kp.sign(&r.signing_payload_bytes());
        r.signature = hex::encode(sig);
        r
    }

    fn build_log(kp: &KeyPair, count: usize) -> ReceiptLog {
        let mut log = ReceiptLog::new();
        for i in 0..count {
            let prev = log.last_hash();
            let r = make_signed_receipt(kp, i as u64, &prev);
            log.append(r);
        }
        log
    }

    #[test]
    fn test_verify_integrity_passes_for_valid_chain() {
        let kp = KeyPair::generate();
        let log = build_log(&kp, 5);
        assert!(log.verify_integrity().is_ok());
    }

    /// S2: verify_integrity_with_key() must catch forged receipts.
    ///
    /// An attacker with write access can create a receipt with correct hash
    /// chaining but an invalid signature. This must be rejected.
    #[test]
    fn test_s2_forged_receipt_rejected_by_integrity_with_key() {
        let kp = KeyPair::generate();
        let mut log = build_log(&kp, 3);
        let pub_bytes = kp.public_key_bytes();

        // Passes with correct key
        assert!(log.verify_integrity_with_key(&pub_bytes).is_ok());

        // Forge the last receipt by mutating the action after signing
        let last = log.entries.last_mut().unwrap();
        last.action.status = "forged_by_attacker".to_string();

        // Hash chain still passes (attacker got the structure right)
        // but signature check must catch the tampering
        assert!(
            log.verify_integrity_with_key(&pub_bytes).is_err(),
            "forged receipt must be rejected by verify_integrity_with_key"
        );
    }

    #[test]
    fn test_verify_integrity_with_key_rejects_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let log = build_log(&kp1, 3);
        let wrong_pub = kp2.public_key_bytes();
        assert!(
            log.verify_integrity_with_key(&wrong_pub).is_err(),
            "wrong key must fail verify_integrity_with_key"
        );
    }
}
