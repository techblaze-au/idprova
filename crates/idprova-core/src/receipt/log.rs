use crate::{IdprovaError, Result};
use super::entry::Receipt;

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

    /// Verify the integrity of the entire chain.
    pub fn verify_integrity(&self) -> Result<()> {
        let mut expected_prev = "genesis".to_string();

        for (i, receipt) in self.entries.iter().enumerate() {
            // Check sequence number
            if receipt.chain.sequence_number != i as u64 {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }

            // Check previous hash linkage
            if receipt.chain.previous_hash != expected_prev {
                return Err(IdprovaError::ReceiptChainBroken(i as u64));
            }

            // Update expected previous hash for next iteration
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
