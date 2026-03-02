use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::hash::prefixed_blake3;

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

impl Receipt {
    /// Compute the BLAKE3 hash of this receipt (for chain linking).
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        prefixed_blake3(&canonical)
    }
}
