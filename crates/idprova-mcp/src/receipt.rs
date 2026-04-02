//! Receipt logging for MCP tool calls — wraps `idprova_core::receipt::ReceiptLog`.

use chrono::Utc;
use idprova_core::receipt::entry::{ActionDetails, ChainLink};
use idprova_core::receipt::{Receipt, ReceiptLog};

/// MCP-aware receipt log for recording tool calls and denials.
pub struct McpReceiptLog {
    inner: ReceiptLog,
}

impl McpReceiptLog {
    /// Create a new empty receipt log.
    pub fn new() -> Self {
        Self {
            inner: ReceiptLog::new(),
        }
    }

    /// Log a successful MCP tool call.
    pub fn log_tool_call(
        &mut self,
        agent_did: &str,
        dat_jti: &str,
        tool_name: &str,
        input_hash: &str,
        output_hash: Option<&str>,
    ) -> &Receipt {
        let receipt = Receipt {
            id: format!("rcpt_{}", ulid::Ulid::new()),
            timestamp: Utc::now(),
            agent: agent_did.to_string(),
            dat: dat_jti.to_string(),
            action: ActionDetails {
                action_type: "mcp:tool-call".to_string(),
                server: None,
                tool: Some(tool_name.to_string()),
                input_hash: input_hash.to_string(),
                output_hash: output_hash.map(|s| s.to_string()),
                status: "success".to_string(),
                duration_ms: None,
            },
            context: None,
            chain: ChainLink {
                previous_hash: self.inner.last_hash(),
                sequence_number: self.inner.next_sequence(),
            },
            signature: String::new(),
        };
        self.inner.append(receipt);
        self.inner.entries().last().unwrap()
    }

    /// Log a denied MCP tool call (scope or auth failure).
    pub fn log_denial(
        &mut self,
        agent_did: &str,
        dat_jti: &str,
        tool_name: &str,
        reason: &str,
    ) -> &Receipt {
        let receipt = Receipt {
            id: format!("rcpt_{}", ulid::Ulid::new()),
            timestamp: Utc::now(),
            agent: agent_did.to_string(),
            dat: dat_jti.to_string(),
            action: ActionDetails {
                action_type: "mcp:tool-call".to_string(),
                server: None,
                tool: Some(tool_name.to_string()),
                input_hash: "n/a".to_string(),
                output_hash: None,
                status: format!("denied: {reason}"),
                duration_ms: None,
            },
            context: None,
            chain: ChainLink {
                previous_hash: self.inner.last_hash(),
                sequence_number: self.inner.next_sequence(),
            },
            signature: String::new(),
        };
        self.inner.append(receipt);
        self.inner.entries().last().unwrap()
    }

    /// Get all receipt entries.
    pub fn entries(&self) -> &[Receipt] {
        self.inner.entries()
    }

    /// Get the number of receipts.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Verify the hash chain integrity.
    pub fn verify_integrity(&self) -> idprova_core::Result<()> {
        self.inner.verify_integrity()
    }

    /// Get a reference to the inner ReceiptLog.
    pub fn inner(&self) -> &ReceiptLog {
        &self.inner
    }
}

impl Default for McpReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}
