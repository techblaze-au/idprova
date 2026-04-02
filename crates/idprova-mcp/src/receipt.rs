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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_log_is_empty() {
        let log = McpReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_log_tool_call() {
        let mut log = McpReceiptLog::new();
        let r = log.log_tool_call(
            "did:aid:test:agent",
            "dat_123",
            "read_file",
            "blake3:abc",
            Some("blake3:def"),
        );
        assert_eq!(r.agent, "did:aid:test:agent");
        assert_eq!(r.action.tool.as_deref(), Some("read_file"));
        assert_eq!(r.action.status, "success");
        assert_eq!(r.chain.sequence_number, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_log_denial() {
        let mut log = McpReceiptLog::new();
        let r = log.log_denial(
            "did:aid:test:agent",
            "dat_123",
            "write_file",
            "insufficient scope",
        );
        assert!(r.action.status.contains("denied"));
        assert!(r.action.status.contains("insufficient scope"));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_chain_sequence_numbers() {
        let mut log = McpReceiptLog::new();
        log.log_tool_call("did:aid:test:a", "dat_1", "tool1", "h1", None);
        log.log_tool_call("did:aid:test:a", "dat_1", "tool2", "h2", None);
        log.log_denial("did:aid:test:b", "dat_2", "tool3", "denied");

        assert_eq!(log.len(), 3);
        let entries = log.entries();
        assert_eq!(entries[0].chain.sequence_number, 0);
        assert_eq!(entries[1].chain.sequence_number, 1);
        assert_eq!(entries[2].chain.sequence_number, 2);
    }

    #[test]
    fn test_chain_integrity() {
        let mut log = McpReceiptLog::new();
        log.log_tool_call("did:aid:test:a", "dat_1", "tool1", "h1", None);
        log.log_tool_call("did:aid:test:a", "dat_1", "tool2", "h2", None);
        log.log_tool_call("did:aid:test:a", "dat_1", "tool3", "h3", None);

        assert!(log.verify_integrity().is_ok());
    }

    #[test]
    fn test_genesis_hash_link() {
        let mut log = McpReceiptLog::new();
        log.log_tool_call("did:aid:test:a", "dat_1", "tool1", "h1", None);
        assert_eq!(log.entries()[0].chain.previous_hash, "genesis");
    }

    #[test]
    fn test_default_creates_empty() {
        let log = McpReceiptLog::default();
        assert!(log.is_empty());
    }
}
