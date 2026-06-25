//! Cross-standard agent resolution.

use serde::{Deserialize, Serialize};

/// A reference to an agent across various standards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentRef {
    DidAid(String),
    WebBotAuthKey {
        keyid: String,
        directory_url: String,
    },
    Ap2Issuer(String),
    McpClient(String),
    EntraAgent(String),
}

/// The resolved state of an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAgent {
    pub did_aid: String,
    pub attestations: Vec<String>, // Simplified for design phase
    pub trust_status: String,
}

/// Backend trait for resolving specific `AgentRef` types.
pub trait ResolverBackend: Send + Sync {
    /// Attempts to resolve an `AgentRef` to a `ResolvedAgent`.
    /// Returns `None` if the backend does not support this reference type.
    fn try_resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent>;
}

/// Coordinates resolution across multiple backends.
pub struct CrossStandardResolver {
    pub backends: Vec<Box<dyn ResolverBackend>>,
}

impl CrossStandardResolver {
    /// Attempts to resolve an agent using its registered backends.
    pub fn resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent> {
        self.backends
            .iter()
            .find_map(|backend| backend.try_resolve(agent_ref))
    }
}
