//! Cross-standard agent resolution.
use crate::store::TrustStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAgent {
    pub did_aid: String,
    pub attestations: Vec<String>,
    pub trust_status: String,
}

pub trait ResolverBackend: Send + Sync {
    fn try_resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent>;
}

pub struct CrossStandardResolver {
    pub backends: Vec<Box<dyn ResolverBackend>>,
}

impl CrossStandardResolver {
    pub fn resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent> {
        self.backends
            .iter()
            .find_map(|backend| backend.try_resolve(agent_ref))
    }
}

/// Resolves `did:aid:` references against the trust store.
pub struct DidAidBackend {
    pub store: Arc<dyn TrustStore>,
}

impl ResolverBackend for DidAidBackend {
    fn try_resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent> {
        match agent_ref {
            AgentRef::DidAid(did) => {
                idprova_core::aid::AidIdentifier::parse(did).ok()?;
                let issuer = self.store.get_issuer(did).ok()??;
                Some(ResolvedAgent {
                    did_aid: did.clone(),
                    attestations: issuer.credential_types.clone(),
                    trust_status: format!("{:?}", issuer.status),
                })
            }
            // TODO: cross-standard envelope->did:aid mapping table (follow-up round)
            _ => None,
        }
    }
}
