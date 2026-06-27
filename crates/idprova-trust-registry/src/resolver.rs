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

impl DidAidBackend {
    fn resolve_did_aid(&self, did: &str) -> Option<ResolvedAgent> {
        idprova_core::aid::AidIdentifier::parse(did).ok()?;
        let issuer = self.store.get_issuer(did).ok()??;
        Some(ResolvedAgent {
            did_aid: did.to_string(),
            attestations: issuer.credential_types.clone(),
            trust_status: format!("{:?}", issuer.status),
        })
    }
}

impl ResolverBackend for DidAidBackend {
    fn try_resolve(&self, agent_ref: &AgentRef) -> Option<ResolvedAgent> {
        match agent_ref {
            AgentRef::DidAid(did) => self.resolve_did_aid(did),
            AgentRef::WebBotAuthKey { keyid, .. } => {
                let did_aid = self
                    .store
                    .resolve_external_ref("webbotauth_keyid", keyid)
                    .ok()??;
                self.resolve_did_aid(&did_aid)
            }
            AgentRef::Ap2Issuer(id) => {
                let did_aid = self.store.resolve_external_ref("ap2_issuer", id).ok()??;
                self.resolve_did_aid(&did_aid)
            }
            AgentRef::McpClient(id) => {
                let did_aid = self.store.resolve_external_ref("mcp_client", id).ok()??;
                self.resolve_did_aid(&did_aid)
            }
            AgentRef::EntraAgent(id) => {
                let did_aid = self.store.resolve_external_ref("entra_agent", id).ok()??;
                self.resolve_did_aid(&did_aid)
            }
        }
    }
}
