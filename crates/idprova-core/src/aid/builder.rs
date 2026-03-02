use chrono::Utc;

use super::document::*;
use crate::crypto::KeyPair;
use crate::{IdprovaError, Result};

/// Fluent builder for constructing AID documents.
pub struct AidBuilder {
    id: Option<String>,
    controller: Option<String>,
    name: Option<String>,
    description: Option<String>,
    model: Option<String>,
    runtime: Option<String>,
    config_attestation: Option<String>,
    verification_methods: Vec<VerificationMethod>,
    trust_level: Option<String>,
}

impl AidBuilder {
    pub fn new() -> Self {
        Self {
            id: None,
            controller: None,
            name: None,
            description: None,
            model: None,
            runtime: None,
            config_attestation: None,
            verification_methods: Vec::new(),
            trust_level: None,
        }
    }

    /// Set the DID identifier (e.g., "did:idprova:example.com:my-agent").
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the controller DID (e.g., "did:idprova:example.com:alice").
    pub fn controller(mut self, controller: impl Into<String>) -> Self {
        self.controller = Some(controller.into());
        self
    }

    /// Set the agent's human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set an optional description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the AI model identifier.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set the runtime environment.
    pub fn runtime(mut self, runtime: impl Into<String>) -> Self {
        self.runtime = Some(runtime.into());
        self
    }

    /// Set config attestation hash.
    pub fn config_attestation(mut self, hash: impl Into<String>) -> Self {
        self.config_attestation = Some(hash.into());
        self
    }

    /// Add an Ed25519 verification method from a keypair.
    pub fn add_ed25519_key(mut self, keypair: &KeyPair) -> Self {
        let did = self.id.clone().unwrap_or_default();
        self.verification_methods.push(VerificationMethod {
            id: "#key-ed25519".to_string(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: self.controller.clone().unwrap_or(did),
            public_key_multibase: keypair.public_key_multibase(),
        });
        self
    }

    /// Set the trust level.
    pub fn trust_level(mut self, level: impl Into<String>) -> Self {
        self.trust_level = Some(level.into());
        self
    }

    /// Build the AID document.
    pub fn build(self) -> Result<AidDocument> {
        let id = self
            .id
            .ok_or_else(|| IdprovaError::AidValidation("id is required".into()))?;
        let controller = self
            .controller
            .ok_or_else(|| IdprovaError::AidValidation("controller is required".into()))?;
        let name = self
            .name
            .ok_or_else(|| IdprovaError::AidValidation("name is required".into()))?;

        if self.verification_methods.is_empty() {
            return Err(IdprovaError::AidValidation(
                "at least one verification method required".into(),
            ));
        }

        let auth_refs: Vec<String> = self.verification_methods.iter().map(|vm| vm.id.clone()).collect();

        let metadata = AgentMetadata {
            name,
            description: self.description,
            model: self.model,
            runtime: self.runtime,
            config_attestation: self.config_attestation,
        };

        let service = vec![AidService {
            id: "#idprova-metadata".to_string(),
            service_type: "IdprovaAgentMetadata".to_string(),
            service_endpoint: serde_json::to_value(&metadata)?,
        }];

        let now = Utc::now();

        let doc = AidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://idprova.dev/v1".to_string(),
            ],
            id,
            controller,
            verification_method: self.verification_methods,
            authentication: auth_refs,
            service: Some(service),
            trust_level: self.trust_level,
            version: Some(1),
            created: Some(now),
            updated: Some(now),
            proof: None,
        };

        doc.validate()?;
        Ok(doc)
    }
}

impl Default for AidBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_build_minimal_aid() {
        let kp = KeyPair::generate();
        let doc = AidBuilder::new()
            .id("did:idprova:example.com:test-agent")
            .controller("did:idprova:example.com:alice")
            .name("Test Agent")
            .add_ed25519_key(&kp)
            .build()
            .unwrap();

        assert_eq!(doc.id, "did:idprova:example.com:test-agent");
        assert_eq!(doc.controller, "did:idprova:example.com:alice");
        assert_eq!(doc.verification_method.len(), 1);
        assert!(doc.proof.is_none());
    }

    #[test]
    fn test_build_full_aid() {
        let kp = KeyPair::generate();
        let doc = AidBuilder::new()
            .id("did:idprova:techblaze.com.au:kai")
            .controller("did:idprova:techblaze.com.au:pratyush")
            .name("Kai Lead Agent")
            .description("Primary orchestration agent")
            .model("anthropic/claude-opus-4")
            .runtime("openclaw/v2.1")
            .config_attestation("blake3:abcdef1234567890")
            .trust_level("L1")
            .add_ed25519_key(&kp)
            .build()
            .unwrap();

        assert_eq!(doc.trust_level.as_deref(), Some("L1"));
        assert!(doc.service.is_some());
    }

    #[test]
    fn test_build_missing_id_fails() {
        let kp = KeyPair::generate();
        let result = AidBuilder::new()
            .controller("did:idprova:example.com:alice")
            .name("Test")
            .add_ed25519_key(&kp)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_no_keys_fails() {
        let result = AidBuilder::new()
            .id("did:idprova:example.com:agent")
            .controller("did:idprova:example.com:alice")
            .name("Test")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let kp = KeyPair::generate();
        let doc = AidBuilder::new()
            .id("did:idprova:example.com:agent")
            .controller("did:idprova:example.com:alice")
            .name("Test Agent")
            .add_ed25519_key(&kp)
            .build()
            .unwrap();

        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: AidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.controller, doc.controller);
    }
}
