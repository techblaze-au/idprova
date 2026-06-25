//! DIF Presentation Exchange adapter.

use crate::model::{DataIntegrityProof, VerifiableCredential, VerifiablePresentation};

/// Defines required inputs for a presentation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes a specific constraint on an input VC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    pub schema: Vec<String>,
    pub constraints: serde_json::Value,
}

/// Maps presented credentials to definition requirements.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMap>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DescriptorMap {
    pub id: String,
    pub format: String,
    pub path: String,
}

/// Outcome of evaluating a presentation against a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalOutcome {
    Valid,
    Invalid(String),
}

/// Builds a Verifiable Presentation from a set of credentials matching a definition.
pub fn build_submission(
    def: &PresentationDefinition,
    creds: Vec<VerifiableCredential>,
    proof: DataIntegrityProof,
) -> (VerifiablePresentation, PresentationSubmission) {
    let submission = PresentationSubmission {
        id: format!("urn:uuid:{}", chrono::Utc::now().timestamp()),
        definition_id: def.id.clone(),
        descriptor_map: def
            .input_descriptors
            .iter()
            .enumerate()
            .map(|(i, d)| DescriptorMap {
                id: d.id.clone(),
                format: "ldp_vc".to_string(),
                path: format!("$.verifiableCredential[{}]", i),
            })
            .collect(),
    };

    let vp = VerifiablePresentation {
        context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
        types: vec!["VerifiablePresentation".to_string()],
        verifiable_credential: creds,
        proof,
    };

    (vp, submission)
}

/// Evaluates a Verifiable Presentation against a Definition.
pub fn evaluate(def: &PresentationDefinition, vp: &VerifiablePresentation) -> EvalOutcome {
    // TODO: Implement actual JSONPath / JSON-LD framing evaluation
    if vp.verifiable_credential.is_empty() {
        return EvalOutcome::Invalid("No credentials provided".to_string());
    }

    EvalOutcome::Valid
}
