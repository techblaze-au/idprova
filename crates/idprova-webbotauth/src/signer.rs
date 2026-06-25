//! HTTP Message Signer.
//!
//! Handles the creation of HTTP signatures for outbound requests.

use super::components::{build_signature_base, Component, SignatureParams};
use super::request::SignableRequest;
use super::Result;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

/// Container for the generated HTTP headers needed to sign a request.
#[derive(Debug, Clone)]
pub struct SignatureHeaders {
    /// The `Signature-Input` header value.
    pub sig_input_value: String,
    /// The `Signature` header value.
    pub sig_value: String,
    /// The `Signature-Agent` header value (directory URI).
    pub agent_value: String,
}

/// Signer for HTTP requests.
pub struct HttpSigner {
    /// The Key ID (RFC 7638 thumbprint).
    pub keyid: String,
    /// The Ed25519 signing key.
    pub signing_key: SigningKey,
    /// Application-specific tag (optional).
    pub tag: Option<String>,
}

impl HttpSigner {
    /// Create a new signer.
    pub fn new(keyid: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            keyid: keyid.into(),
            signing_key,
            tag: None,
        }
    }

    /// Sign an HTTP request.
    ///
    /// # Arguments
    /// * `req` - The request to sign.
    /// * `covered` - List of components to cover.
    /// * `created` - Unix timestamp of creation.
    /// * `expires` - Optional Unix timestamp of expiration.
    /// * `directory_uri` - The URI for the `Signature-Agent` header.
    pub fn sign(
        &self,
        req: &SignableRequest,
        covered: &[Component],
        created: i64,
        expires: Option<i64>,
        directory_uri: &str,
    ) -> Result<SignatureHeaders> {
        // 1. Construct Signature Params
        let params = SignatureParams {
            keyid: self.keyid.clone(),
            created,
            expires,
            alg: "ed25519".to_string(),
            nonce: None, // TODO: expose in API if needed
            tag: self.tag.clone(),
        };

        // 2. Build Signature Base
        let base = build_signature_base(req, covered, &params)?;

        // 3. Sign
        let signature = self.signing_key.sign(base.as_bytes());
        let sig_bytes = signature.to_bytes();

        // 4. Serialize Headers (SFV)
        // Signature-Input: label=(params)
        let label = "sig1"; // TODO: support custom labels
        let param_str = params.to_param_string();
        let covered_list = covered
            .iter()
            .filter_map(|c| {
                if c == &Component::SignatureParams {
                    None
                } else {
                    Some(c.name())
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        // Manual SFV construction for efficiency
        let sig_input_val = format!("{}=(\"{}\");{}", label, covered_list, param_str);

        // Signature: label=:base64:
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
        let sig_val = format!("{}={}", label, sig_b64);

        // 5. Signature-Agent header
        let agent_val = directory_uri.to_string();

        Ok(SignatureHeaders {
            sig_input_value: sig_input_val,
            sig_value: sig_val,
            agent_value: agent_val,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9421 Appendix-B Ed25519 vector placeholder
    #[test]
    #[ignore]
    fn test_rfc_9421_appendix_b() {
        // "The test vector for Ed25519 (Appendix B) verifies that the base construction
        // and signature logic conform to the RFC."
        todo!("Run against RFC 9421 Appendix B vectors");
    }
}
