//! HTTP Message Signer.
//!
//! Handles the creation of HTTP signatures for outbound requests.

use super::components::{build_signature_base, Component, SignatureParams};
use super::request::SignableRequest;
use super::Result;
use ed25519_dalek::{Signer, SigningKey};
use sfv::{BareItem, Dictionary, InnerList, Item, ListEntry, Num, Parameters, SerializeValue};

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

        // 4. Serialize Headers via the sfv crate (RFC 8941) so they are valid
        //    structured fields and round-trip with the verifier.
        let label = "sig1"; // TODO: support custom labels

        // Signature-Input: label=("@method" "@authority" ...);created=...;keyid=...;alg=...
        // Each covered component is a SEPARATE string item in the inner list.
        let items: Vec<Item> = covered
            .iter()
            .filter(|c| **c != Component::SignatureParams)
            .map(|c| Item(BareItem::String(c.name().to_string()), Parameters::new()))
            .collect();

        // Insertion order MUST match SignatureParams::to_param_string so the
        // signer's signed base equals the verifier's reconstructed base:
        // created, keyid, alg, [expires, tag]. (nonce is always None here.)
        let mut sig_params = Parameters::new();
        sig_params.insert(
            "created".to_string(),
            BareItem::Number(Num::Integer(created)),
        );
        sig_params.insert("keyid".to_string(), BareItem::String(self.keyid.clone()));
        sig_params.insert("alg".to_string(), BareItem::String("ed25519".to_string()));
        if let Some(exp) = expires {
            sig_params.insert("expires".to_string(), BareItem::Number(Num::Integer(exp)));
        }
        if let Some(tag) = &self.tag {
            sig_params.insert("tag".to_string(), BareItem::String(tag.clone()));
        }

        let inner = InnerList(items, sig_params);
        let mut si_dict: Dictionary = Dictionary::new();
        si_dict.insert(label.to_string(), ListEntry::InnerList(inner));
        let sig_input_val = si_dict
            .serialize_value()
            .map_err(|e| crate::Error::InvalidStructuredField(e.to_string()))?;

        // Signature: label=:<base64 byte sequence>:
        let mut sig_dict: Dictionary = Dictionary::new();
        sig_dict.insert(
            label.to_string(),
            ListEntry::Item(Item(
                BareItem::ByteSeq(sig_bytes.to_vec()),
                Parameters::new(),
            )),
        );
        let sig_val = sig_dict
            .serialize_value()
            .map_err(|e| crate::Error::InvalidStructuredField(e.to_string()))?;

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
    use crate::components::Component;
    use crate::request::SignableRequest;
    use crate::verifier::{HttpVerifier, KeyResolver, VerifyOutcome};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;

    // RFC 9421 Appendix-B Ed25519 vector placeholder
    #[test]
    #[ignore]
    fn test_rfc_9421_appendix_b() {
        // "The test vector for Ed25519 (Appendix B) verifies that the base construction
        // and signature logic conform to the RFC."
        todo!("Run against RFC 9421 Appendix B vectors");
    }

    struct OneKey(ed25519_dalek::VerifyingKey);
    impl KeyResolver for OneKey {
        fn resolve(&self, keyid: &str) -> Option<ed25519_dalek::VerifyingKey> {
            if keyid == "test-key" {
                Some(self.0)
            } else {
                None
            }
        }
    }

    /// End-to-end: a request signed by `HttpSigner` must verify via `HttpVerifier`
    /// after the headers are parsed back through the sfv helpers.
    #[test]
    fn test_sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let signer = HttpSigner::new("test-key", sk);
        let req = SignableRequest::new("POST", "example.com", "/foo", None::<&str>);
        let covered = vec![Component::Method, Component::Authority, Component::Path];
        let now = Utc::now().timestamp();
        let headers = signer
            .sign(
                &req,
                &covered,
                now - 10,
                Some(now + 300),
                "https://dir.example/keys",
            )
            .unwrap();
        let si = crate::sfv::parse_dictionary(&headers.sig_input_value).expect("sig-input parses");
        let sg = crate::sfv::parse_dictionary(&headers.sig_value).expect("signature parses");
        let outcome = HttpVerifier::verify(
            &req,
            &si,
            &sg,
            &OneKey(vk),
            now,
            &[Component::Method, Component::Authority, Component::Path],
        );
        assert_eq!(outcome, VerifyOutcome::Valid, "round-trip must verify");
    }
}
