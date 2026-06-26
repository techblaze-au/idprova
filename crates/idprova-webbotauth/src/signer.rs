//! HTTP Message Signer.
//!
//! Handles the creation of HTTP signatures for outbound requests.

use super::components::{build_signature_base, Component};
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
        // 1. Build the Signature-Input inner list (covered components + signature params).
        //    Each covered component is a SEPARATE string item in the inner list.
        let label = "sig1"; // TODO: support custom labels
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

        // 2. Serialize the VERBATIM @signature-params VALUE (the `(...);params` string,
        //    WITHOUT a label) by serializing a one-element List. This exact value is both
        //    fed into the signature base AND carried in the Signature-Input header, so the
        //    bytes the verifier reconstructs are identical (RFC 9421 §2.5).
        let sig_params_value =
            crate::sfv::serialize_list(&vec![ListEntry::InnerList(inner.clone())])?;

        // 3. Build the signature base from the verbatim params value, then sign.
        let base = build_signature_base(req, covered, &sig_params_value)?;
        let signature = self.signing_key.sign(base.as_bytes());
        let sig_bytes = signature.to_bytes();

        // 4. Signature-Input header value: label=(...);params. Equivalent to the dictionary
        //    serialization below; we keep the dictionary form for a canonical header string.
        let mut si_dict: Dictionary = Dictionary::new();
        si_dict.insert(label.to_string(), ListEntry::InnerList(inner));
        let sig_input_val = si_dict
            .serialize_value()
            .map_err(|e| crate::Error::InvalidStructuredField(e.to_string()))?;

        // 5. Signature header value: label=:<base64 byte sequence>:
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

        // 6. Signature-Agent header
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

    /// Verifies the OFFICIAL RFC 9421 Appendix B.2.6 Ed25519 test vector end-to-end.
    ///
    /// The base, params (note: NO `alg`), label (`sig-b26`), and signature are taken verbatim
    /// from the RFC. A passing result proves our signature-base construction is conformant.
    #[test]
    fn test_rfc_9421_appendix_b_ed25519() {
        use crate::components::Component;
        use crate::request::SignableRequest;
        use crate::verifier::{HttpVerifier, KeyResolver, VerifyOutcome};
        use ed25519_dalek::VerifyingKey;

        // test-key-ed25519 public key (RFC 9421 B.1.4), raw 32 bytes.
        let pk_hex = "26b40b8f93fff3d897112f7ebc582b232dbd72517d082fe83cfb30ddce43d1bb";
        let mut pk = [0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&pk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let vk = VerifyingKey::from_bytes(&pk).unwrap();

        struct R(VerifyingKey);
        impl KeyResolver for R {
            fn resolve(&self, keyid: &str) -> Option<VerifyingKey> {
                if keyid == "test-key-ed25519" {
                    Some(self.0)
                } else {
                    None
                }
            }
        }

        // RFC B.2 test-request — only the covered fields matter; headers lowercased.
        let mut req =
            SignableRequest::new("POST", "example.com", "/foo", Some("param=Value&Pet=dog"));
        req.headers
            .insert("date".into(), "Tue, 20 Apr 2021 02:07:55 GMT".into());
        req.headers
            .insert("content-type".into(), "application/json".into());
        req.headers.insert("content-length".into(), "18".into());

        let si = crate::sfv::parse_dictionary(
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        )
        .unwrap();
        let sg = crate::sfv::parse_dictionary(
            "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
        )
        .unwrap();

        let outcome = HttpVerifier::verify(
            &req,
            &si,
            &sg,
            &R(vk),
            1618884473,
            &[Component::Method, Component::Path, Component::Authority],
        );
        assert_eq!(
            outcome,
            VerifyOutcome::Valid,
            "official RFC 9421 B.2.6 Ed25519 vector must verify"
        );
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
