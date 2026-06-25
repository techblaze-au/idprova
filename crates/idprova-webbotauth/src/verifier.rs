//! HTTP Message Verifier.
//!
//! Handles verification of inbound signed requests.

use super::components::{build_signature_base, Component, SignatureParams};
use super::request::SignableRequest;
use super::Error;
use super::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sfv::{BareItem, Dictionary, Num};

/// Outcome of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Signature is valid.
    Valid,
    /// Signature is invalid (crypto fail).
    InvalidSignature,
    /// Signature expired or not yet valid.
    InvalidTime,
    /// Required components missing.
    MissingComponents,
    /// Key ID not found.
    KeyNotFound,
}

/// Resolver for finding verifying keys by Key ID.
pub trait KeyResolver {
    /// Resolve a Key ID to a Verifying Key.
    fn resolve(&self, keyid: &str) -> Option<VerifyingKey>;
}

/// HTTP Request Verifier.
pub struct HttpVerifier;

impl HttpVerifier {
    /// Verify a request.
    ///
    /// # Arguments
    /// * `req` - The request being verified.
    /// * `sig_input_dict` - The parsed `Signature-Input` dictionary.
    /// * `sig_dict` - The parsed `Signature` dictionary.
    /// * `resolver` - Trait object to resolve keys.
    /// * `now` - Current time (Unix timestamp) for checking validity.
    /// * `required_components` - Components that MUST be present in the covered list.
    pub fn verify(
        req: &SignableRequest,
        sig_input_dict: &Dictionary,
        sig_dict: &Dictionary,
        resolver: &impl KeyResolver,
        now: i64,
        required_components: &[Component],
    ) -> VerifyOutcome {
        // 1. Extract label and params (Simplified: assuming single entry "sig1")
        let label = "sig1";
        let entry = match sig_input_dict.get(label) {
            Some(e) => e,
            None => return VerifyOutcome::InvalidSignature,
        };

        // 2. Parse Signature Params from the entry
        let params = match Self::extract_params_from_entry(entry) {
            Ok(p) => p,
            Err(_) => return VerifyOutcome::InvalidSignature,
        };

        // 3. Check Time
        if params.created > now {
            return VerifyOutcome::InvalidTime;
        }
        if let Some(exp) = params.expires {
            if exp <= now {
                return VerifyOutcome::InvalidTime;
            }
        }

        // 4. Check Required Components
        // We need to reconstruct the covered list from the SFV entry.
        // This requires parsing the Item's parameters or the value if it's a List.
        // For this skeleton, we assume the `covered` list is passed implicitly or derived.
        // Actually, RFC 9421 says the covered list is in the param values of the Signature-Input.
        // SFV parser: `Item` has parameters.
        // The spec says: `Signature-Input: sig1=("@method" "@path");created=...`
        // The value of `sig1` is a List of strings.

        // Since `sfv` crate parsing details are complex for a skeleton, we assume:
        // We have extracted `covered_components` from the entry value (List).
        let covered_components = match Self::extract_covered_from_entry(entry) {
            Ok(c) => c,
            Err(_) => return VerifyOutcome::MissingComponents,
        };

        for req_comp in required_components {
            if !covered_components.contains(req_comp) {
                return VerifyOutcome::MissingComponents;
            }
        }

        // 5. Reconstruct Base
        let base = match build_signature_base(req, &covered_components, &params) {
            Ok(b) => b,
            Err(_) => return VerifyOutcome::MissingComponents,
        };

        // 6. Resolve Key
        let vk = match resolver.resolve(&params.keyid) {
            Some(k) => k,
            None => return VerifyOutcome::KeyNotFound,
        };

        // 7. Verify Signature
        let sig_entry = match sig_dict.get(label) {
            Some(e) => e,
            None => return VerifyOutcome::InvalidSignature,
        };

        let sig_bytes = match Self::extract_signature_bytes(sig_entry) {
            Ok(b) => b,
            Err(_) => return VerifyOutcome::InvalidSignature,
        };

        match vk.verify(base.as_bytes(), &sig_bytes) {
            Ok(()) => VerifyOutcome::Valid,
            Err(_) => VerifyOutcome::InvalidSignature,
        }
    }

    /// Extract the signature parameters (`keyid`, `created`, `alg`, ...) from the
    /// `Signature-Input` inner-list entry's parameters.
    fn extract_params_from_entry(entry: &sfv::ListEntry) -> Result<SignatureParams> {
        let inner = match entry {
            sfv::ListEntry::InnerList(il) => il,
            _ => return Err(Error::InvalidStructuredField("expected inner list".into())),
        };
        let params = &inner.1;

        let keyid = params
            .get("keyid")
            .and_then(as_string)
            .ok_or_else(|| Error::MissingComponent("keyid".into()))?;

        let created = params
            .get("created")
            .and_then(as_int)
            .ok_or_else(|| Error::MissingComponent("created".into()))?;

        let alg = params
            .get("alg")
            .and_then(as_string)
            .unwrap_or_else(|| "ed25519".to_string());

        let expires = params.get("expires").and_then(as_int);
        let nonce = params.get("nonce").and_then(as_string);
        let tag = params.get("tag").and_then(as_string);

        Ok(SignatureParams {
            keyid,
            created,
            expires,
            alg,
            nonce,
            tag,
        })
    }

    /// Extract the ordered list of covered components from the `Signature-Input`
    /// inner-list entry's items.
    fn extract_covered_from_entry(entry: &sfv::ListEntry) -> Result<Vec<Component>> {
        let inner = match entry {
            sfv::ListEntry::InnerList(il) => il,
            _ => return Err(Error::InvalidStructuredField("expected inner list".into())),
        };

        let mut covered = Vec::with_capacity(inner.0.len());
        for item in &inner.0 {
            let s = match &item.0 {
                BareItem::String(s) => s,
                _ => {
                    return Err(Error::InvalidStructuredField(
                        "covered component must be a string".into(),
                    ))
                }
            };
            let component = match s.as_str() {
                "@method" => Component::Method,
                "@authority" => Component::Authority,
                "@path" => Component::Path,
                "@query" => Component::Query,
                "@signature-params" => Component::SignatureParams,
                other => Component::Header(other.to_lowercase()),
            };
            covered.push(component);
        }
        Ok(covered)
    }

    /// Extract the raw signature bytes from the `Signature` dictionary entry,
    /// which is an `Item` carrying a byte sequence.
    fn extract_signature_bytes(entry: &sfv::ListEntry) -> Result<Signature> {
        let item = match entry {
            sfv::ListEntry::Item(it) => it,
            _ => return Err(Error::InvalidStructuredField("expected item".into())),
        };
        let bytes = match &item.0 {
            BareItem::ByteSeq(b) => b,
            _ => {
                return Err(Error::InvalidStructuredField(
                    "expected byte sequence".into(),
                ))
            }
        };
        Signature::from_slice(bytes).map_err(|e| Error::Crypto(e.to_string()))
    }
}

/// Helper: extract a `String` bare item.
fn as_string(b: &BareItem) -> Option<String> {
    if let BareItem::String(s) = b {
        Some(s.clone())
    } else {
        None
    }
}

/// Helper: extract an integer bare item.
fn as_int(b: &BareItem) -> Option<i64> {
    if let BareItem::Number(Num::Integer(i)) = b {
        Some(*i)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    struct DummyResolver;

    impl KeyResolver for DummyResolver {
        fn resolve(&self, _: &str) -> Option<VerifyingKey> {
            None
        }
    }

    #[test]
    fn test_verify_missing_key() {
        // A well-formed Signature-Input/Signature pair whose keyid the resolver
        // cannot resolve must yield KeyNotFound (not InvalidSignature).
        let req = SignableRequest::new("GET", "example.com", "/", None::<&str>);

        let created = Utc::now().timestamp() - 60;
        // 64-byte (Ed25519-sized) all-zero signature, base64-encoded for the
        // structured-field byte sequence `:...:`.
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);

        let sig_input = super::super::sfv::parse_dictionary(&format!(
            r#"sig1=("@method");created={};keyid="unknown-key";alg="ed25519""#,
            created
        ))
        .expect("valid signature-input");
        let sig = super::super::sfv::parse_dictionary(&format!("sig1=:{}:", sig_b64))
            .expect("valid signature");

        let outcome = HttpVerifier::verify(
            &req,
            &sig_input,
            &sig,
            &DummyResolver,
            Utc::now().timestamp(),
            &[Component::Method],
        );

        assert_eq!(outcome, VerifyOutcome::KeyNotFound);
    }
}
