//! HTTP Message Verifier.
//!
//! Handles verification of inbound signed requests.

use super::components::{build_signature_base, Component, SignatureParams};
use super::request::SignableRequest;
use super::Error;
use super::Result;
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sfv::Dictionary;

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

    /// Placeholder: Extract params from the SFV Item.
    fn extract_params_from_entry(_entry: &sfv::ListEntry) -> Result<SignatureParams> {
        // TODO: Implement SFV parsing logic.
        // "Parse the `created`, `expires`, `keyid`, `alg` from the Item's parameters."
        todo!("Extract params from SFV Item")
    }

    /// Placeholder: Extract covered components from the SFV Item (List value).
    fn extract_covered_from_entry(_entry: &sfv::ListEntry) -> Result<Vec<Component>> {
        // TODO: Implement SFV parsing logic.
        // "Parse the List of strings (e.g. \"@method\", \"@path\") into Vec<Component>."
        todo!("Extract covered components from SFV Item")
    }

    /// Placeholder: Extract the signature from the SFV entry (byte sequence).
    fn extract_signature_bytes(_entry: &sfv::ListEntry) -> Result<Signature> {
        // TODO: Implement SFV parsing logic.
        todo!("Extract signature from SFV entry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyResolver;

    impl KeyResolver for DummyResolver {
        fn resolve(&self, _: &str) -> Option<VerifyingKey> {
            None
        }
    }

    #[test]
    fn test_verify_missing_key() {
        let req = SignableRequest::new("GET", "example.com", "/", None::<&str>);
        let dummy_dict = Dictionary::new();
        let dummy_sig = Dictionary::new();

        let outcome = HttpVerifier::verify(
            &req,
            &dummy_dict,
            &dummy_sig,
            &DummyResolver,
            Utc::now().timestamp(),
            &[Component::Method],
        );

        assert_eq!(outcome, VerifyOutcome::KeyNotFound);
    }
}
