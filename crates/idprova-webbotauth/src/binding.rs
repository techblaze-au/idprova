//! Binding logic between Web Bot Auth keys and AID identity.
//!
//! Connects the `kid` (JWK thumbprint) used in HTTP signatures to
//! verification methods in the `did:aid:` document.

use super::Error;
use super::Result;
use base64::Engine as _;
use idprova_core::aid::AidDocument;
use idprova_core::crypto::KeyPair;
use sha2::{Digest, Sha256};

/// Represents the binding between a Key ID and an AID.
pub struct KeyBinding {
    /// The Key ID (RFC 7638 Thumbprint).
    pub keyid: String,
    /// The AID URI (`did:aid:...`).
    pub aid: String,
    /// The index of the verification method in the AID document.
    pub verification_method_index: usize,
}

/// Compute the RFC 7638 JWK thumbprint for an Ed25519 public key.
///
/// The thumbprint is the base64url(no-pad) SHA-256 over the JWK with its
/// required members (`crv`, `kty`, `x`) in lexicographic order and no
/// insignificant whitespace.
fn jwk_thumbprint_from_pubkey(pubkey: &[u8; 32]) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey);
    let json = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", x);
    let mut h = Sha256::new();
    h.update(json.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Bind a Key ID to a specific AID by verifying the key exists in the AID document.
///
/// This involves:
/// 1. Computing the JWK thumbprint for the key pair (to match `kid`).
/// 2. Locating the corresponding public key in the AID's `verificationMethod` array.
pub fn bind_keyid_to_aid(key_pair: &KeyPair, aid: &AidDocument) -> Result<KeyBinding> {
    let kid = compute_jwk_thumbprint(key_pair)?;
    for (i, vm) in aid.verification_method.iter().enumerate() {
        if vm_jwk_thumbprint(vm)? == kid {
            return Ok(KeyBinding {
                keyid: kid,
                aid: aid.id.clone(),
                verification_method_index: i,
            });
        }
    }
    Err(Error::KeyNotFound(kid))
}

/// Resolve a WBA Key ID back to the DID it is bound to.
///
/// Checks if the `kid` matches any verification method in the provided AID.
/// This is useful for inbound verification where we have the `kid` from the signature.
pub fn resolve_keyid_to_aid(kid: &str, aid: &AidDocument) -> Result<String> {
    for vm in &aid.verification_method {
        if vm_jwk_thumbprint(vm)? == kid {
            return Ok(aid.id.clone());
        }
    }
    Err(Error::KeyNotFound(kid.to_string()))
}

/// Compute the RFC 7638 JWK Thumbprint for a key pair.
fn compute_jwk_thumbprint(key_pair: &KeyPair) -> Result<String> {
    Ok(jwk_thumbprint_from_pubkey(&key_pair.public_key_bytes()))
}

/// Compute the JWK Thumbprint for a verification method's public key.
fn vm_jwk_thumbprint(vm: &idprova_core::aid::VerificationMethod) -> Result<String> {
    let pk = KeyPair::decode_multibase_pubkey(&vm.public_key_multibase)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(jwk_thumbprint_from_pubkey(&pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use idprova_core::aid::VerificationMethod;

    #[test]
    fn test_bind_resolve_roundtrip() {
        let kp = KeyPair::generate();
        let vm = VerificationMethod {
            id: "#key-1".into(),
            key_type: "Ed25519VerificationKey2020".into(),
            controller: "did:aid:example.com:agent".into(),
            public_key_multibase: kp.public_key_multibase(),
        };

        let aid = AidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://idprova.dev/ns/v1".into(),
            ],
            id: "did:aid:example.com:agent".into(),
            controller: "did:aid:example.com:root".into(),
            verification_method: vec![vm],
            authentication: vec!["#key-1".into()],
            service: None,
            trust_level: None,
            version: None,
            created: None,
            updated: None,
            proof: None,
        };

        let binding = bind_keyid_to_aid(&kp, &aid).unwrap();
        assert_eq!(binding.verification_method_index, 0);

        let resolved = resolve_keyid_to_aid(&binding.keyid, &aid).unwrap();
        assert_eq!(resolved, "did:aid:example.com:agent");
    }
}
