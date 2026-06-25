//! Binding logic between Web Bot Auth keys and AID identity.
//!
//! Connects the `kid` (JWK thumbprint) used in HTTP signatures to
//! verification methods in the `did:aid:` document.

use super::Error;
use super::Result;
use idprova_core::aid::AidDocument;
use idprova_core::crypto::KeyPair;

/// Represents the binding between a Key ID and an AID.
pub struct KeyBinding {
    /// The Key ID (RFC 7638 Thumbprint).
    pub keyid: String,
    /// The AID URI (`did:aid:...`).
    pub aid: String,
    /// The index of the verification method in the AID document.
    pub verification_method_index: usize,
}

/// Bind a Key ID to a specific AID by verifying the key exists in the AID document.
///
/// This involves:
/// 1. Computing the JWK thumbprint for the key pair (to match `kid`).
/// 2. Locating the corresponding public key in the AID's `verificationMethod` array.
pub fn bind_keyid_to_aid(key_pair: &KeyPair, aid: &AidDocument) -> Result<KeyBinding> {
    // DESIGN-ONLY skeleton. Real impl:
    //   1. compute RFC 7638 JWK thumbprint of `key_pair` -> kid
    //   2. find the matching entry in `aid.verification_method` by public-key bytes
    //   3. return KeyBinding { kid, aid.id, index }
    let _ = (key_pair, aid);
    todo!("bind WBA keyid to a did:aid verification method")
}

/// Resolve a WBA Key ID back to the DID it is bound to.
///
/// Checks if the `kid` matches any verification method in the provided AID.
/// This is useful for inbound verification where we have the `kid` from the signature.
pub fn resolve_keyid_to_aid(kid: &str, aid: &AidDocument) -> Result<String> {
    // DESIGN-ONLY: match `kid` against each verification method's JWK thumbprint,
    // returning the bound `did:aid:` on success.
    let _ = (kid, aid);
    todo!("resolve WBA kid back to a did:aid")
}

/// Stub: Compute RFC 7638 JWK Thumbprint.
fn compute_jwk_thumbprint(_key_pair: &KeyPair) -> Result<String> {
    // TODO: Serialize JWK (kty, crv, x) -> SHA-256 -> Base64URL
    todo!("Compute JWK thumbprint for binding")
}

/// Stub: Get JWK Thumbprint from a Verification Method reference.
fn vm_jwk_thumbprint(_vm: &idprova_core::aid::VerificationMethod) -> String {
    // TODO: Extract public key from VM and compute thumbprint
    todo!("Get JWK thumbprint from VerificationMethod")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_resolve_roundtrip() {
        // "Verify that a KeyPair binding to an AID can be resolved back to the AID ID."
        todo!("Implement roundtrip binding test")
    }
}
