//! Curated trust authority: signing and verifying `TrustList`s.

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::model::{SignedTrustList, TrustList};
use crate::store::TrustStore;

/// Manages the creation and verification of signed TrustLists.
pub struct TrustAuthority {
    /// The Ed25519 private key used to sign lists.
    pub signing_key: SigningKey,
}

impl TrustAuthority {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Publishes a signed trust list from the current state of the store.
    ///
    /// Sorts entries, serializes via RFC 8785 JCS, and signs with Ed25519.
    pub fn publish(&self, store: &dyn TrustStore) -> Result<SignedTrustList> {
        todo!("Query store, build TrustList, canonicalize, sign, return SignedTrustList")
    }

    /// Verifies a signed trust list offline.
    ///
    /// Re-canonicalizes the list and verifies the signature.
    pub fn verify_signed_list(list: &SignedTrustList, key: &VerifyingKey) -> bool {
        todo!("Canonicalize list, parse signature, verify against key")
    }
}
