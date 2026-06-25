//! Append-only Trust Log and Merkle proofs (Spec + Skeleton).
//!
//! See `DESIGN-pillar-b.md` Section 4 for the full protocol specification.
//! Implementation deferred.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::model::Issuer;

/// A peer in the federation network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeer {
    pub url: String,
    pub pubkey: String, // Base64 encoded VerifyingKey
}

/// A Signed Tree Head (STH) committing to the state of the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub size: u64,
    pub root_hash: Vec<u8>, // BLAKE3 hash
    pub sequence: u64,
    pub signature: Vec<u8>, // Ed25519 signature over size || root_hash || sequence
}

/// A Merkle consistency proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<Vec<u8>>, // Intermediate hashes
}

/// Appends an issuer state change to the log.
pub fn append(entry: &Issuer) -> Result<SignedTreeHead> {
    todo!("Implement Merkle tree append and STH generation")
}

/// Generates a consistency proof between two tree sizes.
pub fn prove_consistency(old_size: u64, new_size: u64) -> Result<ConsistencyProof> {
    todo!("Implement Merkle consistency proof generation")
}

/// Verifies a consistency proof.
pub fn verify_consistency(
    old_sth: &SignedTreeHead,
    new_sth: &SignedTreeHead,
    proof: &ConsistencyProof,
) -> bool {
    todo!("Implement Merkle consistency verification")
}

/// Mirrors the log from a peer.
pub fn mirror(peer: &FederationPeer) -> Result<()> {
    todo!("Implement mirror handshake: fetch STH, verify consistency, fetch entries")
}
