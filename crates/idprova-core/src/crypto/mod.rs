//! Cryptographic primitives for IDProva.
//!
//! Provides Ed25519 key generation, signing, and verification,
//! plus BLAKE3/SHA-256 hashing utilities.

pub mod hash;
pub mod keys;

pub use hash::{blake3_hash, sha256_hash};
pub use keys::KeyPair;
