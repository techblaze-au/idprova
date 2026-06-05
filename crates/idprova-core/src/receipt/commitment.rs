//! Privacy-preserving receipt commitments for the IDProva transparency log.
//!
//! Instead of anchoring a raw SHA-512 hash of a receipt payload to the public
//! transparency log, we anchor an opaque HMAC commitment whose key is derived
//! per-receipt via HKDF.  This ensures the public log never contains a value
//! that can be trivially brute-forced back to the receipt payload.
//!
//! **Construction** (see ADR 0012):
//!
//! 1. A fresh 32-byte random **nonce** is generated per receipt.
//! 2. A 64-byte **commitment key** is derived with
//!    `HKDF-SHA-512(salt = nonce, ikm = tenant_key, info = "idprova/anchor/commitment/v1")`.
//! 3. The **commitment leaf** is `HMAC-SHA-512(commitment_key, payload)`.
//!
//! Because the nonce is unique per receipt and the tenant key is secret,
//! the commitment is opaque to any party that does not possess the tenant key.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;

/// Output length of the HMAC-SHA-512 commitment (64 bytes).
pub const COMMITMENT_LEN: usize = 64;

/// Length of the per-receipt nonce (32 bytes).
pub const NONCE_LEN: usize = 32;

/// HKDF info label for domain separation.
/// Do not change without bumping the version suffix.
const HKDF_INFO: &[u8] = b"idprova/anchor/commitment/v1";

/// Generate a fresh cryptographically-random per-receipt nonce.
///
/// Uses the OS random number generator (`OsRng`) to produce 32 bytes
/// of cryptographic randomness suitable for use as an HKDF salt.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive the per-receipt commitment key.
///
/// Computes `HKDF-SHA-512(salt = nonce, ikm = tenant_key, info = HKDF_INFO)`
/// and expands to exactly 64 bytes.  This is infallible: expanding 64 bytes
/// from SHA-512 (whose output is 64 bytes) is always well within the HKDF
/// limit of `255 * HashLen` bytes.
///
/// # Panics
///
/// Will not panic under normal circumstances.  The `.expect()` call guards
/// against a length error in the HKDF expand counter, which is impossible
/// when requesting only 64 bytes from SHA-512.
pub fn derive_commitment_key(tenant_key: &[u8], nonce: &[u8]) -> [u8; 64] {
    let hk = Hkdf::<Sha512>::new(Some(nonce), tenant_key);
    let mut okm = [0u8; COMMITMENT_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF expand to 64 bytes is always valid for SHA-512 (well under 255*64)");
    okm
}

/// Compute the privacy-preserving commitment leaf.
///
/// 1. Derives the per-receipt key with [`derive_commitment_key`].
/// 2. Computes `HMAC-SHA-512(key, payload)`.
/// 3. Returns the 64-byte commitment.
///
/// This function is infallible.  HMAC accepts keys of arbitrary length via
/// `new_from_slice`, and the derived key is always exactly 64 bytes.
///
/// # Panics
///
/// Will not panic under normal circumstances.  The `.expect()` call is
/// present only because `Mac::new_from_slice` returns a `Result`; it cannot
/// fail for any key length.
pub fn commit(tenant_key: &[u8], nonce: &[u8], payload: &[u8]) -> [u8; COMMITMENT_LEN] {
    let key = derive_commitment_key(tenant_key, nonce);
    let mut mac =
        <Hmac<Sha512>>::new_from_slice(&key).expect("HMAC-SHA-512 accepts any key length");
    mac.update(payload);
    let out = mac.finalize().into_bytes();
    let mut commitment = [0u8; COMMITMENT_LEN];
    commitment.copy_from_slice(&out);
    commitment
}

/// Hex-encode a commitment (convenience wrapper).
///
/// Equivalent to `hex::encode(commit(tenant_key, nonce, payload))` but saves
/// the caller from importing the `hex` crate directly.  Returns 128
/// lowercase hexadecimal characters.
///
/// # Panics
///
/// Same as [`commit`]; will not panic under normal circumstances.
pub fn commit_hex(tenant_key: &[u8], nonce: &[u8], payload: &[u8]) -> String {
    hex::encode(commit(tenant_key, nonce, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_same_inputs_yield_same_commitment() {
        let tenant_key = b"tenant-secret-key";
        let nonce = generate_nonce();
        let payload = b"receipt payload v1";
        let c1 = commit(tenant_key, &nonce, payload);
        let c2 = commit(tenant_key, &nonce, payload);
        assert_eq!(c1, c2);
    }

    #[test]
    fn nonce_sensitivity() {
        let tenant_key = b"tenant-secret-key";
        let payload = b"receipt payload v1";
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        let c1 = commit(tenant_key, &nonce1, payload);
        let c2 = commit(tenant_key, &nonce2, payload);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tenant_key_sensitivity() {
        let nonce = generate_nonce();
        let payload = b"receipt payload v1";
        let key_a = b"tenant-key-alpha";
        let key_b = b"tenant-key-beta!";
        let c_a = commit(key_a, &nonce, payload);
        let c_b = commit(key_b, &nonce, payload);
        assert_ne!(c_a, c_b);
    }

    #[test]
    fn payload_sensitivity() {
        let tenant_key = b"tenant-secret-key";
        let nonce = generate_nonce();
        let c1 = commit(tenant_key, &nonce, b"payload A");
        let c2 = commit(tenant_key, &nonce, b"payload B");
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_length_is_64() {
        let tenant_key = b"key";
        let nonce = generate_nonce();
        let c = commit(tenant_key, &nonce, b"data");
        assert_eq!(c.len(), COMMITMENT_LEN);
        assert_eq!(c.len(), 64);
    }

    #[test]
    fn nonce_length_is_32_and_two_nonces_differ() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_eq!(n1.len(), NONCE_LEN);
        assert_eq!(n2.len(), 32);
        assert_ne!(n1, n2);
    }

    #[test]
    fn derive_commitment_key_is_deterministic_and_nonce_sensitive() {
        let tenant_key = b"tenant-secret-key";
        let nonce1 = [1u8; NONCE_LEN];
        let nonce2 = [2u8; NONCE_LEN];
        let k1a = derive_commitment_key(tenant_key, &nonce1);
        let k1b = derive_commitment_key(tenant_key, &nonce1);
        let k2 = derive_commitment_key(tenant_key, &nonce2);
        assert_eq!(k1a, k1b, "same inputs must yield the same key");
        assert_ne!(k1a, k2, "different nonces must yield different keys");
        assert_eq!(k1a.len(), 64);
    }

    #[test]
    fn commit_hex_length_and_encoding() {
        let tenant_key = b"tenant-secret-key";
        let nonce = generate_nonce();
        let payload = b"receipt payload v1";
        let c = commit(tenant_key, &nonce, payload);
        let h = commit_hex(tenant_key, &nonce, payload);
        assert_eq!(h.len(), 128);
        assert_eq!(h, hex::encode(c));
    }
}
