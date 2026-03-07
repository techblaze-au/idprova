use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{IdprovaError, Result};

/// An Ed25519 keypair for IDProva identity operations.
///
/// # Security: SR-1 (zeroize on drop)
///
/// The signing key bytes are zeroed from memory when this struct is dropped,
/// preventing private key material from being retained in process memory.
#[derive(Debug, ZeroizeOnDrop)]
pub struct KeyPair {
    signing_key: SigningKey,
}

/// Public key representation for serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey {
    /// The key type identifier.
    #[serde(rename = "type")]
    pub key_type: String,
    /// The public key encoded as multibase (base58btc).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl KeyPair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from existing secret key bytes (32 bytes).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the secret key bytes for serialization.
    ///
    /// # Security: S5 (restricted API)
    ///
    /// This method is intentionally `pub(crate)` — external callers should never
    /// access raw private key bytes directly. Use `sign()` for cryptographic operations.
    /// For key persistence, use the encrypted export (SR-7, Phase 8).
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// Get the public key as a multibase-encoded string (base58btc, prefix 'z').
    pub fn public_key_multibase(&self) -> String {
        let bytes = self.public_key_bytes();
        multibase::encode(multibase::Base::Base58Btc, bytes)
    }

    /// Get the public key as a serializable struct.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: self.public_key_multibase(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature against a public key.
    pub fn verify(
        public_key_bytes: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| IdprovaError::InvalidKey(e.to_string()))?;

        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| IdprovaError::VerificationFailed("invalid signature length".into()))?;

        let signature = Signature::from_bytes(&signature_array);

        verifying_key
            .verify(message, &signature)
            .map_err(|e| IdprovaError::VerificationFailed(e.to_string()))
    }

    /// Decode a multibase-encoded public key to raw bytes.
    pub fn decode_multibase_pubkey(multibase_str: &str) -> Result<[u8; 32]> {
        let (_, bytes) = multibase::decode(multibase_str)
            .map_err(|e| IdprovaError::InvalidKey(format!("multibase decode: {e}")))?;

        bytes
            .try_into()
            .map_err(|_| IdprovaError::InvalidKey("expected 32-byte public key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let kp = KeyPair::generate();
        let message = b"hello idprova";
        let signature = kp.sign(message);

        let pub_bytes = kp.public_key_bytes();
        assert!(KeyPair::verify(&pub_bytes, message, &signature).is_ok());
    }

    #[test]
    fn test_invalid_signature_fails() {
        let kp = KeyPair::generate();
        let message = b"hello idprova";
        let mut signature = kp.sign(message);
        signature[0] ^= 0xFF; // corrupt signature

        let pub_bytes = kp.public_key_bytes();
        assert!(KeyPair::verify(&pub_bytes, message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let message = b"hello idprova";
        let signature = kp1.sign(message);

        let wrong_pub = kp2.public_key_bytes();
        assert!(KeyPair::verify(&wrong_pub, message, &signature).is_err());
    }

    #[test]
    fn test_multibase_roundtrip() {
        let kp = KeyPair::generate();
        let multibase = kp.public_key_multibase();
        let decoded = KeyPair::decode_multibase_pubkey(&multibase).unwrap();
        assert_eq!(decoded, kp.public_key_bytes());
    }

    #[test]
    fn test_deterministic_from_bytes() {
        let kp1 = KeyPair::generate();
        let secret = *kp1.secret_bytes();
        let kp2 = KeyPair::from_secret_bytes(&secret);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}
