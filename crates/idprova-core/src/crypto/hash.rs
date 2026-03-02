use sha2::{Digest, Sha256};

/// Compute a BLAKE3 hash and return it as a hex string.
pub fn blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Compute a BLAKE3 hash and return raw bytes.
pub fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute a SHA-256 hash and return it as a hex string (for interop).
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Compute a SHA-256 hash and return raw bytes.
pub fn sha256_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

/// Format a hash with the algorithm prefix for IDProva (e.g., "blake3:abcdef...").
pub fn prefixed_blake3(data: &[u8]) -> String {
    format!("blake3:{}", blake3_hash(data))
}

/// Format a hash with the algorithm prefix for interop (e.g., "sha256:abcdef...").
pub fn prefixed_sha256(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hash(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_deterministic() {
        let data = b"hello idprova";
        let h1 = blake3_hash(data);
        let h2 = blake3_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"hello idprova";
        let h1 = sha256_hash(data);
        let h2 = sha256_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let h1 = blake3_hash(b"hello");
        let h2 = blake3_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_prefixed_format() {
        let h = prefixed_blake3(b"test");
        assert!(h.starts_with("blake3:"));

        let h = prefixed_sha256(b"test");
        assert!(h.starts_with("sha256:"));
    }
}
