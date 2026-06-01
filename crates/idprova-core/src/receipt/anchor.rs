//! Transparency anchoring of Action Receipts to a Sigstore Rekor log.
//!
//! See ADR 0011. The anchored hash is **SHA-512** of the canonical signing
//! payload, and the Rekor signature is **Ed25519ph** (pre-hashed, RFC 8032
//! §5.1) over that payload — verified empirically against the public Rekor
//! instance (pure Ed25519 + SHA-256 are both rejected).

use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Error types for transparency-log anchoring.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
}

impl From<base64::DecodeError> for AnchorError {
    fn from(e: base64::DecodeError) -> Self {
        AnchorError::Encoding(e.to_string())
    }
}

impl From<serde_json::Error> for AnchorError {
    fn from(e: serde_json::Error) -> Self {
        AnchorError::Parse(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for AnchorError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        AnchorError::Crypto(e.to_string())
    }
}

impl From<hex::FromHexError> for AnchorError {
    fn from(e: hex::FromHexError) -> Self {
        AnchorError::Encoding(e.to_string())
    }
}

/// Details of a Sigstore Rekor transparency-log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyAnchor {
    /// Log name (e.g. "rekor").
    pub log: String,
    /// URL of the Rekor instance.
    pub instance_url: String,
    /// Index in the log.
    pub log_index: i64,
    /// UUID of the entry.
    pub entry_uuid: String,
    /// Server-side timestamp (Unix epoch seconds).
    pub integrated_time: i64,
    /// Base64-encoded Signed Entry Timestamp.
    pub signed_entry_timestamp: String,
    /// Inclusion proof (opaque JSON).
    pub inclusion_proof: serde_json::Value,
    /// The SHA-512 hash that was anchored, in hex.
    pub anchored_sha512: String,
}

// ---------------------------------------------------------------------------
// TransparencyLog trait (sync, for mocks / future blocking impls)
// ---------------------------------------------------------------------------

pub trait TransparencyLog {
    fn submit(
        &self,
        sha512_hex: &str,
        pubkey_pem_b64: &str,
        ed25519ph_sig_b64: &str,
    ) -> Result<TransparencyAnchor, AnchorError>;

    fn fetch(&self, entry_uuid: &str) -> Result<TransparencyAnchor, AnchorError>;
}

// ---------------------------------------------------------------------------
// Pure crypto helpers
// ---------------------------------------------------------------------------

/// Returns the hex-encoded SHA-512 digest of `payload`.
pub fn sha512_hex(payload: &[u8]) -> String {
    let digest = Sha512::digest(payload);
    hex::encode(digest)
}

/// Produces an Ed25519ph (pre-hashed, RFC 8032 §5.1) signature over `payload`
/// and returns it as a base64-encoded string.
///
/// Internally feeds `payload` into `Sha512`, then calls
/// `signing_key.sign_prehashed(…, None)`.
pub fn ed25519ph_sign(signing_key: &SigningKey, payload: &[u8]) -> Result<String, AnchorError> {
    let mut prehash = Sha512::new();
    prehash.update(payload);
    let sig: Signature = signing_key
        .sign_prehashed(prehash, None)
        .map_err(|e| AnchorError::Crypto(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Returns the PKIX/SubjectPublicKeyInfo PEM of an Ed25519 public key,
/// base64-encoded (the full PEM string → base64).
pub fn ed25519_pubkey_pem_b64(verifying_key: &VerifyingKey) -> Result<String, AnchorError> {
    let raw = verifying_key.to_bytes();

    // 12-byte Ed25519 SPKI prefix
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(12 + 32);
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(&raw);

    let b64_der = base64::engine::general_purpose::STANDARD.encode(&der);
    // Wrap at 64 chars per line (standard PEM)
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64_der.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----");

    // The caller expects base64 of the PEM string
    Ok(base64::engine::general_purpose::STANDARD.encode(pem.as_bytes()))
}

/// Verifies an Ed25519ph (pre-hashed) signature over `payload`.
pub fn ed25519ph_verify(verifying_key: &VerifyingKey, payload: &[u8], sig_b64: &str) -> bool {
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut prehash = Sha512::new();
    prehash.update(payload);
    verifying_key
        .verify_prehashed(prehash, None, &signature)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Rekor proposed-entry builder
// ---------------------------------------------------------------------------

/// Builds the Rekor v1 `hashedrekord` v0.0.1 proposed-entry JSON.
pub fn build_hashedrekord_entry(
    sha512_hex: &str,
    pubkey_pem_b64: &str,
    sig_b64: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha512",
                    "value": sha512_hex
                }
            },
            "signature": {
                "content": sig_b64,
                "publicKey": {
                    "content": pubkey_pem_b64
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// RekorClient (http feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "http")]
pub struct RekorClient {
    pub instance_url: String,
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl RekorClient {
    pub fn new(instance_url: impl Into<String>) -> Self {
        Self {
            instance_url: instance_url.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn default_instance() -> Self {
        Self::new("https://rekor.sigstore.dev")
    }

    /// Submit a hashedrekord entry and return the resulting anchor.
    pub async fn submit(
        &self,
        sha512_hex: &str,
        pubkey_pem_b64: &str,
        ed25519ph_sig_b64: &str,
    ) -> Result<TransparencyAnchor, AnchorError> {
        let entry = build_hashedrekord_entry(sha512_hex, pubkey_pem_b64, ed25519ph_sig_b64);

        let url = format!("{}/api/v1/log/entries", self.instance_url);
        let resp = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| AnchorError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| AnchorError::Http(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AnchorError::Parse(e.to_string()))?;
        parse_log_entries_response(&body, &self.instance_url, sha512_hex)
    }

    /// Fetch an existing entry by UUID.
    pub async fn fetch(&self, entry_uuid: &str) -> Result<TransparencyAnchor, AnchorError> {
        let url = format!("{}/api/v1/log/entries/{}", self.instance_url, entry_uuid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AnchorError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| AnchorError::Http(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AnchorError::Parse(e.to_string()))?;
        // The GET response is `{ entry_uuid: { ... } }` — same shape as POST.
        parse_single_entry_response(&body, entry_uuid, &self.instance_url)
    }
}

/// Anchor a receipt to a Rekor transparency log (ADR 0011).
///
/// Computes SHA-512 over the receipt's canonical signing payload (the exact
/// bytes the receipt signature covers), produces a dedicated **Ed25519ph**
/// signature with `signing_key`, and submits a `hashedrekord` entry. Returns
/// the resulting [`TransparencyAnchor`] (store it in `Receipt::anchor`).
///
/// Best-effort: callers should treat an `Err` as "left unanchored" rather than
/// failing the action.
#[cfg(feature = "http")]
pub async fn anchor_receipt(
    receipt: &crate::receipt::entry::Receipt,
    signing_key: &SigningKey,
    client: &RekorClient,
) -> Result<TransparencyAnchor, AnchorError> {
    let payload = receipt.signing_payload_bytes();
    let sha = sha512_hex(&payload);
    let sig = ed25519ph_sign(signing_key, &payload)?;
    let pem = ed25519_pubkey_pem_b64(&signing_key.verifying_key())?;
    client.submit(&sha, &pem, &sig).await
}

#[cfg(feature = "http")]
fn parse_log_entries_response(
    body: &serde_json::Value,
    instance_url: &str,
    sha512_hex: &str,
) -> Result<TransparencyAnchor, AnchorError> {
    // POST returns `{ "<uuid>": { body, ... } }`  (one entry)
    let obj = body
        .as_object()
        .ok_or_else(|| AnchorError::Parse("response is not a JSON object".into()))?;
    let (entry_uuid, entry) = obj
        .iter()
        .next()
        .ok_or_else(|| AnchorError::Parse("empty response object".into()))?;

    let entry = entry
        .as_object()
        .ok_or_else(|| AnchorError::Parse("entry is not a JSON object".into()))?;

    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AnchorError::Parse("missing logIndex".into()))?;

    let integrated_time = entry
        .get("integratedTime")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AnchorError::Parse("missing integratedTime".into()))?;

    let verification = entry
        .get("verification")
        .and_then(|v| v.as_object())
        .ok_or_else(|| AnchorError::Parse("missing verification".into()))?;

    let signed_entry_timestamp = verification
        .get("signedEntryTimestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let inclusion_proof = verification
        .get("inclusionProof")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(TransparencyAnchor {
        log: "rekor".to_string(),
        instance_url: instance_url.to_string(),
        log_index,
        entry_uuid: entry_uuid.clone(),
        integrated_time,
        signed_entry_timestamp,
        inclusion_proof,
        anchored_sha512: sha512_hex.to_string(),
    })
}

#[cfg(feature = "http")]
fn parse_single_entry_response(
    body: &serde_json::Value,
    entry_uuid: &str,
    instance_url: &str,
) -> Result<TransparencyAnchor, AnchorError> {
    let entry = body
        .as_object()
        .ok_or_else(|| AnchorError::Parse("response is not a JSON object".into()))?
        .get(entry_uuid)
        .ok_or_else(|| AnchorError::Parse("entry UUID not found in response".into()))?
        .as_object()
        .ok_or_else(|| AnchorError::Parse("entry is not a JSON object".into()))?;

    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AnchorError::Parse("missing logIndex".into()))?;

    let integrated_time = entry
        .get("integratedTime")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AnchorError::Parse("missing integratedTime".into()))?;

    let verification = entry
        .get("verification")
        .and_then(|v| v.as_object())
        .ok_or_else(|| AnchorError::Parse("missing verification".into()))?;

    let signed_entry_timestamp = verification
        .get("signedEntryTimestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let inclusion_proof = verification
        .get("inclusionProof")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // We don't know the anchored hash from a fetch — leave empty.
    Ok(TransparencyAnchor {
        log: "rekor".to_string(),
        instance_url: instance_url.to_string(),
        log_index,
        entry_uuid: entry_uuid.to_string(),
        integrated_time,
        signed_entry_timestamp,
        inclusion_proof,
        anchored_sha512: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_sha512_hex_known_vector() {
        // SHA-512 of empty input
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                        47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        assert_eq!(sha512_hex(b""), expected);
    }

    #[test]
    fn test_sha512_hex_hello() {
        // SHA-512 of "hello"
        let expected = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7\
                        2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
        assert_eq!(sha512_hex(b"hello"), expected);
    }

    #[test]
    fn test_ed25519ph_sign_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let payload = b"round-trip test payload for ed25519ph";
        let sig_b64 = ed25519ph_sign(&signing_key, payload).unwrap();

        assert!(ed25519ph_verify(&verifying_key, payload, &sig_b64));

        // Wrong payload must fail
        assert!(!ed25519ph_verify(&verifying_key, b"tampered", &sig_b64));

        // Wrong key must fail
        let other_key = SigningKey::generate(&mut OsRng);
        assert!(!ed25519ph_verify(
            &other_key.verifying_key(),
            payload,
            &sig_b64
        ));
    }

    #[test]
    fn test_ed25519ph_signature_is_64_bytes() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let sig_b64 = ed25519ph_sign(&signing_key, b"test").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        assert_eq!(decoded.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn test_pubkey_pem_b64_has_markers() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pem_b64 = ed25519_pubkey_pem_b64(&verifying_key).unwrap();

        // Decode the base64 → PEM string
        let pem_bytes = base64::engine::general_purpose::STANDARD
            .decode(&pem_b64)
            .unwrap();
        let pem_str = std::str::from_utf8(&pem_bytes).unwrap();

        assert!(
            pem_str.contains("-----BEGIN PUBLIC KEY-----"),
            "PEM must contain BEGIN marker"
        );
        assert!(
            pem_str.contains("-----END PUBLIC KEY-----"),
            "PEM must contain END marker"
        );

        // Decode the inner base64 payload → DER must be 44 bytes (12 prefix + 32 key)
        let lines: Vec<&str> = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der_b64: String = lines.concat();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&der_b64)
            .unwrap();
        assert_eq!(
            der.len(),
            44,
            "SPKI DER must be 44 bytes (12 prefix + 32 key)"
        );

        // Verify the SPKI prefix
        assert_eq!(
            &der[..12],
            &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
        );
        // The last 32 bytes must match the raw key
        assert_eq!(&der[12..], verifying_key.as_bytes());
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    #[ignore = "network: submits a real (throwaway-key, opaque-hash) entry to public rekor.sigstore.dev"]
    async fn live_rekor_roundtrip() {
        // ADR 0011 v0.3 acceptance test: submit a real entry to the public log
        // and verify it round-trips. Proves Rust Ed25519ph is accepted by Rekor.
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let payload = br#"{"idprova":"adr-0011-live","note":"rust ed25519ph roundtrip"}"#;
        let sha = sha512_hex(payload);
        let sig = ed25519ph_sign(&sk, payload).unwrap();
        let pem = ed25519_pubkey_pem_b64(&vk).unwrap();

        let client = RekorClient::default_instance();
        let anchor = client.submit(&sha, &pem, &sig).await.expect("rekor submit");
        assert_eq!(anchor.anchored_sha512, sha);
        assert!(!anchor.entry_uuid.is_empty(), "must get an entry UUID");
        assert!(anchor.log_index >= 0, "must get a log index");
        println!(
            "LIVE OK: logIndex={} uuid={} integratedTime={}",
            anchor.log_index, anchor.entry_uuid, anchor.integrated_time
        );

        let fetched = client.fetch(&anchor.entry_uuid).await.expect("rekor fetch");
        assert_eq!(
            fetched.log_index, anchor.log_index,
            "fetch must match submit"
        );
    }

    #[test]
    fn test_build_hashedrekord_entry_shape() {
        let entry = build_hashedrekord_entry("abcd1234", "cHVia2V5", "c2lnbmF0dXJl");

        assert_eq!(entry["apiVersion"], "0.0.1");
        assert_eq!(entry["kind"], "hashedrekord");

        let spec = &entry["spec"];
        assert_eq!(spec["data"]["hash"]["algorithm"], "sha512");
        assert_eq!(spec["data"]["hash"]["value"], "abcd1234");
        assert_eq!(spec["signature"]["content"], "c2lnbmF0dXJl");
        assert_eq!(spec["signature"]["publicKey"]["content"], "cHVia2V5");
    }
}
