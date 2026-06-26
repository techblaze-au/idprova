//! Curated trust authority: signing and verifying `TrustList`s.
use crate::model::{SignedTrustList, TrustList};
use crate::store::TrustStore;
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub struct TrustAuthority {
    pub signing_key: SigningKey,
}

impl TrustAuthority {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn publish(&self, store: &dyn TrustStore) -> Result<SignedTrustList> {
        let entries = store.list_issuers(None)?;
        let mut list = TrustList {
            version: "1".to_string(),
            sequence: entries.len() as u64,
            issued_at: chrono::Utc::now(),
            entries,
            proof: None,
        };
        list.canonicalize();

        let msg = serde_json_canonicalizer::to_string(&list)?;
        let sig = self.signing_key.sign(msg.as_bytes());
        let signer_keyid = to_hex(&self.signing_key.verifying_key().to_bytes());

        Ok(SignedTrustList {
            list,
            signature: sig.to_bytes().to_vec(),
            signer_keyid,
        })
    }

    pub fn verify_signed_list(signed: &SignedTrustList, key: &VerifyingKey) -> bool {
        let msg = match serde_json_canonicalizer::to_string(&signed.list) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match <[u8; 64]>::try_from(signed.signature.as_slice()) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);

        key.verify(msg.as_bytes(), &sig).is_ok()
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! to a String is infallible; ignore the Result to satisfy clippy.
        let _ = write!(s, "{b:02x}");
    }
    s
}
