//! Local, append-only, hash-chained anchoring of Action Receipts (ADR 0013).
//!
//! A data-residency-sensitive or air-gapped deployment can anchor receipt-batch
//! Merkle roots to a **local append-only file** instead of (or before) submitting
//! them to the public Sigstore/Rekor log (ADR 0011/0012). An auditor who is given
//! `(receipt log, this anchor file, producer public key)` can verify **fully
//! offline — zero network** — that the producer committed, in an append-only
//! hash chain, to exactly this set and ordering of receipts.
//!
//! ## What this guarantees
//! - **Tamper-evident append-only commitment.** Each record is hash-chained to
//!   the previous one (BLAKE3) and optionally Ed25519-signed by the producer.
//!   Anyone holding *any* earlier copy of the file (or any earlier record hash)
//!   can detect a later rewrite, reorder, or omission.
//! - **Inclusion.** Each record commits a Merkle root over a contiguous range of
//!   receipts; re-deriving the root from the receipts proves which receipts the
//!   producer anchored.
//! - **A network-free, self-hostable anchoring path** for environments that may
//!   not reach (or may not trust) public transparency infrastructure.
//!
//! ## What this deliberately does NOT guarantee (honesty boundary)
//! This anchor is **producer-controlled: there is NO independent third-party
//! witness.** It therefore does **not** provide independent temporal attestation
//! and does **not** prevent equivocation / split-view — a producer with full
//! control of the file could rewrite its entire history. It is *not* a substitute
//! for a witnessed transparency log. For independent attestation, use the
//! networked Rekor path (ADR 0011) or the privacy-preserving batched path
//! (ADR 0012); this local mode complements them for offline / sovereign use.

use crate::crypto::hash::prefixed_blake3;
use crate::receipt::entry::Receipt;
use crate::receipt::merkle::{MerkleTree, NODE_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

/// Sentinel `previousHash` value for the first record in a local anchor log.
pub const LOCAL_ANCHOR_GENESIS_PREV: &str = "genesis";

/// Errors produced while building or verifying a local anchor log.
#[derive(Debug, Error)]
pub enum LocalAnchorError {
    /// No leaves / receipts were supplied for the batch.
    #[error("empty batch")]
    EmptyBatch,
    /// The receipts (or leaves) are not a contiguous, gap-free sequence.
    #[error("non-contiguous sequence: expected {expected}, got {got}")]
    NonContiguousSequence {
        /// The sequence number / count that was expected.
        expected: u64,
        /// The sequence number / count that was actually found.
        got: u64,
    },
    /// The anchor chain failed an integrity check (with a human-readable reason).
    #[error("chain broken: {0}")]
    ChainBroken(String),
    /// A (de)serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for LocalAnchorError {
    fn from(e: serde_json::Error) -> Self {
        LocalAnchorError::Serialization(e.to_string())
    }
}

/// One append-only record in a local anchor log: a Merkle root over a contiguous
/// range of receipts, chained to the previous record and optionally signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAnchorRecord {
    /// 0-based, contiguous index within the log.
    pub index: u64,
    /// The previous record's [`record_hash`](Self::record_hash), or
    /// [`LOCAL_ANCHOR_GENESIS_PREV`] for the first record.
    pub previous_hash: String,
    /// Producer-supplied anchor time (Unix seconds). This module performs no I/O
    /// and reads no clock; the caller supplies the timestamp.
    pub anchored_at: i64,
    /// First receipt sequence number covered (inclusive).
    pub first_seq: u64,
    /// Last receipt sequence number covered (inclusive).
    pub last_seq: u64,
    /// Number of leaves in the batch (`last_seq - first_seq + 1`).
    pub leaf_count: usize,
    /// Hex of the 64-byte Merkle root over the covered receipts.
    pub root: String,
    /// Optional producer DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_did: Option<String>,
    /// Optional hex-encoded Ed25519 signature over the signing payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Signing payload — every record field **except** the signature.
///
/// The signature is computed over this payload, so it must never include itself
/// (mirrors the S3 fix in [`crate::receipt::entry`]). The payload is also the
/// pre-image for [`LocalAnchorRecord::record_hash`], which forms the chain.
/// `producer_did` is serialized unconditionally here (even when `None`) so the
/// payload is deterministic regardless of the wire-format skip rule.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAnchorSigningPayload<'a> {
    index: u64,
    previous_hash: &'a str,
    anchored_at: i64,
    first_seq: u64,
    last_seq: u64,
    leaf_count: usize,
    root: &'a str,
    producer_did: &'a Option<String>,
}

impl LocalAnchorRecord {
    fn signing_payload(&self) -> LocalAnchorSigningPayload<'_> {
        LocalAnchorSigningPayload {
            index: self.index,
            previous_hash: &self.previous_hash,
            anchored_at: self.anchored_at,
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            leaf_count: self.leaf_count,
            root: &self.root,
            producer_did: &self.producer_did,
        }
    }

    /// Canonical signing-payload bytes (the record without its signature).
    fn signing_payload_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.signing_payload()).unwrap_or_default()
    }

    /// The BLAKE3 record hash (`"blake3:<hex>"`) that the next record's
    /// `previous_hash` links to. Stable regardless of whether the record is
    /// signed (the signature is excluded from the payload).
    pub fn record_hash(&self) -> String {
        prefixed_blake3(&self.signing_payload_bytes())
    }

    /// Sign the record in place with the producer key (hex-encoded Ed25519).
    pub fn sign(&mut self, key: &SigningKey) {
        let sig = key.sign(&self.signing_payload_bytes());
        self.signature = Some(hex::encode(sig.to_bytes()));
    }

    /// Verify the record's producer signature. Returns `false` on a missing
    /// signature, malformed hex, wrong length, or verification failure; never
    /// panics.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let sig_hex = match &self.signature {
            Some(s) => s,
            None => return false,
        };
        let bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if bytes.len() != 64 {
            return false;
        }
        let sig = match Signature::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(&self.signing_payload_bytes(), &sig).is_ok()
    }
}

/// The Merkle leaf for a receipt: `SHA-512(receipt.signing_payload_bytes())`.
///
/// Local mode is producer-controlled and not protecting against a public log, so
/// (unlike ADR 0012) the leaf is the receipt's signed bytes directly rather than
/// a salted HMAC commitment.
pub fn receipt_leaf(receipt: &Receipt) -> [u8; NODE_LEN] {
    let hash = Sha512::digest(receipt.signing_payload_bytes());
    let mut out = [0u8; NODE_LEN];
    out.copy_from_slice(&hash);
    out
}

/// Build a record from raw 64-byte Merkle leaves (pure; no clock, no I/O).
#[allow(clippy::too_many_arguments)]
pub fn build_record_from_leaves(
    leaves: &[[u8; NODE_LEN]],
    index: u64,
    first_seq: u64,
    last_seq: u64,
    prev_hash: &str,
    anchored_at: i64,
    signing_key: Option<&SigningKey>,
    producer_did: Option<String>,
) -> Result<LocalAnchorRecord, LocalAnchorError> {
    if leaves.is_empty() {
        return Err(LocalAnchorError::EmptyBatch);
    }
    let expected = last_seq - first_seq + 1;
    if leaves.len() as u64 != expected {
        return Err(LocalAnchorError::NonContiguousSequence {
            expected,
            got: leaves.len() as u64,
        });
    }
    let tree = MerkleTree::from_leaves(leaves).ok_or(LocalAnchorError::EmptyBatch)?;
    let mut record = LocalAnchorRecord {
        index,
        previous_hash: prev_hash.to_string(),
        anchored_at,
        first_seq,
        last_seq,
        leaf_count: leaves.len(),
        root: tree.root_hex(),
        producer_did,
        signature: None,
    };
    if let Some(key) = signing_key {
        record.sign(key);
    }
    Ok(record)
}

/// Build a record from a contiguous slice of receipts (pure).
///
/// Derives the covered sequence range from the receipts' chain sequence numbers
/// and validates they are gap-free and strictly increasing by one.
pub fn build_record_from_receipts(
    receipts: &[Receipt],
    index: u64,
    prev_hash: &str,
    anchored_at: i64,
    signing_key: Option<&SigningKey>,
    producer_did: Option<String>,
) -> Result<LocalAnchorRecord, LocalAnchorError> {
    if receipts.is_empty() {
        return Err(LocalAnchorError::EmptyBatch);
    }
    let first_seq = receipts[0].chain.sequence_number;
    for (i, r) in receipts.iter().enumerate() {
        let expected_seq = first_seq + i as u64;
        if r.chain.sequence_number != expected_seq {
            return Err(LocalAnchorError::NonContiguousSequence {
                expected: expected_seq,
                got: r.chain.sequence_number,
            });
        }
    }
    let last_seq = first_seq + receipts.len() as u64 - 1;
    let leaves: Vec<[u8; NODE_LEN]> = receipts.iter().map(receipt_leaf).collect();
    build_record_from_leaves(
        &leaves,
        index,
        first_seq,
        last_seq,
        prev_hash,
        anchored_at,
        signing_key,
        producer_did,
    )
}

/// An append-only log of [`LocalAnchorRecord`]s.
#[derive(Debug, Clone, Default)]
pub struct LocalAnchorLog {
    records: Vec<LocalAnchorRecord>,
}

impl LocalAnchorLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a log from existing records (e.g. parsed from a file).
    pub fn from_records(records: Vec<LocalAnchorRecord>) -> Self {
        Self { records }
    }

    /// The records in order.
    pub fn records(&self) -> &[LocalAnchorRecord] {
        &self.records
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The hash of the last record (the next record's `previous_hash`), or
    /// [`LOCAL_ANCHOR_GENESIS_PREV`] if the log is empty.
    pub fn last_record_hash(&self) -> String {
        match self.records.last() {
            Some(r) => r.record_hash(),
            None => LOCAL_ANCHOR_GENESIS_PREV.to_string(),
        }
    }

    /// The index the next appended record should use.
    pub fn next_index(&self) -> u64 {
        match self.records.last() {
            Some(r) => r.index + 1,
            None => 0,
        }
    }

    /// Append a record (caller is responsible for correct chaining; verify with
    /// [`verify_chain`](Self::verify_chain)).
    pub fn append(&mut self, record: LocalAnchorRecord) {
        self.records.push(record);
    }

    /// Serialize the log as JSONL (one compact record per line).
    pub fn to_jsonl(&self) -> Result<String, LocalAnchorError> {
        let mut s = String::new();
        for rec in &self.records {
            let line = serde_json::to_string(rec)?;
            s.push_str(&line);
            s.push('\n');
        }
        Ok(s)
    }

    /// Parse a log from JSONL, skipping blank lines.
    pub fn from_jsonl(s: &str) -> Result<Self, LocalAnchorError> {
        let mut records = Vec::new();
        for line in s.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: LocalAnchorRecord = serde_json::from_str(trimmed)?;
            records.push(rec);
        }
        Ok(Self { records })
    }

    /// Verify the append-only chain: contiguous indices from 0, a genesis first
    /// record, each `previous_hash` linking the prior record, and a consistent
    /// `leaf_count`. Does NOT check Merkle roots or signatures (see
    /// [`verify_local_anchor`]).
    pub fn verify_chain(&self) -> Result<(), LocalAnchorError> {
        if self.records.is_empty() {
            return Ok(());
        }
        for (i, rec) in self.records.iter().enumerate() {
            if rec.index != i as u64 {
                return Err(LocalAnchorError::ChainBroken(format!(
                    "record index {} != expected {}",
                    rec.index, i
                )));
            }
            if i == 0 {
                if rec.previous_hash != LOCAL_ANCHOR_GENESIS_PREV {
                    return Err(LocalAnchorError::ChainBroken(format!(
                        "first record previous_hash {} != genesis",
                        rec.previous_hash
                    )));
                }
            } else {
                let expected_prev = self.records[i - 1].record_hash();
                if rec.previous_hash != expected_prev {
                    return Err(LocalAnchorError::ChainBroken(format!(
                        "record {} previous_hash {} != expected {}",
                        i, rec.previous_hash, expected_prev
                    )));
                }
            }
            let expected_count = rec.last_seq - rec.first_seq + 1;
            if rec.leaf_count as u64 != expected_count {
                return Err(LocalAnchorError::ChainBroken(format!(
                    "record {} leaf_count {} != expected {}",
                    i, rec.leaf_count, expected_count
                )));
            }
        }
        Ok(())
    }
}

/// Summary of a successful [`verify_local_anchor`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAnchorVerification {
    /// Number of anchor records verified.
    pub records_verified: usize,
    /// Total receipts (leaves) covered across all records.
    pub receipts_covered: u64,
    /// Whether every record carried a producer signature that verified (only
    /// possible when a producer public key was supplied).
    pub all_signed: bool,
    /// Whether the append-only chain verified.
    pub chain_ok: bool,
}

/// Offline-verify a receipt log against its local anchor log.
///
/// `leaves[i]` must be the [`receipt_leaf`] of the receipt with sequence number
/// `i`. Verifies the chain, re-derives each record's Merkle root over its covered
/// range and compares it to the stored root, and (when `producer_pubkey` is
/// supplied) requires every record's producer signature to verify. Returns
/// [`LocalAnchorError::ChainBroken`] on any mismatch.
pub fn verify_local_anchor(
    leaves: &[[u8; NODE_LEN]],
    log: &LocalAnchorLog,
    producer_pubkey: Option<&VerifyingKey>,
) -> Result<LocalAnchorVerification, LocalAnchorError> {
    log.verify_chain()?;
    let all_signed = producer_pubkey.is_some();
    let mut covered: u64 = 0;

    for rec in log.records() {
        let last = rec.last_seq as usize;
        if last >= leaves.len() {
            return Err(LocalAnchorError::ChainBroken(format!(
                "record {} last_seq {} out of range (leaves len {})",
                rec.index,
                last,
                leaves.len()
            )));
        }
        let first = rec.first_seq as usize;
        let slice = &leaves[first..=last];
        let tree = MerkleTree::from_leaves(slice).ok_or(LocalAnchorError::EmptyBatch)?;
        if tree.root_hex() != rec.root {
            return Err(LocalAnchorError::ChainBroken(format!(
                "record {} root mismatch: computed {} != stored {}",
                rec.index,
                tree.root_hex(),
                rec.root
            )));
        }
        if let Some(pk) = producer_pubkey {
            if !rec.verify_signature(pk) {
                return Err(LocalAnchorError::ChainBroken(format!(
                    "record {} signature verification failed",
                    rec.index
                )));
            }
        }
        covered += rec.leaf_count as u64;
    }

    Ok(LocalAnchorVerification {
        records_verified: log.len(),
        receipts_covered: covered,
        all_signed,
        chain_ok: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn leaf(b: u8) -> [u8; 64] {
        let mut a = [0u8; 64];
        a[0] = b;
        a[63] = b.wrapping_add(1);
        a
    }

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn push(log: &mut LocalAnchorLog, leaves: &[[u8; 64]], first: u64, last: u64, sk: &SigningKey) {
        let idx = log.next_index();
        let prev = log.last_record_hash();
        let rec = build_record_from_leaves(
            leaves,
            idx,
            first,
            last,
            &prev,
            1_700_000_000,
            Some(sk),
            None,
        )
        .unwrap();
        log.append(rec);
    }

    #[test]
    fn single_signed_record_verifies() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();
        let mut log = LocalAnchorLog::new();
        push(&mut log, &leaves, 0, 3, &sk);

        let vk = sk.verifying_key();
        let result = verify_local_anchor(&leaves, &log, Some(&vk)).unwrap();
        assert_eq!(result.records_verified, 1);
        assert_eq!(result.receipts_covered, 4);
        assert!(result.all_signed);
        assert!(result.chain_ok);
    }

    #[test]
    fn wrong_pubkey_fails() {
        let sk_a = key();
        let sk_b = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();
        let mut log = LocalAnchorLog::new();
        push(&mut log, &leaves, 0, 3, &sk_a);

        let vk_b = sk_b.verifying_key();
        assert!(verify_local_anchor(&leaves, &log, Some(&vk_b)).is_err());
    }

    #[test]
    fn three_record_chain_verifies() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..7u8).map(leaf).collect();
        let mut log = LocalAnchorLog::new();
        push(&mut log, &leaves[0..3], 0, 2, &sk);
        push(&mut log, &leaves[3..6], 3, 5, &sk);
        push(&mut log, &leaves[6..7], 6, 6, &sk);

        log.verify_chain().unwrap();

        let result = verify_local_anchor(&leaves, &log, None).unwrap();
        assert_eq!(result.records_verified, 3);
        assert_eq!(result.receipts_covered, 7);
        assert!(!result.all_signed);
        assert!(result.chain_ok);
    }

    #[test]
    fn tampered_leaf_fails() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();
        let mut log = LocalAnchorLog::new();
        push(&mut log, &leaves, 0, 3, &sk);

        let mut tampered = leaves.clone();
        tampered[2] = leaf(0xFF);

        assert!(verify_local_anchor(&tampered, &log, None).is_err());
    }

    #[test]
    fn corrupt_previous_hash_breaks_chain() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..6u8).map(leaf).collect();

        let rec0 = build_record_from_leaves(
            &leaves[0..3],
            0,
            0,
            2,
            LOCAL_ANCHOR_GENESIS_PREV,
            1_700_000_000,
            Some(&sk),
            None,
        )
        .unwrap();

        let mut rec1 = build_record_from_leaves(
            &leaves[3..6],
            1,
            3,
            5,
            &rec0.record_hash(),
            1_700_000_001,
            Some(&sk),
            None,
        )
        .unwrap();

        rec1.previous_hash = "blake3:00".to_string();

        let log = LocalAnchorLog::from_records(vec![rec0, rec1]);
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn bad_index_breaks_chain() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..6u8).map(leaf).collect();

        let rec0 = build_record_from_leaves(
            &leaves[0..3],
            0,
            0,
            2,
            LOCAL_ANCHOR_GENESIS_PREV,
            1_700_000_000,
            Some(&sk),
            None,
        )
        .unwrap();

        let rec1 = build_record_from_leaves(
            &leaves[3..6],
            0,
            3,
            5,
            &rec0.record_hash(),
            1_700_000_001,
            Some(&sk),
            None,
        )
        .unwrap();

        let log = LocalAnchorLog::from_records(vec![rec0, rec1]);
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn leaf_count_mismatch_breaks_chain() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();

        let mut rec = build_record_from_leaves(
            &leaves,
            0,
            0,
            3,
            LOCAL_ANCHOR_GENESIS_PREV,
            1_700_000_000,
            Some(&sk),
            None,
        )
        .unwrap();

        rec.leaf_count = 99;

        let log = LocalAnchorLog::from_records(vec![rec]);
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn signature_roundtrip() {
        let sk_a = key();
        let sk_b = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();

        let mut rec = build_record_from_leaves(
            &leaves,
            0,
            0,
            3,
            LOCAL_ANCHOR_GENESIS_PREV,
            1_700_000_000,
            None,
            None,
        )
        .unwrap();

        let vk_a = sk_a.verifying_key();
        let vk_b = sk_b.verifying_key();

        assert!(!rec.verify_signature(&vk_a));
        assert!(!rec.verify_signature(&vk_b));

        rec.sign(&sk_a);

        assert!(rec.verify_signature(&vk_a));
        assert!(!rec.verify_signature(&vk_b));
    }

    #[test]
    fn jsonl_roundtrip() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..6u8).map(leaf).collect();
        let mut log = LocalAnchorLog::new();
        push(&mut log, &leaves[0..3], 0, 2, &sk);
        push(&mut log, &leaves[3..6], 3, 5, &sk);

        let jsonl = log.to_jsonl().unwrap();
        let log2 = LocalAnchorLog::from_jsonl(&jsonl).unwrap();

        assert_eq!(log.records().len(), log2.records().len());
        for (a, b) in log.records().iter().zip(log2.records().iter()) {
            assert_eq!(a, b);
        }

        log2.verify_chain().unwrap();
    }

    #[test]
    fn record_hash_stable_across_signing() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();

        let mut rec = build_record_from_leaves(
            &leaves,
            0,
            0,
            3,
            LOCAL_ANCHOR_GENESIS_PREV,
            1_700_000_000,
            None,
            None,
        )
        .unwrap();

        let h1 = rec.record_hash();
        rec.sign(&sk);
        let h2 = rec.record_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn non_genesis_first_record_fails() {
        let sk = key();
        let leaves: Vec<[u8; 64]> = (0..4u8).map(leaf).collect();

        let rec = build_record_from_leaves(
            &leaves,
            0,
            0,
            3,
            "blake3:not_genesis",
            1_700_000_000,
            Some(&sk),
            None,
        )
        .unwrap();

        let log = LocalAnchorLog::from_records(vec![rec]);
        assert!(log.verify_chain().is_err());
    }
}
