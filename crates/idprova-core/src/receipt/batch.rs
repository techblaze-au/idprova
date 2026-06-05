//! Batched privacy-preserving anchoring (ADR 0012).
//!
//! This module ties together the [`commitment`](super::commitment) and
//! [`merkle`](super::merkle) primitives into the operational pieces of the
//! ADR-0012 design:
//!
//! * [`AnchorConfig`] — the **default-OFF**, opt-in configuration gate. Live
//!   anchoring is disabled unless explicitly enabled, and a kill-switch can
//!   hard-disable it regardless.
//! * [`BatchAccumulator`] — accumulates per-receipt commitment leaves and
//!   flushes a [`ReadyBatch`] when **either** the leaf cap (default 256) **or**
//!   the time window (default 60s) is reached, whichever comes first. The
//!   accumulator is pure: the caller supplies the clock (Unix seconds), so it
//!   is fully unit-testable and has no hidden timer or I/O.
//! * [`attach_commitment_evidence`] — given the Rekor anchor of a batch root,
//!   builds the per-receipt [`TransparencyAnchor`] (commitment mode) carrying
//!   the receipt's nonce + Merkle inclusion proof.
//! * [`verify_commitment_anchor`] — the **offline** verifier: recompute the
//!   commitment from `(payload, nonce, tenant_key)`, verify Merkle inclusion
//!   against the anchored root. (Confirming the root itself is in the public
//!   log via Rekor's SET / inclusion proof is the caller's existing path.)
//!
//! Only the batch **root** is ever submitted to the transparency log, and the
//! leaves are opaque HMAC commitments — so the public log learns neither the
//! receipt contents nor a per-action signal.

use super::anchor::TransparencyAnchor;
use super::commitment::commit;
use super::merkle::{InclusionProof, MerkleTree, NODE_LEN};

/// Default maximum number of commitment leaves per batch.
pub const DEFAULT_MAX_BATCH_LEAVES: usize = 256;
/// Default maximum batch window, in seconds (flush whichever comes first).
pub const DEFAULT_MAX_BATCH_INTERVAL_SECS: u64 = 60;
/// Default rate budget: maximum root anchors submitted per minute.
pub const DEFAULT_MAX_ANCHORS_PER_MIN: u32 = 30;

// ---------------------------------------------------------------------------
// Configuration — default-OFF, opt-in
// ---------------------------------------------------------------------------

/// Runtime configuration for batched anchoring.
///
/// **Security default: anchoring is OFF.** [`AnchorConfig::default`] and
/// [`AnchorConfig::from_env`] both produce a disabled config; anchoring only
/// becomes active when explicitly enabled AND the kill-switch is not set
/// (see [`AnchorConfig::is_active`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorConfig {
    /// Master enable flag. Default `false`.
    pub enabled: bool,
    /// Hard kill-switch. When `true`, anchoring is disabled regardless of
    /// `enabled`. Default `false`.
    pub kill_switch: bool,
    /// Flush the batch once it holds this many leaves. Default 256.
    pub max_batch_leaves: usize,
    /// Flush the batch once this many seconds have elapsed since the first
    /// leaf was added. Default 60.
    pub max_batch_interval_secs: u64,
    /// Rate budget: maximum root anchors per minute. Default 30.
    pub max_anchors_per_min: u32,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kill_switch: false,
            max_batch_leaves: DEFAULT_MAX_BATCH_LEAVES,
            max_batch_interval_secs: DEFAULT_MAX_BATCH_INTERVAL_SECS,
            max_anchors_per_min: DEFAULT_MAX_ANCHORS_PER_MIN,
        }
    }
}

impl AnchorConfig {
    /// Build a config from environment variables, **defaulting to OFF**.
    ///
    /// * `IDPROVA_ANCHOR_ENABLED` — enables anchoring only when set to
    ///   `1`/`true`/`yes`/`on` (case-insensitive). Any other value, or unset,
    ///   leaves it disabled.
    /// * `IDPROVA_ANCHOR_KILL_SWITCH` — same truthy parsing; when truthy,
    ///   hard-disables anchoring.
    /// * `IDPROVA_ANCHOR_MAX_BATCH_LEAVES` / `IDPROVA_ANCHOR_MAX_BATCH_INTERVAL_SECS`
    ///   / `IDPROVA_ANCHOR_MAX_PER_MIN` — numeric overrides; malformed values
    ///   fall back to the defaults.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            enabled: env_truthy("IDPROVA_ANCHOR_ENABLED"),
            kill_switch: env_truthy("IDPROVA_ANCHOR_KILL_SWITCH"),
            max_batch_leaves: env_num("IDPROVA_ANCHOR_MAX_BATCH_LEAVES", d.max_batch_leaves),
            max_batch_interval_secs: env_num(
                "IDPROVA_ANCHOR_MAX_BATCH_INTERVAL_SECS",
                d.max_batch_interval_secs,
            ),
            max_anchors_per_min: env_num("IDPROVA_ANCHOR_MAX_PER_MIN", d.max_anchors_per_min),
        }
    }

    /// Whether anchoring should actually run: enabled AND not killed.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.kill_switch
    }

    /// Construct a [`BatchAccumulator`] sized from this config.
    pub fn accumulator(&self) -> BatchAccumulator {
        BatchAccumulator::new(self.max_batch_leaves, self.max_batch_interval_secs)
    }
}

/// Parse an environment variable as a strict boolean (default `false`).
fn env_truthy(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Parse an environment variable as a number, falling back to `default`.
fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<T>().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Batch accumulation — pure, caller-driven clock
// ---------------------------------------------------------------------------

/// A single pending leaf awaiting batch flush.
#[derive(Debug, Clone)]
struct PendingLeaf {
    receipt_id: String,
    nonce_hex: String,
    commitment: [u8; NODE_LEN],
}

/// One receipt's entry in a flushed batch: its nonce and Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// The receipt this entry belongs to.
    pub receipt_id: String,
    /// The per-receipt nonce (hex) used to derive the commitment.
    pub nonce_hex: String,
    /// The Merkle inclusion proof for this receipt's commitment.
    pub proof: InclusionProof,
}

/// A flushed batch: the Merkle root (hex) to anchor, plus a per-receipt entry
/// (nonce + inclusion proof) for every leaf in the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyBatch {
    /// Hex of the 64-byte batch Merkle root — the only value submitted to the log.
    pub root_hex: String,
    /// One entry per receipt in the batch, in insertion order.
    pub entries: Vec<BatchEntry>,
}

/// Accumulates commitment leaves and flushes when the leaf cap or time window
/// is reached. The clock is supplied by the caller (Unix seconds) — this type
/// performs no I/O and starts no timers.
#[derive(Debug, Clone)]
pub struct BatchAccumulator {
    max_leaves: usize,
    max_interval_secs: u64,
    leaves: Vec<PendingLeaf>,
    /// Unix-seconds timestamp of the first leaf in the current batch.
    opened_at: Option<i64>,
}

impl BatchAccumulator {
    /// Create an accumulator with the given leaf cap and time window.
    ///
    /// `max_leaves` is clamped to at least 1 so a tree can always be built.
    pub fn new(max_leaves: usize, max_interval_secs: u64) -> Self {
        Self {
            max_leaves: max_leaves.max(1),
            max_interval_secs,
            leaves: Vec::new(),
            opened_at: None,
        }
    }

    /// Number of leaves currently pending.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether there are no pending leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Add a receipt's commitment to the current batch.
    ///
    /// Returns `Some(ReadyBatch)` (and resets the accumulator) when this add
    /// reaches the leaf cap; otherwise `None`. Use [`Self::due`] +
    /// [`Self::flush`] to flush on the time window.
    pub fn add(
        &mut self,
        receipt_id: impl Into<String>,
        nonce_hex: impl Into<String>,
        commitment: [u8; NODE_LEN],
        now_unix: i64,
    ) -> Option<ReadyBatch> {
        if self.leaves.is_empty() {
            self.opened_at = Some(now_unix);
        }
        self.leaves.push(PendingLeaf {
            receipt_id: receipt_id.into(),
            nonce_hex: nonce_hex.into(),
            commitment,
        });
        if self.leaves.len() >= self.max_leaves {
            self.flush()
        } else {
            None
        }
    }

    /// Whether the current (non-empty) batch is due to flush on the time
    /// window: at least `max_interval_secs` have elapsed since the first leaf.
    pub fn due(&self, now_unix: i64) -> bool {
        match self.opened_at {
            Some(opened) if !self.leaves.is_empty() => {
                now_unix.saturating_sub(opened) >= self.max_interval_secs as i64
            }
            _ => false,
        }
    }

    /// Build a [`ReadyBatch`] from the pending leaves and reset the
    /// accumulator. Returns `None` if there are no pending leaves.
    pub fn flush(&mut self) -> Option<ReadyBatch> {
        if self.leaves.is_empty() {
            return None;
        }
        let drained = std::mem::take(&mut self.leaves);
        self.opened_at = None;

        let commitments: Vec<[u8; NODE_LEN]> = drained.iter().map(|l| l.commitment).collect();
        // Safe: `drained` is non-empty (checked above), so the tree builds.
        let tree =
            MerkleTree::from_leaves(&commitments).expect("non-empty leaves always build a tree");
        let root_hex = tree.root_hex();

        let entries = drained
            .into_iter()
            .enumerate()
            .map(|(i, leaf)| BatchEntry {
                receipt_id: leaf.receipt_id,
                nonce_hex: leaf.nonce_hex,
                // Safe: `i` is a valid leaf index by construction.
                proof: tree.proof(i).expect("valid leaf index yields a proof"),
            })
            .collect();

        Some(ReadyBatch { root_hex, entries })
    }
}

// ---------------------------------------------------------------------------
// Per-receipt commitment-mode anchor construction
// ---------------------------------------------------------------------------

/// Build a commitment-mode [`TransparencyAnchor`] for one receipt.
///
/// `root_anchor` is the Rekor anchor of the batch **root** (its
/// `anchored_sha512` is the root); this clones that evidence and attaches the
/// receipt's `nonce` + Merkle `proof`. The resulting anchor's `anchored_sha512`
/// therefore equals `proof.root`, which is the invariant
/// [`verify_commitment_anchor`] checks.
///
/// Returns `None` if the proof's root does not match the anchored root (a
/// programming error — the proof belongs to a different batch).
pub fn attach_commitment_evidence(
    root_anchor: &TransparencyAnchor,
    nonce_hex: String,
    proof: InclusionProof,
) -> Option<TransparencyAnchor> {
    if proof.root != root_anchor.anchored_sha512 {
        return None;
    }
    Some(TransparencyAnchor {
        nonce: Some(nonce_hex),
        merkle_proof: Some(proof),
        ..root_anchor.clone()
    })
}

// ---------------------------------------------------------------------------
// Offline verification (ADR 0012 step d)
// ---------------------------------------------------------------------------

/// Offline-verify a commitment-mode anchor.
///
/// Given the receipt's canonical signing `payload`, the per-tenant `tenant_key`,
/// and the stored commitment-mode `anchor`:
///
/// 1. Recompute the commitment `HMAC-SHA512(HKDF(tenant_key, nonce), payload)`.
/// 2. Confirm the anchor binds the proof's root to the anchored value
///    (`merkle_proof.root == anchored_sha512`).
/// 3. Verify the Merkle inclusion proof for the recomputed commitment.
///
/// Returns `false` for a raw-hash (ADR-0011) anchor — i.e. one with no
/// `nonce`/`merkle_proof` — or on any malformed field. Confirming that the
/// root itself is recorded in the public transparency log (Rekor SET /
/// inclusion proof at `log_index`) is the caller's responsibility and is
/// performed via the existing ADR-0011 verification path; this function is the
/// commitment → batch-root half and is fully offline.
pub fn verify_commitment_anchor(
    payload: &[u8],
    tenant_key: &[u8],
    anchor: &TransparencyAnchor,
) -> bool {
    let (nonce_hex, proof) = match (&anchor.nonce, &anchor.merkle_proof) {
        (Some(n), Some(p)) => (n, p),
        _ => return false,
    };
    // The anchored value must be the batch root the proof attests to.
    if proof.root != anchor.anchored_sha512 {
        return false;
    }
    let nonce = match hex::decode(nonce_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let commitment = commit(tenant_key, &nonce, payload);
    proof.verify(&commitment)
}

#[cfg(test)]
mod tests {
    use super::super::commitment::{commit, generate_nonce};
    use super::*;

    /// Build a root anchor stub with `anchored_sha512 = root`.
    fn root_anchor_stub(root_hex: &str) -> TransparencyAnchor {
        TransparencyAnchor {
            log: "rekor".to_string(),
            instance_url: "https://rekor.sigstore.dev".to_string(),
            log_index: 42,
            entry_uuid: "batch-root-uuid".to_string(),
            integrated_time: 1_700_000_000,
            signed_entry_timestamp: String::new(),
            inclusion_proof: serde_json::json!({}),
            anchored_sha512: root_hex.to_string(),
            nonce: None,
            merkle_proof: None,
        }
    }

    #[test]
    fn default_config_is_off() {
        let c = AnchorConfig::default();
        assert!(!c.enabled);
        assert!(!c.is_active());
        assert_eq!(c.max_batch_leaves, 256);
        assert_eq!(c.max_batch_interval_secs, 60);
    }

    #[test]
    fn kill_switch_overrides_enabled() {
        let c = AnchorConfig {
            enabled: true,
            kill_switch: true,
            ..AnchorConfig::default()
        };
        assert!(!c.is_active(), "kill-switch must hard-disable anchoring");
    }

    #[test]
    fn accumulator_flushes_on_leaf_cap() {
        let tenant_key = b"tenant";
        let mut acc = BatchAccumulator::new(4, 60);
        let mut ready = None;
        for i in 0..4 {
            let nonce = generate_nonce();
            let c = commit(tenant_key, &nonce, format!("payload-{i}").as_bytes());
            ready = acc.add(format!("rcpt-{i}"), hex::encode(nonce), c, 1000 + i as i64);
        }
        let batch = ready.expect("4th add must flush at the cap of 4");
        assert_eq!(batch.entries.len(), 4);
        assert!(acc.is_empty(), "accumulator resets after flush");
        // Every entry's proof verifies against the batch root.
        for e in &batch.entries {
            assert_eq!(e.proof.root, batch.root_hex);
        }
    }

    #[test]
    fn accumulator_flushes_on_time_window() {
        let mut acc = BatchAccumulator::new(256, 60);
        let nonce = generate_nonce();
        let c = commit(b"k", &nonce, b"p");
        assert!(acc.add("r0", hex::encode(nonce), c, 1000).is_none());
        assert!(!acc.due(1059), "59s elapsed — not yet due");
        assert!(acc.due(1060), "60s elapsed — due to flush");
        let batch = acc.flush().expect("flush returns the pending batch");
        assert_eq!(batch.entries.len(), 1);
        assert!(acc.flush().is_none(), "second flush is empty");
    }

    #[test]
    fn full_round_trip_verifies_offline() {
        let tenant_key = b"per-tenant-hmac-key";
        let payloads: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("receipt #{i}").into_bytes())
            .collect();

        // Mint commitments and accumulate.
        let mut acc = BatchAccumulator::new(256, 60);
        let mut nonces = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            let nonce = generate_nonce();
            nonces.push(nonce);
            let c = commit(tenant_key, &nonce, p);
            acc.add(format!("rcpt-{i}"), hex::encode(nonce), c, 1000);
        }
        let batch = acc.flush().expect("batch flush");

        // Anchor the root (stubbed), attach per-receipt evidence, and verify.
        let root_anchor = root_anchor_stub(&batch.root_hex);
        for (i, entry) in batch.entries.iter().enumerate() {
            let anchor = attach_commitment_evidence(
                &root_anchor,
                entry.nonce_hex.clone(),
                entry.proof.clone(),
            )
            .expect("proof root matches anchored root");
            assert_eq!(anchor.anchored_sha512, batch.root_hex);

            // Correct (payload, key) verifies.
            assert!(verify_commitment_anchor(&payloads[i], tenant_key, &anchor));
            // Wrong tenant key fails.
            assert!(!verify_commitment_anchor(
                &payloads[i],
                b"wrong-key",
                &anchor
            ));
            // Wrong payload fails.
            assert!(!verify_commitment_anchor(
                b"other payload",
                tenant_key,
                &anchor
            ));
        }
    }

    #[test]
    fn raw_hash_anchor_is_rejected_by_commitment_verifier() {
        // An ADR-0011 anchor (no nonce / no merkle_proof) must not verify here.
        let anchor = root_anchor_stub("deadbeef");
        assert!(!verify_commitment_anchor(b"payload", b"key", &anchor));
    }

    #[test]
    fn mismatched_root_is_rejected() {
        let tenant_key = b"k";
        let mut acc = BatchAccumulator::new(256, 60);
        let nonce = generate_nonce();
        let c = commit(tenant_key, &nonce, b"payload");
        acc.add("r0", hex::encode(nonce), c, 1000);
        let batch = acc.flush().unwrap();
        let entry = &batch.entries[0];

        // Anchor advertises a DIFFERENT root than the proof → attach refuses.
        let wrong_root_anchor = root_anchor_stub("00".repeat(64).as_str());
        assert!(
            attach_commitment_evidence(
                &wrong_root_anchor,
                entry.nonce_hex.clone(),
                entry.proof.clone()
            )
            .is_none(),
            "evidence with a mismatched root must be refused"
        );
    }

    #[test]
    fn empty_accumulator_flush_is_none() {
        let mut acc = BatchAccumulator::new(256, 60);
        assert!(acc.flush().is_none());
        assert!(!acc.due(999_999));
    }
}
