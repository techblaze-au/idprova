//! Append-only Trust Log and Merkle proofs (RFC 6962-style, BLAKE3).
//! open-core boundary: live multi-operator mirroring belongs to the operator/enterprise edition;
//! this open library provides Merkle proof generation + verification + signed tree heads.

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use idprova_core::crypto::hash::blake3_hash_bytes;
use serde::{Deserialize, Serialize};

/// A peer in the federation network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeer {
    pub url: String,
    pub pubkey: String,
}

/// A Signed Tree Head committing to the state of the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub size: u64,
    pub root_hash: Vec<u8>,
    pub sequence: u64,
    pub signature: Vec<u8>,
}

/// A Merkle inclusion (audit) proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<Vec<u8>>,
}

/// A Merkle consistency proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<Vec<u8>>,
}

/// Append-only log of leaf hashes.
#[derive(Debug, Clone, Default)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

fn hash_leaf(entry: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + entry.len());
    b.push(0x00);
    b.extend_from_slice(entry);
    blake3_hash_bytes(&b)
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(65);
    b.push(0x01);
    b.extend_from_slice(left);
    b.extend_from_slice(right);
    blake3_hash_bytes(&b)
}

fn largest_pow2_below(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return blake3_hash_bytes(&[]);
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = largest_pow2_below(leaves.len());
    let left = mth(&leaves[..k]);
    let right = mth(&leaves[k..]);
    hash_node(&left, &right)
}

/// RFC 6962 `PATH(m, D[0:n])` audit path for leaf index `m`.
///
/// Nodes are pushed outermost-last (post-order), so verification consumes them back-to-front.
fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = largest_pow2_below(leaves.len());
    if index < k {
        let mut path = audit_path(index, &leaves[..k]);
        path.push(mth(&leaves[k..]));
        path
    } else {
        let mut path = audit_path(index - k, &leaves[k..]);
        path.push(mth(&leaves[..k]));
        path
    }
}

/// Recompute the root implied by an audit path for `n` leaves and leaf `index`, mirroring
/// [`audit_path`] and consuming `nodes` back-to-front. Returns `None` on path-length mismatch.
fn recompute_audit(
    index: usize,
    n: usize,
    leaf_hash: &[u8; 32],
    nodes: &[[u8; 32]],
    cursor: &mut usize,
) -> Option<[u8; 32]> {
    if n <= 1 {
        return Some(*leaf_hash);
    }
    let k = largest_pow2_below(n);
    // Outermost node was pushed last → consume first.
    let outer = take_back(nodes, cursor)?;
    if index < k {
        // outer = MTH(D[k:n]) is the right sibling.
        let left = recompute_audit(index, k, leaf_hash, nodes, cursor)?;
        Some(hash_node(&left, &outer))
    } else {
        // outer = MTH(D[0:k]) is the left sibling.
        let right = recompute_audit(index - k, n - k, leaf_hash, nodes, cursor)?;
        Some(hash_node(&outer, &right))
    }
}

/// RFC 6962 `PROOF(m, D[0:n]) = SUBPROOF(m, D[0:n], true)`.
///
/// `leaves` must be exactly the `new_size`-leaf prefix `D[0:n]` (the caller slices it).
fn consistency_path(old_size: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    subproof(old_size, leaves, true)
}

/// RFC 6962 `SUBPROOF(m, D[0:n], b)` over the leaf-hash slice `leaves` (where `n = leaves.len()`).
fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    // SUBPROOF(m, D[0:m], true) = {}; SUBPROOF(m, D[0:m], false) = {MTH(D[0:m])}.
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![mth(leaves)];
    }
    let k = largest_pow2_below(n);
    if m <= k {
        // SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        let mut path = subproof(m, &leaves[..k], b);
        path.push(mth(&leaves[k..]));
        path
    } else {
        // SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
        let mut path = subproof(m - k, &leaves[k..], false);
        path.push(mth(&leaves[..k]));
        path
    }
}

/// Result of replaying a consistency SUBPROOF: the implied old/new subtree roots.
enum SubproofRoots {
    /// `b == true` reached `m == n`: the old subtree root is not in the proof; the caller
    /// (or the outer [`verify_consistency`] seed) supplies it. The new subtree root equals it.
    OldFromSeed,
    /// Concrete old and new subtree roots reconstructed from proof nodes.
    Roots([u8; 32], [u8; 32]),
}

/// Mirror of [`subproof`]: replays the recursion against the post-order proof `nodes` (consumed
/// back-to-front) to reconstruct the old and new tree heads. Returns `None` on any shape mismatch.
fn recompute_subproof(
    m: usize,
    n: usize,
    b: bool,
    seed_old: &[u8; 32],
    nodes: &[[u8; 32]],
    cursor: &mut usize,
) -> Option<SubproofRoots> {
    if m == n {
        if b {
            // Old subtree is complete and omitted from the proof; new subtree root == old root.
            return Some(SubproofRoots::OldFromSeed);
        }
        let node = take_back(nodes, cursor)?;
        return Some(SubproofRoots::Roots(node, node));
    }
    let k = largest_pow2_below(n);
    let outer = take_back(nodes, cursor)?;
    if m <= k {
        // outer = MTH(D[k:n]); contributes to the NEW root only.
        let inner = recompute_subproof(m, k, b, seed_old, nodes, cursor)?;
        let (old_l, new_l) = match inner {
            SubproofRoots::OldFromSeed => (*seed_old, *seed_old),
            SubproofRoots::Roots(o, n_) => (o, n_),
        };
        Some(SubproofRoots::Roots(old_l, hash_node(&new_l, &outer)))
    } else {
        // outer = MTH(D[0:k]); contributes to BOTH old and new roots.
        let inner = recompute_subproof(m - k, n - k, false, seed_old, nodes, cursor)?;
        let (old_r, new_r) = match inner {
            // false branch never yields OldFromSeed.
            SubproofRoots::OldFromSeed => return None,
            SubproofRoots::Roots(o, n_) => (o, n_),
        };
        Some(SubproofRoots::Roots(
            hash_node(&outer, &old_r),
            hash_node(&outer, &new_r),
        ))
    }
}

impl MerkleLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, entry_bytes: &[u8]) -> u64 {
        let h = hash_leaf(entry_bytes);
        self.leaves.push(h);
        self.leaves.len() as u64
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn root(&self) -> [u8; 32] {
        mth(&self.leaves)
    }

    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof> {
        let tree_size = self.size();
        if index >= tree_size {
            anyhow::bail!("index out of bounds");
        }
        let path = audit_path(index as usize, &self.leaves);
        let path_vec = path.into_iter().map(|h| h.to_vec()).collect();
        Ok(InclusionProof {
            leaf_index: index,
            tree_size,
            path: path_vec,
        })
    }

    pub fn consistency_proof(&self, old_size: u64, new_size: u64) -> Result<ConsistencyProof> {
        if old_size < 1 {
            anyhow::bail!("old_size must be >= 1");
        }
        if old_size > new_size {
            anyhow::bail!("old_size must be <= new_size");
        }
        if new_size > self.size() {
            anyhow::bail!("new_size must be <= log size");
        }
        let path = consistency_path(old_size as usize, &self.leaves[..new_size as usize]);
        let path_vec = path.into_iter().map(|h| h.to_vec()).collect();
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path: path_vec,
        })
    }
}

pub fn verify_inclusion(leaf_hash: &[u8; 32], proof: &InclusionProof, root: &[u8; 32]) -> bool {
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return false;
    }
    // Decode every path node up front; reject on any length mismatch.
    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(proof.path.len());
    for raw in &proof.path {
        match <[u8; 32]>::try_from(raw.as_slice()) {
            Ok(node) => nodes.push(node),
            Err(_) => return false,
        }
    }
    let mut cursor = nodes.len();
    match recompute_audit(
        proof.leaf_index as usize,
        proof.tree_size as usize,
        leaf_hash,
        &nodes,
        &mut cursor,
    ) {
        Some(computed) if cursor == 0 => &computed == root,
        _ => false,
    }
}

/// Verifies an RFC 6962 consistency proof produced by [`MerkleLog::consistency_proof`].
///
/// The proof path is the post-order node list from `subproof`; verification mirrors that
/// recursion, reconstructing both the old and the new Merkle tree heads and checking each.
pub fn verify_consistency(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &ConsistencyProof,
) -> bool {
    let m = proof.old_size as usize;
    let n = proof.new_size as usize;
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        // Identical trees: empty proof, equal roots.
        return proof.path.is_empty() && old_root == new_root;
    }

    // Decode every path node up front; reject on any length mismatch.
    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(proof.path.len());
    for raw in &proof.path {
        match <[u8; 32]>::try_from(raw.as_slice()) {
            Ok(node) => nodes.push(node),
            Err(_) => return false,
        }
    }

    // Recompute (old_root, new_root) by replaying the SUBPROOF recursion against the
    // post-order path, consuming nodes from the back (outermost pushed last). When the old
    // tree is a complete subtree omitted from the proof, its root is seeded from `old_root`.
    let mut cursor = nodes.len();
    match recompute_subproof(m, n, true, old_root, &nodes, &mut cursor) {
        Some(SubproofRoots::Roots(computed_old, computed_new)) if cursor == 0 => {
            &computed_old == old_root && &computed_new == new_root
        }
        Some(SubproofRoots::OldFromSeed) if cursor == 0 => {
            // Whole old tree was complete: the proof's new root must hash to `new_root`
            // while the old subtree equals `old_root` by construction. This arises only
            // when m == n, already handled above, so treat as a mismatch here.
            false
        }
        _ => false,
    }
}

fn take_back(nodes: &[[u8; 32]], cursor: &mut usize) -> Option<[u8; 32]> {
    if *cursor == 0 {
        return None;
    }
    *cursor -= 1;
    Some(nodes[*cursor])
}

pub fn sign_tree_head(
    size: u64,
    root: &[u8; 32],
    sequence: u64,
    sk: &SigningKey,
) -> SignedTreeHead {
    let mut msg = Vec::with_capacity(8 + 32 + 8);
    msg.extend_from_slice(&size.to_be_bytes());
    msg.extend_from_slice(root);
    msg.extend_from_slice(&sequence.to_be_bytes());
    let sig: Signature = sk.sign(&msg);
    SignedTreeHead {
        size,
        root_hash: root.to_vec(),
        sequence,
        signature: sig.to_bytes().to_vec(),
    }
}

pub fn verify_tree_head(sth: &SignedTreeHead, vk: &VerifyingKey) -> bool {
    let sig_bytes = match <[u8; 64]>::try_from(sth.signature.as_slice()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(8 + 32 + 8);
    msg.extend_from_slice(&sth.size.to_be_bytes());
    msg.extend_from_slice(&sth.root_hash);
    msg.extend_from_slice(&sth.sequence.to_be_bytes());
    vk.verify(&msg, &sig).is_ok()
}

pub fn mirror(peer: &FederationPeer) -> Result<()> {
    idprova_core::http::validate_registry_url(&peer.url)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Err(anyhow::anyhow!(
        "live multi-operator federation mirroring is part of the IDProva operator/enterprise edition; the open library provides Merkle proof generation + verification + signed tree heads"
    ))
}
