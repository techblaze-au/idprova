//! Merkle tree for batched commitment anchoring (ADR 0012).
//!
//! Uses RFC 6962 domain separation over SHA-512:
//! - Leaf hash: `SHA-512(0x00 || commitment)`
//! - Node hash: `SHA-512(0x01 || left || right)`
//!
//! The `0x00` / `0x01` prefixes provide second-preimage resistance (a leaf
//! preimage can never be confused with an internal node).
//!
//! When a level has an odd number of nodes, the last node is carried unchanged
//! to the next level (it is **not** duplicated). Root computation, proof
//! generation, and verification all follow this rule consistently.
//!
//! We accumulate 64-byte commitment leaves (see [`super::commitment`]), build a
//! root, anchor only the root to the transparency log, and keep a per-leaf
//! [`InclusionProof`] on each receipt so anyone can verify offline that a
//! commitment was in the batch whose root was anchored.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Size of each hash node / leaf commitment in bytes (SHA-512 output).
pub const NODE_LEN: usize = 64;

/// Indicates which side a sibling node is on relative to the path node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// The sibling sits to the left of the running hash.
    Left,
    /// The sibling sits to the right of the running hash.
    Right,
}

/// A single sibling entry in an inclusion proof.
///
/// `hash` is the hex-encoded 64-byte hash of the sibling node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofNode {
    /// Which side the sibling is on relative to the current path node.
    pub side: Side,
    /// Hex-encoded 64-byte hash of the sibling node.
    pub hash: String,
}

/// An offline-verifiable inclusion proof for a single commitment leaf.
///
/// Allows independent verification that a commitment was included in a batch
/// whose root was anchored. `leaf_index` / `tree_size` pin the leaf's position
/// (informational); `siblings` is the bottom-up authentication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf this proof covers.
    pub leaf_index: usize,
    /// Number of leaves in the tree at proof-generation time.
    pub tree_size: usize,
    /// Sibling hashes from leaf to root (bottom-up order).
    pub siblings: Vec<ProofNode>,
    /// Hex-encoded 64-byte Merkle root.
    pub root: String,
}

/// A batched Merkle tree over 64-byte commitment leaves.
pub struct MerkleTree {
    leaves: Vec<[u8; NODE_LEN]>,
    /// All levels of the tree, stored bottom-up. `levels[0]` is the
    /// leaf-hash level; the last level holds the single root.
    levels: Vec<Vec<[u8; NODE_LEN]>>,
}

/// Compute the leaf hash for a commitment: `SHA-512(0x00 || commitment)`.
pub fn leaf_hash(commitment: &[u8; NODE_LEN]) -> [u8; NODE_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([0x00u8]);
    hasher.update(commitment);
    let result = hasher.finalize();
    let mut out = [0u8; NODE_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute the node hash for two children: `SHA-512(0x01 || left || right)`.
pub fn node_hash(left: &[u8; NODE_LEN], right: &[u8; NODE_LEN]) -> [u8; NODE_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; NODE_LEN];
    out.copy_from_slice(&result);
    out
}

impl MerkleTree {
    /// Build a Merkle tree from a slice of 64-byte commitment leaves.
    ///
    /// Returns `None` if the slice is empty.
    pub fn from_leaves(leaves: &[[u8; NODE_LEN]]) -> Option<MerkleTree> {
        if leaves.is_empty() {
            return None;
        }

        // Level 0: leaf hashes.
        let level0: Vec<[u8; NODE_LEN]> = leaves.iter().map(leaf_hash).collect();

        let mut levels: Vec<Vec<[u8; NODE_LEN]>> = vec![level0];

        // Build upward until a single root node remains.
        loop {
            // Safe: the loop invariant guarantees at least one level exists.
            let current = levels.last().expect("levels is non-empty by construction");
            if current.len() == 1 {
                break;
            }
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i + 1 < current.len() {
                next.push(node_hash(&current[i], &current[i + 1]));
                i += 2;
            }
            // Odd count: carry the last node unchanged.
            if i < current.len() {
                next.push(current[i]);
            }
            levels.push(next);
        }

        Some(MerkleTree {
            leaves: leaves.to_vec(),
            levels,
        })
    }

    /// The 64-byte Merkle root.
    pub fn root(&self) -> [u8; NODE_LEN] {
        // Safe: `from_leaves` guarantees a last level with exactly one element.
        *self
            .levels
            .last()
            .and_then(|l| l.first())
            .expect("a built tree always has a single root node")
    }

    /// The Merkle root as a hex string.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no leaves (always `false` for a built tree).
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings: Vec<ProofNode> = Vec::new();
        let mut idx = index;

        // Walk every level except the root level.
        for level_nodes in &self.levels[..self.levels.len() - 1] {
            let len = level_nodes.len();

            // A carried odd-last node has no sibling at this level; advance its
            // position to the (last) carried slot in the next level.
            if (len & 1) == 1 && idx == len - 1 {
                idx = len.div_ceil(2) - 1;
                continue;
            }

            let (sibling_idx, side) = if (idx & 1) == 0 {
                // Left child → sibling is on the right.
                (idx + 1, Side::Right)
            } else {
                // Right child → sibling is on the left.
                (idx - 1, Side::Left)
            };

            siblings.push(ProofNode {
                side,
                hash: hex::encode(level_nodes[sibling_idx]),
            });

            idx /= 2;
        }

        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.leaves.len(),
            siblings,
            root: self.root_hex(),
        })
    }
}

/// Constant-time equality of two 64-byte arrays (no early return on mismatch).
fn ct_eq(a: &[u8; NODE_LEN], b: &[u8; NODE_LEN]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

impl InclusionProof {
    /// Verify that `leaf_commitment` was included in the tree that produced
    /// this proof, by recomputing the root from the leaf and the sibling path
    /// and constant-time-comparing it against [`Self::root`].
    ///
    /// Returns `false` on any error (bad hex, wrong length, or mismatch) and
    /// never panics.
    pub fn verify(&self, leaf_commitment: &[u8; NODE_LEN]) -> bool {
        let root_bytes = match decode_hex_64(&self.root) {
            Some(r) => r,
            None => return false,
        };

        // Start from the leaf hash and walk up the authentication path.
        let mut current = leaf_hash(leaf_commitment);
        for pn in &self.siblings {
            let sibling = match decode_hex_64(&pn.hash) {
                Some(s) => s,
                None => return false,
            };
            current = match pn.side {
                Side::Left => node_hash(&sibling, &current),
                Side::Right => node_hash(&current, &sibling),
            };
        }

        ct_eq(&current, &root_bytes)
    }
}

/// Decode a hex string into exactly 64 bytes. Returns `None` on any error.
fn decode_hex_64(s: &str) -> Option<[u8; NODE_LEN]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != NODE_LEN {
        return None;
    }
    let mut out = [0u8; NODE_LEN];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a 64-byte commitment seeded by a single byte.
    fn commitment(b: u8) -> [u8; NODE_LEN] {
        let mut c = [0u8; NODE_LEN];
        c[0] = b;
        c[NODE_LEN - 1] = b.wrapping_add(1);
        c
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let c = commitment(0xAA);
        let tree = MerkleTree::from_leaves(&[c]).unwrap();
        assert_eq!(tree.root(), leaf_hash(&c));
        assert_eq!(tree.root_hex(), hex::encode(leaf_hash(&c)));
    }

    #[test]
    fn single_leaf_empty_siblings_and_verify() {
        let c = commitment(0xAA);
        let tree = MerkleTree::from_leaves(&[c]).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.verify(&c));
    }

    #[test]
    fn two_leaves_root_and_verify() {
        let a = commitment(0x01);
        let b = commitment(0x02);
        let tree = MerkleTree::from_leaves(&[a, b]).unwrap();

        let expected_root = node_hash(&leaf_hash(&a), &leaf_hash(&b));
        assert_eq!(tree.root(), expected_root);

        let pa = tree.proof(0).unwrap();
        let pb = tree.proof(1).unwrap();
        assert!(pa.verify(&a));
        assert!(pb.verify(&b));
        assert!(!pa.verify(&b));
    }

    #[test]
    fn three_leaves_odd_carry_and_verify() {
        let a = commitment(0x01);
        let b = commitment(0x02);
        let c = commitment(0x03);
        let tree = MerkleTree::from_leaves(&[a, b, c]).unwrap();

        // Root must be node_hash(node_hash(lh(a), lh(b)), lh(c)) — c carried.
        let ab = node_hash(&leaf_hash(&a), &leaf_hash(&b));
        let expected_root = node_hash(&ab, &leaf_hash(&c));
        assert_eq!(tree.root(), expected_root);

        let leaves = [a, b, c];
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(leaf), "proof for leaf {i} should verify");
        }
    }

    #[test]
    fn five_leaves_all_verify() {
        let leaves: Vec<[u8; NODE_LEN]> = (0..5u8).map(commitment).collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(tree.len(), 5);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(leaf), "leaf {i} should verify");
        }
    }

    #[test]
    fn eight_leaves_all_verify() {
        let leaves: Vec<[u8; NODE_LEN]> = (0..8u8).map(commitment).collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(tree.len(), 8);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(leaf), "leaf {i} should verify");
        }
    }

    #[test]
    fn seven_leaves_all_verify_multi_level_carry() {
        // 7 leaves exercises odd carries at two successive levels.
        let leaves: Vec<[u8; NODE_LEN]> = (0..7u8).map(commitment).collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(leaf), "leaf {i} should verify");
        }
    }

    #[test]
    fn tamper_proof_fails_for_different_commitment() {
        let a = commitment(0x01);
        let b = commitment(0x02);
        let tree = MerkleTree::from_leaves(&[a, b]).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(proof.verify(&a));
        assert!(!proof.verify(&b));
    }

    #[test]
    fn wrong_root_hex_fails_no_panic() {
        let a = commitment(0x01);
        let tree = MerkleTree::from_leaves(&[a]).unwrap();
        let mut proof = tree.proof(0).unwrap();
        let mut chars: Vec<char> = proof.root.chars().collect();
        chars[0] = if chars[0] == '0' { 'f' } else { '0' };
        proof.root = chars.into_iter().collect();
        assert!(!proof.verify(&a));
    }

    #[test]
    fn malformed_hex_sibling_fails_no_panic() {
        let a = commitment(0x01);
        let b = commitment(0x02);
        let c = commitment(0x03);
        let tree = MerkleTree::from_leaves(&[a, b, c]).unwrap();
        let mut proof = tree.proof(0).unwrap();
        proof.siblings.push(ProofNode {
            side: Side::Right,
            hash: "zzzz".to_string(),
        });
        assert!(!proof.verify(&a));
    }

    #[test]
    fn serde_round_trip_inclusion_proof() {
        let a = commitment(0x01);
        let b = commitment(0x02);
        let tree = MerkleTree::from_leaves(&[a, b]).unwrap();
        let proof = tree.proof(0).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn side_lowercase_in_json() {
        assert_eq!(serde_json::to_string(&Side::Left).unwrap(), "\"left\"");
        assert_eq!(serde_json::to_string(&Side::Right).unwrap(), "\"right\"");
    }

    #[test]
    fn out_of_range_index_returns_none() {
        let a = commitment(0x01);
        let tree = MerkleTree::from_leaves(&[a]).unwrap();
        assert!(tree.proof(1).is_none());
        assert!(tree.proof(100).is_none());
    }

    #[test]
    fn empty_leaves_returns_none() {
        assert!(MerkleTree::from_leaves(&[]).is_none());
    }
}
