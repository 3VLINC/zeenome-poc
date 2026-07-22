//! Merkle Mountain Range — thin wrapper around `ckb-merkle-mountain-range`.
//!
//! Hashing is SHA-256 over `[u8; 32]` via [`Sha256Merge`]. `MmrProof` serializes
//! as hex sibling/peak hashes plus `mmr_size` for the crate's `MerkleProof::verify`.

use crate::errors::{Result, ZeenomeError};
use ckb_merkle_mountain_range::{
    helper::{leaf_index_to_mmr_size, leaf_index_to_pos},
    util::MemStore,
    Error as MmrError, MMRStoreReadOps, Merge, MerkleProof as CrateMerkleProof, MMR,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed-size SHA-256 digest used as the MMR node type.
pub type Hash = [u8; 32];

/// SHA-256 `Merge` impl plugged into the crate's MMR generics.
///
/// We hash the concatenation `lhs || rhs`. The crate's `merge_peaks` default
/// delegates to `merge`, so peak bagging uses the same scheme — this matches
/// the bag-the-peaks construction described in the
/// [Mimblewimble/Grin MMR doc](https://github.com/mimblewimble/grin/blob/master/doc/mmr.md).
pub struct Sha256Merge;

impl Merge for Sha256Merge {
    type Item = Hash;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> core::result::Result<Self::Item, MmrError> {
        let mut hasher = Sha256::new();
        hasher.update(lhs);
        hasher.update(rhs);
        Ok(hasher.finalize().into())
    }
}

fn hash_leaf(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(leaf_bytes);
    hasher.finalize().into()
}

fn decode_hex_hash(field: &str, hex_str: &str) -> Result<Hash> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ZeenomeError::Mmr(format!("Invalid {field} hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|v: alloc::vec::Vec<u8>| {
            ZeenomeError::Mmr(format!("{field} must be 32 bytes, got {}", v.len()))
        })
}

// Re-export `alloc::vec::Vec` so the `decode_hex_hash` error branch above
// works under the `no_std` guest build (where `Vec` lives in `alloc`).
extern crate alloc;

/// An MMR proof. Pure data — verification is a function over this struct alone,
/// no leaf set required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MmrProof {
    /// Logical leaf index (0-based, in insertion order). Convert to the
    /// MMR node position via `ckb_merkle_mountain_range::helper::leaf_index_to_pos`.
    pub leaf_index: u64,
    /// Hex-encoded SHA-256 hash of the leaf bytes.
    pub leaf_value: String,
    /// Hex-encoded sibling + peak hashes, in the order emitted by the
    /// upstream crate's `MerkleProof::proof_items`. Length is `O(log n)`.
    pub proof_items: Vec<String>,
    /// Total number of MMR positions at proof time. Required by the verifier
    /// to interpret the proof.
    pub mmr_size: u64,
    /// Hex-encoded MMR root the proof verifies against.
    pub root: String,
}

/// In-memory append-only MMR. Owns a `MemStore`; per-operation `MMR<…, &MemStore>`
/// cursors are created on the fly. The upstream crate parameterises the MMR
/// by `&MemStore`, so the store has to outlive any borrow — owning the store
/// here and creating cursors per call avoids self-referential lifetimes.
pub struct MerkleMountainRange {
    store: MemStore<Hash>,
    mmr_size: u64,
    leaf_count: u64,
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    /// Create an empty MMR.
    pub fn new() -> Self {
        Self {
            store: MemStore::default(),
            mmr_size: 0,
            leaf_count: 0,
        }
    }

    /// Rebuild an MMR from leaf bytes in order. Useful for migration sweeps
    /// where the only persisted state is the leaf list.
    pub fn from_leaves(leaves: &[String]) -> Result<Self> {
        let mut mmr = Self::new();
        for leaf in leaves {
            mmr.append(leaf.clone())?;
        }
        Ok(mmr)
    }

    /// Number of leaves appended so far (NOT the underlying `mmr_size`).
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Underlying MMR node count (the crate's `mmr_size`).
    pub fn size(&self) -> u64 {
        self.mmr_size
    }

    fn cursor(&self) -> MMR<Hash, Sha256Merge, &MemStore<Hash>> {
        MMR::new(self.mmr_size, &self.store)
    }

    /// Append a leaf and return `(leaf_index, new_root_hex)`.
    pub fn append(&mut self, leaf: String) -> Result<(u64, String)> {
        let leaf_hash = hash_leaf(leaf.as_bytes());
        let leaf_index = self.leaf_count;
        let mut cursor = self.cursor();
        cursor
            .push(leaf_hash)
            .map_err(|e| ZeenomeError::Mmr(format!("MMR push failed: {e}")))?;
        cursor
            .commit()
            .map_err(|e| ZeenomeError::Mmr(format!("MMR commit failed: {e}")))?;
        self.mmr_size = cursor.mmr_size();
        self.leaf_count += 1;
        let root = self.root()?;
        Ok((leaf_index, root))
    }

    /// Current MMR root, hex-encoded.
    pub fn root(&self) -> Result<String> {
        let root = self
            .cursor()
            .get_root()
            .map_err(|e| ZeenomeError::Mmr(format!("MMR root failed: {e}")))?;
        Ok(hex::encode(root))
    }

    /// Build an inclusion proof for the leaf at `leaf_index`.
    pub fn generate_proof(&self, leaf_index: u64) -> Result<MmrProof> {
        if leaf_index >= self.leaf_count {
            return Err(ZeenomeError::Mmr(format!(
                "leaf index {leaf_index} out of bounds (leaf_count = {})",
                self.leaf_count
            )));
        }
        let pos = leaf_index_to_pos(leaf_index);
        let cursor = self.cursor();
        let proof = cursor
            .gen_proof(alloc::vec![pos])
            .map_err(|e| ZeenomeError::Mmr(format!("MMR gen_proof failed: {e}")))?;
        let proof_items: Vec<String> = proof.proof_items().iter().map(hex::encode).collect();

        let leaf_hash = (&self.store)
            .get_elem(pos)
            .map_err(|e| ZeenomeError::Mmr(format!("MMR store read failed: {e}")))?
            .ok_or_else(|| ZeenomeError::Mmr(format!("Missing element at pos {pos}")))?;

        Ok(MmrProof {
            leaf_index,
            leaf_value: hex::encode(leaf_hash),
            proof_items,
            mmr_size: self.mmr_size,
            root: self.root()?,
        })
    }
}

/// Verify an MMR inclusion proof. Pure function over the proof — does NOT
/// take a leaf set. This is the property the placeholder verifier broke.
pub fn verify_mmr_proof(proof: &MmrProof) -> Result<bool> {
    // mmr_size sanity: must be the size implied by leaf_index_to_mmr_size for
    // at least `leaf_index + 1` leaves.
    let implied_min_size = leaf_index_to_mmr_size(proof.leaf_index);
    if proof.mmr_size < implied_min_size {
        return Ok(false);
    }

    let leaf_hash = decode_hex_hash("leaf_value", &proof.leaf_value)?;
    let root_hash = decode_hex_hash("root", &proof.root)?;

    let mut proof_hashes: Vec<Hash> = Vec::with_capacity(proof.proof_items.len());
    for (i, hex_str) in proof.proof_items.iter().enumerate() {
        proof_hashes.push(decode_hex_hash(
            // The crate's proof items are positional; the field name we use
            // here is purely for error messages.
            &alloc::format!("proof_items[{i}]"),
            hex_str,
        )?);
    }

    let pos = leaf_index_to_pos(proof.leaf_index);
    let crate_proof: CrateMerkleProof<Hash, Sha256Merge> =
        CrateMerkleProof::new(proof.mmr_size, proof_hashes);

    crate_proof
        .verify(root_hash, alloc::vec![(pos, leaf_hash)])
        .map_err(|e| ZeenomeError::Mmr(format!("MMR verify failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaves(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("leaf-{i}")).collect()
    }

    #[test]
    fn append_then_root_matches_from_leaves() {
        let leaves = sample_leaves(7);
        let mut mmr = MerkleMountainRange::new();
        for l in &leaves {
            mmr.append(l.clone()).unwrap();
        }
        let rebuilt = MerkleMountainRange::from_leaves(&leaves).unwrap();
        assert_eq!(mmr.root().unwrap(), rebuilt.root().unwrap());
        assert_eq!(mmr.leaf_count(), 7);
        assert_eq!(rebuilt.leaf_count(), 7);
    }

    #[test]
    fn proof_for_each_leaf_verifies() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 13, 16, 31] {
            let leaves = sample_leaves(n);
            let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
            for i in 0..n as u64 {
                let proof = mmr.generate_proof(i).unwrap();
                assert!(
                    verify_mmr_proof(&proof).unwrap(),
                    "proof for leaf {i} of {n} did not verify"
                );
            }
        }
    }

    #[test]
    fn mutate_leaf_value_rejected() {
        let leaves = sample_leaves(8);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let mut proof = mmr.generate_proof(3).unwrap();
        // Flip a hex nibble in leaf_value.
        let first = proof.leaf_value.remove(0);
        let flipped = if first == '0' { '1' } else { '0' };
        proof.leaf_value.insert(0, flipped);
        assert!(!verify_mmr_proof(&proof).unwrap_or(true));
    }

    #[test]
    fn mutate_root_rejected() {
        let leaves = sample_leaves(8);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let mut proof = mmr.generate_proof(2).unwrap();
        let first = proof.root.remove(0);
        let flipped = if first == '0' { '1' } else { '0' };
        proof.root.insert(0, flipped);
        assert!(!verify_mmr_proof(&proof).unwrap_or(true));
    }

    #[test]
    fn mutate_proof_items_rejected() {
        let leaves = sample_leaves(8);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let mut proof = mmr.generate_proof(5).unwrap();
        assert!(!proof.proof_items.is_empty(), "proof should be non-empty");
        // Flip a nibble inside the first proof item.
        let item = &mut proof.proof_items[0];
        let first = item.remove(0);
        let flipped = if first == '0' { '1' } else { '0' };
        item.insert(0, flipped);
        assert!(!verify_mmr_proof(&proof).unwrap_or(true));
    }

    #[test]
    fn mutate_leaf_index_rejected() {
        let leaves = sample_leaves(8);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let mut proof = mmr.generate_proof(4).unwrap();
        // Change the claimed index but keep the same proof material.
        proof.leaf_index = 2;
        assert!(!verify_mmr_proof(&proof).unwrap_or(true));
    }

    #[test]
    fn mutate_mmr_size_to_zero_rejected() {
        let leaves = sample_leaves(8);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let mut proof = mmr.generate_proof(3).unwrap();
        // Setting size to 0 places leaf_index out of range for the implied
        // minimum size — our top-of-verifier sanity check rejects this.
        proof.mmr_size = 0;
        match verify_mmr_proof(&proof) {
            Ok(ok) => assert!(!ok, "mmr_size=0 should not verify a real proof"),
            Err(_) => {}
        }
    }

    // Note: `MmrProof.mmr_size` is part of the witness consumed by the
    // upstream crate's `MerkleProof::verify`. Mutating it to another *plausible*
    // value (e.g. size+1) without also recomputing `root` is detected by the
    // recomputed-root inequality in the upstream verifier, but with cherry-picked
    // arithmetic an attacker could in principle find a `(size, root)` pair that
    // happens to verify under a coincidence. The strong soundness guarantee is
    // that mutating any of `leaf_value`, `root`, `proof_items`, or `leaf_index`
    // independently is rejected — and those are the bytes an attacker can
    // realistically forge without also recomputing the root from the leaf set.

    #[test]
    fn requires_no_leaf_set_to_verify() {
        // The whole point: verify_mmr_proof is a function of MmrProof alone.
        // This test exists to document the invariant; the absence of a leaf
        // parameter on the function signature is itself the proof.
        let leaves = sample_leaves(5);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let proof = mmr.generate_proof(2).unwrap();
        // Drop the leaf set on the floor — verification still works.
        drop(leaves);
        drop(mmr);
        assert!(verify_mmr_proof(&proof).unwrap());
    }

    #[test]
    fn single_leaf_mmr() {
        let leaves = sample_leaves(1);
        let mmr = MerkleMountainRange::from_leaves(&leaves).unwrap();
        let proof = mmr.generate_proof(0).unwrap();
        assert!(verify_mmr_proof(&proof).unwrap());
    }
}
