use crate::errors::{Result, ZeenomeError};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Digest};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_value: String,
    pub path: Vec<ProofNode>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: String,
    pub is_left: bool,
}

/// Compute Merkle root from string leaves
pub fn compute_root(leaves: &[String]) -> Result<String> {
    if leaves.is_empty() {
        return Err(ZeenomeError::Merkle(
            "Cannot build tree with empty leaves".to_string(),
        ));
    }

    let hashed_leaves: Vec<Hash> = leaves
        .iter()
        .map(|leaf| Sha256::hash(leaf.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&hashed_leaves);
    let root = tree
        .root()
        .ok_or_else(|| ZeenomeError::Merkle("Failed to compute root".to_string()))?;

    Ok(hex::encode(root))
}

/// Generate a proof for a given leaf index
pub fn generate_proof(leaves: &[String], leaf_index: usize) -> Result<MerkleProof> {
    if leaf_index >= leaves.len() {
        return Err(ZeenomeError::Merkle(format!(
            "Leaf index {} out of bounds",
            leaf_index
        )));
    }

    let hashed_leaves: Vec<Hash> = leaves
        .iter()
        .map(|leaf| Sha256::hash(leaf.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&hashed_leaves);
    let root_bytes = tree
        .root()
        .ok_or_else(|| ZeenomeError::Merkle("Failed to compute root".to_string()))?;
    let root = hex::encode(root_bytes);

    // Build tree levels and extract sibling hashes in bottom-up order
    // rs_merkle returns proof_hashes() in bottom-up order (leaf to root)
    let mut path = Vec::new();
    let mut current_level = hashed_leaves.clone();
    let mut current_pos = leaf_index;

    // Traverse from leaf to root, extracting sibling at each level
    while current_level.len() > 1 {
        // Determine sibling position: XOR with 1 to get sibling
        let sibling_pos = current_pos ^ 1;
        let has_sibling = sibling_pos < current_level.len();
        let is_odd_length = current_level.len() % 2 == 1;
        let is_last_node = is_odd_length && current_pos == current_level.len() - 1;

        if has_sibling && !is_last_node {
            // Sibling exists, add it to path
            let sibling_hash = current_level[sibling_pos];

            // Determine if sibling is on the left
            // If current_pos is odd (right child), sibling is on left (is_left = true)
            // If current_pos is even (left child), sibling is on right (is_left = false)
            let is_left = (current_pos % 2) == 1;

            path.push(ProofNode {
                hash: hex::encode(sibling_hash),
                is_left,
            });
        }
        // If no sibling (is_last_node), don't add path node - node will be promoted

        // Build next level: hash pairs of nodes
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let combined = {
                    let mut hasher = Sha256Digest::new();
                    hasher.update(chunk[0]);
                    hasher.update(chunk[1]);
                    hasher.finalize().into()
                };
                next_level.push(combined);
            } else {
                // Odd number of nodes: promote the last node
                next_level.push(chunk[0]);
            }
        }

        // Update position for next level
        if is_last_node {
            // Promoted node goes to end of next level
            current_pos = next_level.len() - 1;
        } else {
            // Paired node: position is half (integer division)
            current_pos /= 2;
        }

        current_level = next_level;
    }

    // Path is stored in bottom-up order (leaf to root), matching verification algorithm

    // leaf_value should be the hex-encoded hash for rs_merkle compatibility
    let leaf_value = hex::encode(hashed_leaves[leaf_index]);

    Ok(MerkleProof {
        leaf_index,
        leaf_value,
        path,
        root,
    })
}

/// Verify a Merkle inclusion proof against its embedded root.
///
/// Walks `proof.path` bottom-up from `proof.leaf_value`, hashing each step in
/// the order indicated by `is_left`, and checks the result against `proof.root`.
///
/// A correct Merkle verifier MUST NOT require the original leaf set — needing
/// the leaves defeats the purpose (succinct membership without holding the
/// data). The previous implementation took `&[String]` and rebuilt the proof
/// from those leaves, ignoring `proof.path`, `proof.leaf_value`, and `proof.root`
/// entirely; tampered proofs were accepted as long as `leaf_index` was in range.
/// This implementation matches `zk::verify_merkle_proof` so on-chain/off-chain
/// verification stay in agreement.
pub fn verify_proof(proof: &MerkleProof) -> Result<bool> {
    fn decode_hash(field: &str, hex_str: &str) -> Result<Hash> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| ZeenomeError::Merkle(format!("Invalid {} hex: {}", field, e)))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| ZeenomeError::Merkle(format!(
                "{} must be 32 bytes, got {}",
                field,
                v.len()
            )))
    }

    let mut current_hash: Hash = decode_hash("leaf_value", &proof.leaf_value)?;

    // Path is stored bottom-up (leaf -> root). At each step the sibling is
    // either to the left or right of the running hash; matches `generate_proof`
    // which uses `current_pos % 2 == 1` to set `is_left`.
    for node in &proof.path {
        let sibling: Hash = decode_hash("path node", &node.hash)?;

        let mut hasher = Sha256Digest::new();
        if node.is_left {
            hasher.update(sibling);
            hasher.update(current_hash);
        } else {
            hasher.update(current_hash);
            hasher.update(sibling);
        }
        current_hash = hasher.finalize().into();
    }

    let expected_root: Hash = decode_hash("root", &proof.root)?;
    Ok(current_hash == expected_root)
}

/// Build merkle tree and return root (for backward compatibility)
pub fn build_merkle_tree(leaves: &[String]) -> Result<(String, Vec<Vec<String>>)> {
    let root = compute_root(leaves)?;
    // Return empty levels since we don't need them anymore
    Ok((root, Vec::new()))
}
