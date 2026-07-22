//! Zeenome ZK Library
//!
//! This module provides reusable components for ZK applications:
//! - SNP Merkle proof verification
//! - MMR proof verification
//! - SP1 input/output helpers for reading and verifying proofs (requires "sp1" feature)

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    crypto,
    errors::{Result, ZeenomeError},
    json_canon::{self, JsonPathLeaf},
    signing, variant,
};

/// Error types for ZK verification operations
#[derive(Debug, Error)]
pub enum ZkVerificationError {
    #[error("Merkle proof verification failed: {0}")]
    MerkleVerificationFailed(String),
    #[error("MMR proof verification failed: {0}")]
    MmrVerificationFailed(String),
    #[error("Proof validation error: {0}")]
    ProofValidationError(String),
}

impl From<ZkVerificationError> for ZeenomeError {
    fn from(err: ZkVerificationError) -> Self {
        match err {
            ZkVerificationError::MerkleVerificationFailed(msg) => {
                ZeenomeError::Merkle(format!("ZK verification: {}", msg))
            }
            ZkVerificationError::MmrVerificationFailed(msg) => {
                ZeenomeError::Mmr(format!("ZK verification: {}", msg))
            }
            ZkVerificationError::ProofValidationError(msg) => {
                ZeenomeError::InvalidFormat(format!("ZK verification: {}", msg))
            }
        }
    }
}

/// Merkle proof structure for SNP verification
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

// `MmrProof` and the verifier live in `crate::mmr` (real MMR via
// `ckb-merkle-mountain-range`). Re-exported here so the SP1 guest crates that
// `use zeenome_core::zk::MmrProof;` keep compiling.
pub use crate::mmr::{verify_mmr_proof, MmrProof};

/// Verified SNP inputs after proof verification
#[derive(Debug, Clone)]
pub struct VerifiedSnpInputs<T> {
    pub snps: Vec<T>,
    pub merkle_root: String,
    pub mmr_root: String,
    pub job_id: String,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub epoch_number: i32,
    pub signature: String,
    pub registry_root: String,
}

#[derive(Debug, Clone)]
pub struct GenomicCommitmentInputs {
    pub expected_mmr_root: String,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub epoch_number: i32,
    pub signature: String,
    pub expected_registry_root: String,
    pub registry_proof: MerkleProof,
}

#[derive(Debug, Clone)]
pub struct ClinicianCommitmentInputs {
    pub expected_mmr_root: String,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub epoch_number: i32,
    pub signature: String,
    pub expected_registry_root: String,
    pub registry_proof: MerkleProof,
}

/// Verified phenotype JSON inputs after proof verification.
#[derive(Debug, Clone)]
pub struct VerifiedPhenotypeJsonInputs {
    pub json_paths: Vec<JsonPathLeaf>,
    pub merkle_root: String,
    pub mmr_root: String,
    pub job_id: String,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub epoch_number: i32,
    pub signature: String,
    pub registry_root: String,
}

/// Unified verified inputs supporting both SNP and phenotype JSON data
#[derive(Debug, Clone)]
pub struct VerifiedInputs {
    // SNP / genomic track (optional)
    pub snps: Option<Vec<variant::NormalizedVariant>>,
    pub snp_merkle_root: Option<String>,
    pub snp_mmr_root: Option<String>,
    pub genomic_clinician_id: Option<String>,
    pub genomic_clinician_pubkey: Option<String>,
    pub genomic_epoch_number: Option<i32>,
    pub genomic_signature: Option<String>,
    pub genomic_registry_root: Option<String>,

    // Phenotype JSON track (optional)
    pub json_paths: Option<Vec<JsonPathLeaf>>,
    pub json_merkle_root: Option<String>,
    pub phenotype_mmr_root: Option<String>,
    pub phenotype_clinician_id: Option<String>,
    pub phenotype_clinician_pubkey: Option<String>,
    pub phenotype_epoch_number: Option<i32>,
    pub phenotype_signature: Option<String>,
    pub phenotype_registry_root: Option<String>,

    // Common fields
    pub job_id: String,
    /// Policy roots committed in [`PublicOutput`] for verifier-visible anchoring.
    pub policy: PublicPolicyCommitment,
}


/// Policy fields committed alongside guest results (verifier-visible; no clinician pubkey).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicPolicyCommitment {
    pub whitelist_registry_root: String,
    pub job_id: String,
}

/// Public outputs committed by zk programs.
///
/// **Privacy model:** `clinician_pubkey` and Merkle witness material stay on SP1 stdin (witness).
/// Only this struct is `io::commit`-visible (bincode-serialized as committed public values).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicOutput {
    pub policy: PublicPolicyCommitment,
    pub nullifier: String,
    pub payload: String,
}

/// Decode SP1 committed public values (bincode `PublicOutput` only).
#[must_use]
pub fn deserialize_public_output_bincode(bytes: &[u8]) -> Result<PublicOutput> {
    bincode::deserialize(bytes).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("deserialize PublicOutput (bincode): {e}"))
    })
}

/// Canonical `PublicOutput.payload` suffix for demos when a guest rejects eligibility.
/// Uses `key:value` lines compatible with CLI JSON decoding (avoid `:` inside values).
#[must_use]
pub fn payload_status_ineligible(reason_slug: &str) -> String {
    let sanitized: String = reason_slug.chars().map(|c| if c == ':' { '_' } else { c }).collect();
    format!("status:INELIGIBLE\nreason:{sanitized}")
}

/// Types that can expose a canonical Merkle leaf preimage string.
pub trait MerkleLeafPreimage {
    fn merkle_leaf_preimage(&self) -> String;
}

impl MerkleLeafPreimage for variant::NormalizedVariant {
    fn merkle_leaf_preimage(&self) -> String {
        variant::canonical_variant_leaf_preimage(self)
    }
}

impl MerkleLeafPreimage for JsonPathLeaf {
    fn merkle_leaf_preimage(&self) -> String {
        format!(
            "{}|{}|{}",
            json_canon::LEAF_PREFIX_V1,
            self.pointer,
            self.jcs_value
        )
    }
}

/// Parse genome build from stdin / job metadata (must match variant rows).
pub fn parse_genome_build(s: &str) -> Result<variant::GenomeBuild> {
    match s.trim() {
        "GRCh38" => Ok(variant::GenomeBuild::GRCh38),
        other => Err(ZeenomeError::InvalidFormat(format!(
            "Unsupported or mismatched genome_build: {}",
            other
        ))),
    }
}

/// Verify variant Merkle and MMR proofs against expected commitments.
pub fn verify_inputs(
    snps: Vec<variant::NormalizedVariant>,
    snp_proofs: Vec<MerkleProof>,
    expected_merkle_root: String,
    mmr_proof: MmrProof,
    commitment: GenomicCommitmentInputs,
    job_id: String,
    expected_genome_build: variant::GenomeBuild,
) -> Result<VerifiedSnpInputs<variant::NormalizedVariant>> {
    let expected_mmr_root = commitment.expected_mmr_root.clone();
    let expected_registry_root = commitment.expected_registry_root.clone();

    if snp_proofs.len() != snps.len() {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Number of SNP proofs ({}) does not match number of SNPs ({})",
            snp_proofs.len(),
            snps.len()
        )));
    }

    for (idx, (snp, proof)) in snps.iter().zip(&snp_proofs).enumerate() {
        if snp.genome_build != expected_genome_build {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Variant genome_build mismatch at index {} (expected {:?})",
                idx, expected_genome_build
            )));
        }
        let preimage = snp.merkle_leaf_preimage();
        let expected_leaf_hash = hash_data(preimage.as_bytes());

        if proof.leaf_value != expected_leaf_hash {
            return Err(ZeenomeError::InvalidFormat(format!(
                "SNP Merkle proof leaf hash mismatch at index {}",
                idx
            )));
        }

        if !verify_merkle_proof(proof)? {
            return Err(ZeenomeError::Merkle(
                "SNP Merkle proof verification returned false".to_string(),
            ));
        }

        if proof.root != expected_merkle_root {
            return Err(ZeenomeError::InvalidFormat(
                "SNP Merkle proof root does not match expected root".to_string(),
            ));
        }
    }

    if !verify_mmr_proof(&mmr_proof)? {
        return Err(ZeenomeError::Mmr(
            "MMR proof verification returned false".to_string(),
        ));
    }

    if mmr_proof.root != expected_mmr_root {
        return Err(ZeenomeError::InvalidFormat(
            "MMR proof root does not match expected MMR root".to_string(),
        ));
    }

    // MMR leaves are raw `merkle_root` hex strings; the new MMR's `append`
    // hashes the leaf bytes via SHA-256 before storing, so the on-proof
    // `leaf_value` is `hex(SHA256(merkle_root_bytes))` — matching the
    // convention `merkle::generate_proof` already uses for the registry tree.
    let expected_mmr_leaf = crypto::hash_data(expected_merkle_root.as_bytes());
    if mmr_proof.leaf_value != expected_mmr_leaf {
        return Err(ZeenomeError::InvalidFormat(
            "MMR leaf value does not match SNP Merkle root".to_string(),
        ));
    }

    // Verify clinician signature over the genomic commitment tuple
    let pubkey_bytes = hex::decode(&commitment.clinician_pubkey)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid clinician pubkey hex: {}", e)))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Crypto("Clinician pubkey must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid clinician public key bytes: {e}")))?;

    let signature_bytes = hex::decode(&commitment.signature)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid commitment signature hex: {}", e)))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Crypto("Genomic commitment signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&signature_array);

    let message = signing::commitment_message(
        signing::ArtifactDomain::GenomicVcf,
        &commitment.clinician_id,
        &expected_merkle_root,
        commitment.epoch_number,
        &expected_mmr_root,
        &expected_registry_root,
    );
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|e| {
            ZeenomeError::Crypto(format!(
                "Genomic commitment signature verification failed: {e}"
            ))
        })?;

    // Registry leaves are raw `mmr_root` strings; inclusion proofs use
    // `leaf_value = hex(SHA256(mmr_root_bytes))` (see `merkle::generate_proof`).
    let expected_registry_leaf = crypto::hash_data(expected_mmr_root.as_bytes());
    if commitment.registry_proof.leaf_value != expected_registry_leaf {
        return Err(ZeenomeError::InvalidFormat(
            "Registry proof leaf hash does not match MMR root".to_string(),
        ));
    }

    if commitment.registry_proof.root != expected_registry_root {
        return Err(ZeenomeError::InvalidFormat(
            "Registry proof root does not match expected registry root".to_string(),
        ));
    }

    if !verify_merkle_proof(&commitment.registry_proof)? {
        return Err(ZeenomeError::Merkle(
            "Registry proof verification returned false".to_string(),
        ));
    }

    Ok(VerifiedSnpInputs {
        snps,
        merkle_root: expected_merkle_root,
        mmr_root: expected_mmr_root,
        job_id,
        clinician_id: commitment.clinician_id,
        clinician_pubkey: commitment.clinician_pubkey,
        epoch_number: commitment.epoch_number,
        signature: commitment.signature,
        registry_root: expected_registry_root,
    })
}

/// Verify that a signer's Ed25519 public key (hex) is a leaf of the whitelist registry Merkle tree.
/// Leaf preimages are the raw UTF-8 hex strings (same convention as `merkle::compute_root` over `&[String]`).
///
/// **Provenance:** accreditors allowlist one stable pubkey per org
/// (`organizations.signing_pubkey`), not individual clinician keys — see #736/#722. The pubkey
/// checked here is whichever key the caller supplies as the epoch signer (`clinician_pubkey` on
/// [`VerifiedInputs`]); this function itself is agnostic to whether that key belongs to a
/// clinician or an org and requires no change to prove org-key membership — only the allowlist
/// Merkle tree's leaf set (built by the accreditor) needs to be org-keyed.
pub fn verify_org_whitelist_inclusion(
    pubkey_hex: &str,
    proof: &MerkleProof,
    expected_registry_root: &str,
) -> Result<()> {
    let expected_leaf_hash = hash_data(pubkey_hex.as_bytes());
    if proof.leaf_value != expected_leaf_hash {
        return Err(ZeenomeError::InvalidFormat(
            "Whitelist Merkle proof leaf hash does not match pubkey hex".to_string(),
        ));
    }
    if proof.root != expected_registry_root {
        return Err(ZeenomeError::InvalidFormat(
            "Whitelist proof root does not match expected registry root".to_string(),
        ));
    }
    if !verify_merkle_proof(proof)? {
        return Err(ZeenomeError::Merkle(
            "Whitelist Merkle proof verification returned false".to_string(),
        ));
    }
    Ok(())
}

/// Verify a Merkle proof using rs_merkle's algorithm
/// This verifies that the leaf + inclusion proof reconstructs to the given root.
/// For zkVM contexts, we only need the root and the proof path - no tree size needed.
pub fn verify_merkle_proof(proof: &MerkleProof) -> Result<bool> {
    // Decode leaf_value from hex (it should be a hex-encoded hash)
    let leaf_hash_bytes = hex::decode(&proof.leaf_value)
        .map_err(|e| ZeenomeError::Merkle(format!("Invalid leaf_value hex: {}", e)))?;

    if leaf_hash_bytes.len() != 32 {
        return Err(ZeenomeError::Merkle(format!(
            "Leaf hash must be 32 bytes, got {}",
            leaf_hash_bytes.len()
        )));
    }

    let mut current_hash: [u8; 32] = leaf_hash_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Merkle("Failed to convert leaf hash to [u8; 32]".to_string()))?;

    // Reconstruct the path using rs_merkle's algorithm
    // rs_merkle concatenates child hashes as bytes, then hashes
    // proof.path is stored bottom-up (leaf to root), so we iterate in order
    for node in &proof.path {
        let sibling_hash_bytes = hex::decode(&node.hash)
            .map_err(|e| ZeenomeError::Merkle(format!("Invalid proof node hex: {}", e)))?;

        if sibling_hash_bytes.len() != 32 {
            return Err(ZeenomeError::Merkle(format!(
                "Proof node hash must be 32 bytes, got {}",
                sibling_hash_bytes.len()
            )));
        }

        let sibling_hash: [u8; 32] = sibling_hash_bytes.try_into().map_err(|_| {
            ZeenomeError::Merkle("Failed to convert proof node hash to [u8; 32]".to_string())
        })?;

        // rs_merkle concatenates left then right child as bytes
        let combined = if node.is_left {
            // Sibling is on left, current is on right: [sibling, current]
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&sibling_hash);
            combined.extend_from_slice(&current_hash);
            combined
        } else {
            // Current is on left, sibling is on right: [current, sibling]
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&current_hash);
            combined.extend_from_slice(&sibling_hash);
            combined
        };

        // Hash using SHA-256 (same as rs_merkle's Sha256::hash)
        let mut hasher = Sha256::new();
        hasher.update(&combined);
        current_hash = hasher.finalize().into();
    }

    // Compare with expected root (decode from hex)
    let root_bytes = hex::decode(&proof.root)
        .map_err(|e| ZeenomeError::Merkle(format!("Invalid root hex: {}", e)))?;

    if root_bytes.len() != 32 {
        return Err(ZeenomeError::Merkle(format!(
            "Root must be 32 bytes, got {}",
            root_bytes.len()
        )));
    }

    let expected_root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Merkle("Failed to convert root to [u8; 32]".to_string()))?;

    Ok(current_hash == expected_root)
}

// `verify_mmr_proof` previously lived here as a flat-hash placeholder that
// re-concatenated every leaf in `proof.peaks` (which was actually "every other
// leaf in the dataset") to recompute the root. The real verifier now lives in
// `crate::mmr::verify_mmr_proof` and is re-exported at the top of this file.

/// Verify phenotype JSON path leaves and MMR proofs against expected commitments.
pub fn verify_json_path_inputs(
    json_paths: Vec<JsonPathLeaf>,
    json_path_proofs: Vec<MerkleProof>,
    expected_merkle_root: String,
    mmr_proof: MmrProof,
    commitment: ClinicianCommitmentInputs,
    job_id: String,
) -> Result<VerifiedPhenotypeJsonInputs> {
    let expected_mmr_root = commitment.expected_mmr_root.clone();
    let expected_registry_root = commitment.expected_registry_root.clone();

    if json_path_proofs.len() != json_paths.len() {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Number of JSON path proofs ({}) does not match number of leaves ({})",
            json_path_proofs.len(),
            json_paths.len()
        )));
    }

    for (idx, (leaf, proof)) in json_paths.iter().zip(&json_path_proofs).enumerate() {
        let preimage = leaf.merkle_leaf_preimage();
        let expected_leaf_hash = hash_data(preimage.as_bytes());

        if proof.leaf_value != expected_leaf_hash {
            return Err(ZeenomeError::InvalidFormat(format!(
                "JSON path Merkle proof leaf hash mismatch at index {}",
                idx
            )));
        }

        if !verify_merkle_proof(proof)? {
            return Err(ZeenomeError::Merkle(
                "JSON path Merkle proof verification returned false".to_string(),
            ));
        }

        if proof.root != expected_merkle_root {
            return Err(ZeenomeError::InvalidFormat(
                "JSON path Merkle proof root does not match expected root".to_string(),
            ));
        }
    }

    if !verify_mmr_proof(&mmr_proof)? {
        return Err(ZeenomeError::Mmr(
            "MMR proof verification returned false".to_string(),
        ));
    }

    if mmr_proof.root != expected_mmr_root {
        return Err(ZeenomeError::InvalidFormat(
            "MMR proof root does not match expected MMR root".to_string(),
        ));
    }

    let expected_mmr_leaf = crypto::hash_data(expected_merkle_root.as_bytes());
    if mmr_proof.leaf_value != expected_mmr_leaf {
        return Err(ZeenomeError::InvalidFormat(
            "MMR leaf value does not match phenotype JSON Merkle root".to_string(),
        ));
    }

    let pubkey_bytes = hex::decode(&commitment.clinician_pubkey)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid clinician pubkey hex: {}", e)))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Crypto("Clinician pubkey must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid clinician public key bytes: {e}")))?;

    let signature_bytes = hex::decode(&commitment.signature)
        .map_err(|e| ZeenomeError::Crypto(format!("Invalid commitment signature hex: {}", e)))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ZeenomeError::Crypto("Clinician signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&signature_array);

    let message = signing::commitment_message(
        signing::ArtifactDomain::Phenotype,
        &commitment.clinician_id,
        &expected_merkle_root,
        commitment.epoch_number,
        &expected_mmr_root,
        &expected_registry_root,
    );
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|e| {
            ZeenomeError::Crypto(format!(
                "Clinician commitment signature verification failed: {e}"
            ))
        })?;

    let expected_registry_leaf = crypto::hash_data(expected_mmr_root.as_bytes());
    if commitment.registry_proof.leaf_value != expected_registry_leaf {
        return Err(ZeenomeError::InvalidFormat(
            "Registry proof leaf hash does not match MMR root".to_string(),
        ));
    }

    if commitment.registry_proof.root != expected_registry_root {
        return Err(ZeenomeError::InvalidFormat(
            "Registry proof root does not match expected registry root".to_string(),
        ));
    }

    if !verify_merkle_proof(&commitment.registry_proof)? {
        return Err(ZeenomeError::Merkle(
            "Registry proof verification returned false".to_string(),
        ));
    }

    Ok(VerifiedPhenotypeJsonInputs {
        json_paths,
        merkle_root: expected_merkle_root,
        mmr_root: expected_mmr_root,
        job_id,
        clinician_id: commitment.clinician_id,
        clinician_pubkey: commitment.clinician_pubkey,
        epoch_number: commitment.epoch_number,
        signature: commitment.signature,
        registry_root: expected_registry_root,
    })
}

fn hash_data(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn compute_nullifier(job_id: &str, merkle_root: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(merkle_root.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(feature = "sp1")]
/// Read and verify all SP1 inputs for a ZK program
///
/// This function reads all inputs from SP1 stdin and verifies:
/// - SNP Merkle proofs match the expected merkle root (if provided)
/// - HPO Merkle proofs match the expected merkle root (if provided)
/// - MMR proofs match the expected MMR roots
/// - MMR leaf values match the Merkle roots
///
/// **Witness vs public:** clinician pubkey, signatures, and Merkle witnesses are read from stdin
/// (SP1 witness). Only [`commit_public_output`] material is publicly committed.
///
/// Returns the verified inputs (SNP and/or HPO) for use in the application logic.
pub fn read_and_verify_inputs() -> Result<VerifiedInputs> {
    let job_id: String = sp1_zkvm::io::read::<String>();

    // Read SNP data (optional - check if present)
    let has_snp_data: bool = sp1_zkvm::io::read::<bool>();

    let (
        snps,
        snp_merkle_root,
        snp_mmr_root,
        genomic_clinician_id,
        genomic_clinician_pubkey,
        genomic_epoch_number,
        genomic_signature,
        genomic_registry_root,
    ) = if has_snp_data {
        let genome_build_str: String = sp1_zkvm::io::read::<String>();
        let expected_genome_build = parse_genome_build(&genome_build_str)?;
        let snps: Vec<variant::NormalizedVariant> =
            sp1_zkvm::io::read::<Vec<variant::NormalizedVariant>>();

        let snp_proofs: Vec<MerkleProof> = sp1_zkvm::io::read::<Vec<MerkleProof>>();
        let expected_merkle_root: String = sp1_zkvm::io::read::<String>();
        let mmr_proof: MmrProof = sp1_zkvm::io::read::<MmrProof>();
        let expected_mmr_root: String = sp1_zkvm::io::read::<String>();
        let g_clinician_id: String = sp1_zkvm::io::read::<String>();
        let g_clinician_pubkey: String = sp1_zkvm::io::read::<String>();
        let epoch_number: i32 = sp1_zkvm::io::read::<i32>();
        let commitment_signature: String = sp1_zkvm::io::read::<String>();
        let registry_root: String = sp1_zkvm::io::read::<String>();
        let registry_proof: MerkleProof = sp1_zkvm::io::read::<MerkleProof>();

        let verified = verify_inputs(
            snps,
            snp_proofs,
            expected_merkle_root.clone(),
            mmr_proof,
            GenomicCommitmentInputs {
                expected_mmr_root: expected_mmr_root.clone(),
                clinician_id: g_clinician_id.clone(),
                clinician_pubkey: g_clinician_pubkey.clone(),
                epoch_number,
                signature: commitment_signature.clone(),
                expected_registry_root: registry_root.clone(),
                registry_proof,
            },
            job_id.clone(),
            expected_genome_build,
        )?;

        (
            Some(verified.snps),
            Some(verified.merkle_root),
            Some(verified.mmr_root),
            Some(verified.clinician_id),
            Some(verified.clinician_pubkey),
            Some(verified.epoch_number),
            Some(verified.signature),
            Some(verified.registry_root),
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };

    // Read phenotype JSON data (optional)
    let has_phenotype_json: bool = sp1_zkvm::io::read::<bool>();

    let (
        json_paths,
        json_merkle_root,
        phenotype_mmr_root,
        phenotype_clinician_id,
        phenotype_clinician_pubkey,
        phenotype_epoch_number,
        phenotype_signature,
        phenotype_registry_root,
    ) = if has_phenotype_json {
        let json_paths: Vec<JsonPathLeaf> = sp1_zkvm::io::read::<Vec<JsonPathLeaf>>();
        let json_path_proofs: Vec<MerkleProof> = sp1_zkvm::io::read::<Vec<MerkleProof>>();
        let expected_merkle_root: String = sp1_zkvm::io::read::<String>();
        let mmr_proof: MmrProof = sp1_zkvm::io::read::<MmrProof>();
        let expected_mmr_root: String = sp1_zkvm::io::read::<String>();
        let p_clinician_id: String = sp1_zkvm::io::read::<String>();
        let p_clinician_pubkey: String = sp1_zkvm::io::read::<String>();
        let epoch_number: i32 = sp1_zkvm::io::read::<i32>();
        let commitment_signature: String = sp1_zkvm::io::read::<String>();
        let registry_root: String = sp1_zkvm::io::read::<String>();
        let registry_proof: MerkleProof = sp1_zkvm::io::read::<MerkleProof>();

        let verified = verify_json_path_inputs(
            json_paths,
            json_path_proofs,
            expected_merkle_root.clone(),
            mmr_proof,
            ClinicianCommitmentInputs {
                expected_mmr_root: expected_mmr_root.clone(),
                clinician_id: p_clinician_id.clone(),
                clinician_pubkey: p_clinician_pubkey.clone(),
                epoch_number,
                signature: commitment_signature.clone(),
                expected_registry_root: registry_root.clone(),
                registry_proof,
            },
            job_id.clone(),
        )?;

        (
            Some(verified.json_paths),
            Some(verified.merkle_root),
            Some(verified.mmr_root),
            Some(verified.clinician_id),
            Some(verified.clinician_pubkey),
            Some(verified.epoch_number),
            Some(verified.signature),
            Some(verified.registry_root),
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };

    // Ensure at least one type of data is present
    if snps.is_none() && json_paths.is_none() {
        return Err(ZeenomeError::InvalidFormat(
            "At least one of SNP or phenotype JSON data must be provided".to_string(),
        ));
    }

    if let (Some(gp), Some(pp)) = (&genomic_clinician_pubkey, &phenotype_clinician_pubkey) {
        if gp != pp {
            return Err(ZeenomeError::InvalidFormat(
                "Genomic and phenotype tracks must attest the same clinician public key".to_string(),
            ));
        }
    }
    if let (Some(gi), Some(pi)) = (&genomic_clinician_id, &phenotype_clinician_id) {
        if gi != pi {
            return Err(ZeenomeError::InvalidFormat(
                "Genomic and phenotype tracks must attest the same clinician id".to_string(),
            ));
        }
    }

    let whitelist_pubkey = genomic_clinician_pubkey
        .clone()
        .or(phenotype_clinician_pubkey.clone())
        .ok_or_else(|| ZeenomeError::InvalidFormat("missing clinician pubkey".to_string()))?;

    let expected_whitelist_registry_root: String = sp1_zkvm::io::read::<String>();
    let whitelist_proof: MerkleProof = sp1_zkvm::io::read::<MerkleProof>();

    verify_org_whitelist_inclusion(
        &whitelist_pubkey,
        &whitelist_proof,
        &expected_whitelist_registry_root,
    )?;

    let policy = PublicPolicyCommitment {
        whitelist_registry_root: expected_whitelist_registry_root,
        job_id: job_id.clone(),
    };

    Ok(VerifiedInputs {
        snps,
        snp_merkle_root,
        snp_mmr_root,
        genomic_clinician_id,
        genomic_clinician_pubkey,
        genomic_epoch_number,
        genomic_signature,
        genomic_registry_root,
        json_paths,
        json_merkle_root,
        phenotype_mmr_root,
        phenotype_clinician_id,
        phenotype_clinician_pubkey,
        phenotype_epoch_number,
        phenotype_signature,
        phenotype_registry_root,
        job_id,
        policy,
    })
}

#[cfg(feature = "sp1")]
/// Commit public output to SP1
/// This is a convenience wrapper around sp1_zkvm::io::commit
pub fn commit_output<T: Serialize>(output: &T) {
    sp1_zkvm::io::commit(output);
}

/// SP1 `io::commit` helper for [`PublicOutput`] (bincode-serialized committed public values).
#[cfg(feature = "sp1")]
pub fn commit_public_output(output: &PublicOutput) {
    commit_output(output);
}

/// Build and commit a [`PublicOutput`] using committed policy + standard nullifier rule.
#[cfg(feature = "sp1")]
pub fn commit_public_output_with_policy(
    policy: &PublicPolicyCommitment,
    job_id: &str,
    merkle_root: &str,
    payload: String,
) {
    commit_public_output(&PublicOutput {
        policy: policy.clone(),
        nullifier: compute_nullifier(job_id, merkle_root),
        payload,
    });
}

/// Convenience when `verified_inputs` is still fully borrowable (no partial moves yet).
#[cfg(feature = "sp1")]
pub fn commit_public_output_from_verified(verified: &VerifiedInputs, merkle_root: &str, payload: String) {
    commit_public_output_with_policy(&verified.policy, &verified.job_id, merkle_root, payload);
}

#[cfg(test)]
mod public_output_tests {
    use super::{deserialize_public_output_bincode, PublicOutput, PublicPolicyCommitment};

    #[test]
    fn public_output_bincode_roundtrip() {
        let o = PublicOutput {
            policy: PublicPolicyCommitment {
                whitelist_registry_root: "wlroot".to_string(),
                job_id: "job1".to_string(),
            },
            nullifier: "nullifier-test".to_string(),
            payload: "k:v".to_string(),
        };
        let bytes = bincode::serialize(&o).expect("serialize");
        let back = deserialize_public_output_bincode(&bytes).expect("decode");
        assert_eq!(back, o);
    }
}
