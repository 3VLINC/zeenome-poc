use zeenome_core::errors::ZeenomeError;
use zeenome_core::{crypto, merkle, mmr, signing, snp, variant, zk};

fn nv(
    chrom: &str,
    pos: u32,
    ref_a: &str,
    alt_a: &str,
    gt: snp::Genotype,
) -> variant::NormalizedVariant {
    variant::NormalizedVariant {
        genome_build: variant::GenomeBuild::GRCh38,
        chrom: chrom.to_string(),
        pos,
        ref_allele: ref_a.to_string(),
        alt_allele: alt_a.to_string(),
        genotype: gt,
    }
}

#[test]
fn test_variant_merkle_proof_verification() {
    let snps = vec![
        nv("chr15", 28120472, "A", "G", snp::Genotype::Heterozygous),
        nv("chr15", 27985172, "C", "T", snp::Genotype::HomozygousAlt),
        nv("chr14", 92307319, "G", "T", snp::Genotype::HomozygousRef),
        nv("chr5", 33951588, "C", "G", snp::Genotype::Heterozygous),
        nv("chr11", 89277878, "G", "A", snp::Genotype::HomozygousRef),
        nv("chr6", 396321, "C", "T", snp::Genotype::HomozygousAlt),
    ];
    let snps = variant::sort_variants_for_merkle(snps).expect("sort");

    let snp_leaves: Vec<String> = snps
        .iter()
        .map(variant::canonical_variant_leaf_preimage)
        .collect();

    let (merkle_root, _) =
        merkle::build_merkle_tree(&snp_leaves).expect("Failed to build Merkle tree");

    let mut snp_merkle_proofs: Vec<zk::MerkleProof> = Vec::new();
    for (i, _) in snp_leaves.iter().enumerate() {
        let zeenome_proof =
            merkle::generate_proof(&snp_leaves, i).expect("Failed to generate Merkle proof");

        let verified = merkle::verify_proof(&zeenome_proof).expect("Failed to verify Merkle proof");
        assert!(verified, "Merkle proof verification failed for SNP {}", i);
        assert_eq!(
            zeenome_proof.root, merkle_root,
            "Proof root doesn't match Merkle root"
        );

        let zk_proof = convert_merkle_proof(&zeenome_proof);
        snp_merkle_proofs.push(zk_proof);
    }

    for (i, snp) in snps.iter().enumerate() {
        let expected_leaf = variant::canonical_variant_leaf_preimage(snp);
        let expected_leaf_value = crypto::hash_data(expected_leaf.as_bytes());

        let proof = snp_merkle_proofs
            .iter()
            .find(|p| p.leaf_value == expected_leaf_value)
            .unwrap_or_else(|| {
                panic!(
                    "No proof for index {} expected leaf hash {}",
                    i, expected_leaf_value
                )
            });

        assert_eq!(proof.leaf_value, expected_leaf_value);
        let verified = zk::verify_merkle_proof(proof).expect("Failed to verify Merkle proof");
        assert!(verified);
        assert_eq!(proof.root, merkle_root);
    }
}

#[test]
fn test_verify_inputs_rejects_tampered_snps() {
    let snps = vec![
        nv("chr15", 28120472, "A", "G", snp::Genotype::Heterozygous),
        nv("chr15", 27985172, "C", "T", snp::Genotype::HomozygousAlt),
        nv("chr14", 92307319, "G", "T", snp::Genotype::HomozygousRef),
        nv("chr5", 33951588, "C", "G", snp::Genotype::Heterozygous),
        nv("chr11", 89277878, "G", "A", snp::Genotype::HomozygousRef),
        nv("chr6", 396321, "C", "T", snp::Genotype::HomozygousAlt),
    ];
    let snps = variant::sort_variants_for_merkle(snps).expect("sort");

    let snp_leaves: Vec<String> = snps
        .iter()
        .map(variant::canonical_variant_leaf_preimage)
        .collect();
    let (merkle_root, _) =
        merkle::build_merkle_tree(&snp_leaves).expect("Failed to build Merkle tree");

    let zk_snp_proofs: Vec<zk::MerkleProof> = snp_leaves
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let proof = merkle::generate_proof(&snp_leaves, i).expect("Failed to generate proof");
            convert_merkle_proof(&proof)
        })
        .collect();

    let mut mmr_tree = mmr::MerkleMountainRange::new();
    let (leaf_index, mmr_root) = mmr_tree
        .append(merkle_root.clone())
        .expect("Failed to append leaf to MMR");
    let mmr_proof = mmr_tree
        .generate_proof(leaf_index)
        .expect("Failed to generate MMR proof");
    let zk_mmr_proof: zk::MmrProof = mmr_proof.clone();

    let registry_leaves = vec![mmr_root.clone()];
    let registry_root = merkle::compute_root(&registry_leaves).expect("registry root");
    let registry_proof = merkle::generate_proof(&registry_leaves, 0).expect("registry proof");
    let zk_registry_proof = convert_merkle_proof(&registry_proof);

    let keypair = crypto::KeyPair::generate();
    let clinician_lineage_id = "seq-test-001".to_string();
    let epoch_number = 7;

    let message = signing::commitment_message(
        signing::ArtifactDomain::GenomicVcf,
        &clinician_lineage_id,
        &merkle_root,
        epoch_number,
        &mmr_root,
        &registry_root,
    );
    let signature = crypto::sign_message(&message, &keypair).expect("sign commitment");

    let commitment = zk::GenomicCommitmentInputs {
        expected_mmr_root: mmr_root.clone(),
        clinician_id: clinician_lineage_id.clone(),
        clinician_pubkey: keypair.public_key.clone(),
        epoch_number,
        signature: signature.clone(),
        expected_registry_root: registry_root.clone(),
        registry_proof: zk_registry_proof.clone(),
    };
    let job_id = "TEST_JOB_123".to_string();

    let verified = zk::verify_inputs(
        snps.clone(),
        zk_snp_proofs.clone(),
        merkle_root.clone(),
        zk_mmr_proof.clone(),
        commitment.clone(),
        job_id.clone(),
        variant::GenomeBuild::GRCh38,
    )
    .expect("Expected verification to succeed for honest data");
    assert_eq!(verified.merkle_root, merkle_root);
    assert_eq!(verified.mmr_root, mmr_root);

    let mut tampered_snps = snps.clone();
    tampered_snps[0].genotype = snp::Genotype::HomozygousAlt;

    let err = zk::verify_inputs(
        tampered_snps,
        zk_snp_proofs.clone(),
        merkle_root.clone(),
        zk_mmr_proof.clone(),
        commitment.clone(),
        job_id.clone(),
        variant::GenomeBuild::GRCh38,
    )
    .expect_err("Tampered variants should be rejected");

    match err {
        ZeenomeError::InvalidFormat(msg) => {
            assert!(
                msg.contains("leaf hash mismatch"),
                "Unexpected error message: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {:?}", other),
    }

    let mut bad_commitment = commitment.clone();
    if bad_commitment.signature.len() >= 2 {
        bad_commitment.signature.replace_range(..2, "ff");
    } else {
        bad_commitment.signature.push_str("ff");
    }

    let err = zk::verify_inputs(
        snps.clone(),
        zk_snp_proofs.clone(),
        merkle_root.clone(),
        zk_mmr_proof.clone(),
        bad_commitment,
        job_id.clone(),
        variant::GenomeBuild::GRCh38,
    )
    .expect_err("Invalid signature should be rejected");

    match err {
        ZeenomeError::Crypto(msg) => {
            assert!(
                msg.contains("Genomic commitment signature verification failed"),
                "Unexpected crypto error message: {msg}"
            );
        }
        other => panic!("Expected crypto error, got {:?}", other),
    }

    let mut bad_registry_commitment = commitment;
    bad_registry_commitment.registry_proof.leaf_value = "00".repeat(32);
    let err = zk::verify_inputs(
        snps,
        zk_snp_proofs,
        merkle_root,
        zk_mmr_proof,
        bad_registry_commitment,
        job_id,
        variant::GenomeBuild::GRCh38,
    )
    .expect_err("Tampered registry proof should be rejected");
    match err {
        ZeenomeError::InvalidFormat(msg) => assert!(
            msg.contains("Registry proof leaf hash does not match"),
            "Unexpected error message: {msg}"
        ),
        other => panic!("Expected invalid format error, got {:?}", other),
    }
}

fn convert_merkle_proof(proof: &merkle::MerkleProof) -> zk::MerkleProof {
    zk::MerkleProof {
        leaf_index: proof.leaf_index,
        leaf_value: proof.leaf_value.clone(),
        path: proof
            .path
            .iter()
            .map(|n| zk::ProofNode {
                hash: n.hash.clone(),
                is_left: n.is_left,
            })
            .collect(),
        root: proof.root.clone(),
    }
}

// convert_mmr_proof shim removed: zeenome_core::mmr::MmrProof === zk::MmrProof now.
