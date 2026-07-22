use zeenome_core::{merkle, zk};

#[test]
fn test_merkle_proof_generation_and_verification() {
    let leaves = vec![
        "leaf0".to_string(),
        "leaf1".to_string(),
        "leaf2".to_string(),
        "leaf3".to_string(),
    ];

    println!("Testing Merkle proof generation and verification\n");

    for i in 0..leaves.len() {
        println!("=== Testing leaf {} ===", i);

        // Generate proof
        let proof = merkle::generate_proof(&leaves, i).unwrap();
        println!("Generated proof: root={}", proof.root);
        println!("  leaf_value={}", proof.leaf_value);
        println!("  path length: {}", proof.path.len());
        for (j, node) in proof.path.iter().enumerate() {
            println!(
                "    Path[{}]: is_left={}, hash={}...",
                j,
                node.is_left,
                &node.hash[..16]
            );
        }

        // Verify with zeenome-core merkle module
        let verified_zeenome = merkle::verify_proof(&proof).unwrap();
        println!("  Verified with zeenome-core merkle: {}", verified_zeenome);
        assert!(verified_zeenome, "zeenome-core merkle verification failed");

        let zk_proof = zk::MerkleProof {
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
        };

        match zk::verify_merkle_proof(&zk_proof) {
            Ok(true) => println!("  ✓ Verified with zeenome-core zk: PASSED\n"),
            Ok(false) => {
                println!("  ✗ Verified with zeenome-core zk: FAILED (returned false)\n");
                panic!("zk verification failed for leaf {}", i);
            }
            Err(e) => {
                println!("  ✗ Verified with zeenome-core zk: ERROR - {}\n", e);
                panic!("zk verification error for leaf {}: {}", i, e);
            }
        }
    }

    println!("✅ All tests passed!");
}

#[test]
fn test_merkle_proof_rejects_invalid_proofs() {
    let leaves = vec![
        "leaf0".to_string(),
        "leaf1".to_string(),
        "leaf2".to_string(),
        "leaf3".to_string(),
    ];

    println!("Testing that invalid Merkle proofs are rejected\n");

    // Generate a valid proof first
    let valid_proof = merkle::generate_proof(&leaves, 0).unwrap();

    // Test 1: Invalid root
    // Both merkle::verify_proof and zk::verify_merkle_proof must reject this.
    println!("=== Test 1: Invalid root ===");
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.root =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    assert!(
        !merkle::verify_proof(&invalid_proof).unwrap_or(false),
        "merkle::verify_proof must reject a tampered root"
    );

    let zk_proof_invalid_root = zk::MerkleProof {
        leaf_index: invalid_proof.leaf_index,
        leaf_value: invalid_proof.leaf_value.clone(),
        path: invalid_proof
            .path
            .iter()
            .map(|n| zk::ProofNode {
                hash: n.hash.clone(),
                is_left: n.is_left,
            })
            .collect(),
        root: invalid_proof.root.clone(),
    };

    match zk::verify_merkle_proof(&zk_proof_invalid_root) {
        Ok(false) => println!("  ✓ Correctly rejected invalid root\n"),
        Ok(true) => panic!("zk verification should fail for invalid root"),
        Err(_) => println!("  ✓ Correctly rejected invalid root (error)\n"),
    }

    // Test 2: Invalid leaf value
    // Both merkle::verify_proof and zk::verify_merkle_proof must reject this.
    println!("=== Test 2: Invalid leaf value ===");
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.leaf_value =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    assert!(
        !merkle::verify_proof(&invalid_proof).unwrap_or(false),
        "merkle::verify_proof must reject a tampered leaf_value"
    );

    let zk_proof_invalid_leaf = zk::MerkleProof {
        leaf_index: invalid_proof.leaf_index,
        leaf_value: invalid_proof.leaf_value.clone(),
        path: invalid_proof
            .path
            .iter()
            .map(|n| zk::ProofNode {
                hash: n.hash.clone(),
                is_left: n.is_left,
            })
            .collect(),
        root: invalid_proof.root.clone(),
    };

    match zk::verify_merkle_proof(&zk_proof_invalid_leaf) {
        Ok(false) => println!("  ✓ Correctly rejected invalid leaf value\n"),
        Ok(true) => panic!("zk verification should fail for invalid leaf value"),
        Err(_) => println!("  ✓ Correctly rejected invalid leaf value (error)\n"),
    }

    // Test 3: Invalid path hash
    // Both merkle::verify_proof and zk::verify_merkle_proof must reject this.
    println!("=== Test 3: Invalid path hash ===");
    let mut invalid_proof = valid_proof.clone();
    if !invalid_proof.path.is_empty() {
        invalid_proof.path[0].hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    }

    assert!(
        !merkle::verify_proof(&invalid_proof).unwrap_or(false),
        "merkle::verify_proof must reject a tampered path hash"
    );

    let zk_proof_invalid_path = zk::MerkleProof {
        leaf_index: invalid_proof.leaf_index,
        leaf_value: invalid_proof.leaf_value.clone(),
        path: invalid_proof
            .path
            .iter()
            .map(|n| zk::ProofNode {
                hash: n.hash.clone(),
                is_left: n.is_left,
            })
            .collect(),
        root: invalid_proof.root.clone(),
    };

    match zk::verify_merkle_proof(&zk_proof_invalid_path) {
        Ok(false) => println!("  ✓ Correctly rejected invalid path hash\n"),
        Ok(true) => panic!("zk verification should fail for invalid path hash"),
        Err(_) => println!("  ✓ Correctly rejected invalid path hash (error)\n"),
    }

    println!("✅ All invalid proof tests passed!");
}
