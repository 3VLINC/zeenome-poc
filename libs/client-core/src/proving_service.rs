use anyhow::Context;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofMode, SP1Stdin,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofMode {
    Core,
    Groth16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    pub proof_type: String,
    pub proof_blob_base64: Option<String>,
    pub proof_blob_digest: Option<String>,
    pub public_values_hex: String,
    pub vk_hash_hex: String,
}

#[derive(Default)]
pub struct ProvingService;

impl ProvingService {
    /// SP1 prove + verify on the current Tokio runtime (e.g. `#[tokio::main]` in `client-cli`).
    pub async fn prove_prepared_stdin(
        &self,
        elf_bytes: &[u8],
        stdin: &SP1Stdin,
        proof_mode: ProofMode,
    ) -> anyhow::Result<ProofResult> {
        let elf = Elf::from(elf_bytes);

        let client = ProverClient::from_env().await;
        let pk = client.setup(elf).await.context("SP1 setup failed")?;
        let vk = pk.verifying_key();

        let stdin = stdin.clone();
        let (proof, proof_type) = match proof_mode {
            ProofMode::Groth16 => (
                client
                    .prove(&pk, stdin.clone())
                    .mode(SP1ProofMode::Groth16)
                    .await
                    .context("prove failed")?,
                "groth16",
            ),
            ProofMode::Core => (
                client.prove(&pk, stdin).await.context("prove failed")?,
                "core",
            ),
        };

        client
            .verify(&proof, vk, None)
            .context("proof verification failed")?;

        let (blob, digest) = if proof_type == "groth16" {
            let raw = proof.bytes();
            let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
            let digest = zeenome_core::crypto::hash_data(&raw);
            (Some(encoded), Some(digest))
        } else {
            match bincode::serialize(&proof) {
                Ok(proof_bytes) => {
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode(&proof_bytes);
                    let digest = zeenome_core::crypto::hash_data(&proof_bytes);
                    (Some(encoded), Some(digest))
                }
                Err(_) => (None, None),
            }
        };

        Ok(ProofResult {
            proof_type: proof_type.to_string(),
            proof_blob_base64: blob,
            proof_blob_digest: digest,
            public_values_hex: hex::encode(proof.public_values.as_slice()),
            vk_hash_hex: hex::encode(vk.bytes32()),
        })
    }
}
