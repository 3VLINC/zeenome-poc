use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSubmission {
    pub client_id: String,
    pub job_id: String,
    #[serde(default)]
    pub sequence_run_id: String,
    #[serde(default)]
    pub nullifier: String,
    pub proof_blob: Option<String>,
    pub proof_blob_digest: Option<String>,
    pub public_values_bytes: String,
    pub bundle_id: String,
    pub vk_hash: String,
    pub proof_type: String,
    pub public_outputs: Value,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub merkle_root: String,
    pub mmr_proof: Value,
    pub snp_proofs: Value,
    pub expected_mmr_root: String,
    pub registry_root: String,
    pub registry_proof: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub survey_responses: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifacts {
    pub pending_submission_path: PathBuf,
    pub public_outputs_path: PathBuf,
    pub proof_type: String,
    pub proof_digest: Option<String>,
}

pub struct ArtifactLayout;

impl ArtifactLayout {
    pub fn write_submission_to_output_dir(
        output_dir: &Path,
        pending: &PendingSubmission,
        public_outputs: &Value,
        proof_digest: Option<String>,
    ) -> anyhow::Result<ProofArtifacts> {
        fs::create_dir_all(output_dir).with_context(|| {
            format!(
                "failed to create output directory {}",
                output_dir.display()
            )
        })?;
        let pending_submission_path = output_dir.join("pending_submission.json");
        let public_outputs_path = output_dir.join("public_outputs.json");
        fs::write(
            &pending_submission_path,
            serde_json::to_string_pretty(pending)?,
        )
        .with_context(|| {
            format!(
                "failed writing pending submission {}",
                pending_submission_path.display()
            )
        })?;
        fs::write(
            &public_outputs_path,
            serde_json::to_string_pretty(public_outputs)?,
        )
        .with_context(|| {
            format!(
                "failed writing public outputs {}",
                public_outputs_path.display()
            )
        })?;

        Ok(ProofArtifacts {
            pending_submission_path,
            public_outputs_path,
            proof_type: pending.proof_type.clone(),
            proof_digest,
        })
    }
}
