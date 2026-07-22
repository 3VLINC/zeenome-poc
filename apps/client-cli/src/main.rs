use anyhow::Error as AnyhowError;
use clap::{Parser, Subcommand, ValueEnum};
use client_core::{ArtifactLayout, PendingSubmission, ProofMode as CoreProofMode, ProvingService};
use serde::Deserialize;
use serde_json::Value;
use sp1_sdk::{Elf, Prover, ProverClient};
use std::fs;
use std::path::{Path, PathBuf};
use zeenome_core::errors::Result;

mod execute_job_prepare;
mod inquiry_survey;
mod payload_deserializer;
use execute_job_prepare::ExecuteJobInput;
use payload_deserializer::{
    deserialize_public_output, deserialize_public_output_from_execute_bytes,
};

fn format_anyhow_chain(err: &AnyhowError) -> String {
    err.chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// SP1 zkVM expects a little-endian **`ET_EXEC`** ELF with **`EM_RISCV`** (`sp1-core-executor`).
/// Preview (`run-only`) and full proving load the **same** `program.elf`, resolved by content
/// hash via optional `--bundle-elf-path`, local cache, or registry HTTP
/// (`execute_job_prepare::resolve_bundle_elf`).
pub(crate) fn validate_sp1_guest_elf_header(
    bundle_id: &str,
    elf_path: &Path,
    elf_bytes: &[u8],
) -> Result<()> {
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    /// `ELFCLASS32` / `ELFCLASS64`
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    /// `ET_EXEC`
    const ET_EXEC: u16 = 2;
    /// `EM_RISCV`
    const EM_RISCV: u16 = 243;

    let path_disp = elf_path.display();
    if elf_bytes.len() < 20 {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "guest ELF `{path_disp}` for bundle `{bundle_id}` is too small to parse. \
             Preview and full proof both require the compiled SP1 guest fetched from the registry's \
             `/public/bundles/{{bundle}}/program.elf`."
        )));
    }
    if elf_bytes[0..4] != ELF_MAGIC {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "`{path_disp}` does not begin with ELF magic (bundle `{bundle_id}`); expected the SP1 guest program. \
             Preview and full proof both load `program.elf`; fix the downloaded file."
        )));
    }
    let elf_class = elf_bytes[4];
    if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "guest ELF `{path_disp}` (bundle `{bundle_id}`): unknown ELF class {elf_class}; expected ELF32 or ELF64."
        )));
    }
    if elf_bytes[5] != ELFDATA2LSB {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "guest ELF `{path_disp}` must be little-endian SP1 zkVM ELF (bundle `{bundle_id}`)."
        )));
    }
    let e_type = u16::from_le_bytes([elf_bytes[16], elf_bytes[17]]);
    let e_machine = u16::from_le_bytes([elf_bytes[18], elf_bytes[19]]);
    if e_type != ET_EXEC {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "guest ELF `{path_disp}` must be type ET_EXEC ({ET_EXEC}); got {e_type} (bundle `{bundle_id}`)."
        )));
    }
    if e_machine != EM_RISCV {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "`{path_disp}` for bundle `{bundle_id}` is not SP1 zkVM ELF (ELF e_machine={e_machine}, need EM_RISCV {EM_RISCV}). \
             Preview and full proof load the **same** ELF fetched from the registry's \
             `/public/bundles/{bundle_id}/program.elf` — verify that's your compiled guest ELF, \
             not a host binary nor an HTML/error page."
        )));
    }
    Ok(())
}

pub fn decode_public_output_from_execute_bytes(public_values_bytes: &[u8]) -> Result<Value> {
    deserialize_public_output_from_execute_bytes(public_values_bytes)
}

pub fn decode_public_output_from_proof_bytes(
    bundle_id: &str,
    public_values_bytes: &[u8],
) -> Result<Value> {
    deserialize_public_output(bundle_id, public_values_bytes)
}

#[cfg(test)]
mod tests {
    use super::validate_sp1_guest_elf_header;
    use std::path::Path;
    use zeenome_core::errors::ZeenomeError;

    fn valid_sp1_header() -> Vec<u8> {
        let mut header = vec![0_u8; 20];
        header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        header[4] = 2; // ELFCLASS64
        header[5] = 1; // little-endian
        header[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
        header[18..20].copy_from_slice(&243_u16.to_le_bytes()); // EM_RISCV
        header
    }

    #[test]
    fn validates_expected_sp1_elf_header() {
        let bytes = valid_sp1_header();
        let res = validate_sp1_guest_elf_header("bundle", Path::new("program.elf"), &bytes);
        assert!(res.is_ok());
    }

    #[test]
    fn rejects_non_elf_magic() {
        let mut bytes = valid_sp1_header();
        bytes[0] = 0;
        let err = validate_sp1_guest_elf_header("bundle", Path::new("program.elf"), &bytes)
            .expect_err("expected invalid magic");
        assert!(matches!(err, ZeenomeError::InvalidFormat(msg) if msg.contains("ELF magic")));
    }

    #[test]
    fn rejects_non_riscv_machine() {
        let mut bytes = valid_sp1_header();
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // x86_64
        let err = validate_sp1_guest_elf_header("bundle", Path::new("program.elf"), &bytes)
            .expect_err("expected invalid machine");
        assert!(matches!(err, ZeenomeError::InvalidFormat(msg) if msg.contains("EM_RISCV")));
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
enum ExecutionMode {
    /// Full SP1 proof (default); can submit to DB when `--submit true`.
    #[default]
    Full,
    /// SP1 execute only (no cryptographic proof); persists preview to DB; never submits.
    #[value(name = "run-only")]
    RunOnly,
}

#[derive(Parser)]
#[command(name = "client")]
#[command(about = "Client CLI for checking jobs and submitting proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check for new jobs available to this client
    CheckJobs {
        /// Client ID (e.g., ERR3243155/HG01766)
        #[arg(long = "client-id")]
        client_id: String,
        /// JSON input file containing eligible jobs snapshot
        #[arg(long)]
        input: PathBuf,
    },
    /// Execute a zk job (optionally skipping submission)
    ExecuteJob {
        /// Client ID
        #[arg(long)]
        client_id: String,
        /// Job ID
        #[arg(long)]
        job_id: String,
        /// `full` runs SP1 prove + optional submit; `run-only` runs SP1 execute only and stores a DB preview (no submit).
        #[arg(long = "proof-mode", value_enum, default_value_t = ExecutionMode::Full)]
        proof_mode: ExecutionMode,
        /// Whether to submit the response after execution
        #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
        submit: bool,
        /// JSON file containing survey answers (object); required when job has `inquirySurveyV1.requireAnswers`
        #[arg(long = "survey-answers")]
        survey_answers: Option<PathBuf>,
        /// JSON input file with pre-resolved execution context
        #[arg(long)]
        input: PathBuf,
        /// Optional path where submission payload is written (defaults beside output artifacts)
        #[arg(long = "submission-output")]
        submission_output: Option<PathBuf>,
        /// Local guest ELF path (must hash to input.bundle_id). Skips registry HTTP fetch.
        #[arg(long = "bundle-elf-path")]
        bundle_elf_path: Option<PathBuf>,
    },
    /// Submit a previously executed response (uses saved artifacts)
    SubmitResponse {
        /// Client ID
        #[arg(long)]
        client_id: String,
        /// Job ID
        #[arg(long)]
        job_id: String,
        /// Optional output path for generated submission payload JSON
        #[arg(long = "submission-output")]
        submission_output: Option<PathBuf>,
    },
    /// Print whitelist Merkle inclusion proof JSON for this client's lab pubkey at a whitelist epoch
    WhitelistProof {
        #[arg(long)]
        client_id: String,
        #[arg(long = "whitelist-epoch-id")]
        whitelist_epoch_id: i32,
        /// JSON input file containing whitelist proof material
        #[arg(long)]
        input: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::CheckJobs { client_id, input } => {
            check_jobs(&client_id, &input).await?;
        }
        Commands::ExecuteJob {
            client_id,
            job_id,
            proof_mode,
            submit,
            survey_answers,
            input,
            submission_output,
            bundle_elf_path,
        } => {
            execute_job(
                &client_id,
                &job_id,
                proof_mode,
                submit,
                survey_answers.as_deref(),
                &input,
                submission_output.as_deref(),
                bundle_elf_path.as_deref(),
            )
            .await?;
        }
        Commands::SubmitResponse {
            client_id,
            job_id,
            submission_output,
        } => {
            submit_stored_response(&client_id, &job_id, submission_output.as_deref()).await?;
        }
        Commands::WhitelistProof {
            client_id,
            whitelist_epoch_id,
            input,
        } => {
            print_whitelist_proof(&client_id, whitelist_epoch_id, &input).await?;
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct CheckJobsInput {
    jobs: Vec<CheckJobRow>,
}

#[derive(Debug, Deserialize)]
struct CheckJobRow {
    id: String,
    bundle_id: String,
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhitelistProofInput {
    whitelist_epoch_id: i32,
    pubkey_hex: String,
    merkle_proof: Value,
    #[serde(default)]
    client_id: Option<String>,
}

fn load_json_from_path<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Invalid JSON in {}: {}",
            path.display(),
            e
        ))
    })
}

async fn print_whitelist_proof(
    client_id: &str,
    whitelist_epoch_id: i32,
    input_path: &Path,
) -> Result<()> {
    let input: WhitelistProofInput = load_json_from_path(input_path)?;
    if input.whitelist_epoch_id != whitelist_epoch_id {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "--whitelist-epoch-id ({whitelist_epoch_id}) does not match input.whitelist_epoch_id ({})",
            input.whitelist_epoch_id
        )));
    }
    if let Some(snapshot_client_id) = input.client_id.as_ref() {
        if snapshot_client_id != client_id {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "--client-id ({client_id}) does not match input.client_id ({snapshot_client_id})"
            )));
        }
    }
    let out = serde_json::json!({
        "whitelist_epoch_id": input.whitelist_epoch_id,
        "pubkey_hex": input.pubkey_hex,
        "merkle_proof": input.merkle_proof,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!("json: {}", e))
        })?
    );
    Ok(())
}

async fn check_jobs(client_id: &str, input_path: &Path) -> Result<()> {
    let input: CheckJobsInput = load_json_from_path(input_path)?;
    if input.jobs.is_empty() {
        println!("No eligible jobs found for client {}", client_id);
        return Ok(());
    }

    println!("📋 Available jobs for client {}:", client_id);
    println!("{}", "=".repeat(80));

    for row in input.jobs {
        println!("\nJob: {}", row.id);
        println!("  Bundle: {}", row.bundle_id);
        if let Some(created_at) = row.created_at {
            println!("  Created: {}", created_at);
        }
        println!("  Status: Available");
    }

    Ok(())
}

fn write_submission_payload(path: &Path, payload: &PendingSubmission) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(payload)?)?;
    Ok(())
}

async fn execute_job(
    client_id: &str,
    job_id: &str,
    execution_mode: ExecutionMode,
    submit: bool,
    survey_answers_path: Option<&Path>,
    input_path: &Path,
    submission_output: Option<&Path>,
    bundle_elf_path: Option<&Path>,
) -> Result<()> {
    if execution_mode == ExecutionMode::RunOnly && submit {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "--proof-mode run-only cannot be combined with --submit true (no proof to submit)"
                .to_string(),
        ));
    }

    println!(
        "🔄 Executing job {} for client {} ({:?}{})...",
        job_id,
        client_id,
        execution_mode,
        if submit && execution_mode == ExecutionMode::Full {
            ""
        } else if execution_mode == ExecutionMode::Full {
            ", offline"
        } else {
            ", preview only"
        }
    );

    let input: ExecuteJobInput = load_json_from_path(input_path)?;
    if input.client_id != client_id {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "--client-id ({client_id}) does not match input.client_id ({})",
            input.client_id
        )));
    }
    if input.job_id != job_id {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "--job-id ({job_id}) does not match input.job_id ({})",
            input.job_id
        )));
    }
    let prep = execute_job_prepare::prepare_execute_job_artifacts(
        &input,
        survey_answers_path,
        bundle_elf_path,
    )
    .await?;

    let output_dir = prep.client_folder.join("outputs").join(job_id);
    let elf = Elf::from(prep.elf_bytes.as_slice());
    let stdin = prep.stdin;
    let bundle_id = prep.bundle_id.clone();
    let merkle_root = prep.merkle_root.clone();
    let mmr_proof_provenance = prep.mmr_proof.clone();
    let snp_proofs_provenance = prep.snp_proofs.clone();
    let expected_mmr_root = prep.expected_mmr_root.clone();
    let registry_root = prep.registry_root.clone();
    let registry_proof_provenance = prep.registry_proof.clone();
    let survey_responses = prep.survey_responses.clone();
    let clinician_id = prep.clinician_id.clone();
    let clinician_pubkey = prep.clinician_pubkey.clone();

    fs::create_dir_all(&output_dir)?;

    let client = ProverClient::from_env().await;

    if execution_mode == ExecutionMode::RunOnly {
        println!("   Running SP1 execute only (no cryptographic proof)…");
        let (exec_out, _report) = client.execute(elf.clone(), stdin).await.map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!("SP1 execute failed: {}", e))
        })?;

        let public_outputs = deserialize_public_output_from_execute_bytes(exec_out.as_slice())?;

        fs::write(
            output_dir.join("public_outputs.json"),
            serde_json::to_string_pretty(&public_outputs)?,
        )?;

        fs::write(
            output_dir.join("preview_submission.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "client_id": client_id,
                "job_id": job_id,
                "sequence_run_id": prep.sequence_run_id,
                "public_outputs": public_outputs,
            }))?,
        )?;
        println!("✅ Preview saved (run-only). Public outputs written to disk.");
        println!(
            "   Next: npm run client -- execute-job --client-id {} --job-id {} --proof-mode full --submit true",
            client_id, job_id
        );
        return Ok(());
    }

    // Determine proof type: use core proof (no Docker) unless explicitly requested
    // Set SP1_PROOF_TYPE=groth16 to use Groth16 (requires Docker or SP1_PROVER=network)
    let proof_type_env = std::env::var("SP1_PROOF_TYPE").unwrap_or_else(|_| "core".to_string());
    let proving_mode = match proof_type_env.as_str() {
        "groth16" => {
            println!("   Using Groth16 proof (requires Docker or SP1_PROVER=network)");
            CoreProofMode::Groth16
        }
        "core" => {
            println!("   Using core proof (no Docker required)");
            CoreProofMode::Core
        }
        _ => {
            println!(
                "   Unknown proof type '{}', defaulting to core proof (no Docker required)",
                proof_type_env
            );
            CoreProofMode::Core
        }
    };

    let proving = ProvingService::default()
        .prove_prepared_stdin(&prep.elf_bytes, &stdin, proving_mode)
        .await
        .map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "proof generation failed: {}",
                format_anyhow_chain(&e)
            ))
        })?;
    let proof_type = proving.proof_type.clone();
    if proof_type == "core" {
        println!("   Stored core proof (serialized) for later verification");
    }

    // Decode public outputs from proof
    let public_values_bytes = hex::decode(&proving.public_values_hex).map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Failed to decode proof public values: {}",
            e
        ))
    })?;
    let public_outputs = deserialize_public_output(&bundle_id, &public_values_bytes)?;

    // Extract nullifier from public_outputs
    let nullifier = public_outputs
        .get("nullifier")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Persist pending submission payload
    let pending_submission = PendingSubmission {
        client_id: client_id.to_string(),
        job_id: job_id.to_string(),
        sequence_run_id: prep.sequence_run_id.clone(),
        nullifier,
        proof_blob: proving.proof_blob_base64.clone(),
        proof_blob_digest: proving.proof_blob_digest.clone(),
        public_values_bytes: proving.public_values_hex.clone(),
        bundle_id: bundle_id.clone(),
        vk_hash: proving.vk_hash_hex.clone(),
        proof_type: proof_type.clone(),
        public_outputs: public_outputs.clone(),
        clinician_id: clinician_id.clone(),
        clinician_pubkey: clinician_pubkey.clone(),
        merkle_root: merkle_root.trim().to_string(),
        mmr_proof: mmr_proof_provenance.clone(),
        snp_proofs: snp_proofs_provenance.clone(),
        expected_mmr_root: expected_mmr_root.clone(),
        registry_root: registry_root.clone(),
        registry_proof: registry_proof_provenance.clone(),
        survey_responses: survey_responses.clone(),
    };

    let artifacts = ArtifactLayout::write_submission_to_output_dir(
        &output_dir,
        &pending_submission,
        &public_outputs,
        proving.proof_blob_digest.clone(),
    )
    .map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "failed to persist output artifacts: {e}"
        ))
    })?;
    let pending_path = artifacts.pending_submission_path;

    let submission_payload_path = submission_output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| output_dir.join("submission_payload.json"));
    write_submission_payload(&submission_payload_path, &pending_submission)?;

    if submit {
        println!("✅ Proof generated successfully.");
        println!(
            "   Submission payload written to {}",
            submission_payload_path.display()
        );
        println!("   Apply this payload with your server-side finalize step.");
    } else {
        println!("✅ Execution complete (submission skipped)");
        println!("   Pending submission saved to {}", pending_path.display());
        println!(
            "   Optional submission payload written to {}",
            submission_payload_path.display()
        );
    }

    Ok(())
}

async fn submit_stored_response(
    client_id: &str,
    job_id: &str,
    submission_output: Option<&Path>,
) -> Result<()> {
    println!(
        "📤 Submitting stored response for client {} and job {}...",
        client_id, job_id
    );

    let client_folder = PathBuf::from("data/clients").join(client_id.replace("/", "_"));
    let output_dir = client_folder.join("outputs").join(job_id);
    let pending_path = output_dir.join("pending_submission.json");

    if !pending_path.exists() {
        return Err(zeenome_core::errors::ZeenomeError::NotFound(format!(
            "Pending submission not found at {}",
            pending_path.display()
        )));
    }

    let data = fs::read_to_string(&pending_path)?;
    let mut pending: PendingSubmission = serde_json::from_str(&data)?;

    let public_outputs_path = output_dir.join("public_outputs.json");
    if let Ok(public_outputs_str) = fs::read_to_string(&public_outputs_path) {
        if let Ok(value) = serde_json::from_str(&public_outputs_str) {
            pending.public_outputs = value;
            if pending.nullifier.is_empty() {
                if let Some(nullifier_value) = pending
                    .public_outputs
                    .get("nullifier")
                    .and_then(|v| v.as_str())
                {
                    pending.nullifier = nullifier_value.to_string();
                }
            }
        }
    }

    let output_path = submission_output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| output_dir.join("submission_payload.json"));
    write_submission_payload(&output_path, &pending)?;
    println!("✅ Stored response payload prepared successfully!");
    println!("   Payload path: {}", output_path.display());
    println!("   Apply this payload with your server-side finalize step.");

    Ok(())
}
