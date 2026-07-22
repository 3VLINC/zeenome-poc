use clap::{Parser, Subcommand};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeenome_core::{
    crypto::KeyPair,
    errors::{Result, ZeenomeError},
    merkle::{compute_root, generate_proof},
    zk::deserialize_public_output_bincode,
};

#[derive(Parser)]
#[command(name = "researcher")]
#[command(about = "Researcher CLI with disk-only input/output contracts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a signed job payload from a pre-resolved input snapshot.
    CreateJob {
        #[arg(long)]
        researcher_id: String,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        elf_path: String,
        /// Optional manifest path; if omitted we infer likely locations.
        #[arg(long)]
        manifest_path: Option<String>,
        #[arg(long = "whitelist-epoch-id")]
        whitelist_epoch_id: i32,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compute the next whitelist epoch payload from pubkeys supplied in input.
    PublishWhitelist {
        #[arg(long = "whitelist-id")]
        whitelist_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print responses from a supplied input snapshot.
    ListResponses {
        #[arg(long = "job-id")]
        job_id: String,
        #[arg(long)]
        input: PathBuf,
    },
    /// Verify a proof from a supplied input snapshot and write DB-delta output.
    VerifyResponse {
        #[arg(long = "response-id")]
        response_id: i32,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print pubkey from a supplied input snapshot.
    GetPubkey {
        #[arg(long = "researcher-id")]
        researcher_id: String,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct CreateJobInput {
    researcher_pubkey: String,
    researcher_privkey_encrypted: String,
    org_whitelist_epoch_id: i32,
    whitelist_epoch_number: i32,
    whitelist_registry_root: String,
    #[serde(default)]
    constraints: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct CreateJobOutput {
    job_id: String,
    researcher_id: String,
    bundle_id: String,
    org_whitelist_epoch_id: i32,
    whitelist_registry_root: String,
    whitelist_epoch_number: i32,
    constraints: Value,
    signature: String,
    status: String,
    created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PublishWhitelistInput {
    whitelist_id: String,
    epoch_number: i32,
    org_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishWhitelistOutput {
    whitelist_id: String,
    epoch_number: i32,
    key_count: usize,
    epoch_root: String,
    registry_root: String,
    leaves: Vec<PublishWhitelistLeaf>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishWhitelistLeaf {
    leaf_index: i32,
    pubkey_hex: String,
    merkle_proof: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ListResponsesInput {
    job_id: String,
    responses: Vec<ListResponseRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ListResponseRow {
    id: i32,
    status: Option<String>,
    created_at: Option<String>,
    public_outputs: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct VerifyResponseInput {
    response_id: i32,
    #[serde(default)]
    job_id: Option<String>,
    proof_blob: String,
    public_values_bytes: String,
    bundle_id: String,
    // NOTE: the submitter-supplied vk_hash is intentionally NOT accepted here. The program
    // identity is always re-derived from the pinned bundle ELF (see verify_response); reading
    // a caller-provided vk_hash would let a proof of a different circuit verify. Any `vk_hash`
    // key in the input JSON is ignored by serde.
    proof_type: String,
    #[serde(default)]
    bundle_program_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct VerifyResponseOutput {
    response_id: i32,
    status: String,
    verifier_log: String,
    verified_at: String,
    nullifier: String,
    payload: Value,
    policy_job_id: Option<String>,
    policy_whitelist_registry_root: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GetPubkeyInput {
    researcher_id: String,
    #[serde(alias = "researcher_pubkey", alias = "pubkey")]
    pubkey: String,
}

fn load_json_from_path<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Could not parse JSON from {}: {}", path.display(), e))
    })
}

fn write_json_to_path<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn output_path_near_input(
    explicit: Option<PathBuf>,
    input_path: &Path,
    fallback_name: &str,
) -> PathBuf {
    explicit.unwrap_or_else(|| {
        input_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(fallback_name)
    })
}

fn maybe_copy_manifest(elf_path: &Path, manifest_path: Option<&str>, bundle_dir: &Path) -> Result<()> {
    if bundle_dir.join("manifest.toml").exists() {
        return Ok(());
    }

    let manifest_source = if let Some(manifest) = manifest_path {
        PathBuf::from(manifest)
    } else {
        let elf_dir = elf_path.parent().ok_or_else(|| {
            ZeenomeError::InvalidFormat(format!("Invalid ELF path: {}", elf_path.display()))
        })?;

        let next_to_elf = elf_dir.join("manifest.toml");
        if next_to_elf.exists() {
            next_to_elf
        } else {
            let parent_manifest = elf_dir
                .parent()
                .map(|p| p.join("manifest.toml"))
                .unwrap_or_else(|| elf_dir.join("manifest.toml"));
            if parent_manifest.exists() {
                parent_manifest
            } else {
                let elf_name = elf_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if let Some(program_name) = elf_name.strip_suffix("-program") {
                    let inferred_path = PathBuf::from("apps").join(program_name).join("manifest.toml");
                    if inferred_path.exists() {
                        inferred_path
                    } else {
                        parent_manifest
                    }
                } else {
                    parent_manifest
                }
            }
        }
    };

    if manifest_source.exists() {
        fs::copy(&manifest_source, bundle_dir.join("manifest.toml"))?;
    }
    Ok(())
}

fn parse_payload_lines(payload: &str) -> Value {
    let mut payload_obj = BTreeMap::new();
    for line in payload.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            let json_value = if let Ok(num) = value.parse::<i64>() {
                Value::Number(serde_json::Number::from(num))
            } else if let Ok(num) = value.parse::<f64>() {
                serde_json::Number::from_f64(num)
                    .map(Value::Number)
                    .unwrap_or_else(|| Value::String(value.to_string()))
            } else {
                Value::String(value.to_string())
            };
            payload_obj.insert(key.to_string(), json_value);
        }
    }
    Value::Object(payload_obj.into_iter().collect())
}

async fn create_job(
    researcher_id: &str,
    job_id: &str,
    elf_path: &Path,
    manifest_path: Option<&str>,
    whitelist_epoch_id: i32,
    input_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let input: CreateJobInput = load_json_from_path(input_path)?;
    if input.org_whitelist_epoch_id != whitelist_epoch_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "whitelist epoch mismatch: arg={} input={}",
            whitelist_epoch_id, input.org_whitelist_epoch_id
        )));
    }

    let elf_bytes = fs::read(elf_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let bundle_id = hex::encode(hasher.finalize());

    let bundle_dir = PathBuf::from("data/bundles").join(&bundle_id);
    fs::create_dir_all(&bundle_dir)?;
    if !bundle_dir.join("program.elf").exists() {
        fs::copy(elf_path, bundle_dir.join("program.elf"))?;
    }
    maybe_copy_manifest(elf_path, manifest_path, &bundle_dir)?;

    let keypair = KeyPair {
        public_key: input.researcher_pubkey.clone(),
        private_key: input.researcher_privkey_encrypted.clone(),
    };
    let constraints = input.constraints.unwrap_or_else(|| json!({}));
    let signature_payload = json!({
        "job_id": job_id,
        "researcher_id": researcher_id,
        "bundle_id": bundle_id,
        "org_whitelist_epoch_id": input.org_whitelist_epoch_id,
        "whitelist_registry_root": input.whitelist_registry_root,
        "whitelist_epoch_number": input.whitelist_epoch_number,
        "constraints": constraints,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let signature = zeenome_core::crypto::sign_message(
        serde_json::to_string(&signature_payload)?.as_bytes(),
        &keypair,
    )?;

    let output = CreateJobOutput {
        job_id: job_id.to_string(),
        researcher_id: researcher_id.to_string(),
        bundle_id,
        org_whitelist_epoch_id: input.org_whitelist_epoch_id,
        whitelist_registry_root: input.whitelist_registry_root,
        whitelist_epoch_number: input.whitelist_epoch_number,
        constraints,
        signature,
        status: "published".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    write_json_to_path(output_path, &output)?;
    println!("✅ Job payload written to {}", output_path.display());
    Ok(())
}

async fn publish_whitelist(
    whitelist_id: &str,
    input_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let mut input: PublishWhitelistInput = load_json_from_path(input_path)?;
    if input.whitelist_id != whitelist_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "whitelist id mismatch: arg={} input={}",
            whitelist_id, input.whitelist_id
        )));
    }
    if input.epoch_number < 0 {
        return Err(ZeenomeError::InvalidFormat(
            "epoch_number must be >= 0".to_string(),
        ));
    }

    input.org_pubkeys.sort();
    input.org_pubkeys.dedup();
    if input.org_pubkeys.is_empty() {
        return Err(ZeenomeError::InvalidFormat(
            "No org pubkeys in input snapshot".to_string(),
        ));
    }

    let registry_root = compute_root(&input.org_pubkeys)?;
    let mut leaves = Vec::with_capacity(input.org_pubkeys.len());
    for (idx, pk) in input.org_pubkeys.iter().enumerate() {
        let proof = generate_proof(&input.org_pubkeys, idx)?;
        leaves.push(PublishWhitelistLeaf {
            leaf_index: idx as i32,
            pubkey_hex: pk.clone(),
            merkle_proof: serde_json::to_value(proof)?,
        });
    }

    let output = PublishWhitelistOutput {
        whitelist_id: whitelist_id.to_string(),
        epoch_number: input.epoch_number,
        key_count: input.org_pubkeys.len(),
        epoch_root: registry_root.clone(),
        registry_root,
        leaves,
    };
    write_json_to_path(output_path, &output)?;
    println!("✅ Whitelist epoch payload written to {}", output_path.display());
    Ok(())
}

async fn list_responses(job_id: &str, input_path: &Path) -> Result<()> {
    let input: ListResponsesInput = load_json_from_path(input_path)?;
    if input.job_id != job_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "job id mismatch: arg={} input={}",
            job_id, input.job_id
        )));
    }
    if input.responses.is_empty() {
        println!("No responses found for job {}", job_id);
        return Ok(());
    }

    println!("📋 Responses for job {}:", job_id);
    println!("{}", "=".repeat(80));
    for row in input.responses {
        println!("\nResponse #{}", row.id);
        println!(
            "  Status: {}",
            row.status.unwrap_or_else(|| "pending".to_string())
        );
        if let Some(created_at) = row.created_at {
            println!("  Created: {}", created_at);
        }
        if let Some(outputs) = row.public_outputs {
            println!("  Outputs: {}", serde_json::to_string_pretty(&outputs)?);
        }
    }
    Ok(())
}

/// Base URL of the registry's public API (same env var + local default as the TS
/// `registry-client` package and `client-cli`'s `execute_job_prepare::registry_api_base`).
fn registry_api_base() -> String {
    std::env::var("REGISTRY_API_BASE").unwrap_or_else(|_| "http://localhost:5190".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Resolve the ELF bytes for a pinned bundle, verifying the content hash matches
/// `bundle_id` no matter where the bytes came from. Checks a local override path,
/// then a local cache, then falls back to fetching from the registry's public
/// content-addressed bundle store (`GET /public/bundles/<bundle_id>/program.elf`) —
/// the same store `client-cli` downloads from before proving.
///
/// This is what lets verification bind the proof to the circuit the inquiry
/// actually pinned instead of trusting a submitter-supplied `vk_hash`: the caller
/// re-derives the verifying key from these bytes via SP1 `setup`.
async fn resolve_bundle_elf_bytes(
    bundle_id: &str,
    bundle_program_path: Option<&Path>,
) -> Result<Vec<u8>> {
    if let Some(path) = bundle_program_path {
        let bytes = fs::read(path)?;
        if sha256_hex(&bytes) != bundle_id {
            return Err(ZeenomeError::InvalidFormat(format!(
                "bundle_program_path `{}` does not hash to bundle_id `{}`",
                path.display(),
                bundle_id
            )));
        }
        return Ok(bytes);
    }

    let cache_path = PathBuf::from("data/bundles").join(bundle_id).join("program.elf");
    if let Ok(cached) = fs::read(&cache_path) {
        if sha256_hex(&cached) == bundle_id {
            return Ok(cached);
        }
    }

    let base = registry_api_base();
    let url = format!(
        "{}/public/bundles/{}/program.elf",
        base.trim_end_matches('/'),
        bundle_id
    );
    let response = reqwest::get(&url).await.map_err(|e| {
        ZeenomeError::NotFound(format!(
            "Failed to fetch pinned bundle `{bundle_id}` from registry at {url}: {e}"
        ))
    })?;
    if !response.status().is_success() {
        return Err(ZeenomeError::NotFound(format!(
            "Registry returned {} for pinned bundle `{bundle_id}` at {url}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| {
            ZeenomeError::InvalidFormat(format!(
                "Failed to read pinned bundle `{bundle_id}` response body from {url}: {e}"
            ))
        })?
        .to_vec();
    if sha256_hex(&bytes) != bundle_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Downloaded ELF content hash does not match pinned bundle id `{bundle_id}` (fetched from {url})"
        )));
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cache_path, &bytes)?;
    Ok(bytes)
}

/// Re-derive the SP1 program's verifying key hash from the pinned bundle's ELF via
/// SP1 `setup`. This is the program identity as it actually exists on disk/registry —
/// never trust a submitter-supplied `vk_hash` for verification.
async fn derive_vk_hash_from_bundle(
    bundle_id: &str,
    bundle_program_path: Option<&Path>,
) -> Result<String> {
    let elf_bytes = resolve_bundle_elf_bytes(bundle_id, bundle_program_path).await?;
    let elf = Elf::from(elf_bytes);
    let client = ProverClient::from_env().await;
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| ZeenomeError::InvalidFormat(format!("SP1 setup failed: {}", e)))?;
    Ok(hex::encode(pk.verifying_key().bytes32()))
}

async fn verify_response(response_id: i32, input_path: &Path, output_path: &Path) -> Result<()> {
    let input: VerifyResponseInput = load_json_from_path(input_path)?;
    if input.response_id != response_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "response id mismatch: arg={} input={}",
            response_id, input.response_id
        )));
    }
    println!("🔍 Verifying response {}...", response_id);

    let proof_bytes = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&input.proof_blob)
            .map_err(|e| ZeenomeError::InvalidFormat(format!("Failed to decode proof blob: {}", e)))?
    };
    let public_values_bytes = hex::decode(&input.public_values_bytes).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Failed to decode public_values_bytes: {}", e))
    })?;
    let outputs = deserialize_public_output_bincode(&public_values_bytes).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Failed to decode public outputs: {}", e))
    })?;
    let payload = parse_payload_lines(&outputs.payload);

    let verifier_log = match input.proof_type.as_str() {
        "groth16" => {
            // Re-derive the program identity from the pinned bundle's ELF (the submitter
            // never supplies a vk_hash — it isn't a field on VerifyResponseInput) so a proof
            // of a *different* circuit than the one the inquiry pinned fails verification,
            // even if the submitter set `bundle_id` to the listing's real value.
            let vk_hash =
                derive_vk_hash_from_bundle(&input.bundle_id, input.bundle_program_path.as_deref())
                    .await?;
            Groth16Verifier::verify(
                &proof_bytes,
                &public_values_bytes,
                &vk_hash,
                &GROTH16_VK_BYTES,
            )
            .map_err(|e| {
                ZeenomeError::InvalidFormat(format!("Groth16 proof verification failed: {:?}", e))
            })?;
            println!("   ✅ Groth16 proof verified successfully (vk re-derived from pinned bundle {})!", input.bundle_id);
            format!(
                "Groth16 proof verified with sp1-verifier (vk_hash {} re-derived from pinned bundle ELF)",
                vk_hash
            )
        }
        "core" => {
            // Re-derive the program identity from the pinned bundle ELF (same rule as
            // groth16). The core path needs the proving key itself for `client.verify`,
            // so set up locally rather than through `derive_vk_hash_from_bundle` (whose
            // proving-key type — an SP1 `ProvingKey` trait object — cannot be named in a
            // return position).
            let elf_bytes =
                resolve_bundle_elf_bytes(&input.bundle_id, input.bundle_program_path.as_deref())
                    .await?;
            let elf = Elf::from(elf_bytes);
            let client = ProverClient::from_env().await;
            let pk = client
                .setup(elf)
                .await
                .map_err(|e| ZeenomeError::InvalidFormat(format!("SP1 setup failed: {}", e)))?;
            let vk = pk.verifying_key();
            let vk_hash = hex::encode(vk.bytes32());
            let proof: SP1ProofWithPublicValues = bincode::deserialize(&proof_bytes).map_err(|e| {
                ZeenomeError::InvalidFormat(format!("Failed to deserialize core proof: {}", e))
            })?;
            // Core proofs embed public values inside the serialized proof object. The
            // researcher output (nullifier/payload) is decoded from `public_values_bytes`,
            // so reject a mismatch — otherwise a submitter could pass a valid proof and
            // a different public-values hex, and we'd report the wrong payload as verified.
            if proof.public_values.as_slice() != public_values_bytes.as_slice() {
                return Err(ZeenomeError::InvalidFormat(
                    "Core proof public values do not match public_values_bytes".to_string(),
                ));
            }
            client.verify(&proof, vk, None).map_err(|e| {
                ZeenomeError::InvalidFormat(format!("Core proof verification failed: {:?}", e))
            })?;
            println!("   ✅ Core proof verified successfully!");
            format!(
                "Core proof verified with SP1 SDK (vk_hash {} re-derived from pinned bundle ELF)",
                vk_hash
            )
        }
        other => {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Unsupported proof type: {}",
                other
            )));
        }
    };

    let output = VerifyResponseOutput {
        response_id,
        status: "verified".to_string(),
        verifier_log,
        verified_at: chrono::Utc::now().to_rfc3339(),
        nullifier: outputs.nullifier,
        payload,
        policy_job_id: if outputs.policy.job_id.is_empty() {
            input.job_id
        } else {
            Some(outputs.policy.job_id)
        },
        policy_whitelist_registry_root: if outputs.policy.whitelist_registry_root.is_empty() {
            None
        } else {
            Some(outputs.policy.whitelist_registry_root)
        },
    };
    write_json_to_path(output_path, &output)?;
    println!("✅ Verification result written to {}", output_path.display());
    Ok(())
}

async fn get_pubkey(researcher_id: &str, input_path: &Path) -> Result<()> {
    let input: GetPubkeyInput = load_json_from_path(input_path)?;
    if input.researcher_id != researcher_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "researcher id mismatch: arg={} input={}",
            researcher_id, input.researcher_id
        )));
    }
    println!("{}", input.pubkey);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::CreateJob {
            researcher_id,
            job_id,
            elf_path,
            manifest_path,
            whitelist_epoch_id,
            input,
            output,
        } => {
            let output_path = output_path_near_input(output, &input, "create_job_output.json");
            create_job(
                &researcher_id,
                &job_id,
                Path::new(&elf_path),
                manifest_path.as_deref(),
                whitelist_epoch_id,
                &input,
                &output_path,
            )
            .await?;
        }
        Commands::PublishWhitelist {
            whitelist_id,
            input,
            output,
        } => {
            let output_path = output_path_near_input(output, &input, "publish_whitelist_output.json");
            publish_whitelist(&whitelist_id, &input, &output_path).await?;
        }
        Commands::ListResponses { job_id, input } => {
            list_responses(&job_id, &input).await?;
        }
        Commands::VerifyResponse {
            response_id,
            input,
            output,
        } => {
            let output_path = output_path_near_input(output, &input, "verify_response_output.json");
            verify_response(response_id, &input, &output_path).await?;
        }
        Commands::GetPubkey {
            researcher_id,
            input,
        } => {
            get_pubkey(&researcher_id, &input).await?;
        }
    }

    Ok(())
}
