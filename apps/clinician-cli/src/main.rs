mod genome;
mod registry_epoch;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use zeenome_core::{
    crypto::KeyPair,
    errors::{Result, ZeenomeError},
    json_canon::{self, JsonPathLeaf},
    merkle::{compute_root, generate_proof},
    signing,
};

#[derive(Parser)]
#[command(name = "clinician")]
#[command(about = "Clinician CLI: genomic (VCF) processing and phenotype (HPO) attestations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the public key for a clinician from a disk-only `--input`
    /// snapshot containing `{ actor_id, pubkey }`. The server side is
    /// expected to produce this snapshot from the `clinicians` table before
    /// invoking the CLI.
    GetPubkey {
        /// Actor ID (must match the snapshot's `actor_id`)
        #[arg(long = "actor-id")]
        actor_id: String,
        /// Path to a JSON snapshot: `{ "actor_id": "...", "pubkey": "..." }`.
        #[arg(long)]
        input: PathBuf,
    },
    /// Process a phenopacket JSON document. Disk-only: takes an `--input`
    /// snapshot of the existing-staging/published leaves for idempotency
    /// checks; writes both on-disk artifact files (under
    /// `data/clients/<id>/phenotype-attestations/<attestation_id>/`) and a
    /// `--output` JSON describing the staged row to insert.
    ProcessPhenopacket {
        /// Acting wallet address (must match the snapshot's `actor_id`).
        #[arg(long = "actor-id")]
        actor_id: String,
        /// Client ID (e.g., ERR3243155/HG01766)
        #[arg(long)]
        client_id: String,
        /// Path to GA4GH Phenopacket v2 JSON to attest.
        #[arg(long)]
        phenopacket_json: PathBuf,
        /// Path to JSON snapshot of existing staging + published leaves
        /// + owner check (see `ProcessPhenopacketInput`).
        #[arg(long)]
        input: PathBuf,
        /// Path to write the staged-row payload JSON.
        #[arg(long)]
        output: PathBuf,
    },
    /// Publish all staged phenopackets into a single epoch. Disk-only:
    /// `--input` carries pending staging rows + existing leaves + epoch
    /// roots + the signing keypair; `--output` emits the per-leaf
    /// commitments + MMR proofs the worker writes into
    /// `clinician_epochs` / `phenotype_artifacts` / `phenotype_attestations`.
    /// The CLI also writes `mmr_proof.json` + `commitment.json` into each
    /// staged row's `artifacts_path` on disk.
    PublishPhenotypeEpoch {
        /// Acting wallet address (must match the snapshot's `actor_id`).
        #[arg(long = "actor-id")]
        actor_id: String,
        /// Path to JSON snapshot (see `PublishPhenotypeEpochInput`).
        #[arg(long)]
        input: PathBuf,
        /// Path to write the epoch + per-leaf commitment payload JSON.
        #[arg(long)]
        output: PathBuf,
        /// Compute MMR/registry and emit `messages_to_sign` (no keypair in snapshot).
        #[arg(long, conflicts_with = "apply_signatures")]
        prepare: bool,
        /// Apply client signatures to a prior `--prepare` output.
        #[arg(long, conflicts_with = "prepare")]
        apply_signatures: bool,
        /// Signatures JSON `{ "signatures": { "epoch": "hex", "commitment:<id>": "hex" } }`.
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Refresh phenotype commitment/proofs for a client against a newer
    /// registry root. Disk-only: `--input` carries the existing per-client
    /// `artifacts_path` + epoch roots + signing keypair; the CLI rewrites
    /// `<artifacts_path>/commitment.json` and emits a `--output` JSON
    /// summary. Worker finalizer is a no-op except to record success.
    RefreshCommitment {
        /// Acting wallet address (must match the snapshot's `actor_id`).
        #[arg(long = "actor-id")]
        actor_id: String,
        /// Client ID to refresh.
        #[arg(long)]
        client_id: String,
        /// Target registry root to align with.
        #[arg(long)]
        registry_root: String,
        /// Path to JSON snapshot (see `RefreshCommitmentInput`).
        #[arg(long)]
        input: PathBuf,
        /// Path to write the refresh summary JSON.
        #[arg(long)]
        output: PathBuf,
    },
    /// Process a genomic sample (VCF extraction + Merkle/MMR; formerly
    /// `sequencer process-sample`). Disk-only: `--input` carries the
    /// existing client row (or absence-of) + dup checks; `--output`
    /// emits the rows the worker INSERTs. CLI does no DB I/O.
    ProcessGenomeSample {
        #[arg(long = "actor-id")]
        actor_id: String,
        #[arg(long)]
        client_id: String,
        #[arg(long = "catalog-sample-id")]
        catalog_sample_id: String,
        #[arg(long = "sequencing-panel", default_value = "irisplex")]
        sequencing_panel: String,
        /// Local VCF path. When set, skips CRAM/S3 extraction and uses this file as
        /// `work/variants.vcf` for Merkle/proof generation (service-free POC path).
        #[arg(long = "vcf-path")]
        vcf_path: Option<PathBuf>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Publish all staged genomic samples into a single epoch. Disk-only;
    /// mirror of `publish-phenotype-epoch`.
    PublishGenomeEpoch {
        #[arg(long = "actor-id")]
        actor_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, conflicts_with = "apply_signatures")]
        prepare: bool,
        #[arg(long, conflicts_with = "prepare")]
        apply_signatures: bool,
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Refresh genomic `commitment.json` against a newer data registry root.
    /// Disk-only; mirror of `refresh-commitment`.
    RefreshGenomicCommitment {
        #[arg(long = "actor-id")]
        actor_id: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        registry_root: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::GetPubkey {
            actor_id,
            input,
        } => {
            get_pubkey_from_input(&actor_id, &input)?;
        }
        Commands::ProcessPhenopacket {
            actor_id,
            client_id,
            phenopacket_json,
            input,
            output,
        } => {
            process_phenopacket_disk(
                &actor_id,
                &client_id,
                &phenopacket_json,
                &input,
                &output,
            )?;
        }
        Commands::PublishPhenotypeEpoch {
            actor_id,
            input,
            output,
            prepare,
            apply_signatures,
            signatures,
        } => {
            publish_phenotype_epoch_disk(
                &actor_id,
                &input,
                &output,
                prepare,
                apply_signatures,
                signatures.as_ref(),
            )?;
        }
        Commands::RefreshCommitment {
            actor_id,
            client_id,
            registry_root,
            input,
            output,
        } => {
            refresh_commitment_disk(
                &actor_id,
                &client_id,
                &registry_root,
                &input,
                &output,
            )?;
        }
        Commands::ProcessGenomeSample {
            actor_id,
            client_id,
            catalog_sample_id,
            sequencing_panel,
            vcf_path,
            input,
            output,
        } => {
            genome::genome_process_sample_disk(
                &actor_id,
                &client_id,
                &catalog_sample_id,
                &sequencing_panel,
                vcf_path.as_deref(),
                &input,
                &output,
            )?;
        }
        Commands::PublishGenomeEpoch {
            actor_id,
            input,
            output,
            prepare,
            apply_signatures,
            signatures,
        } => {
            genome::genome_publish_epoch_disk(
                &actor_id,
                &input,
                &output,
                prepare,
                apply_signatures,
                signatures.as_ref(),
            )?;
        }
        Commands::RefreshGenomicCommitment {
            actor_id,
            client_id,
            registry_root,
            input,
            output,
        } => {
            genome::genome_refresh_commitment_disk(
                &actor_id,
                &client_id,
                &registry_root,
                &input,
                &output,
            )?;
        }
    }

    Ok(())
}

/// Disk-only `get-pubkey`: read a JSON snapshot of `{ actor_id, pubkey }`
/// and print the pubkey. Mirrors `accreditor-cli get-pubkey`. The server is
/// responsible for pulling the row from `clinicians` and writing the snapshot
/// before invoking the CLI.
#[derive(Debug, serde::Deserialize)]
struct GetPubkeyInput {
    actor_id: String,
    pubkey: String,
}

fn get_pubkey_from_input(actor_id: &str, input_path: &PathBuf) -> Result<()> {
    let raw = std::fs::read_to_string(input_path)?;
    let input: GetPubkeyInput = serde_json::from_str(&raw).map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Could not parse get-pubkey input snapshot at {}: {}",
            input_path.display(),
            e
        ))
    })?;
    if input.actor_id != actor_id {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "actor id mismatch: arg={} input={}",
            actor_id, input.actor_id
        )));
    }
    println!("{}", input.pubkey);
    Ok(())
}

/// Disk-only `process-phenopacket` input snapshot. The server is responsible
/// for assembling this from the relevant `clients` / `phenotype_artifact_staging`
/// / `phenotype_artifacts` rows before invoking the CLI. The CLI then performs
/// all validation in pure Rust (no DB access).
#[derive(Debug, serde::Deserialize)]
struct ProcessPhenopacketInput {
    actor_id: String,
    client_id: String,
    /// Wallet that created the client row (`clients.created_by_wallet_address`);
    /// the CLI rejects the run if this does not match `--actor-id`.
    client_created_by_wallet: String,
    /// True when at least one row in `phenotype_artifact_staging` with the
    /// given `(client_id, actor_id)` and `published_epoch_id IS NULL`
    /// exists. The CLI rejects the run when true.
    existing_pending_for_client: bool,
    /// `phenotype_artifact_staging.phenotype_merkle_root` values for the
    /// `(client_id, actor_id)` pair. Used for duplicate-leaf detection.
    existing_staged_leaves: Vec<String>,
    /// `phenotype_artifacts.phenotype_merkle_root` values for the
    /// `(client_id, actor_id)` pair. Used for duplicate-leaf detection.
    existing_published_leaves: Vec<String>,
    /// Deterministic id the server generates so retries don't accumulate
    /// orphan artifact directories. Convention: `pat-<safe_client_id>-<ts_ms>`.
    phenotype_attestation_id: String,
    /// Absolute filesystem path where the CLI writes on-disk artifact files
    /// (`json_merkle_root.txt`, `json_path_leaves.json`, `json_path_proofs.json`).
    artifacts_dir: PathBuf,
}

/// Disk-only `process-phenopacket` output: the worker reads this back and
/// inserts a `phenotype_artifact_staging` row.
#[derive(Debug, serde::Serialize)]
struct ProcessPhenopacketOutput {
    phenotype_attestation_id: String,
    client_id: String,
    actor_id: String,
    phenotype_merkle_root: String,
    json_path_leaves: Vec<JsonPathLeaf>,
    /// Serialized as `Vec<MerkleProof>`; opaque to the worker.
    json_inclusion_proofs: serde_json::Value,
    /// Same as `input.artifacts_dir` as a string (so the worker doesn't
    /// have to re-derive it). Persisted in `phenotype_artifact_staging.artifacts_path`.
    artifacts_path: String,
    staging_digest: String,
}

fn process_phenopacket_disk(
    actor_id: &str,
    client_id: &str,
    phenopacket_json_path: &PathBuf,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    println!("📋 Processing phenopacket for client {}", client_id);

    let raw_input = std::fs::read_to_string(input_path)?;
    let input: ProcessPhenopacketInput = serde_json::from_str(&raw_input).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse process-phenopacket snapshot at {}: {}",
            input_path.display(),
            e
        ))
    })?;

    if input.actor_id != actor_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "actor_id mismatch: arg={} input={}",
            actor_id, input.actor_id
        )));
    }
    if input.client_id != client_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "client id mismatch: arg={} input={}",
            client_id, input.client_id
        )));
    }
    if input.client_created_by_wallet != actor_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Client {} was created by wallet {}, not {}",
            client_id, input.client_created_by_wallet, actor_id
        )));
    }
    if input.existing_pending_for_client {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has an unpublished staged phenopacket",
            client_id
        )));
    }

    // Load and canonicalize phenopacket JSON.
    println!("🔍 Loading phenopacket JSON...");
    let phenopacket_raw = std::fs::read_to_string(phenopacket_json_path)?;
    let phenopacket_value: serde_json::Value = serde_json::from_str(&phenopacket_raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse phenopacket JSON at {}: {}",
            phenopacket_json_path.display(),
            e
        ))
    })?;

    let json_path_leaves = json_canon::collect_all_scalar_leaves(&phenopacket_value)?;
    if json_path_leaves.is_empty() {
        return Err(ZeenomeError::InvalidFormat(
            "Phenopacket JSON has no attested scalar fields".to_string(),
        ));
    }

    let leaf_preimages: Vec<String> = json_path_leaves
        .iter()
        .map(|leaf| leaf.merkle_leaf_preimage())
        .collect();
    let mut json_proofs = Vec::with_capacity(leaf_preimages.len());
    for i in 0..leaf_preimages.len() {
        json_proofs.push(generate_proof(&leaf_preimages, i)?);
    }
    let merkle_root = compute_root(&leaf_preimages)?;

    if input.existing_staged_leaves.iter().any(|r| r == &merkle_root) {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has staged phenotype artifacts with this Merkle root",
            client_id
        )));
    }
    if input
        .existing_published_leaves
        .iter()
        .any(|r| r == &merkle_root)
    {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has published phenotype artifacts with this Merkle root",
            client_id
        )));
    }

    std::fs::create_dir_all(&input.artifacts_dir)?;
    let canonical_jcs = json_canon::canonicalize_json(&phenopacket_value)?;
    std::fs::write(
        input.artifacts_dir.join("json_merkle_root.txt"),
        &merkle_root,
    )?;
    std::fs::write(
        input.artifacts_dir.join("json_path_leaves.json"),
        serde_json::to_string_pretty(&json_path_leaves)?,
    )?;
    std::fs::write(
        input.artifacts_dir.join("json_path_proofs.json"),
        serde_json::to_string_pretty(&json_proofs)?,
    )?;
    std::fs::write(
        input.artifacts_dir.join("phenopacket_canonical.jcs"),
        canonical_jcs,
    )?;

    let json_proofs_json = serde_json::to_value(&json_proofs)?;
    let staging_digest = zeenome_core::crypto::hash_data(
        serde_json::to_string(&json!({
            "client_id": client_id,
            "actor_id": actor_id,
            "phenotype_attestation_id": input.phenotype_attestation_id,
            "json_path_leaves": json_path_leaves,
            "phenotype_merkle_root": merkle_root.clone(),
        }))?
        .as_bytes(),
    );

    let artifacts_path = input.artifacts_dir.to_string_lossy().to_string();
    let output = ProcessPhenopacketOutput {
        phenotype_attestation_id: input.phenotype_attestation_id.clone(),
        client_id: client_id.to_string(),
        actor_id: actor_id.to_string(),
        phenotype_merkle_root: merkle_root.clone(),
        json_path_leaves,
        json_inclusion_proofs: json_proofs_json,
        artifacts_path: artifacts_path.clone(),
        staging_digest,
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Phenopacket processed and staged successfully!");
    println!("   Client folder: {}", artifacts_path);
    println!("   Staged phenotype Merkle root: {}", merkle_root);
    println!(
        "   Staged-row payload written to {}",
        output_path.display()
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// publish-phenotype-epoch (disk-only)
//
// Snapshot carries: pending staging rows, existing published leaves (with
// nullable `leaf_index` so the CLI can renumber if stale), all prior epoch
// roots in order, the previous epoch's id (so the worker writes the
// `prev_epoch_id` FK), and the clinician's signing keypair.
//
// Output carries: the computed `epoch_root` / `registry_root` /
// `signed_epoch_json` plus, per appended leaf, the `mmr_proof` /
// `phenotype_signature` / `leaf_index` / repeated `json_path_leaves` /
// `json_inclusion_proofs` / `artifacts_path` / `phenotype_attestation_id` /
// `client_id` / `staging_id` the worker writes into the four destination
// tables in one transaction.
// -----------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct PublishPhenotypePendingRow {
    staging_id: i32,
    phenotype_attestation_id: String,
    client_id: String,
    phenotype_merkle_root: String,
    json_path_leaves: serde_json::Value,
    json_inclusion_proofs: serde_json::Value,
    artifacts_path: String,
}

#[derive(Debug, serde::Deserialize)]
struct PublishPhenotypeExistingLeaf {
    client_id: String,
    mmr_leaf: String,
    leaf_index: Option<i32>,
}

#[derive(Debug, serde::Deserialize)]
struct PublishPhenotypeLatestEpoch {
    id: i32,
    epoch_number: i32,
}

#[derive(Debug, serde::Deserialize)]
struct PublishPhenotypeKeypair {
    public_key: String,
    private_key: String,
}

#[derive(Debug, serde::Deserialize)]
struct PublishPhenotypeEpochInput {
    actor_id: String,
    pending_rows: Vec<PublishPhenotypePendingRow>,
    /// Existing `phenotype_artifacts` rows for this clinician, ordered by
    /// `COALESCE(leaf_index, 2147483647), created_at, client_id` so the CLI's
    /// position-based MMR matches the prior layout.
    existing_published_leaves: Vec<PublishPhenotypeExistingLeaf>,
    /// `clinician_epochs.epoch_root` values ordered by `epoch_number`.
    existing_epoch_roots: Vec<String>,
    /// `None` if this is the clinician's first epoch on this route.
    latest_epoch: Option<PublishPhenotypeLatestEpoch>,
    /// Public directory tip for this registry route (`-1` = genesis).
    #[serde(default)]
    directory_prev_epoch_number: Option<i32>,
    /// Next epoch number on this registry route (from directory tip + 1).
    #[serde(default)]
    next_registry_epoch_number: Option<i32>,
    #[serde(default)]
    keypair: Option<PublishPhenotypeKeypair>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PublishPhenotypeMessageToSign {
    id: String,
    kind: String,
    message_hex: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PublishPhenotypePrepareRow {
    staging_id: i32,
    phenotype_attestation_id: String,
    client_id: String,
    leaf: String,
    leaf_index: i32,
    mmr_proof: serde_json::Value,
    json_path_leaves: serde_json::Value,
    json_inclusion_proofs: serde_json::Value,
    artifacts_path: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PublishPhenotypePrepareOutput {
    actor_id: String,
    epoch_number: i32,
    epoch_root: String,
    registry_root: String,
    registry_proof: serde_json::Value,
    epoch_json: String,
    prev_epoch_id: Option<i32>,
    leaf_reindex: Vec<LeafReindexRow>,
    pending_finalize: Vec<PublishPhenotypePrepareRow>,
    messages_to_sign: Vec<PublishPhenotypeMessageToSign>,
}

#[derive(Debug, serde::Deserialize)]
struct ApplySignaturesInput {
    signatures: std::collections::HashMap<String, String>,
}

fn bytes_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LeafReindexRow {
    client_id: String,
    mmr_leaf: String,
    leaf_index: i32,
}

#[derive(Debug, serde::Serialize)]
struct PublishPhenotypeFinalizedRow {
    staging_id: i32,
    phenotype_attestation_id: String,
    client_id: String,
    /// The phenotype merkle root (== mmr_leaf, post-MMR-upgrade).
    leaf: String,
    leaf_index: i32,
    mmr_proof: serde_json::Value,
    phenotype_signature: String,
    /// Same payload the CLI writes to `artifacts_path/commitment.json`.
    commitment_json: serde_json::Value,
    json_path_leaves: serde_json::Value,
    json_inclusion_proofs: serde_json::Value,
    artifacts_path: String,
}

#[derive(Debug, serde::Serialize)]
struct PublishPhenotypeEpochOutput {
    actor_id: String,
    epoch_number: i32,
    epoch_root: String,
    registry_root: String,
    registry_proof: serde_json::Value,
    signed_epoch_json: serde_json::Value,
    prev_epoch_id: Option<i32>,
    /// Reindex updates the worker must apply to `phenotype_artifacts` BEFORE
    /// inserting the new epoch's rows (mirrors the in-CLI UPDATE the legacy
    /// implementation did when `leaf_index` was stale or NULL).
    leaf_reindex: Vec<LeafReindexRow>,
    finalized_rows: Vec<PublishPhenotypeFinalizedRow>,
}

fn publish_phenotype_prepare_disk(
    actor_id: &str,
    input: &PublishPhenotypeEpochInput,
    output_path: &PathBuf,
) -> Result<()> {
    let mut existing_leaves: Vec<String> = Vec::with_capacity(input.existing_published_leaves.len());
    let mut leaf_reindex: Vec<LeafReindexRow> = Vec::new();
    for (expected_idx, row) in input.existing_published_leaves.iter().enumerate() {
        existing_leaves.push(row.mmr_leaf.clone());
        if row.leaf_index.map(|v| v as usize) != Some(expected_idx) {
            leaf_reindex.push(LeafReindexRow {
                client_id: row.client_id.clone(),
                mmr_leaf: row.mmr_leaf.clone(),
                leaf_index: expected_idx as i32,
            });
        }
    }
    let mut mmr = zeenome_core::mmr::MerkleMountainRange::from_leaves(&existing_leaves)?;

    struct Appended {
        staging_id: i32,
        phenotype_attestation_id: String,
        client_id: String,
        leaf: String,
        json_path_leaves: serde_json::Value,
        json_inclusion_proofs: serde_json::Value,
        artifacts_path: String,
        leaf_index: u64,
    }
    let mut appended: Vec<Appended> = Vec::with_capacity(input.pending_rows.len());
    let mut mmr_root = mmr.root().unwrap_or_default();
    for row in &input.pending_rows {
        let (leaf_index, new_root) = mmr.append(row.phenotype_merkle_root.clone())?;
        mmr_root = new_root;
        appended.push(Appended {
            staging_id: row.staging_id,
            phenotype_attestation_id: row.phenotype_attestation_id.clone(),
            client_id: row.client_id.clone(),
            leaf: row.phenotype_merkle_root.clone(),
            json_path_leaves: row.json_path_leaves.clone(),
            json_inclusion_proofs: row.json_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
            leaf_index,
        });
    }

    let prev_epoch_id = input.latest_epoch.as_ref().map(|e| e.id);
    let epoch_number = registry_epoch::resolve_registry_epoch_number(
        input.next_registry_epoch_number,
        input.directory_prev_epoch_number,
        input.latest_epoch.as_ref().map(|e| e.epoch_number),
    )?;

    let mut registry_leaves = input.existing_epoch_roots.clone();
    registry_leaves.push(mmr_root.clone());
    let registry_root = if registry_leaves.len() == 1 {
        zeenome_core::crypto::hash_data(registry_leaves[0].as_bytes())
    } else {
        compute_root(&registry_leaves)?
    };
    let registry_proof = generate_proof(&registry_leaves, registry_leaves.len() - 1)?;

    let epoch_data = json!({
        "actor_id": actor_id,
        "epoch_number": epoch_number,
        "epoch_root": mmr_root.clone(),
        "registry_root": registry_root.clone(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let epoch_json = serde_json::to_string(&epoch_data)?;

    let mut messages_to_sign = vec![PublishPhenotypeMessageToSign {
        id: "epoch".to_string(),
        kind: "epoch".to_string(),
        message_hex: bytes_hex(epoch_json.as_bytes()),
    }];
    let mut pending_finalize = Vec::with_capacity(appended.len());
    for row in &appended {
        let mmr_proof = mmr.generate_proof(row.leaf_index)?;
        let commitment_message = signing::commitment_message(
            signing::ArtifactDomain::Phenotype,
            actor_id,
            &row.leaf,
            epoch_number,
            &mmr_root,
            &registry_root,
        );
        let id = format!("commitment:{}", row.staging_id);
        messages_to_sign.push(PublishPhenotypeMessageToSign {
            id: id.clone(),
            kind: "commitment".to_string(),
            message_hex: bytes_hex(&commitment_message),
        });
        pending_finalize.push(PublishPhenotypePrepareRow {
            staging_id: row.staging_id,
            phenotype_attestation_id: row.phenotype_attestation_id.clone(),
            client_id: row.client_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index as i32,
            mmr_proof: serde_json::to_value(&mmr_proof)?,
            json_path_leaves: row.json_path_leaves.clone(),
            json_inclusion_proofs: row.json_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishPhenotypePrepareOutput {
        actor_id: actor_id.to_string(),
        epoch_number,
        epoch_root: mmr_root,
        registry_root,
        registry_proof: serde_json::to_value(&registry_proof)?,
        epoch_json,
        prev_epoch_id,
        leaf_reindex,
        pending_finalize,
        messages_to_sign,
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;
    println!(
        "✅ Prepare complete — {} message(s) to sign",
        output.messages_to_sign.len()
    );
    Ok(())
}

fn publish_phenotype_apply_signatures(
    actor_id: &str,
    prepare_path: &PathBuf,
    signatures_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    let prepare_raw = std::fs::read_to_string(prepare_path)?;
    let prepare: PublishPhenotypePrepareOutput = serde_json::from_str(&prepare_raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Invalid prepare output: {}", e))
    })?;
    if prepare.actor_id != actor_id {
        return Err(ZeenomeError::InvalidFormat("actor_id mismatch".into()));
    }

    let sig_raw = std::fs::read_to_string(signatures_path)?;
    let sig_input: ApplySignaturesInput = serde_json::from_str(&sig_raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Invalid signatures file: {}", e))
    })?;

    let epoch_signature = sig_input
        .signatures
        .get("epoch")
        .ok_or_else(|| ZeenomeError::InvalidFormat("Missing epoch signature".into()))?
        .clone();
    let epoch_data: serde_json::Value = serde_json::from_str(&prepare.epoch_json)?;
    let signed_epoch = json!({
        "data": epoch_data,
        "signature": epoch_signature,
    });

    let mut finalized_rows: Vec<PublishPhenotypeFinalizedRow> =
        Vec::with_capacity(prepare.pending_finalize.len());
    for row in &prepare.pending_finalize {
        let sig_id = format!("commitment:{}", row.staging_id);
        let phenotype_signature = sig_input
            .signatures
            .get(&sig_id)
            .ok_or_else(|| {
                ZeenomeError::InvalidFormat(format!("Missing signature for {}", sig_id))
            })?
            .clone();
        let commitment = json!({
            "actor_id": actor_id,
            "phenotype_merkle_root": row.leaf,
            "signature": phenotype_signature,
            "epoch_number": prepare.epoch_number,
            "epoch_root": prepare.epoch_root,
            "registry_root": prepare.registry_root,
            "registry_proof": prepare.registry_proof,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let artifacts_dir = PathBuf::from(&row.artifacts_path);
        fs::create_dir_all(&artifacts_dir)?;
        fs::write(
            artifacts_dir.join("mmr_proof.json"),
            serde_json::to_string_pretty(&row.mmr_proof)?,
        )?;
        fs::write(
            artifacts_dir.join("commitment.json"),
            serde_json::to_string_pretty(&commitment)?,
        )?;

        finalized_rows.push(PublishPhenotypeFinalizedRow {
            staging_id: row.staging_id,
            phenotype_attestation_id: row.phenotype_attestation_id.clone(),
            client_id: row.client_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index,
            mmr_proof: row.mmr_proof.clone(),
            phenotype_signature,
            commitment_json: commitment,
            json_path_leaves: row.json_path_leaves.clone(),
            json_inclusion_proofs: row.json_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishPhenotypeEpochOutput {
        actor_id: actor_id.to_string(),
        epoch_number: prepare.epoch_number,
        epoch_root: prepare.epoch_root.clone(),
        registry_root: prepare.registry_root.clone(),
        registry_proof: prepare.registry_proof.clone(),
        signed_epoch_json: signed_epoch,
        prev_epoch_id: prepare.prev_epoch_id,
        leaf_reindex: prepare.leaf_reindex.clone(),
        finalized_rows,
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;
    println!("✅ Applied signatures and wrote publish output");
    Ok(())
}

fn publish_phenotype_epoch_disk(
    actor_id: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
    prepare: bool,
    apply_signatures: bool,
    signatures_path: Option<&PathBuf>,
) -> Result<()> {
    if apply_signatures {
        let sig_path = signatures_path.ok_or_else(|| {
            ZeenomeError::InvalidFormat("--signatures required with --apply-signatures".into())
        })?;
        return publish_phenotype_apply_signatures(actor_id, input_path, sig_path, output_path);
    }

    println!(
        "📦 Publishing staged phenopackets for actor {} (disk-only)",
        actor_id
    );

    let raw = std::fs::read_to_string(input_path)?;
    let input: PublishPhenotypeEpochInput = serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse publish-phenotype-epoch snapshot at {}: {}",
            input_path.display(),
            e
        ))
    })?;

    if input.actor_id != actor_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "actor_id mismatch: arg={} input={}",
            actor_id, input.actor_id
        )));
    }
    if input.pending_rows.is_empty() {
        return Err(ZeenomeError::NotFound(format!(
            "No staged phenopackets found for actor {}",
            actor_id
        )));
    }

    if prepare {
        return publish_phenotype_prepare_disk(actor_id, &input, output_path);
    }

    let keypair = input.keypair.as_ref().ok_or_else(|| {
        ZeenomeError::InvalidFormat(
            "keypair required for full publish (use --prepare for client signing)".into(),
        )
    })?;
    let keypair = KeyPair {
        public_key: keypair.public_key.clone(),
        private_key: keypair.private_key.clone(),
    };

    // Rebuild the historical MMR. Renumbering rows whose `leaf_index` was
    // stale or NULL is recorded in `leaf_reindex` for the worker to apply.
    let mut existing_leaves: Vec<String> = Vec::with_capacity(input.existing_published_leaves.len());
    let mut leaf_reindex: Vec<LeafReindexRow> = Vec::new();
    for (expected_idx, row) in input.existing_published_leaves.iter().enumerate() {
        existing_leaves.push(row.mmr_leaf.clone());
        if row.leaf_index.map(|v| v as usize) != Some(expected_idx) {
            leaf_reindex.push(LeafReindexRow {
                client_id: row.client_id.clone(),
                mmr_leaf: row.mmr_leaf.clone(),
                leaf_index: expected_idx as i32,
            });
        }
    }
    let mut mmr = zeenome_core::mmr::MerkleMountainRange::from_leaves(&existing_leaves)?;

    // Append each pending leaf in (client_id, staging_digest, created_at) order
    // — the server is expected to have sorted `pending_rows` accordingly.
    struct Appended {
        staging_id: i32,
        phenotype_attestation_id: String,
        client_id: String,
        leaf: String,
        json_path_leaves: serde_json::Value,
        json_inclusion_proofs: serde_json::Value,
        artifacts_path: String,
        leaf_index: u64,
    }
    let mut appended: Vec<Appended> = Vec::with_capacity(input.pending_rows.len());
    let mut mmr_root = mmr.root().unwrap_or_default();
    for row in input.pending_rows {
        let (leaf_index, new_root) = mmr.append(row.phenotype_merkle_root.clone())?;
        mmr_root = new_root;
        appended.push(Appended {
            staging_id: row.staging_id,
            phenotype_attestation_id: row.phenotype_attestation_id,
            client_id: row.client_id,
            leaf: row.phenotype_merkle_root,
            json_path_leaves: row.json_path_leaves,
            json_inclusion_proofs: row.json_inclusion_proofs,
            artifacts_path: row.artifacts_path,
            leaf_index,
        });
    }

    let prev_epoch_id = input.latest_epoch.as_ref().map(|e| e.id);
    let epoch_number = registry_epoch::resolve_registry_epoch_number(
        input.next_registry_epoch_number,
        input.directory_prev_epoch_number,
        input.latest_epoch.as_ref().map(|e| e.epoch_number),
    )?;

    let mut registry_leaves = input.existing_epoch_roots.clone();
    registry_leaves.push(mmr_root.clone());
    let registry_root = if registry_leaves.len() == 1 {
        zeenome_core::crypto::hash_data(registry_leaves[0].as_bytes())
    } else {
        compute_root(&registry_leaves)?
    };
    let registry_proof = generate_proof(&registry_leaves, registry_leaves.len() - 1)?;

    let epoch_data = json!({
        "actor_id": actor_id,
        "epoch_number": epoch_number,
        "epoch_root": mmr_root.clone(),
        "registry_root": registry_root.clone(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let epoch_json_str = serde_json::to_string(&epoch_data)?;
    let epoch_signature = zeenome_core::crypto::sign_message(epoch_json_str.as_bytes(), &keypair)?;
    let signed_epoch = json!({
        "data": epoch_data,
        "signature": epoch_signature,
    });

    let mut finalized_rows: Vec<PublishPhenotypeFinalizedRow> = Vec::with_capacity(appended.len());
    for row in &appended {
        let mmr_proof = mmr.generate_proof(row.leaf_index)?;
        let commitment_message = signing::commitment_message(
            signing::ArtifactDomain::Phenotype,
            actor_id,
            &row.leaf,
            epoch_number,
            &mmr_root,
            &registry_root,
        );
        let phenotype_signature =
            zeenome_core::crypto::sign_message(&commitment_message, &keypair)?;
        let commitment = json!({
            "actor_id": actor_id,
            "phenotype_merkle_root": row.leaf,
            "signature": phenotype_signature,
            "epoch_number": epoch_number,
            "epoch_root": mmr_root.clone(),
            "registry_root": registry_root.clone(),
            "registry_proof": registry_proof.clone(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let artifacts_dir = PathBuf::from(&row.artifacts_path);
        fs::create_dir_all(&artifacts_dir)?;
        fs::write(
            artifacts_dir.join("mmr_proof.json"),
            serde_json::to_string_pretty(&mmr_proof)?,
        )?;
        fs::write(
            artifacts_dir.join("commitment.json"),
            serde_json::to_string_pretty(&commitment)?,
        )?;

        finalized_rows.push(PublishPhenotypeFinalizedRow {
            staging_id: row.staging_id,
            phenotype_attestation_id: row.phenotype_attestation_id.clone(),
            client_id: row.client_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index as i32,
            mmr_proof: serde_json::to_value(&mmr_proof)?,
            phenotype_signature,
            commitment_json: commitment,
            json_path_leaves: row.json_path_leaves.clone(),
            json_inclusion_proofs: row.json_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishPhenotypeEpochOutput {
        actor_id: actor_id.to_string(),
        epoch_number,
        epoch_root: mmr_root.clone(),
        registry_root: registry_root.clone(),
        registry_proof: serde_json::to_value(&registry_proof)?,
        signed_epoch_json: signed_epoch,
        prev_epoch_id,
        leaf_reindex,
        finalized_rows,
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Published {} staged phenopacket(s)", appended.len());
    println!("   Epoch number: {}", epoch_number);
    println!("   Epoch root: {}", mmr_root);
    println!("   Registry root: {}", registry_root);
    println!("   Payload written to {}", output_path.display());

    Ok(())
}

// -----------------------------------------------------------------------------
// refresh-commitment (disk-only)
//
// Snapshot carries the per-client `artifacts_path` (from
// phenotype_attestations.artifacts_path, latest), the matching
// `target_epoch_number` + `target_epoch_root` for the requested
// registry_root, every prior epoch_root up to and including the target (so
// the CLI can recompute the registry tree + the inclusion proof for the
// target leaf), and the clinician's signing keypair.
//
// The CLI rewrites `<artifacts_path>/commitment.json`. The worker
// finalizer (`finalizeClinicianRefresh`) records the success on
// cli_runs.stdout — there is no DB write because the per-client
// commitment lives only on disk.
// -----------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct RefreshCommitmentInput {
    actor_id: String,
    client_id: String,
    /// `phenotype_attestations.artifacts_path` for the latest attestation by
    /// `(client_id, actor_id)`. The CLI reads
    /// `<artifacts_path>/json_merkle_root.txt` to find the leaf and rewrites
    /// `<artifacts_path>/commitment.json`.
    artifacts_path: String,
    /// `clinician_epochs.epoch_number` of the target.
    target_epoch_number: i32,
    /// `clinician_epochs.epoch_root` of the target.
    target_epoch_root: String,
    /// `clinician_epochs.epoch_root` for every `epoch_number <= target_epoch_number`,
    /// ordered by `epoch_number`. Used to rebuild the registry tree.
    epoch_roots_up_to_target: Vec<String>,
    keypair: RefreshCommitmentKeypair,
}

#[derive(Debug, serde::Deserialize)]
struct RefreshCommitmentKeypair {
    public_key: String,
    private_key: String,
}

#[derive(Debug, serde::Serialize)]
struct RefreshCommitmentOutput {
    actor_id: String,
    client_id: String,
    artifacts_path: String,
    target_epoch_number: i32,
    target_epoch_root: String,
    target_registry_root: String,
    phenotype_merkle_root: String,
    signature: String,
}

fn refresh_commitment_disk(
    actor_id: &str,
    client_id: &str,
    target_registry_root: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    println!("🔄 Refreshing commitment for client {} (disk-only)", client_id);

    let raw = std::fs::read_to_string(input_path)?;
    let input: RefreshCommitmentInput = serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse refresh-commitment snapshot at {}: {}",
            input_path.display(),
            e
        ))
    })?;
    if input.actor_id != actor_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "actor_id mismatch: arg={} input={}",
            actor_id, input.actor_id
        )));
    }
    if input.client_id != client_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "client id mismatch: arg={} input={}",
            client_id, input.client_id
        )));
    }

    let artifacts_dir = PathBuf::from(&input.artifacts_path);
    let phenotype_merkle_root =
        std::fs::read_to_string(artifacts_dir.join("json_merkle_root.txt"))?;

    // Verify the supplied registry leaves rebuild to the target registry root.
    let registry_leaves = &input.epoch_roots_up_to_target;
    let computed_registry_root = if registry_leaves.len() == 1 {
        zeenome_core::crypto::hash_data(registry_leaves[0].as_bytes())
    } else {
        compute_root(registry_leaves)?
    };
    if computed_registry_root != target_registry_root {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Computed registry root ({}) does not match expected ({})",
            computed_registry_root, target_registry_root
        )));
    }

    let registry_index = registry_leaves
        .iter()
        .position(|r| r == &input.target_epoch_root)
        .ok_or_else(|| {
            ZeenomeError::InvalidFormat(
                "Target epoch root not found among registry leaves".to_string(),
            )
        })?;
    let registry_proof = generate_proof(registry_leaves, registry_index)?;

    let keypair = KeyPair {
        public_key: input.keypair.public_key.clone(),
        private_key: input.keypair.private_key.clone(),
    };
    let commitment_message = signing::commitment_message(
        signing::ArtifactDomain::Phenotype,
        actor_id,
        &phenotype_merkle_root,
        input.target_epoch_number,
        &input.target_epoch_root,
        target_registry_root,
    );
    let phenotype_signature = zeenome_core::crypto::sign_message(&commitment_message, &keypair)?;

    let commitment = json!({
        "actor_id": actor_id,
        "phenotype_merkle_root": phenotype_merkle_root,
        "signature": phenotype_signature,
        "epoch_number": input.target_epoch_number,
        "epoch_root": input.target_epoch_root,
        "registry_root": target_registry_root,
        "registry_proof": registry_proof,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    fs::create_dir_all(&artifacts_dir)?;
    fs::write(
        artifacts_dir.join("commitment.json"),
        serde_json::to_string_pretty(&commitment)?,
    )?;

    let output = RefreshCommitmentOutput {
        actor_id: actor_id.to_string(),
        client_id: client_id.to_string(),
        artifacts_path: input.artifacts_path,
        target_epoch_number: input.target_epoch_number,
        target_epoch_root: input.target_epoch_root,
        target_registry_root: target_registry_root.to_string(),
        phenotype_merkle_root,
        signature: phenotype_signature,
    };
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Commitment refreshed successfully!");
    println!("   Registry root: {}", target_registry_root);
    println!("   Epoch: {}", input.target_epoch_number);
    println!("   Payload written to {}", output_path.display());

    Ok(())
}
