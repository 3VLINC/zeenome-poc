use clap::{Parser, Subcommand};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeenome_core::{
    errors::{Result, ZeenomeError},
    merkle::{compute_root, generate_proof},
};

#[derive(Parser)]
#[command(name = "accreditor")]
#[command(about = "Accreditor CLI with disk-only input/output contracts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute whitelist epoch payload from supplied clinician pubkeys. Disk-only,
    /// two-phase: `--prepare` computes the Merkle root/leaves and emits
    /// `messages_to_sign` (no keypair — signing happens client-side with the
    /// accreditor's Ed25519 key); `--apply-signatures` embeds the signed
    /// epoch into the final output.
    PublishWhitelist {
        #[arg(long = "whitelist-id")]
        whitelist_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Compute Merkle root/leaves and emit `messages_to_sign` (no keypair in snapshot).
        #[arg(long, conflicts_with = "apply_signatures")]
        prepare: bool,
        /// Apply the accreditor-key signature to a prior `--prepare` output.
        #[arg(long, conflicts_with = "prepare")]
        apply_signatures: bool,
        /// Signatures JSON `{ "signatures": { "epoch": "hex" } }`.
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
    /// Print pubkey from a supplied input snapshot.
    GetPubkey {
        #[arg(long = "accreditor-id")]
        accreditor_id: String,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct PublishWhitelistInput {
    whitelist_id: String,
    epoch_number: i32,
    org_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishWhitelistLeaf {
    leaf_index: i32,
    pubkey_hex: String,
    merkle_proof: Value,
}

/// A single canonical message the accreditor must sign. The whitelist
/// epoch has exactly one — unlike phenotype/genome epochs there are no
/// per-leaf commitments, since member clinician pubkeys are not individually signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhitelistMessageToSign {
    id: String,
    kind: String,
    message_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishWhitelistPrepareOutput {
    whitelist_id: String,
    epoch_number: i32,
    key_count: usize,
    epoch_root: String,
    registry_root: String,
    leaves: Vec<PublishWhitelistLeaf>,
    messages_to_sign: Vec<WhitelistMessageToSign>,
}

#[derive(Debug, Deserialize)]
struct WhitelistApplySignaturesInput {
    signatures: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishWhitelistOutput {
    whitelist_id: String,
    epoch_number: i32,
    key_count: usize,
    epoch_root: String,
    registry_root: String,
    leaves: Vec<PublishWhitelistLeaf>,
    /// `{ data: <canonical epoch message JSON>, signature: <accreditor-key sig hex> }`,
    /// mirroring the clinician genome/phenotype `signed_epoch_json` shape.
    signed_epoch_json: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct GetPubkeyInput {
    accreditor_id: String,
    #[serde(alias = "accreditor_pubkey", alias = "pubkey")]
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

fn bytes_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Canonical UTF-8 message the accreditor key signs for a whitelist epoch commit.
/// Mirrors `whitelistEpochCanonicalMessage` in
/// `packages/registry-backend/src/services/whitelistWrites.ts` — field order
/// must match exactly (both sides serialize compact JSON with alphabetically
/// sorted keys, so a literal-order match here is enough).
fn whitelist_epoch_canonical_message(
    whitelist_id: &str,
    epoch_number: i32,
    registry_root: &str,
    key_count: usize,
) -> Result<String> {
    let payload = json!({
        "epoch_number": epoch_number,
        "key_count": key_count,
        "registry_root": registry_root,
        "whitelist_id": whitelist_id,
    });
    Ok(serde_json::to_string(&payload)?)
}

fn publish_whitelist_prepare(
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

    let key_count = input.org_pubkeys.len();
    let epoch_message =
        whitelist_epoch_canonical_message(whitelist_id, input.epoch_number, &registry_root, key_count)?;
    let messages_to_sign = vec![WhitelistMessageToSign {
        id: "epoch".to_string(),
        kind: "epoch".to_string(),
        message_hex: bytes_hex(epoch_message.as_bytes()),
    }];

    let output = PublishWhitelistPrepareOutput {
        whitelist_id: whitelist_id.to_string(),
        epoch_number: input.epoch_number,
        key_count,
        epoch_root: registry_root.clone(),
        registry_root,
        leaves,
        messages_to_sign,
    };
    write_json_to_path(output_path, &output)?;
    println!(
        "✅ Prepare complete — {} message(s) to sign",
        output.messages_to_sign.len()
    );
    Ok(())
}

fn publish_whitelist_apply_signatures(
    whitelist_id: &str,
    prepare_path: &Path,
    signatures_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let prepare: PublishWhitelistPrepareOutput = load_json_from_path(prepare_path)?;
    if prepare.whitelist_id != whitelist_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "whitelist id mismatch: arg={} input={}",
            whitelist_id, prepare.whitelist_id
        )));
    }

    let sig_input: WhitelistApplySignaturesInput = load_json_from_path(signatures_path)?;
    let epoch_signature = sig_input
        .signatures
        .get("epoch")
        .ok_or_else(|| ZeenomeError::InvalidFormat("Missing epoch signature".into()))?
        .clone();

    let epoch_message = whitelist_epoch_canonical_message(
        &prepare.whitelist_id,
        prepare.epoch_number,
        &prepare.registry_root,
        prepare.key_count,
    )?;
    let epoch_data: Value = serde_json::from_str(&epoch_message)?;
    let signed_epoch_json = json!({
        "data": epoch_data,
        "signature": epoch_signature,
    });

    let output = PublishWhitelistOutput {
        whitelist_id: prepare.whitelist_id,
        epoch_number: prepare.epoch_number,
        key_count: prepare.key_count,
        epoch_root: prepare.epoch_root,
        registry_root: prepare.registry_root,
        leaves: prepare.leaves,
        signed_epoch_json,
    };
    write_json_to_path(output_path, &output)?;
    println!(
        "✅ Applied signature and wrote publish output to {}",
        output_path.display()
    );
    Ok(())
}

async fn publish_whitelist(
    whitelist_id: &str,
    input_path: &Path,
    output_path: &Path,
    prepare: bool,
    apply_signatures: bool,
    signatures_path: Option<&Path>,
) -> Result<()> {
    if apply_signatures {
        let sig_path = signatures_path.ok_or_else(|| {
            ZeenomeError::InvalidFormat("--signatures required with --apply-signatures".into())
        })?;
        return publish_whitelist_apply_signatures(whitelist_id, input_path, sig_path, output_path);
    }
    if prepare {
        return publish_whitelist_prepare(whitelist_id, input_path, output_path);
    }
    Err(ZeenomeError::InvalidFormat(
        "publish-whitelist requires --prepare or --apply-signatures".into(),
    ))
}

async fn get_pubkey(accreditor_id: &str, input_path: &Path) -> Result<()> {
    let input: GetPubkeyInput = load_json_from_path(input_path)?;
    if input.accreditor_id != accreditor_id {
        return Err(ZeenomeError::InvalidFormat(format!(
            "accreditor id mismatch: arg={} input={}",
            accreditor_id, input.accreditor_id
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
        Commands::PublishWhitelist {
            whitelist_id,
            input,
            output,
            prepare,
            apply_signatures,
            signatures,
        } => {
            let output_path = output_path_near_input(output, &input, "publish_whitelist_output.json");
            publish_whitelist(
                &whitelist_id,
                &input,
                &output_path,
                prepare,
                apply_signatures,
                signatures.as_deref(),
            )
            .await?;
        }
        Commands::GetPubkey {
            accreditor_id,
            input,
        } => {
            get_pubkey(&accreditor_id, &input).await?;
        }
    }

    Ok(())
}
