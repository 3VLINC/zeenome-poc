//! Shared preparation for `execute-job` (stdin + provenance for in-process SP1 prove).

use crate::inquiry_survey::{parse_inquiry_survey, validate_survey_answers};
use crate::validate_sp1_guest_elf_header;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::SP1Stdin;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use zeenome_core::{
    errors::Result,
    json_canon::JsonPathLeaf,
    snp::SnpData,
    zk::{MerkleProof, MmrProof},
};

pub struct ExecuteJobArtifacts {
    pub client_folder: PathBuf,
    pub sequence_run_id: String,
    pub elf_path: PathBuf,
    pub elf_bytes: Vec<u8>,
    pub stdin: SP1Stdin,
    pub bundle_id: String,
    pub survey_responses: Option<Value>,
    pub clinician_id: String,
    pub clinician_pubkey: String,
    pub merkle_root: String,
    pub mmr_proof: Value,
    pub snp_proofs: Value,
    pub expected_mmr_root: String,
    pub registry_root: String,
    pub registry_proof: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecuteJobInput {
    pub client_id: String,
    pub job_id: String,
    pub bundle_id: String,
    pub job_constraints: Option<Value>,
    pub org_whitelist_epoch_id: i32,
    pub whitelist_registry_root: String,
    pub whitelist_merkle_proof: Value,
    pub sequence_run_id: String,
    pub sequence_run_artifacts_path: PathBuf,
    pub genomic_clinician_id: String,
    pub genomic_clinician_pubkey: String,
    pub phenotype_clinician_pubkey: Option<String>,
}

#[derive(Deserialize)]
struct PhenotypeCommitmentFile {
    actor_id: String,
    phenotype_merkle_root: String,
    signature: String,
    epoch_number: i32,
    epoch_root: String,
    registry_root: String,
    registry_proof: zeenome_core::merkle::MerkleProof,
}

fn load_phenotype_commitment(path: &Path) -> Result<PhenotypeCommitmentFile> {
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| {
        zeenome_core::errors::ZeenomeError::NotFound(format!(
            "Failed to read phenotype commitment file at {}: {}",
            path.display(),
            e
        ))
    })?)
    .map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Failed to parse phenotype commitment file: {}",
            e
        ))
    })
}

fn add_matching_phenotype_candidate(
    candidates: &mut Vec<(i32, u128, PathBuf)>,
    path: PathBuf,
    genomic_clinician_id: &str,
) -> Result<()> {
    let commitment_path = path.join("commitment.json");
    if !commitment_path.exists() {
        return Ok(());
    }
    let commitment = load_phenotype_commitment(&commitment_path)?;
    if commitment.actor_id.trim() != genomic_clinician_id.trim() {
        return Ok(());
    }

    for name in [
        "json_merkle_root.txt",
        "json_path_leaves.json",
        "json_path_proofs.json",
        "mmr_proof.json",
    ] {
        if !path.join(name).exists() {
            return Err(zeenome_core::errors::ZeenomeError::NotFound(format!(
                "Published phenotype artifacts at {} are missing phenotype artifact {}",
                path.display(),
                name
            )));
        }
    }
    let modified_nanos = fs::metadata(&commitment_path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    candidates.push((commitment.epoch_number, modified_nanos, path));
    Ok(())
}

fn find_published_phenotype_folder(
    sequence_run_artifacts_path: &Path,
    genomic_clinician_id: &str,
) -> Result<Option<PathBuf>> {
    let mut candidates: Vec<(i32, u128, PathBuf)> = Vec::new();
    add_matching_phenotype_candidate(
        &mut candidates,
        sequence_run_artifacts_path.join("phenotype"),
        genomic_clinician_id,
    )?;

    let mut client_roots = vec![sequence_run_artifacts_path.to_path_buf()];
    if let Some(parent) = sequence_run_artifacts_path.parent() {
        if let Some(grandparent) = parent.parent() {
            client_roots.push(grandparent.to_path_buf());
        }
    }

    for client_root in client_roots {
        add_matching_phenotype_candidate(
            &mut candidates,
            client_root.join("phenotype"),
            genomic_clinician_id,
        )?;

        let attestations_dir = client_root.join("phenotype-attestations");
        let Ok(entries) = fs::read_dir(&attestations_dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.map_err(|e| {
                zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                    "Failed to inspect phenotype attestation directory {}: {}",
                    attestations_dir.display(),
                    e
                ))
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                add_matching_phenotype_candidate(
                    &mut candidates,
                    entry_path,
                    genomic_clinician_id,
                )?;
            }
        }
    }

    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.2.cmp(&a.2))
    });
    Ok(candidates.into_iter().next().map(|(_, _, path)| path))
}

/// Base URL of the registry's public API (same env var + local default as the TS
/// `registry-client` package's `resolveRegistryApiBaseUrl`).
fn registry_api_base() -> String {
    env::var("REGISTRY_API_BASE").unwrap_or_else(|_| "http://localhost:5190".to_string())
}

/// Local on-disk cache directory for bundles fetched from the registry. Not part of
/// any shared/durable volume — a fresh container simply re-downloads on first use.
fn bundle_cache_dir() -> PathBuf {
    match env::var("ZEENOME_BUNDLE_CACHE_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => PathBuf::from("data/bundles-cache"),
    }
}

/// Resolve `bundle_id`'s `program.elf` for proving.
///
/// Precedence (mirrors researcher-cli verification):
/// 1. Optional local `--bundle-elf-path` override (content hash must equal `bundle_id`)
/// 2. Local cache under `ZEENOME_BUNDLE_CACHE_DIR` / `data/bundles-cache`
/// 3. Registry HTTP `GET /public/bundles/<bundle_id>/program.elf` (#888)
///
/// A cache hit whose content no longer hashes to `bundle_id` is treated as stale
/// and re-fetched.
async fn resolve_bundle_elf(
    bundle_id: &str,
    bundle_elf_path: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = bundle_elf_path {
        let bytes = fs::read(path).map_err(|e| {
            zeenome_core::errors::ZeenomeError::NotFound(format!(
                "Failed to read --bundle-elf-path `{}`: {e}",
                path.display()
            ))
        })?;
        let digest = zeenome_core::crypto::hash_data(&bytes);
        if digest != bundle_id {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "--bundle-elf-path `{}` content hash `{digest}` does not match bundle_id `{bundle_id}`",
                path.display()
            )));
        }
        return Ok(path.to_path_buf());
    }

    let cache_path = bundle_cache_dir().join(bundle_id).join("program.elf");
    if let Ok(cached) = fs::read(&cache_path) {
        if zeenome_core::crypto::hash_data(&cached) == bundle_id {
            return Ok(cache_path);
        }
    }

    let base = registry_api_base();
    let url = format!(
        "{}/public/bundles/{}/program.elf",
        base.trim_end_matches('/'),
        bundle_id
    );
    let response = reqwest::get(&url).await.map_err(|e| {
        zeenome_core::errors::ZeenomeError::NotFound(format!(
            "Failed to fetch bundle `{bundle_id}` from registry at {url}: {e}"
        ))
    })?;
    if !response.status().is_success() {
        return Err(zeenome_core::errors::ZeenomeError::NotFound(format!(
            "Registry returned {} for bundle `{bundle_id}` at {url}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Failed to read bundle `{bundle_id}` response body from {url}: {e}"
            ))
        })?
        .to_vec();
    let digest = zeenome_core::crypto::hash_data(&bytes);
    if digest != bundle_id {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Downloaded ELF content hash `{digest}` does not match bundle id `{bundle_id}` \
             (fetched from {url})"
        )));
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cache_path, &bytes)?;
    Ok(cache_path)
}

pub async fn prepare_execute_job_artifacts(
    input: &ExecuteJobInput,
    survey_answers_path: Option<&Path>,
    bundle_elf_path: Option<&Path>,
) -> Result<ExecuteJobArtifacts> {
    if input.client_id.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.client_id is required".to_string(),
        ));
    }
    if input.job_id.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.job_id is required".to_string(),
        ));
    }
    if input.bundle_id.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.bundle_id is required".to_string(),
        ));
    }
    if input.whitelist_registry_root.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.whitelist_registry_root is required".to_string(),
        ));
    }
    if input.sequence_run_id.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.sequence_run_id is required".to_string(),
        ));
    }
    if input.genomic_clinician_id.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.genomic_clinician_id is required".to_string(),
        ));
    }
    if input.genomic_clinician_pubkey.trim().is_empty() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "input.genomic_clinician_pubkey is required".to_string(),
        ));
    }

    let resolved_sequence_run_id = input.sequence_run_id.clone();
    let client_folder = input.sequence_run_artifacts_path.clone();
    let client_folder_for_return = client_folder.clone();
    let genomic_clinician_id = input.genomic_clinician_id.clone();
    let genomic_clinician_pubkey = input.genomic_clinician_pubkey.clone();
    let whitelist_proof_raw = input.whitelist_merkle_proof.clone();
    let job_constraints = input.job_constraints.clone();

    let survey_cfg = parse_inquiry_survey(&job_constraints);
    let answers_from_file = if let Some(path) = survey_answers_path {
        let s = fs::read_to_string(path).map_err(|e| {
            zeenome_core::errors::ZeenomeError::NotFound(format!(
                "Could not read --survey-answers {}: {}",
                path.display(),
                e
            ))
        })?;
        let v: Value = serde_json::from_str(&s).map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Invalid JSON in --survey-answers: {}",
                e
            ))
        })?;
        Some(v)
    } else {
        None
    };

    // Set by the web/worker (`api.patient-execute`) when the queue cannot share a filesystem path with the client.
    let answers_from_env: Option<Value> = match env::var("ZEENOME_SURVEY_ANSWERS_JSON") {
        Ok(raw) => {
            let t = raw.trim();
            if t.is_empty() {
                None
            } else {
                Some(serde_json::from_str(t).map_err(|e| {
                    zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                        "ZEENOME_SURVEY_ANSWERS_JSON: invalid JSON: {}",
                        e
                    ))
                })?)
            }
        }
        Err(_) => None,
    };

    if answers_from_file.is_some() && answers_from_env.is_some() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "Provide either --survey-answers or ZEENOME_SURVEY_ANSWERS_JSON, not both".to_string(),
        ));
    }

    let answers_provided = answers_from_file.or(answers_from_env);
    let survey_responses = validate_survey_answers(survey_cfg.as_ref(), answers_provided.as_ref())?;

    // Load VCF file
    let vcf_file = client_folder.join("work").join("variants.vcf");
    if !vcf_file.exists() {
        return Err(zeenome_core::errors::ZeenomeError::NotFound(format!(
            "VCF file not found at {}",
            vcf_file.display()
        )));
    }

    // Load artifacts
    let merkle_root = fs::read_to_string(client_folder.join("genome/vcf_merkle_root.txt"))?;
    // Deserialize proofs to zeenome_core types, and keep raw JSON for provenance
    let snp_proofs_json_str = fs::read_to_string(client_folder.join("genome/snp_proofs.json"))?;
    let snp_proofs_provenance: serde_json::Value = serde_json::from_str(&snp_proofs_json_str)?;
    let snp_proofs_zeenome: Vec<zeenome_core::merkle::MerkleProof> =
        serde_json::from_str(&snp_proofs_json_str)?;

    fn load_mmr_proof(
        path: &Path,
    ) -> zeenome_core::errors::Result<(serde_json::Value, zeenome_core::mmr::MmrProof)> {
        let json_str = fs::read_to_string(path)?;
        let provenance: serde_json::Value = serde_json::from_str(&json_str)?;
        let proof: zeenome_core::mmr::MmrProof = serde_json::from_str(&json_str)?;
        Ok((provenance, proof))
    }

    let mmr_path = client_folder.join("genome/mmr_proof.json");
    let (mmr_proof_provenance, mmr_proof_zeenome) = load_mmr_proof(&mmr_path)?;

    let epoch_root_hint = fs::read_to_string(client_folder.join("genome/epoch_root.txt"))
        .ok()
        .map(|s| s.trim().to_string());

    #[derive(Deserialize)]
    struct CommitmentFile {
        actor_id: String,
        vcf_merkle_root: String,
        signature: String,
        epoch_number: i32,
        epoch_root: String,
        registry_root: String,
        registry_proof: zeenome_core::merkle::MerkleProof,
    }

    let commitment_path = client_folder.join("genome/commitment.json");
    let commitment: CommitmentFile =
        serde_json::from_str(&fs::read_to_string(&commitment_path).map_err(|e| {
            zeenome_core::errors::ZeenomeError::NotFound(format!(
                "Failed to read commitment file at {}: {}",
                commitment_path.display(),
                e
            ))
        })?)
        .map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Failed to parse commitment file: {}",
                e
            ))
        })?;

    if commitment.actor_id.trim() != genomic_clinician_id.trim() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Genomic commitment actor_id ({}) does not match client owner ({})",
            commitment.actor_id.trim(),
            genomic_clinician_id.trim()
        )));
    }
    if commitment.vcf_merkle_root.trim() != merkle_root.trim() {
        return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
            "VCF merkle root mismatch between artifacts file and commitment".to_string(),
        ));
    }

    let registry_root = commitment.registry_root.trim().to_string();

    let expected_mmr_root = if !commitment.epoch_root.trim().is_empty() {
        commitment.epoch_root.trim().to_string()
    } else if let Some(hint) = epoch_root_hint.clone() {
        hint
    } else {
        mmr_proof_zeenome.root.clone()
    };

    let signature = commitment.signature.trim().to_string();
    let epoch_number = commitment.epoch_number;

    // Get bundle_id for loading ELF
    let bundle_id = input.bundle_id.clone();

    // Resolve ELF: optional local path → cache → registry HTTP (#888).
    let elf_path = resolve_bundle_elf(&bundle_id, bundle_elf_path).await?;
    let elf_bytes = fs::read(&elf_path)?;
    validate_sp1_guest_elf_header(&bundle_id, &elf_path, &elf_bytes)?;

    println!("   Using ELF: {}", elf_path.display());
    println!("   Bundle ID: {}", bundle_id);

    // Parse VCF to SNPs expected by zk program
    let vcf_content = fs::read_to_string(&vcf_file)?;
    let snps: Vec<SnpData> =
        zeenome_core::snp::parse_vcf_for_sequencing_panel(&vcf_content, "irisplex").map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!("VCF parse error: {}", e))
        })?;

    // Convert proofs to zk format expected by zk program
    fn convert_merkle_proof(p: &zeenome_core::merkle::MerkleProof) -> MerkleProof {
        MerkleProof {
            leaf_index: p.leaf_index,
            leaf_value: p.leaf_value.clone(),
            path: p
                .path
                .iter()
                .map(|n| zeenome_core::zk::ProofNode {
                    hash: n.hash.clone(),
                    is_left: n.is_left,
                })
                .collect(),
            root: p.root.clone(),
        }
    }
    // `zeenome_core::mmr::MmrProof` IS `zeenome_core::zk::MmrProof` (re-export
    // after MMR unification), so what used to be a `convert_mmr_proof` shim
    // collapses to a clone.

    let snp_merkle_proofs: Vec<MerkleProof> = snp_proofs_zeenome
        .iter()
        .map(convert_merkle_proof)
        .collect();
    let mmr_proof_zk: MmrProof = mmr_proof_zeenome.clone();
    let registry_proof_zk: MerkleProof = convert_merkle_proof(&commitment.registry_proof);
    let registry_proof_provenance = serde_json::to_value(&commitment.registry_proof)?;

    // Load phenotype JSON data if published phenotype artifacts exist.
    let phenotype_folder = find_published_phenotype_folder(&client_folder, &genomic_clinician_id)?;
    let has_phenotype_json = phenotype_folder.is_some();
    println!(
        "   🔍 Phenotype JSON data check: has_phenotype_json = {}",
        has_phenotype_json
    );
    if let Some(path) = phenotype_folder.as_ref() {
        println!("      Using phenotype artifacts: {}", path.display());
    }

    let (
        json_paths,
        json_path_proofs,
        json_merkle_root,
        phenotype_mmr_proof_zk,
        phenotype_expected_mmr_root,
        ph_clinician_id,
        ph_clinician_pubkey,
        ph_epoch_number,
        ph_signature,
        ph_registry_root,
        phenotype_registry_proof_zk,
    ) = if let Some(phenotype_folder) = phenotype_folder.as_ref() {
        let phenotype_commitment =
            load_phenotype_commitment(&phenotype_folder.join("commitment.json"))?;

        let json_merkle_root = fs::read_to_string(phenotype_folder.join("json_merkle_root.txt"))
            .map_err(|e| {
                zeenome_core::errors::ZeenomeError::NotFound(format!(
                    "Failed to read phenotype JSON merkle root: {}",
                    e
                ))
            })?
            .trim()
            .to_string();

        if json_merkle_root != phenotype_commitment.phenotype_merkle_root.trim() {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
                "Phenotype JSON merkle root mismatch between artifacts file and commitment"
                    .to_string(),
            ));
        }

        let json_proofs_json_str =
            fs::read_to_string(phenotype_folder.join("json_path_proofs.json")).map_err(|e| {
                zeenome_core::errors::ZeenomeError::NotFound(format!(
                    "Failed to read phenotype JSON proofs: {}",
                    e
                ))
            })?;
        let json_proofs_zeenome: Vec<zeenome_core::merkle::MerkleProof> =
            serde_json::from_str(&json_proofs_json_str).map_err(|e| {
                zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                    "Failed to parse phenotype JSON proofs: {}",
                    e
                ))
            })?;

        let json_paths: Vec<JsonPathLeaf> = serde_json::from_str(
            &fs::read_to_string(phenotype_folder.join("json_path_leaves.json")).map_err(|e| {
                zeenome_core::errors::ZeenomeError::NotFound(format!(
                    "Failed to read phenotype JSON path leaves: {}",
                    e
                ))
            })?,
        )
        .map_err(|e| {
            zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Failed to parse phenotype JSON path leaves: {}",
                e
            ))
        })?;

        println!(
            "   🔍 Loaded {} phenotype JSON path leaves",
            json_paths.len()
        );

        let json_path_proofs: Vec<MerkleProof> = json_proofs_zeenome
            .iter()
            .map(convert_merkle_proof)
            .collect();

        if json_paths.len() != json_path_proofs.len() {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Phenotype JSON leaves count ({}) doesn't match proofs count ({})",
                json_paths.len(),
                json_path_proofs.len()
            )));
        }

        let (_, phenotype_mmr_proof_zeenome) =
            load_mmr_proof(&phenotype_folder.join("mmr_proof.json"))?;
        let phenotype_mmr_proof_zk: MmrProof = phenotype_mmr_proof_zeenome.clone();

        let phenotype_expected_mmr_root = if !phenotype_commitment.epoch_root.trim().is_empty() {
            phenotype_commitment.epoch_root.trim().to_string()
        } else {
            phenotype_mmr_proof_zeenome.root.clone()
        };

        let phenotype_pub = if phenotype_commitment.actor_id.trim()
            == genomic_clinician_id.trim()
        {
            genomic_clinician_pubkey.clone()
        } else if let Some(pubkey) = input.phenotype_clinician_pubkey.as_ref() {
            pubkey.clone()
        } else {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Missing phenotype clinician pubkey for clinician {}; provide input.phenotype_clinician_pubkey",
                phenotype_commitment.actor_id
            )));
        };

        let phenotype_registry_proof_zk: MerkleProof =
            convert_merkle_proof(&phenotype_commitment.registry_proof);

        (
            json_paths,
            json_path_proofs,
            json_merkle_root,
            phenotype_mmr_proof_zk,
            phenotype_expected_mmr_root,
            phenotype_commitment.actor_id,
            phenotype_pub,
            phenotype_commitment.epoch_number,
            phenotype_commitment.signature.trim().to_string(),
            phenotype_commitment.registry_root.trim().to_string(),
            phenotype_registry_proof_zk,
        )
    } else {
        (
            Vec::new(),
            Vec::new(),
            String::new(),
            MmrProof {
                leaf_index: 0,
                leaf_value: String::new(),
                proof_items: Vec::new(),
                mmr_size: 0,
                root: String::new(),
            },
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
            String::new(),
            MerkleProof {
                leaf_index: 0,
                leaf_value: String::new(),
                path: Vec::new(),
                root: String::new(),
            },
        )
    };

    if has_phenotype_json {
        if ph_clinician_id.trim() != genomic_clinician_id.trim() {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
                "Phenotype commitment clinician_id ({}) does not match sequencing clinician_id ({})",
                ph_clinician_id.trim(),
                genomic_clinician_id.trim()
            )));
        }
        if ph_clinician_pubkey.trim() != genomic_clinician_pubkey.trim() {
            return Err(zeenome_core::errors::ZeenomeError::InvalidFormat(
                "Phenotype clinician pubkey does not match sequencing clinician pubkey".to_string(),
            ));
        }
    }

    // Prepare zkVM stdin in the exact order expected by the guest
    let mut stdin = SP1Stdin::new();

    println!("   📝 Writing stdin data:");
    println!("      1. job_id: {}", input.job_id);

    let job_id_string = input.job_id.clone();
    stdin.write(&job_id_string);

    // Write SNP data (if present)
    let has_snp_data = !snps.is_empty();
    println!("      2. has_snp_data: {}", has_snp_data);
    stdin.write(&has_snp_data);
    if has_snp_data {
        println!(
            "      3-14. Writing genome_build, {} variants, {} proofs, and genomic clinician data",
            snps.len(),
            snp_merkle_proofs.len()
        );
        let genome_build = "GRCh38".to_string();
        stdin.write(&genome_build);
        stdin.write(&snps);
        stdin.write(&snp_merkle_proofs);
        let merkle_root_trimmed = merkle_root.trim().to_string();
        stdin.write(&merkle_root_trimmed);
        stdin.write(&mmr_proof_zk);
        stdin.write(&expected_mmr_root);
        stdin.write(&genomic_clinician_id);
        stdin.write(&genomic_clinician_pubkey);
        stdin.write(&epoch_number);
        stdin.write(&signature);
        stdin.write(&registry_root);
        stdin.write(&registry_proof_zk);
    }

    // Write phenotype JSON data (if present)
    println!(
        "      {}. has_phenotype_json: {}",
        if has_snp_data { "15" } else { "3" },
        has_phenotype_json
    );
    stdin.write(&has_phenotype_json);
    if has_phenotype_json {
        let start_num = if has_snp_data { 16 } else { 4 };
        println!(
            "      {}-{}. Writing {} JSON path leaves, {} proofs, and clinician data",
            start_num,
            start_num + 10,
            json_paths.len(),
            json_path_proofs.len()
        );
        stdin.write(&json_paths);
        stdin.write(&json_path_proofs);
        stdin.write(&json_merkle_root);
        stdin.write(&phenotype_mmr_proof_zk);
        stdin.write(&phenotype_expected_mmr_root);
        stdin.write(&ph_clinician_id);
        stdin.write(&ph_clinician_pubkey);
        stdin.write(&ph_epoch_number);
        stdin.write(&ph_signature);
        stdin.write(&ph_registry_root);
        stdin.write(&phenotype_registry_proof_zk);
    }

    let whitelist_proof_zk: MerkleProof = serde_json::from_value(whitelist_proof_raw)?;
    stdin.write(&input.whitelist_registry_root);
    stdin.write(&whitelist_proof_zk);

    println!("   ✅ Finished writing stdin data");

    Ok(ExecuteJobArtifacts {
        client_folder: client_folder_for_return,
        sequence_run_id: resolved_sequence_run_id,
        elf_path,
        elf_bytes,
        stdin,
        bundle_id,
        survey_responses,
        clinician_id: genomic_clinician_id.clone(),
        clinician_pubkey: genomic_clinician_pubkey.clone(),
        merkle_root: merkle_root.trim().to_string(),
        mmr_proof: mmr_proof_provenance,
        snp_proofs: snp_proofs_provenance,
        expected_mmr_root,
        registry_root,
        registry_proof: registry_proof_provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "zeenome-execute-job-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    fn write_published_phenotype_dir(
        dir: &Path,
        clinician_id: &str,
        epoch_number: i32,
    ) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(
            dir.join("commitment.json"),
            format!(
                r#"{{
  "actor_id": "{clinician_id}",
  "phenotype_merkle_root": "root-{epoch_number}",
  "signature": "sig",
  "epoch_number": {epoch_number},
  "epoch_root": "epoch-root-{epoch_number}",
  "registry_root": "registry-root",
  "registry_proof": {{"leaf_index":0,"leaf_value":"v","path":[],"root":"registry-root"}}
}}"#
            ),
        )?;
        fs::write(
            dir.join("json_merkle_root.txt"),
            format!("root-{epoch_number}"),
        )?;
        fs::write(dir.join("json_path_leaves.json"), "[]")?;
        fs::write(dir.join("json_path_proofs.json"), "[]")?;
        fs::write(dir.join("mmr_proof.json"), "{}")?;
        Ok(())
    }

    #[test]
    fn find_published_phenotype_folder_discovers_matching_sibling_attestation() {
        let root = unique_temp_dir("sibling-attestation");
        let sequence_run_dir = root.join("data/clients/client-1/sequence-runs/run-1");
        fs::create_dir_all(&sequence_run_dir).expect("create sequence run dir");

        let attestation_root = root.join("data/clients/client-1/phenotype-attestations");
        let matching_old = attestation_root.join("pat-old");
        let matching_new = attestation_root.join("pat-new");
        let other_clinician = attestation_root.join("pat-other");
        write_published_phenotype_dir(&matching_old, "clinician-a", 1)
            .expect("write old attestation");
        write_published_phenotype_dir(&matching_new, "clinician-a", 3)
            .expect("write new attestation");
        write_published_phenotype_dir(&other_clinician, "clinician-b", 99)
            .expect("write other attestation");

        let found = find_published_phenotype_folder(&sequence_run_dir, "clinician-a")
            .expect("discover phenotype folder");

        assert_eq!(found, Some(matching_new));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn find_published_phenotype_folder_errors_on_matching_incomplete_attestation() {
        let root = unique_temp_dir("incomplete-attestation");
        let sequence_run_dir = root.join("data/clients/client-1/sequence-runs/run-1");
        fs::create_dir_all(&sequence_run_dir).expect("create sequence run dir");

        let incomplete = root.join("data/clients/client-1/phenotype-attestations/pat-incomplete");
        fs::create_dir_all(&incomplete).expect("create incomplete attestation dir");
        fs::write(
            incomplete.join("commitment.json"),
            r#"{
  "actor_id": "clinician-a",
  "phenotype_merkle_root": "root",
  "signature": "sig",
  "epoch_number": 1,
  "epoch_root": "epoch-root",
  "registry_root": "registry-root",
  "registry_proof": {"leaf_index":0,"leaf_value":"v","path":[],"root":"registry-root"}
}"#,
        )
        .expect("write commitment");

        let error = find_published_phenotype_folder(&sequence_run_dir, "clinician-a")
            .expect_err("matching incomplete attestation should fail closed");

        assert!(error.to_string().contains("missing phenotype artifact"));

        let _ = fs::remove_dir_all(root);
    }
}
