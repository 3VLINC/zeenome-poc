//! Genome (VCF) pipeline formerly in `sequencer-cli`, merged under the clinician umbrella.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use zeenome_core::{
    crypto::KeyPair,
    errors::{Result, ZeenomeError},
    merkle::{compute_root, generate_proof},
    signing,
    variant::{
        parse_vcf_for_sequencing_panel, parse_vcf_over_bed_intervals, BedIntervalRow, GenomeBuild,
        IRISPLEX_TARGET_VARIANTS,
    },
};

/// Samtools/bcftools log progress and hints to stderr. Discard unless we capture it for an error message.
fn bio_stderr_quiet() -> Stdio {
    Stdio::null()
}

/// `bcftools mpileup | bcftools call`: call may finish and close stdin while mpileup still runs.
/// mpileup then often exits with SIGPIPE (141 on Linux) even though the VCF was written successfully.
fn mpileup_pipe_child_ok(status: ExitStatus, call_succeeded: bool, output_path: &Path) -> bool {
    if status.success() {
        return true;
    }
    if call_succeeded && output_path.is_file() {
        return true;
    }
    #[cfg(unix)]
    if call_succeeded {
        if matches!(status.code(), Some(141) | Some(13)) {
            return true;
        }
    }
    false
}

fn strip_chr_prefix(chrom: &str) -> String {
    let c = chrom.trim();
    if c.len() >= 4 && c[..3].eq_ignore_ascii_case("chr") {
        c[3..].to_string()
    } else {
        c.to_string()
    }
}

/// One genomic slice to fetch from CRAM (samtools `-X` region string is preformatted).
#[derive(Debug, Clone)]
struct SamtoolsSlice {
    work_label: String,
    samtools_region: String,
}

fn write_custom_targets_tsv(work_dir: &Path, intervals: &[BedIntervalRow]) -> Result<PathBuf> {
    let p = work_dir.join("custom_targets.tsv");
    let mut f = fs::File::create(&p).map_err(ZeenomeError::from)?;
    use std::io::Write as _;
    writeln!(f, "#CHROM\tSTART\tEND\tID").map_err(ZeenomeError::from)?;
    for (idx, iv) in intervals.iter().enumerate() {
        let chrom_trim = iv.chrom.trim();
        let chrom_disp = if chrom_trim.len() >= 3 && chrom_trim[..3].eq_ignore_ascii_case("chr") {
            chrom_trim.to_string()
        } else {
            format!("chr{chrom_trim}")
        };
        let start_1 = iv.chrom_start.saturating_add(1);
        let end_1_inc = iv.chrom_end;
        if iv.chrom_end <= iv.chrom_start || start_1 > end_1_inc {
            return Err(ZeenomeError::InvalidFormat(
                "Invalid BED row in sequencing_bed_snapshot (need chrom_end > chrom_start)"
                    .to_string(),
            ));
        }
        writeln!(
            f,
            "{}\t{}\t{}\tcustom_bed_{idx}",
            chrom_disp, start_1, end_1_inc
        )
        .map_err(ZeenomeError::from)?;
    }
    Ok(p)
}

fn targets_tsv_for_panel(panel: &str) -> Result<&'static str> {
    match panel {
        "irisplex" => Ok("data/panel-examples/targets-irisplex.tsv"),
        other => Err(ZeenomeError::InvalidFormat(format!(
            "unknown --sequencing-panel {:?} (expected irisplex)",
            other
        ))),
    }
}

fn build_extraction_slices(
    panel: Option<&str>,
    bed_intervals: Option<&[BedIntervalRow]>,
    work_dir: &Path,
) -> Result<(Vec<SamtoolsSlice>, PathBuf)> {
    match (panel, bed_intervals) {
        (Some(panel), None) => {
            let p = panel.trim().to_lowercase();
            let targets_path = PathBuf::from(targets_tsv_for_panel(&p)?);
            let rows: Vec<SamtoolsSlice> = match p.as_str() {
                "irisplex" => IRISPLEX_TARGET_VARIANTS
                    .iter()
                    .map(|t| {
                        let chrom = strip_chr_prefix(t.chrom);
                        let pos = t.position as u64;
                        SamtoolsSlice {
                            work_label: t.extraction_work_label(),
                            samtools_region: format!("chr{chrom}:{pos}-{pos}"),
                        }
                    })
                    .collect(),
                other => {
                    return Err(ZeenomeError::InvalidFormat(format!(
                        "unknown --sequencing-panel {:?} (expected irisplex)",
                        other
                    )));
                }
            };
            Ok((rows, targets_path))
        }
        (None, Some(ivs)) => {
            if ivs.is_empty() {
                return Err(ZeenomeError::InvalidFormat(
                    "custom BED interval list must be non-empty".to_string(),
                ));
            }
            let tsv = write_custom_targets_tsv(work_dir, ivs)?;
            let mut slices = Vec::with_capacity(ivs.len());
            for (idx, iv) in ivs.iter().enumerate() {
                let chrom_trim = strip_chr_prefix(&iv.chrom);
                let s1 = iv.chrom_start.saturating_add(1);
                let e1 = iv.chrom_end;
                if iv.chrom_end <= iv.chrom_start {
                    return Err(ZeenomeError::InvalidFormat(format!(
                        "BED row idx {idx} has chrom_end <= chrom_start"
                    )));
                }
                slices.push(SamtoolsSlice {
                    work_label: format!("custom_bed_{idx}"),
                    samtools_region: format!("chr{chrom_trim}:{s1}-{e1}"),
                });
            }
            Ok((slices, tsv))
        }
        _ => Err(ZeenomeError::InvalidFormat(
            "internal: extraction panel xor custom bed required".to_string(),
        )),
    }
}

fn panel_regions_for_run(
    panel: &str,
    bed_intervals: Option<&[BedIntervalRow]>,
) -> Vec<BedIntervalRow> {
    if let Some(intervals) = bed_intervals {
        return intervals.to_vec();
    }
    let to_row = |chrom: &str, pos: u32| BedIntervalRow {
        chrom: chrom.to_string(),
        chrom_start: pos.saturating_sub(1),
        chrom_end: pos,
    };
    match panel.trim().to_lowercase().as_str() {
        "irisplex" => IRISPLEX_TARGET_VARIANTS
            .iter()
            .map(|t| to_row(t.chrom, t.position))
            .collect(),
        _ => IRISPLEX_TARGET_VARIANTS
            .iter()
            .map(|t| to_row(t.chrom, t.position))
            .collect(),
    }
}

fn extract_and_combine_vcfs(
    catalog_sample_id: &str,
    work_dir: &PathBuf,
    panel: Option<&str>,
    bed_intervals: Option<&[BedIntervalRow]>,
) -> Result<PathBuf> {
    // Parse catalog id to get run_id and sample_id
    let parts: Vec<&str> = catalog_sample_id.split('/').collect();
    if parts.len() != 2 {
        return Err(ZeenomeError::InvalidFormat(
            "catalog_sample_id must be of the form 'ERRXXXXXXX/HGYYYYY'".to_string(),
        ));
    }
    let run_id = parts[0];
    let sample_id = parts[1];

    // Build CRAM/CRAI paths
    let reference = "s3://1000genomes/technical/reference/GRCh38_reference_genome/GRCh38_full_analysis_set_plus_decoy_hla.fa";
    let cram_url = format!(
        "s3://1000genomes/1000G_2504_high_coverage/data/{}/{}.final.cram",
        run_id, sample_id
    );
    let (slices, targets_path_owned) = build_extraction_slices(panel, bed_intervals, work_dir)?;
    let targets_file_path = targets_path_owned.as_path();
    if let Some(p) = panel {
        println!("   Sequencing panel: {}", p);
    } else {
        println!("   Sequencing panel: custom_bed ({})", slices.len());
    }
    println!("   Targets file: {}", targets_file_path.display());

    println!("   CRAM URL: {}", cram_url);
    println!("   Reference: {}", reference);
    println!("   Processing {} slices...", slices.len());

    let local_cram_index = work_dir.join(format!("{}.final.cram.crai", sample_id));
    download_cram_index(&cram_url, &local_cram_index)?;

    // Step 1: Extract SNP reads for each position
    let mut vcf_files = Vec::new();

    for site in &slices {
        println!(
            "   Processing {} ({})",
            site.work_label, site.samtools_region
        );

        let snp_id = site.work_label.as_str();
        let snp_work_dir = work_dir.join(snp_id);
        std::fs::create_dir_all(&snp_work_dir)?;

        let bam_file = snp_work_dir.join(format!("{}.bam", snp_id));
        let mpileup_file = snp_work_dir.join(format!("{}.mpileup", snp_id));
        let vcf_file = snp_work_dir.join(format!("{}.vcf", snp_id));

        // Extract BAM file for this SNP
        let extract_status = Command::new("samtools")
            .arg("view")
            .arg("-b")
            .arg("-h")
            .arg("--reference")
            .arg(reference)
            .arg(&cram_url)
            .arg("-X")
            .arg(&local_cram_index)
            .arg(&site.samtools_region)
            .stdout(Stdio::from(
                std::fs::File::create(&bam_file).map_err(ZeenomeError::from)?,
            ))
            .stderr(bio_stderr_quiet())
            .status()?;

        if !extract_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to extract BAM for {}",
                snp_id
            )));
        }

        // Index BAM file
        let index_status = Command::new("samtools")
            .arg("index")
            .arg(&bam_file)
            .stderr(bio_stderr_quiet())
            .status()?;

        if !index_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to index BAM for {}",
                snp_id
            )));
        }

        // Create mpileup (for IrisPlex compatibility)
        let mpileup_output = Command::new("samtools")
            .arg("mpileup")
            .arg("-f")
            .arg(reference)
            .arg(&bam_file)
            .stdout(Stdio::piped())
            .stderr(bio_stderr_quiet())
            .output()?;

        if !mpileup_output.status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to create mpileup for {}: {}",
                snp_id,
                String::from_utf8_lossy(&mpileup_output.stderr)
            )));
        }

        std::fs::write(&mpileup_file, &mpileup_output.stdout)?;

        // Call variants using bcftools
        let raw_vcf_gz = snp_work_dir.join(format!("{}.raw.vcf.gz", snp_id));

        // bcftools mpileup | bcftools call (stderr discarded — ploidy hints are not failures).
        let mut mpileup_process = Command::new("bcftools")
            .arg("mpileup")
            .arg("-f")
            .arg(reference)
            .arg("-R")
            .arg(targets_file_path)
            .arg("-Ou")
            .arg(&bam_file)
            .stdout(Stdio::piped())
            .stderr(bio_stderr_quiet())
            .spawn()
            .map_err(ZeenomeError::from)?;

        let call_output =
            Command::new("bcftools")
                .arg("call")
                .arg("-m")
                .arg("-Oz")
                .arg("-o")
                .arg(&raw_vcf_gz)
                .stdin(mpileup_process.stdout.take().ok_or_else(|| {
                    ZeenomeError::InvalidFormat("Failed to pipe mpileup".to_string())
                })?)
                .stderr(Stdio::piped())
                .output()?;

        let mpileup_status = mpileup_process.wait().map_err(ZeenomeError::from)?;

        let call_ok = call_output.status.success() && raw_vcf_gz.is_file();
        if !call_output.status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to call variants for {}: {}",
                snp_id,
                String::from_utf8_lossy(&call_output.stderr)
            )));
        }
        if !raw_vcf_gz.is_file() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "bcftools call did not produce output for {}",
                snp_id
            )));
        }
        if !mpileup_pipe_child_ok(mpileup_status, call_ok, &raw_vcf_gz) {
            return Err(ZeenomeError::InvalidFormat(format!(
                "bcftools mpileup failed for {} (status {:?})",
                snp_id,
                mpileup_status.code()
            )));
        }

        // Annotate with targets file
        let annotated_vcf_gz = snp_work_dir.join(format!("{}.vcf.gz", snp_id));
        let annotate_status = Command::new("bcftools")
            .arg("annotate")
            .arg("-a")
            .arg(targets_file_path)
            .arg("-c")
            .arg("CHROM,FROM,TO,ID")
            .arg("-Oz")
            .arg("-o")
            .arg(&annotated_vcf_gz)
            .arg(&raw_vcf_gz)
            .stderr(bio_stderr_quiet())
            .status()?;

        if !annotate_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to annotate VCF for {}",
                snp_id
            )));
        }

        // Convert to plain VCF
        let convert_status = Command::new("bcftools")
            .arg("convert")
            .arg("-Ov")
            .arg("-o")
            .arg(&vcf_file)
            .arg(&annotated_vcf_gz)
            .stderr(bio_stderr_quiet())
            .status()?;

        if !convert_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to convert VCF for {}",
                snp_id
            )));
        }

        vcf_files.push(vcf_file.clone());
        println!("   ✓ Generated VCF for {}", snp_id);
    }

    // Step 2: Combine all VCF files
    println!("   Combining {} VCF files...", vcf_files.len());

    // Sort and bgzip each VCF file
    let mut sorted_gz_files = Vec::new();
    for vcf_file in &vcf_files {
        let sorted_gz = vcf_file.parent().unwrap().join(format!(
            "{}.sorted.vcf.gz",
            vcf_file.file_stem().unwrap().to_str().unwrap()
        ));

        let sort_status = Command::new("bcftools")
            .arg("sort")
            .arg("-Oz")
            .arg("-o")
            .arg(&sorted_gz)
            .arg(vcf_file)
            .stderr(bio_stderr_quiet())
            .status()?;

        if !sort_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to sort VCF: {:?}",
                vcf_file
            )));
        }

        // Index with tabix
        let tabix_status = Command::new("tabix")
            .arg("-p")
            .arg("vcf")
            .arg(&sorted_gz)
            .stderr(bio_stderr_quiet())
            .status()?;

        if !tabix_status.success() {
            return Err(ZeenomeError::InvalidFormat(format!(
                "Failed to index VCF with tabix: {:?}",
                sorted_gz
            )));
        }

        sorted_gz_files.push(sorted_gz);
    }

    // Concatenate all sorted VCF files
    let concat_vcf_gz = work_dir.join("variants.tmp.vcf.gz");
    let mut concat_cmd = Command::new("bcftools");
    concat_cmd
        .arg("concat")
        .arg("-a")
        .arg("-Oz")
        .arg("-o")
        .arg(&concat_vcf_gz);
    for sorted_gz in &sorted_gz_files {
        concat_cmd.arg(sorted_gz);
    }

    let concat_status = concat_cmd.stderr(bio_stderr_quiet()).status()?;

    if !concat_status.success() {
        return Err(ZeenomeError::InvalidFormat(
            "Failed to concatenate VCF files".to_string(),
        ));
    }

    // Sort the concatenated VCF
    let final_vcf_gz = work_dir.join("variants.vcf.gz");
    let final_sort_status = Command::new("bcftools")
        .arg("sort")
        .arg("-Oz")
        .arg("-o")
        .arg(&final_vcf_gz)
        .arg(&concat_vcf_gz)
        .stderr(bio_stderr_quiet())
        .status()?;

    if !final_sort_status.success() {
        return Err(ZeenomeError::InvalidFormat(
            "Failed to sort final VCF".to_string(),
        ));
    }

    // Index final VCF
    let final_tabix_status = Command::new("tabix")
        .arg("-p")
        .arg("vcf")
        .arg(&final_vcf_gz)
        .stderr(bio_stderr_quiet())
        .status()?;

    if !final_tabix_status.success() {
        return Err(ZeenomeError::InvalidFormat(
            "Failed to index final VCF".to_string(),
        ));
    }

    // Multiallelic split + left-align + trim (bcftools norm -m -any; same reference as mpileup/call)
    let norm_vcf_gz = work_dir.join("variants.norm.vcf.gz");
    let norm_status = Command::new("bcftools")
        .arg("norm")
        .arg("-f")
        .arg(reference)
        .arg("-m")
        .arg("-any")
        .arg("-Oz")
        .arg("-o")
        .arg(&norm_vcf_gz)
        .arg(&final_vcf_gz)
        .stderr(bio_stderr_quiet())
        .status()?;

    if !norm_status.success() {
        return Err(ZeenomeError::InvalidFormat(
            "bcftools norm failed (multiallelic split / left-align)".to_string(),
        ));
    }

    let _ = std::fs::remove_file(&final_vcf_gz);
    let _ = std::fs::remove_file(format!("{}.tbi", final_vcf_gz.display()));

    let norm_tabix = Command::new("tabix")
        .arg("-p")
        .arg("vcf")
        .arg(&norm_vcf_gz)
        .stderr(bio_stderr_quiet())
        .status()?;

    if !norm_tabix.success() {
        return Err(ZeenomeError::InvalidFormat(
            "Failed to tabix normalized VCF".to_string(),
        ));
    }

    // Convert to plain VCF
    let final_vcf = work_dir.join("variants.vcf");
    let final_convert_status = Command::new("bcftools")
        .arg("convert")
        .arg("-Ov")
        .arg("-o")
        .arg(&final_vcf)
        .arg(&norm_vcf_gz)
        .stderr(bio_stderr_quiet())
        .status()?;

    if !final_convert_status.success() {
        return Err(ZeenomeError::InvalidFormat(
            "Failed to convert final VCF to plain format".to_string(),
        ));
    }

    let _ = std::fs::remove_file(&norm_vcf_gz);
    let _ = std::fs::remove_file(format!("{}.tbi", norm_vcf_gz.display()));

    // Cleanup temporary files
    let _ = std::fs::remove_file(&concat_vcf_gz);
    for sorted_gz in &sorted_gz_files {
        let _ = std::fs::remove_file(sorted_gz);
        // Also remove .tbi files
        let tbi = sorted_gz.with_extension("vcf.gz.tbi");
        let _ = std::fs::remove_file(tbi);
    }

    println!("   ✓ Combined VCF created: {}", final_vcf.display());
    Ok(final_vcf)
}

fn download_cram_index(cram_url: &str, dest: &Path) -> Result<()> {
    if dest.exists() {
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let http_url = s3_to_https(cram_url)?;
    let index_url = format!("{}.crai", http_url);

    println!("   Downloading CRAM index: {}", index_url);
    let status = Command::new("curl")
        .arg("-sfL")
        .arg(&index_url)
        .arg("-o")
        .arg(dest)
        .status()?;

    if !status.success() {
        return Err(ZeenomeError::InvalidFormat(format!(
            "Failed to download CRAM index from {}",
            index_url
        )));
    }

    Ok(())
}

fn s3_to_https(s3_url: &str) -> Result<String> {
    if let Some(rest) = s3_url.strip_prefix("s3://") {
        let mut parts = rest.splitn(2, '/');
        let bucket = parts
            .next()
            .ok_or_else(|| ZeenomeError::InvalidFormat(format!("Invalid S3 URL: {}", s3_url)))?;
        let key = parts
            .next()
            .ok_or_else(|| ZeenomeError::InvalidFormat(format!("Invalid S3 URL: {}", s3_url)))?;
        Ok(format!("https://{}.s3.amazonaws.com/{}", bucket, key))
    } else {
        Ok(s3_url.to_string())
    }
}

fn panel_inconclusive_message(panel: &str, parse_err: &str, merkle_empty: bool) -> String {
    let p = panel.trim().to_lowercase();
    let intro = match p.as_str() {
        "irisplex" => "IrisPlex panel inconclusive for this sample.",
        "custom_bed" => "Custom BED sequencing inconclusive for this sample.",
        _ => "Sequencing panel inconclusive for this sample.",
    };
    let causes = "Common causes: low or uneven coverage at required loci; REF/ALT or genome build mismatch vs GRCh38 panel; caller emitted no VCF row or ./. at one or more required sites; extraction or filtering dropped sites.";
    let mut s = format!("{} {}", intro, causes);
    if merkle_empty {
        s.push_str(
            " No variants remained after panel matching, so a Merkle attestation cannot be built.",
        );
    }
    if !parse_err.is_empty() {
        s.push(' ');
        s.push_str(parse_err);
    }
    s
}

// -----------------------------------------------------------------------------
// process-genome-sample (disk-only)
//
// Snapshot carries everything the legacy DB-coupled version SELECTed up-front:
//   * The optional existing `clients` row (used for ownership + panel/bed snapshot).
//   * A flag for the cross-client dup check (catalog_sample_id taken by another
//     client row owned by this clinician).
//   * Pending / staged / published leaf indicators for `vcf_artifact_staging` and
//     `vcf_artifacts` so the CLI can refuse to re-process a sample whose Merkle
//     root would clash.
//
// Output carries the rows the worker INSERTs in one transaction:
//   * Optional `client_row_to_insert` — only set when the server's snapshot
//     had `existing_client_row = None`. The worker INSERTs the row; on
//     failure the transaction rolls back and there's nothing to clean up
//     (replaces the old `rollback_failed_process_sample` / `rollback_duplicate_pre_publish`).
//   * The `client_sequence_runs` row + `client_sequence_run_regions` rows.
//   * The `vcf_artifact_staging` row.
//   * A `clients.folder_path` update target.
//
// The CLI still owns all on-disk artifacts (CRAM download, samtools/bcftools
// extraction, merkle/MMR computation) — only the DB side moves out.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ProcessGenomeExistingClientRow {
    /// `clients.catalog_sample_id` from the last persisted row (informational).
    pub catalog_sample_id: String,
    /// `clients.sequencing_panel` — overrides the arg when set (mirrors the
    /// legacy "trust the persisted panel" behaviour).
    pub sequencing_panel: String,
    /// `clients.sequencing_bed_snapshot` — required when `sequencing_panel == "custom_bed"`.
    pub sequencing_bed_snapshot: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ProcessGenomeSampleInput {
    pub actor_id: String,
    pub client_id: String,
    /// Snapshot equivalents of the CLI args; kept for cross-validation and
    /// future use when callers stop passing them as positional args. The CLI
    /// currently relies on the args and treats these as advisory.
    #[serde(default)]
    #[allow(dead_code)]
    pub catalog_sample_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub sequencing_panel: String,
    /// Only set when `sequencing_panel == "custom_bed"` and the row doesn't exist yet.
    pub sequencing_bed_snapshot: Option<serde_json::Value>,
    pub existing_client_row: Option<ProcessGenomeExistingClientRow>,
    /// True when `clients` has another row for this org with the same
    /// `catalog_sample_id` and a different `id`. Server side: org-scoped dup check.
    pub catalog_taken_by_other_client_in_org: bool,
    /// True when `vcf_artifact_staging` has an unpublished row for this client_id.
    pub existing_pending_for_client: bool,
    pub existing_staged_leaves: Vec<String>,
    pub existing_published_leaves: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessGenomeClientRowToInsert {
    pub id: String,
    pub catalog_sample_id: String,
    pub created_by_wallet: String,
    pub sequencing_panel: String,
    /// `clients.sequencing_bed_snapshot` value when panel is `custom_bed`,
    /// otherwise null.
    pub sequencing_bed_snapshot: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProcessGenomeRunRegion {
    pub chrom: String,
    pub chrom_start: i64,
    pub chrom_end: i64,
}

#[derive(Debug, Serialize)]
pub struct ProcessGenomeStagedVcf {
    pub vcf_merkle_root: String,
    pub snp_inclusion_proofs: serde_json::Value,
    pub staging_digest: String,
    pub artifacts_path: String,
}

#[derive(Debug, Serialize)]
pub struct ProcessGenomeSampleOutput {
    pub actor_id: String,
    pub client_id: String,
    pub catalog_sample_id: String,
    /// Some => the worker INSERTs the row; None => row already exists.
    pub client_row_to_insert: Option<ProcessGenomeClientRowToInsert>,
    /// `clients.sequencing_panel` the worker UPDATEs the row to (matches the
    /// "trust the snapshot panel" behaviour). Always set for both new and
    /// existing rows.
    pub effective_sequencing_panel: String,
    /// Path the worker UPDATEs `clients.folder_path` to.
    pub client_folder_path: String,
    pub sequence_run_id: String,
    pub panel_code: String,
    pub genome_build: String,
    pub run_regions: Vec<ProcessGenomeRunRegion>,
    pub staged_vcf: ProcessGenomeStagedVcf,
}

pub fn genome_process_sample_disk(
    actor_id: &str,
    client_id: &str,
    catalog_sample_id: &str,
    sequencing_panel_arg: &str,
    vcf_path_override: Option<&Path>,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    println!(
        "🔄 Processing client {} (catalog {}) for actor {} (disk-only)",
        client_id, catalog_sample_id, actor_id
    );

    let raw = fs::read_to_string(input_path)?;
    let input: ProcessGenomeSampleInput = serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse process-genome-sample snapshot at {}: {}",
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

    let catalog_trim = catalog_sample_id.trim();
    let mut client_row_to_insert: Option<ProcessGenomeClientRowToInsert> = None;

    // Determine effective panel + bed.
    let (panel_eff, bed_intervals_owned, sequencing_bed_snapshot_for_new_row): (
        String,
        Option<Vec<BedIntervalRow>>,
        Option<serde_json::Value>,
    ) = if let Some(existing) = input.existing_client_row.as_ref() {
        // Repeat attestations for the same client may use a different catalog sample;
        // each sequence run records its own catalog_sample_id (worker updates clients).
        let panel_arg = sequencing_panel_arg.trim();
        let panel = if panel_arg.is_empty() {
            existing.sequencing_panel.trim().to_string()
        } else {
            panel_arg.to_string()
        };
        let bed = if panel.eq_ignore_ascii_case("custom_bed") {
            let snap = existing.sequencing_bed_snapshot.clone().ok_or_else(|| {
                ZeenomeError::InvalidFormat(
                    "existing custom_bed client row missing sequencing_bed_snapshot".to_string(),
                )
            })?;
            Some(serde_json::from_value::<Vec<BedIntervalRow>>(snap).map_err(|e| {
                ZeenomeError::InvalidFormat(format!("sequencing_bed_snapshot JSON invalid: {e}"))
            })?)
        } else {
            None
        };
        (panel, bed, None)
    } else {
        if input.catalog_taken_by_other_client_in_org {
            return Err(ZeenomeError::AlreadyExists(format!(
                "Catalog sample {} already has a client row in this org",
                catalog_trim
            )));
        }
        let panel = sequencing_panel_arg.trim().to_string();
        let (bed, snapshot_for_insert) = if panel.eq_ignore_ascii_case("custom_bed") {
            let snap = input.sequencing_bed_snapshot.clone().ok_or_else(|| {
                ZeenomeError::InvalidFormat(
                    "sequencing_panel=custom_bed requires sequencing_bed_snapshot in input"
                        .to_string(),
                )
            })?;
            let parsed: Vec<BedIntervalRow> =
                serde_json::from_value(snap.clone()).map_err(|e| {
                    ZeenomeError::InvalidFormat(format!("sequencing_bed_snapshot JSON invalid: {e}"))
                })?;
            (Some(parsed), Some(snap))
        } else {
            (None, None)
        };
        client_row_to_insert = Some(ProcessGenomeClientRowToInsert {
            id: client_id.to_string(),
            catalog_sample_id: catalog_trim.to_string(),
            created_by_wallet: actor_id.to_string(),
            sequencing_panel: panel.clone(),
            sequencing_bed_snapshot: snapshot_for_insert.clone(),
        });
        (panel, bed, snapshot_for_insert)
    };
    let _ = sequencing_bed_snapshot_for_new_row; // already moved into client_row_to_insert

    let extraction_bed = bed_intervals_owned.as_ref().map(|v| v.as_slice());
    let extraction_panel_opt: Option<&str> = if extraction_bed.is_some() {
        None
    } else {
        Some(panel_eff.as_str())
    };

    // Run-scoped folder structure.
    let sequence_run_id = format!(
        "srn-{}-{}",
        client_id.replace('/', "_"),
        chrono::Utc::now().timestamp_millis()
    );
    let client_folder = PathBuf::from("data/clients")
        .join(client_id.replace('/', "_"))
        .join("sequence-runs")
        .join(&sequence_run_id);
    fs::create_dir_all(&client_folder)?;
    fs::create_dir_all(client_folder.join("genome"))?;
    fs::create_dir_all(client_folder.join("metadata"))?;
    let work_dir = client_folder.join("work");

    let vcf_file = work_dir.join("variants.vcf");
    let merkle_root_file = client_folder.join("genome/vcf_merkle_root.txt");
    let snp_proofs_file = client_folder.join("genome/snp_proofs.json");
    let data_exists = vcf_file.exists() && merkle_root_file.exists() && snp_proofs_file.exists();

    let run_regions = panel_regions_for_run(&panel_eff, extraction_bed);

    fs::write(
        client_folder.join("metadata/run.json"),
        serde_json::to_string_pretty(&json!({
            "sequence_run_id": sequence_run_id,
            "client_id": client_id,
            "sequencer_id": actor_id,
            "catalog_sample_id": catalog_trim,
            "panel_code": panel_eff,
            "genome_build": "GRCh38",
            "created_at": chrono::Utc::now().to_rfc3339(),
        }))?,
    )?;

    // Step 1: ensure VCF exists.
    let vcf_path = if data_exists {
        println!("   ⚠️  Sample data already exists, skipping extraction and SNP processing");
        vcf_file.clone()
    } else if let Some(override_path) = vcf_path_override {
        println!(
            "📊 Using local VCF at {} (skipping CRAM/S3 extraction)...",
            override_path.display()
        );
        if !override_path.is_file() {
            return Err(ZeenomeError::NotFound(format!(
                "--vcf-path `{}` does not exist or is not a file",
                override_path.display()
            )));
        }
        fs::create_dir_all(&work_dir)?;
        fs::copy(override_path, &vcf_file).map_err(|e| {
            ZeenomeError::InvalidFormat(format!(
                "Failed to copy --vcf-path `{}` to {}: {e}",
                override_path.display(),
                vcf_file.display()
            ))
        })?;
        vcf_file.clone()
    } else {
        println!("📊 Extracting SNPs from CRAM files...");
        fs::create_dir_all(&work_dir)?;
        extract_and_combine_vcfs(catalog_trim, &work_dir, extraction_panel_opt, extraction_bed)?
    };

    // Step 2: parse VCF.
    let vcf_content = fs::read_to_string(&vcf_path).map_err(ZeenomeError::from)?;
    let snp_parse = match &bed_intervals_owned {
        Some(ivs) => parse_vcf_over_bed_intervals(&vcf_content, ivs, GenomeBuild::GRCh38),
        None => parse_vcf_for_sequencing_panel(&vcf_content, &panel_eff),
    };
    let snp_data = snp_parse.map_err(|e| {
        ZeenomeError::PanelInconclusive(panel_inconclusive_message(&panel_eff, &e, false))
    })?;

    let snp_leaves: Vec<String> = snp_data
        .iter()
        .map(zeenome_core::snp::merkle_leaf_preimage)
        .collect();
    if snp_leaves.is_empty() {
        return Err(ZeenomeError::PanelInconclusive(panel_inconclusive_message(
            &panel_eff, "", true,
        )));
    }

    let mut snp_proofs = Vec::with_capacity(snp_leaves.len());
    for (i, _) in snp_leaves.iter().enumerate() {
        snp_proofs.push(generate_proof(&snp_leaves, i)?);
    }
    let merkle_root = match compute_root(&snp_leaves) {
        Ok(r) => r,
        Err(e) => {
            if matches!(&e, ZeenomeError::Merkle(msg) if msg.contains("empty leaves")) {
                return Err(ZeenomeError::PanelInconclusive(panel_inconclusive_message(
                    &panel_eff, "", true,
                )));
            }
            return Err(e);
        }
    };

    fs::write(&merkle_root_file, &merkle_root)?;
    fs::write(&snp_proofs_file, serde_json::to_string_pretty(&snp_proofs)?)?;
    let snp_proofs_json = serde_json::to_value(&snp_proofs)?;

    if input.existing_pending_for_client {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has an unpublished staged genome artifact",
            client_id
        )));
    }
    if input.existing_staged_leaves.iter().any(|r| r == &merkle_root) {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has staged genome artifacts with this Merkle root",
            client_id
        )));
    }
    if input.existing_published_leaves.iter().any(|r| r == &merkle_root) {
        return Err(ZeenomeError::AlreadyExists(format!(
            "Client {} already has published genome artifacts with this Merkle root",
            client_id
        )));
    }

    let staging_digest = zeenome_core::crypto::hash_data(
        serde_json::to_string(&json!({
            "client_id": client_id,
            "sequence_run_id": sequence_run_id,
            "catalog_sample_id": catalog_trim,
            "panel_code": panel_eff.trim(),
            "genome_build": "GRCh38",
            "vcf_merkle_root": merkle_root,
        }))?
        .as_bytes(),
    );

    let artifacts_path = client_folder.to_string_lossy().to_string();
    let output = ProcessGenomeSampleOutput {
        actor_id: actor_id.to_string(),
        client_id: client_id.to_string(),
        catalog_sample_id: catalog_trim.to_string(),
        client_row_to_insert,
        effective_sequencing_panel: panel_eff.trim().to_string(),
        client_folder_path: artifacts_path.clone(),
        sequence_run_id: sequence_run_id.clone(),
        panel_code: panel_eff.trim().to_string(),
        genome_build: "GRCh38".to_string(),
        run_regions: run_regions
            .iter()
            .map(|iv| ProcessGenomeRunRegion {
                chrom: iv.chrom.trim().trim_start_matches("chr").to_string(),
                chrom_start: iv.chrom_start as i64,
                chrom_end: iv.chrom_end as i64,
            })
            .collect(),
        staged_vcf: ProcessGenomeStagedVcf {
            vcf_merkle_root: merkle_root.clone(),
            snp_inclusion_proofs: snp_proofs_json,
            staging_digest,
            artifacts_path: artifacts_path.clone(),
        },
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Sample processed and staged successfully!");
    println!("   Client folder: {}", artifacts_path);
    println!("   Staged VCF Merkle root: {}", merkle_root);
    println!("   Payload written to {}", output_path.display());

    Ok(())
}

// -----------------------------------------------------------------------------
// publish-genome-epoch (disk-only)
//
// Mirror of `publish_phenotype_epoch_disk` in main.rs for the genome side:
// snapshot carries pending `vcf_artifact_staging` rows + existing
// `vcf_artifacts` leaves + the clinician_epochs chain + the signing keypair;
// output carries the per-leaf MMR proofs + commitments the worker writes
// into clinician_epochs / vcf_artifacts / vcf_artifact_staging in one
// transaction.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PublishGenomePendingRow {
    pub staging_id: i32,
    pub client_id: String,
    pub sequence_run_id: String,
    pub vcf_merkle_root: String,
    pub snp_inclusion_proofs: serde_json::Value,
    pub artifacts_path: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishGenomeExistingLeaf {
    pub client_id: String,
    pub mmr_leaf: String,
    pub leaf_index: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct PublishGenomeLatestEpoch {
    pub id: i32,
    pub epoch_number: i32,
}

#[derive(Debug, Deserialize)]
pub struct PublishGenomeKeypair {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishGenomeEpochInput {
    pub actor_id: String,
    pub pending_rows: Vec<PublishGenomePendingRow>,
    pub existing_published_leaves: Vec<PublishGenomeExistingLeaf>,
    pub existing_epoch_roots: Vec<String>,
    pub latest_epoch: Option<PublishGenomeLatestEpoch>,
    #[serde(default)]
    pub directory_prev_epoch_number: Option<i32>,
    #[serde(default)]
    pub next_registry_epoch_number: Option<i32>,
    #[serde(default)]
    pub keypair: Option<PublishGenomeKeypair>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishGenomeMessageToSign {
    pub id: String,
    pub kind: String,
    pub message_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishGenomePrepareRow {
    pub staging_id: i32,
    pub client_id: String,
    pub sequence_run_id: String,
    pub leaf: String,
    pub leaf_index: i32,
    pub mmr_proof: serde_json::Value,
    pub snp_inclusion_proofs: serde_json::Value,
    pub artifacts_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishGenomePrepareOutput {
    pub actor_id: String,
    pub epoch_number: i32,
    pub epoch_root: String,
    pub registry_root: String,
    pub registry_proof: serde_json::Value,
    pub epoch_json: String,
    pub prev_epoch_id: Option<i32>,
    pub leaf_reindex: Vec<GenomeLeafReindexRow>,
    pub pending_finalize: Vec<PublishGenomePrepareRow>,
    pub messages_to_sign: Vec<PublishGenomeMessageToSign>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyGenomeSignaturesInput {
    pub signatures: std::collections::HashMap<String, String>,
}

fn bytes_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeLeafReindexRow {
    pub client_id: String,
    pub mmr_leaf: String,
    pub leaf_index: i32,
}

#[derive(Debug, Serialize)]
pub struct PublishGenomeFinalizedRow {
    pub staging_id: i32,
    pub client_id: String,
    pub sequence_run_id: String,
    pub leaf: String,
    pub leaf_index: i32,
    pub mmr_proof: serde_json::Value,
    pub vcf_signature: String,
    pub commitment_json: serde_json::Value,
    pub snp_inclusion_proofs: serde_json::Value,
    pub artifacts_path: String,
}

#[derive(Debug, Serialize)]
pub struct PublishGenomeEpochOutput {
    pub actor_id: String,
    pub epoch_number: i32,
    pub epoch_root: String,
    pub registry_root: String,
    pub registry_proof: serde_json::Value,
    pub signed_epoch_json: serde_json::Value,
    pub prev_epoch_id: Option<i32>,
    pub leaf_reindex: Vec<GenomeLeafReindexRow>,
    pub finalized_rows: Vec<PublishGenomeFinalizedRow>,
}

fn genome_prepare_disk(
    actor_id: &str,
    input: &PublishGenomeEpochInput,
    output_path: &PathBuf,
) -> Result<()> {
    let mut existing_leaves: Vec<String> = Vec::with_capacity(input.existing_published_leaves.len());
    let mut leaf_reindex: Vec<GenomeLeafReindexRow> = Vec::new();
    for (expected_idx, row) in input.existing_published_leaves.iter().enumerate() {
        existing_leaves.push(row.mmr_leaf.clone());
        if row.leaf_index.map(|v| v as usize) != Some(expected_idx) {
            leaf_reindex.push(GenomeLeafReindexRow {
                client_id: row.client_id.clone(),
                mmr_leaf: row.mmr_leaf.clone(),
                leaf_index: expected_idx as i32,
            });
        }
    }
    let mut mmr = zeenome_core::mmr::MerkleMountainRange::from_leaves(&existing_leaves)?;

    struct Appended {
        staging_id: i32,
        client_id: String,
        sequence_run_id: String,
        leaf: String,
        snp_inclusion_proofs: serde_json::Value,
        artifacts_path: String,
        leaf_index: u64,
    }
    let mut appended: Vec<Appended> = Vec::with_capacity(input.pending_rows.len());
    let mut mmr_root = mmr.root().unwrap_or_default();
    for row in &input.pending_rows {
        let (leaf_index, new_root) = mmr.append(row.vcf_merkle_root.clone())?;
        mmr_root = new_root;
        appended.push(Appended {
            staging_id: row.staging_id,
            client_id: row.client_id.clone(),
            sequence_run_id: row.sequence_run_id.clone(),
            leaf: row.vcf_merkle_root.clone(),
            snp_inclusion_proofs: row.snp_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
            leaf_index,
        });
    }

    let prev_epoch_id = input.latest_epoch.as_ref().map(|e| e.id);
    let epoch_number = crate::registry_epoch::resolve_registry_epoch_number(
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

    let mut messages_to_sign = vec![PublishGenomeMessageToSign {
        id: "epoch".to_string(),
        kind: "epoch".to_string(),
        message_hex: bytes_hex(epoch_json.as_bytes()),
    }];
    let mut pending_finalize = Vec::with_capacity(appended.len());
    for row in &appended {
        let mmr_proof = mmr.generate_proof(row.leaf_index)?;
        let commitment_message = signing::commitment_message(
            signing::ArtifactDomain::GenomicVcf,
            actor_id,
            &row.leaf,
            epoch_number,
            &mmr_root,
            &registry_root,
        );
        let id = format!("commitment:{}", row.staging_id);
        messages_to_sign.push(PublishGenomeMessageToSign {
            id: id.clone(),
            kind: "commitment".to_string(),
            message_hex: bytes_hex(&commitment_message),
        });
        pending_finalize.push(PublishGenomePrepareRow {
            staging_id: row.staging_id,
            client_id: row.client_id.clone(),
            sequence_run_id: row.sequence_run_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index as i32,
            mmr_proof: serde_json::to_value(&mmr_proof)?,
            snp_inclusion_proofs: row.snp_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishGenomePrepareOutput {
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
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, serde_json::to_string_pretty(&output)?)?;
    println!(
        "✅ Prepare complete — {} message(s) to sign",
        output.messages_to_sign.len()
    );
    Ok(())
}

fn genome_apply_signatures(
    actor_id: &str,
    prepare_path: &PathBuf,
    signatures_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    let prepare_raw = fs::read_to_string(prepare_path)?;
    let prepare: PublishGenomePrepareOutput = serde_json::from_str(&prepare_raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("Invalid prepare output: {}", e))
    })?;
    if prepare.actor_id != actor_id {
        return Err(ZeenomeError::InvalidFormat("actor_id mismatch".into()));
    }

    let sig_raw = fs::read_to_string(signatures_path)?;
    let sig_input: ApplyGenomeSignaturesInput = serde_json::from_str(&sig_raw).map_err(|e| {
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

    let mut finalized_rows: Vec<PublishGenomeFinalizedRow> =
        Vec::with_capacity(prepare.pending_finalize.len());
    for row in &prepare.pending_finalize {
        let sig_id = format!("commitment:{}", row.staging_id);
        let vcf_signature = sig_input
            .signatures
            .get(&sig_id)
            .ok_or_else(|| {
                ZeenomeError::InvalidFormat(format!("Missing signature for {}", sig_id))
            })?
            .clone();
        let commitment = json!({
            "actor_id": actor_id,
            "vcf_merkle_root": row.leaf,
            "signature": vcf_signature,
            "epoch_number": prepare.epoch_number,
            "epoch_root": prepare.epoch_root,
            "registry_root": prepare.registry_root,
            "registry_proof": prepare.registry_proof,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let artifacts_dir = PathBuf::from(&row.artifacts_path).join("genome");
        fs::create_dir_all(&artifacts_dir)?;
        fs::write(
            artifacts_dir.join("mmr_proof.json"),
            serde_json::to_string_pretty(&row.mmr_proof)?,
        )?;
        fs::write(
            artifacts_dir.join("commitment.json"),
            serde_json::to_string_pretty(&commitment)?,
        )?;

        finalized_rows.push(PublishGenomeFinalizedRow {
            staging_id: row.staging_id,
            client_id: row.client_id.clone(),
            sequence_run_id: row.sequence_run_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index,
            mmr_proof: row.mmr_proof.clone(),
            vcf_signature,
            commitment_json: commitment,
            snp_inclusion_proofs: row.snp_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishGenomeEpochOutput {
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
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, serde_json::to_string_pretty(&output)?)?;
    println!("✅ Applied signatures and wrote publish output");
    Ok(())
}

pub fn genome_publish_epoch_disk(
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
        return genome_apply_signatures(actor_id, input_path, sig_path, output_path);
    }

    println!(
        "📦 Publishing staged genome artifacts for actor {} (disk-only)",
        actor_id
    );

    let raw = fs::read_to_string(input_path)?;
    let input: PublishGenomeEpochInput = serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse publish-genome-epoch snapshot at {}: {}",
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
            "No staged genome artifacts found for actor {}",
            actor_id
        )));
    }

    if prepare {
        return genome_prepare_disk(actor_id, &input, output_path);
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

    let mut existing_leaves: Vec<String> = Vec::with_capacity(input.existing_published_leaves.len());
    let mut leaf_reindex: Vec<GenomeLeafReindexRow> = Vec::new();
    for (expected_idx, row) in input.existing_published_leaves.iter().enumerate() {
        existing_leaves.push(row.mmr_leaf.clone());
        if row.leaf_index.map(|v| v as usize) != Some(expected_idx) {
            leaf_reindex.push(GenomeLeafReindexRow {
                client_id: row.client_id.clone(),
                mmr_leaf: row.mmr_leaf.clone(),
                leaf_index: expected_idx as i32,
            });
        }
    }
    let mut mmr = zeenome_core::mmr::MerkleMountainRange::from_leaves(&existing_leaves)?;

    struct Appended {
        staging_id: i32,
        client_id: String,
        sequence_run_id: String,
        leaf: String,
        snp_inclusion_proofs: serde_json::Value,
        artifacts_path: String,
        leaf_index: u64,
    }
    let mut appended: Vec<Appended> = Vec::with_capacity(input.pending_rows.len());
    let mut mmr_root = mmr.root().unwrap_or_default();
    for row in input.pending_rows {
        let (leaf_index, new_root) = mmr.append(row.vcf_merkle_root.clone())?;
        mmr_root = new_root;
        appended.push(Appended {
            staging_id: row.staging_id,
            client_id: row.client_id,
            sequence_run_id: row.sequence_run_id,
            leaf: row.vcf_merkle_root,
            snp_inclusion_proofs: row.snp_inclusion_proofs,
            artifacts_path: row.artifacts_path,
            leaf_index,
        });
    }

    let prev_epoch_id = input.latest_epoch.as_ref().map(|e| e.id);
    let epoch_number = crate::registry_epoch::resolve_registry_epoch_number(
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

    let mut finalized_rows: Vec<PublishGenomeFinalizedRow> = Vec::with_capacity(appended.len());
    for row in &appended {
        let mmr_proof = mmr.generate_proof(row.leaf_index)?;
        let commitment_message = signing::commitment_message(
            signing::ArtifactDomain::GenomicVcf,
            actor_id,
            &row.leaf,
            epoch_number,
            &mmr_root,
            &registry_root,
        );
        let vcf_signature = zeenome_core::crypto::sign_message(&commitment_message, &keypair)?;
        let commitment = json!({
            "actor_id": actor_id,
            "vcf_merkle_root": row.leaf,
            "signature": vcf_signature,
            "epoch_number": epoch_number,
            "epoch_root": mmr_root.clone(),
            "registry_root": registry_root.clone(),
            "registry_proof": registry_proof.clone(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let artifacts_dir = PathBuf::from(&row.artifacts_path).join("genome");
        fs::create_dir_all(&artifacts_dir)?;
        fs::write(
            artifacts_dir.join("mmr_proof.json"),
            serde_json::to_string_pretty(&mmr_proof)?,
        )?;
        fs::write(
            artifacts_dir.join("commitment.json"),
            serde_json::to_string_pretty(&commitment)?,
        )?;

        finalized_rows.push(PublishGenomeFinalizedRow {
            staging_id: row.staging_id,
            client_id: row.client_id.clone(),
            sequence_run_id: row.sequence_run_id.clone(),
            leaf: row.leaf.clone(),
            leaf_index: row.leaf_index as i32,
            mmr_proof: serde_json::to_value(&mmr_proof)?,
            vcf_signature,
            commitment_json: commitment,
            snp_inclusion_proofs: row.snp_inclusion_proofs.clone(),
            artifacts_path: row.artifacts_path.clone(),
        });
    }

    let output = PublishGenomeEpochOutput {
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
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Published {} staged genome artifact(s)", appended.len());
    println!("   Epoch number: {}", epoch_number);
    println!("   Epoch root: {}", mmr_root);
    println!("   Registry root: {}", registry_root);
    println!("   Payload written to {}", output_path.display());

    Ok(())
}

// -----------------------------------------------------------------------------
// refresh-genomic-commitment (disk-only)
//
// Genome mirror of `refresh_commitment_disk` in main.rs. Looks up the
// per-client genome artifacts directory (we expect `<artifacts_path>/genome/`)
// + the registry-leaves-up-to-target + the signing keypair from the snapshot,
// rewrites `<artifacts_path>/genome/commitment.json`, emits a summary payload.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RefreshGenomicCommitmentInput {
    pub actor_id: String,
    pub client_id: String,
    /// `vcf_artifacts.artifacts_path` (root, not the `/genome/` subdir) for
    /// the latest VCF artifact by `(client_id, actor_id)`. The CLI reads
    /// `<artifacts_path>/genome/vcf_merkle_root.txt` and writes
    /// `<artifacts_path>/genome/commitment.json`.
    pub artifacts_path: String,
    pub target_epoch_number: i32,
    pub target_epoch_root: String,
    pub epoch_roots_up_to_target: Vec<String>,
    pub keypair: RefreshGenomicKeypair,
}

#[derive(Debug, Deserialize)]
pub struct RefreshGenomicKeypair {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshGenomicCommitmentOutput {
    pub actor_id: String,
    pub client_id: String,
    pub artifacts_path: String,
    pub target_epoch_number: i32,
    pub target_epoch_root: String,
    pub target_registry_root: String,
    pub vcf_merkle_root: String,
    pub signature: String,
}

pub fn genome_refresh_commitment_disk(
    actor_id: &str,
    client_id: &str,
    target_registry_root: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    println!(
        "🔄 Refreshing genomic commitment for client {} (disk-only)",
        client_id
    );

    let raw = fs::read_to_string(input_path)?;
    let input: RefreshGenomicCommitmentInput = serde_json::from_str(&raw).map_err(|e| {
        ZeenomeError::InvalidFormat(format!(
            "Could not parse refresh-genomic-commitment snapshot at {}: {}",
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

    let genome_dir = PathBuf::from(&input.artifacts_path).join("genome");
    let vcf_merkle_root = fs::read_to_string(genome_dir.join("vcf_merkle_root.txt"))?;

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
        signing::ArtifactDomain::GenomicVcf,
        actor_id,
        &vcf_merkle_root,
        input.target_epoch_number,
        &input.target_epoch_root,
        target_registry_root,
    );
    let vcf_signature = zeenome_core::crypto::sign_message(&commitment_message, &keypair)?;

    let commitment = json!({
        "actor_id": actor_id,
        "vcf_merkle_root": vcf_merkle_root,
        "signature": vcf_signature,
        "epoch_number": input.target_epoch_number,
        "epoch_root": input.target_epoch_root,
        "registry_root": target_registry_root,
        "registry_proof": registry_proof,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    fs::create_dir_all(&genome_dir)?;
    fs::write(
        genome_dir.join("commitment.json"),
        serde_json::to_string_pretty(&commitment)?,
    )?;

    let output = RefreshGenomicCommitmentOutput {
        actor_id: actor_id.to_string(),
        client_id: client_id.to_string(),
        artifacts_path: input.artifacts_path,
        target_epoch_number: input.target_epoch_number,
        target_epoch_root: input.target_epoch_root,
        target_registry_root: target_registry_root.to_string(),
        vcf_merkle_root,
        signature: vcf_signature,
    };
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, serde_json::to_string_pretty(&output)?)?;

    println!("✅ Genomic commitment refreshed successfully!");
    println!("   Registry root: {}", target_registry_root);
    println!("   Epoch: {}", input.target_epoch_number);
    println!("   Payload written to {}", output_path.display());

    Ok(())
}


#[cfg(test)]
mod extraction_plan_tests {
    use super::build_extraction_slices;
    use std::path::Path;

    #[test]
    fn irisplex_work_labels_are_chr_pos_ref_alt() {
        let (rows, _) =
            build_extraction_slices(Some("irisplex"), None, Path::new("/tmp")).expect("plan");
        assert_eq!(rows[0].work_label, "chr15_28120472_A_G");
        assert_eq!(rows[5].work_label, "chr6_396321_C_T");
    }

    #[test]
    fn unknown_panel_is_rejected() {
        let err = build_extraction_slices(Some("ancestry"), None, Path::new("/tmp"))
            .expect_err("ancestry removed");
        assert!(format!("{err}").contains("irisplex"));
    }
}
