//! Canonical normalized variant model for Merkle commitments and zk verification.
//!
//! Identity is `genome_build | chrom | pos | ref | alt` (no RSID in core). Merkle leaves use
//! `ZV1|...|gt_code` per project policy.
//!
//! **Reference build:** IrisPlex panel coordinates are **GRCh38**.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum REF or ALT length (bp) accepted for small-variant proof path.
pub const MAX_ALLELE_LEN: usize = 50;

/// Genome assembly label stored in variants and Merkle preimages (uppercase in preimage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GenomeBuild {
    #[serde(rename = "GRCh38")]
    GRCh38,
}

impl GenomeBuild {
    pub fn as_str(self) -> &'static str {
        match self {
            GenomeBuild::GRCh38 => "GRCh38",
        }
    }
}

/// GA4GH BED-style interval (`chrom_start`/`chrom_end` are 0-based, half-open) for custom sequencing scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BedIntervalRow {
    pub chrom: String,
    #[serde(rename = "chromStart", alias = "chrom_start")]
    pub chrom_start: u32,
    #[serde(rename = "chromEnd", alias = "chrom_end")]
    pub chrom_end: u32,
}

fn vcf_record_overlaps_bed_iv(
    chrom_raw: &str,
    pos_1based: u32,
    ref_allele: &str,
    iv: &BedIntervalRow,
) -> bool {
    if iv.chrom_end <= iv.chrom_start {
        return false;
    }
    if !chrom_matches(chrom_raw, iv.chrom.trim()) {
        return false;
    }
    let ref_len = ref_allele.len();
    let zs = (pos_1based as u64).saturating_sub(1);
    let ze = zs.saturating_add(ref_len as u64);
    let cs = iv.chrom_start as u64;
    let ce = iv.chrom_end as u64;
    zs < ce && ze > cs
}

/// Parse VCF and keep every **biallelic** body row whose reference span overlaps any BED interval.
/// Rows with multiallelic `ALT` (comma-separated) are skipped. Output is Merkle-sort-deduped like panels.
pub fn parse_vcf_over_bed_intervals(
    vcf_content: &str,
    intervals: &[BedIntervalRow],
    genome_build: GenomeBuild,
) -> Result<Vec<NormalizedVariant>, String> {
    if intervals.is_empty() {
        return Err("BED interval list must be non-empty".to_string());
    }
    let mut header_found = false;
    let mut collected: HashMap<(GenomeBuild, String, u32, String, String), NormalizedVariant> =
        HashMap::new();

    for line in vcf_content.lines() {
        if line.starts_with("##") {
            continue;
        }
        if line.starts_with("#CHROM") || line.starts_with("#Chrom") {
            header_found = true;
            continue;
        }
        if !header_found {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 10 {
            continue;
        }

        let chrom_raw = parts[0];
        let pos_str = parts[1];
        let ref_allele = parts[3];
        let alt_field = parts[4];
        let format_field = parts[8];
        let sample_field = parts[9];

        if ref_allele.is_empty() || alt_field.contains(',') {
            continue;
        }

        let pos_parsed: u32 = match pos_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let overlaps_iv = intervals
            .iter()
            .any(|iv| vcf_record_overlaps_bed_iv(chrom_raw, pos_parsed, ref_allele, iv));
        if !overlaps_iv {
            continue;
        }

        if vcf_alt_is_absent_or_placeholder(alt_field) {
            continue;
        }

        if let Err(e) = validate_alleles(ref_allele, alt_field) {
            return Err(format!("VCF line {}:{} invalid: {}", chrom_raw, pos_parsed, e));
        }

        let genotype_str = extract_genotype(format_field, sample_field);
        let genotype = parse_genotype(&genotype_str)?;
        let chrom = normalize_chrom_from_vcf(chrom_raw);

        let nv = NormalizedVariant {
            genome_build,
            chrom,
            pos: pos_parsed,
            ref_allele: ref_allele.to_string(),
            alt_allele: alt_field.trim().to_string(),
            genotype,
        };
        collected.insert(nv.canonical_identity_key(), nv);
    }

    let mut vs: Vec<NormalizedVariant> = collected.into_values().collect();
    sort_variants_for_merkle(std::mem::take(&mut vs))
}

/// Genotype for a biallelic row (canonical `gt_code` via [`Genotype::as_code`]).
///
/// Variant names are explicit Rust identifiers, **not** common VCF shorthand: use
/// [`Genotype::HomozygousRef`] (not `HomRef`), [`Genotype::Heterozygous`] (not `Het`),
/// [`Genotype::HomozygousAlt`] (not `HomAlt`), and [`Genotype::Unknown`] for missing/other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Genotype {
    HomozygousRef,
    Heterozygous,
    HomozygousAlt,
    Unknown,
}

impl Genotype {
    pub fn as_code(&self) -> &'static str {
        match self {
            Genotype::HomozygousRef => "0/0",
            Genotype::Heterozygous => "0/1",
            Genotype::HomozygousAlt => "1/1",
            Genotype::Unknown => "./.",
        }
    }
}

/// One biallelic call after normalization; canonical Merkle identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedVariant {
    pub genome_build: GenomeBuild,
    pub chrom: String,
    pub pos: u32,
    pub ref_allele: String,
    pub alt_allele: String,
    pub genotype: Genotype,
}

impl NormalizedVariant {
    /// Strict identity for panel matching (build, chrom, pos, uppercase ref/alt).
    pub fn canonical_identity_key(&self) -> (GenomeBuild, String, u32, String, String) {
        (
            self.genome_build,
            self.chrom.clone(),
            self.pos,
            self.ref_allele.to_ascii_uppercase(),
            self.alt_allele.to_ascii_uppercase(),
        )
    }
}

/// Static panel row: expected locus and alleles on a given build (no RSID in core).
#[derive(Debug, Clone, Copy)]
pub struct TargetVariant {
    pub chrom: &'static str,
    pub position: u32,
    pub ref_allele: &'static str,
    pub alt_allele: &'static str,
}

impl TargetVariant {
    pub const fn new(
        chrom: &'static str,
        position: u32,
        ref_allele: &'static str,
        alt_allele: &'static str,
    ) -> Self {
        Self {
            chrom,
            position,
            ref_allele,
            alt_allele,
        }
    }

    /// Directory and file-stem label under `data/clients/.../work/` for per-locus extraction
    /// (`chr15_28120472_A_G`, `chrY_2786860_T_G`, …). Uses GRCh38 `chrom`, 1-based `position`, and
    /// upper-case REF/ALT so callers do not maintain a parallel RSID list.
    pub fn extraction_work_label(&self) -> String {
        let chrom = if self.chrom.len() >= 3 && self.chrom[..3].eq_ignore_ascii_case("chr") {
            self.chrom.to_string()
        } else {
            format!("chr{}", self.chrom)
        };
        format!(
            "{}_{}_{}_{}",
            chrom,
            self.position,
            self.ref_allele.to_uppercase(),
            self.alt_allele.to_uppercase()
        )
    }
}

/// IrisPlex panel (GRCh38).
pub const IRISPLEX_TARGET_VARIANTS: &[TargetVariant; 6] = &[
    TargetVariant::new("chr15", 28120472, "A", "G"),
    TargetVariant::new("chr15", 27985172, "C", "T"),
    TargetVariant::new("chr14", 92307319, "G", "T"),
    TargetVariant::new("chr5", 33951588, "C", "G"),
    TargetVariant::new("chr11", 89277878, "G", "A"),
    TargetVariant::new("chr6", 396321, "C", "T"),
];

/// Merkle leaf preimage: `ZV1|GRCh38|chrom|pos|REF|ALT|gt_code` (REF/ALT uppercased).
pub fn canonical_variant_leaf_preimage(v: &NormalizedVariant) -> String {
    let gb = v.genome_build.as_str();
    let chrom = normalize_chrom_for_preimage(&v.chrom);
    let ref_u = v.ref_allele.to_ascii_uppercase();
    let alt_u = v.alt_allele.to_ascii_uppercase();
    format!(
        "ZV1|{}|{}|{}|{}|{}|{}",
        gb,
        chrom,
        v.pos,
        ref_u,
        alt_u,
        v.genotype.as_code()
    )
}

fn normalize_chrom_for_preimage(chrom: &str) -> String {
    let c = chrom.trim();
    if c.is_empty() {
        return String::new();
    }
    if c.starts_with("chr") || c.starts_with("CHR") {
        format!("chr{}", &c[3..])
    } else {
        format!("chr{}", c)
    }
}

/// Sort key for Merkle leaf order: chrom (chr1..chr22, chrX, chrY, chrM) then pos, ref, alt.
pub fn merkle_leaf_sort_key(v: &NormalizedVariant) -> (u8, u32, String, String) {
    let chrom = normalize_chrom_for_preimage(&v.chrom);
    let chr_rank = match chrom.as_str() {
        "chrX" => 23,
        "chrY" => 24,
        "chrM" | "chrMT" => 25,
        _ => {
            if let Some(n) = chrom.strip_prefix("chr").and_then(|s| s.parse::<u8>().ok()) {
                n
            } else {
                99
            }
        }
    };
    (
        chr_rank,
        v.pos,
        v.ref_allele.to_ascii_uppercase(),
        v.alt_allele.to_ascii_uppercase(),
    )
}

/// Sort variants for Merkle construction (deterministic; fail on duplicates).
pub fn sort_variants_for_merkle(
    mut vs: Vec<NormalizedVariant>,
) -> Result<Vec<NormalizedVariant>, String> {
    vs.sort_by(|a, b| {
        let ka = merkle_leaf_sort_key(a);
        let kb = merkle_leaf_sort_key(b);
        ka.cmp(&kb)
    });
    for w in vs.windows(2) {
        if w[0].canonical_identity_key() == w[1].canonical_identity_key() {
            return Err(format!(
                "duplicate canonical variant after sort: {}:{} {}>{}",
                w[0].chrom, w[0].pos, w[0].ref_allele, w[0].alt_allele
            ));
        }
    }
    Ok(vs)
}

pub fn parse_genotype(gt: &str) -> Result<Genotype, String> {
    match gt {
        "0/0" | "0|0" => Ok(Genotype::HomozygousRef),
        "0/1" | "0|1" | "1/0" | "1|0" => Ok(Genotype::Heterozygous),
        "1/1" | "1|1" => Ok(Genotype::HomozygousAlt),
        "./." | "." => Ok(Genotype::Unknown),
        _ => Err(format!("Unknown genotype: {}", gt)),
    }
}

fn chrom_matches(query: &str, target: &str) -> bool {
    if query.eq_ignore_ascii_case(target) {
        return true;
    }
    if let Some(stripped) = target.strip_prefix("chr") {
        if query.eq_ignore_ascii_case(stripped) {
            return true;
        }
    }
    if let Some(stripped) = query.strip_prefix("chr") {
        if stripped.eq_ignore_ascii_case(target) {
            return true;
        }
        if let Some(target_stripped) = target.strip_prefix("chr") {
            return stripped.eq_ignore_ascii_case(target_stripped);
        }
    }
    false
}

fn extract_genotype(format: &str, sample_field: &str) -> String {
    if format == "GT" {
        sample_field.to_string()
    } else if let Some(gt_index) = format.split(':').position(|chunk| chunk == "GT") {
        sample_field
            .split(':')
            .nth(gt_index)
            .unwrap_or("./.")
            .to_string()
    } else {
        "./.".to_string()
    }
}

fn validate_ref_and_single_alt(ref_allele: &str, alt_allele: &str) -> Result<(), String> {
    if ref_allele.is_empty() || alt_allele.is_empty() {
        return Err("REF and ALT must be non-empty".to_string());
    }
    if ref_allele == alt_allele {
        return Err("REF and ALT must differ".to_string());
    }
    if alt_allele.contains(',') {
        return Err("multiallelic ALT passed to single-allele validator".to_string());
    }
    if ref_allele.starts_with('<') || alt_allele.starts_with('<') {
        return Err("symbolic ALT / SV not supported".to_string());
    }
    if ref_allele.len() > MAX_ALLELE_LEN || alt_allele.len() > MAX_ALLELE_LEN {
        return Err(format!("REF/ALT length exceeds max {} bp", MAX_ALLELE_LEN));
    }
    let dna = |s: &str| {
        s.chars()
            .all(|c| matches!(c.to_ascii_uppercase(), 'A' | 'C' | 'G' | 'T' | 'N'))
    };
    if !dna(ref_allele) || !dna(alt_allele) {
        return Err("REF/ALT must be ACGTN only".to_string());
    }
    Ok(())
}

fn validate_alleles(ref_allele: &str, alt_allele: &str) -> Result<(), String> {
    validate_ref_and_single_alt(ref_allele, alt_allele)
}

/// Split VCF ALT on commas; empty fields are skipped.
fn split_vcf_alt_alleles(alt_field: &str) -> Vec<&str> {
    alt_field
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 1-based VCF ALT index where the allele equals `panel_alt` (case-insensitive).
/// `Ok(None)` if no alternate matches; `Err` if more than one match (ambiguous).
fn panel_alt_vcf_index_1based(alt_field: &str, panel_alt: &str) -> Result<Option<u32>, String> {
    let alts = split_vcf_alt_alleles(alt_field);
    let mut hits: Vec<u32> = Vec::new();
    for (i, a) in alts.iter().enumerate() {
        if a.eq_ignore_ascii_case(panel_alt) {
            hits.push((i + 1) as u32);
        }
    }
    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits[0])),
        _ => Err("panel ALT matches multiple ALT fields (ambiguous)".to_string()),
    }
}

/// Map a diploid `GT` to [`Genotype`] vs panel REF (0) and panel ALT (`panel_alt_1based`, VCF 1-based ALT index).
/// Allele indices other than 0 or the panel ALT yield [`Genotype::Unknown`].
fn map_diploid_gt_to_panel_genotype(gt: &str, panel_alt_1based: u32) -> Result<Genotype, String> {
    let gt = gt.trim();
    if matches!(gt, "./." | ".") {
        return Ok(Genotype::Unknown);
    }
    let sep = if gt.contains('|') { '|' } else { '/' };
    let parts: Vec<&str> = gt.split(sep).map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Err(format!("expected diploid GT, got {:?}", gt));
    }
    let mut idx = [0u32; 2];
    for (i, p) in parts.iter().enumerate() {
        if *p == "." {
            return Ok(Genotype::Unknown);
        }
        idx[i] = p
            .parse::<u32>()
            .map_err(|_| format!("invalid GT allele in {:?}", gt))?;
    }
    let k = panel_alt_1based;
    let a = idx[0];
    let b = idx[1];

    if a == 0 && b == 0 {
        return Ok(Genotype::HomozygousRef);
    }
    if a == k && b == k {
        return Ok(Genotype::HomozygousAlt);
    }
    if (a == 0 && b == k) || (a == k && b == 0) {
        return Ok(Genotype::Heterozygous);
    }
    // One allele is panel ALT; the other is a different alternate (no REF in genotype).
    if (a == k && b != 0 && b != k) || (b == k && a != 0 && a != k) {
        let other = if a == k { b } else { a };
        if other < k {
            // e.g. `1/2` when panel ALT is second ALT: two concrete alts, one is the panel effect allele.
            return Ok(Genotype::Heterozygous);
        }
        // e.g. `2/3` when panel ALT is index 2: third ALT confounds strict ref/alt encoding.
        return Ok(Genotype::Unknown);
    }
    Ok(Genotype::Unknown)
}

/// Validate REF and every comma-separated ALT (ACGTN, length, no symbolic).
fn validate_ref_and_multiallelic_alts(ref_allele: &str, alt_field: &str) -> Result<(), String> {
    if ref_allele.is_empty() {
        return Err("REF must be non-empty".to_string());
    }
    if ref_allele.starts_with('<') {
        return Err("symbolic REF not supported".to_string());
    }
    if ref_allele.len() > MAX_ALLELE_LEN {
        return Err(format!("REF length exceeds max {} bp", MAX_ALLELE_LEN));
    }
    let dna = |s: &str| {
        s.chars()
            .all(|c| matches!(c.to_ascii_uppercase(), 'A' | 'C' | 'G' | 'T' | 'N'))
    };
    if !dna(ref_allele) {
        return Err("REF must be ACGTN only".to_string());
    }
    let alts = split_vcf_alt_alleles(alt_field);
    if alts.is_empty() {
        return Err("ALT must list at least one alternate".to_string());
    }
    for a in &alts {
        if a.starts_with('<') {
            return Err("symbolic ALT / SV not supported".to_string());
        }
        if *a == ref_allele {
            return Err("ALT allele equals REF".to_string());
        }
        if a.len() > MAX_ALLELE_LEN {
            return Err(format!("ALT length exceeds max {} bp", MAX_ALLELE_LEN));
        }
        if !dna(a) {
            return Err("ALT must be ACGTN only".to_string());
        }
    }
    Ok(())
}

fn normalize_chrom_from_vcf(chrom: &str) -> String {
    let c = chrom.trim();
    if c.is_empty() {
        return String::new();
    }
    if c.len() >= 3 && c[..3].eq_ignore_ascii_case("chr") {
        format!("chr{}", &c[3..])
    } else {
        format!("chr{}", c)
    }
}

/// True when the VCF has no concrete ALT at this row (bcftools `call` omits ALT for hom-ref sites).
fn vcf_alt_is_absent_or_placeholder(alt: &str) -> bool {
    let a = alt.trim();
    a.is_empty() || a == "." || a == "*" || a.starts_with('<')
}

/// Parse VCF and return panel variants in **panel definition order** (not Merkle-sorted).
///
/// **Matching:** same `CHROM`, `POS`, and `REF` equal to panel REF (case-insensitive). VCF `ID` is ignored.
/// **Biallelic row:** `ALT` equals panel ALT (single alternate). **Multiallelic row:** comma-separated `ALT`
/// contains panel ALT exactly once; diploid `GT` is interpreted vs panel REF (0) and that alternate index;
/// genotypes involving other alternate indices map to [`Genotype::Unknown`].
///
/// VCF `REF` must match the reference genome at `POS`; panel REF/ALT are GRCh38-canonical (see
/// `scripts/verify_panel_targets.py`). We do not accept same-POS REF/ALT column reversal against the panel.
///
/// Homozygous reference sites from bcftools often use `ALT=.`, `ALT=*`, or empty ALT with `GT` ref/ref;
/// when `REF` matches the panel and `GT` is hom-ref, the row is accepted as [`Genotype::HomozygousRef`]
/// for that panel locus (canonical panel `REF`/`ALT` stored for Merkle preimages).
pub fn parse_vcf_for_targets(
    vcf_content: &str,
    targets: &[TargetVariant],
    genome_build: GenomeBuild,
    require_all: bool,
) -> Result<Vec<NormalizedVariant>, String> {
    let mut header_found = false;
    let mut collected: HashMap<usize, NormalizedVariant> = HashMap::with_capacity(targets.len());

    for line in vcf_content.lines() {
        if line.starts_with("##") {
            continue;
        }
        if line.starts_with("#CHROM") || line.starts_with("#Chrom") {
            header_found = true;
            continue;
        }
        if !header_found {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 10 {
            continue;
        }

        let chrom_raw = parts[0];
        let pos_str = parts[1];
        let ref_allele = parts[3];
        let alt_allele = parts[4];
        let format_field = parts[8];
        let sample_field = parts[9];

        let pos_parsed = match pos_str.parse::<u32>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        for (idx, target) in targets.iter().enumerate() {
            if collected.contains_key(&idx) {
                continue;
            }

            let coord_match =
                chrom_matches(chrom_raw, target.chrom) && pos_parsed == target.position;
            if !coord_match {
                continue;
            }

            let ref_m = ref_allele.eq_ignore_ascii_case(target.ref_allele);
            let alt_m = alt_allele.eq_ignore_ascii_case(target.alt_allele);

            let genotype_str = extract_genotype(format_field, sample_field);
            let chrom = normalize_chrom_from_vcf(chrom_raw);

            if ref_m && alt_m {
                let genotype = parse_genotype(&genotype_str)?;
                if let Err(e) = validate_alleles(ref_allele, alt_allele) {
                    return Err(format!(
                        "VCF line {}:{} invalid: {}",
                        chrom_raw, pos_parsed, e
                    ));
                }

                collected.insert(
                    idx,
                    NormalizedVariant {
                        genome_build,
                        chrom,
                        pos: pos_parsed,
                        ref_allele: ref_allele.to_string(),
                        alt_allele: alt_allele.to_string(),
                        genotype,
                    },
                );
                break;
            }

            // Multiallelic ALT: pick the alternate that equals panel ALT (unique).
            if ref_m && alt_allele.contains(',') {
                match panel_alt_vcf_index_1based(alt_allele, target.alt_allele) {
                    Ok(Some(panel_alt_vcf_1based)) => {
                        if let Err(e) = validate_ref_and_multiallelic_alts(ref_allele, alt_allele) {
                            return Err(format!(
                                "VCF line {}:{} invalid: {}",
                                chrom_raw, pos_parsed, e
                            ));
                        }
                        let genotype = map_diploid_gt_to_panel_genotype(
                            &genotype_str,
                            panel_alt_vcf_1based,
                        )
                        .map_err(|e| {
                            format!(
                                "VCF line {}:{} invalid GT {:?}: {}",
                                chrom_raw, pos_parsed, genotype_str, e
                            )
                        })?;
                        collected.insert(
                            idx,
                            NormalizedVariant {
                                genome_build,
                                chrom,
                                pos: pos_parsed,
                                ref_allele: target.ref_allele.to_string(),
                                alt_allele: target.alt_allele.to_string(),
                                genotype,
                            },
                        );
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(format!(
                            "VCF line {}:{} multiallelic ALT: {}",
                            chrom_raw, pos_parsed, e
                        ));
                    }
                }
            }

            // bcftools often emits REF + ALT `.` with GT 0/0 for homozygous reference at a panel SNP.
            // Treat as a match to the panel row with canonical REF/ALT and HomozygousRef.
            let genotype = parse_genotype(&genotype_str)?;
            if ref_m
                && !alt_m
                && vcf_alt_is_absent_or_placeholder(alt_allele)
                && genotype == Genotype::HomozygousRef
            {
                collected.insert(
                    idx,
                    NormalizedVariant {
                        genome_build,
                        chrom,
                        pos: pos_parsed,
                        ref_allele: target.ref_allele.to_string(),
                        alt_allele: target.alt_allele.to_string(),
                        genotype: Genotype::HomozygousRef,
                    },
                );
                break;
            }

            // Multi-base panel REF (e.g. indel `CAAA`) sometimes appears in VCF as only the
            // first base with `ALT=.` and `GT 0/0` after per-locus extraction + `bcftools call -m`.
            if !ref_m
                && !alt_m
                && vcf_alt_is_absent_or_placeholder(alt_allele)
                && genotype == Genotype::HomozygousRef
                && !ref_allele.is_empty()
                && ref_allele.len() < target.ref_allele.len()
                && target
                    .ref_allele
                    .as_bytes()
                    .get(..ref_allele.len())
                    .is_some_and(|pfx| pfx.eq_ignore_ascii_case(ref_allele.as_bytes()))
            {
                collected.insert(
                    idx,
                    NormalizedVariant {
                        genome_build,
                        chrom,
                        pos: pos_parsed,
                        ref_allele: target.ref_allele.to_string(),
                        alt_allele: target.alt_allele.to_string(),
                        genotype: Genotype::HomozygousRef,
                    },
                );
                break;
            }
        }
    }

    let mut missing = Vec::new();
    let mut output = Vec::with_capacity(targets.len());

    for idx in 0..targets.len() {
        if let Some(v) = collected.remove(&idx) {
            output.push(v);
        } else if require_all {
            let t = &targets[idx];
            missing.push(format!(
                "{}:{} {}>{}",
                t.chrom, t.position, t.ref_allele, t.alt_allele
            ));
        }
    }

    if require_all && !missing.is_empty() {
        return Err(format!(
            "Missing target variants (chrom:pos ref>alt): {}",
            missing.join(", ")
        ));
    }

    Ok(output)
}

pub fn parse_vcf_to_irisplex_variants(vcf_content: &str) -> Result<Vec<NormalizedVariant>, String> {
    parse_vcf_for_targets(
        vcf_content,
        IRISPLEX_TARGET_VARIANTS,
        GenomeBuild::GRCh38,
        true,
    )
}

/// Parse VCF for a sequencing panel and order variants for Merkle construction.
/// This POC supports only `irisplex`.
pub fn parse_vcf_for_sequencing_panel(
    vcf_content: &str,
    panel: &str,
) -> Result<Vec<NormalizedVariant>, String> {
    let p = panel.trim().to_lowercase();
    let mut vs = match p.as_str() {
        "irisplex" => parse_vcf_to_irisplex_variants(vcf_content)?,
        other => {
            return Err(format!(
                "unknown sequencing panel {:?} (expected irisplex)",
                other
            ));
        }
    };
    sort_variants_for_merkle(std::mem::take(&mut vs))
}

/// Each panel row must appear in `observed` with matching locus and REF/ALT (order-independent).
pub fn assert_panel_targets_present(
    observed: &[NormalizedVariant],
    panel: &[TargetVariant],
    genome: GenomeBuild,
) -> Result<(), String> {
    for t in panel {
        let tc = normalize_chrom_for_preimage(t.chrom);
        let found = observed.iter().any(|o| {
            o.genome_build == genome
                && normalize_chrom_for_preimage(&o.chrom) == tc
                && o.pos == t.position
                && o.ref_allele.eq_ignore_ascii_case(t.ref_allele)
                && o.alt_allele.eq_ignore_ascii_case(t.alt_allele)
        });
        if !found {
            return Err(format!(
                "missing panel variant {}:{} {}>{}",
                tc, t.position, t.ref_allele, t.alt_allele
            ));
        }
    }
    Ok(())
}
