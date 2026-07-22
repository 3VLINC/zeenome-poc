//! IrisPlex panel parsing against real bcftools-shaped 1000 Genomes VCFs.

use std::path::Path;

use zeenome_core::variant::{
    assert_panel_targets_present, parse_vcf_for_sequencing_panel, GenomeBuild,
    IRISPLEX_TARGET_VARIANTS,
};

const SAMPLES: &[(&str, &str)] = &[
    ("ERR3239277", "NA06986"),
    ("ERR3239292", "NA11894"),
    ("ERR3243155", "HG01766"),
    ("ERR3239278", "NA06994"),
    ("ERR3240114", "HG00096"),
];

fn fixture_tag(run: &str, sample_id: &str) -> String {
    format!("{}_{}", run, sample_id)
}

fn load_irisplex_fixture(run: &str, sample_id: &str) -> String {
    let tag = fixture_tag(run, sample_id);
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{tag}_irisplex.vcf"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

fn assert_irisplex_ok(catalog_label: &str, vcf: &str) {
    let parsed = parse_vcf_for_sequencing_panel(vcf, "irisplex").unwrap_or_else(|e| {
        panic!("{catalog_label} irisplex parse failed: {e}");
    });
    assert_eq!(
        parsed.len(),
        IRISPLEX_TARGET_VARIANTS.len(),
        "{catalog_label} irisplex: expected {} variants, got {}",
        IRISPLEX_TARGET_VARIANTS.len(),
        parsed.len()
    );
    assert_panel_targets_present(&parsed, IRISPLEX_TARGET_VARIANTS, GenomeBuild::GRCh38)
        .unwrap_or_else(|e| panic!("{catalog_label} irisplex panel presence: {e}"));
}

#[test]
fn err3239277_na06986_irisplex_fixture_matches_panel() {
    let (run, sid) = SAMPLES[0];
    assert_irisplex_ok(&fixture_tag(run, sid), &load_irisplex_fixture(run, sid));
}

#[test]
fn err3239292_na11894_irisplex_fixture_matches_panel() {
    let (run, sid) = SAMPLES[1];
    assert_irisplex_ok(&fixture_tag(run, sid), &load_irisplex_fixture(run, sid));
}

#[test]
fn err3243155_hg01766_irisplex_fixture_matches_panel() {
    let (run, sid) = SAMPLES[2];
    assert_irisplex_ok(&fixture_tag(run, sid), &load_irisplex_fixture(run, sid));
}

#[test]
fn err3239278_na06994_irisplex_fixture_matches_panel() {
    let (run, sid) = SAMPLES[3];
    assert_irisplex_ok(&fixture_tag(run, sid), &load_irisplex_fixture(run, sid));
}

#[test]
fn err3240114_hg00096_irisplex_fixture_matches_panel() {
    let (run, sid) = SAMPLES[4];
    assert_irisplex_ok(&fixture_tag(run, sid), &load_irisplex_fixture(run, sid));
}
