//! Compatibility re-exports for IrisPlex SNP / variant types.
//!
//! Prefer `zeenome_core::variant` for new code. Panel coordinates are **GRCh38**.

pub use crate::variant::{
    assert_panel_targets_present, canonical_variant_leaf_preimage, merkle_leaf_sort_key,
    parse_genotype, parse_vcf_for_sequencing_panel, parse_vcf_for_targets,
    parse_vcf_to_irisplex_variants, sort_variants_for_merkle, Genotype, GenomeBuild,
    NormalizedVariant, TargetVariant, IRISPLEX_TARGET_VARIANTS, MAX_ALLELE_LEN,
};

/// Deprecated alias; use [`NormalizedVariant`].
pub type SnpData = NormalizedVariant;

/// Deprecated; use [`TargetVariant`].
pub type TargetSnp = TargetVariant;

pub const IRISPLEX_TARGET_SNPS: &[TargetVariant; 6] = IRISPLEX_TARGET_VARIANTS;

pub fn parse_vcf_to_irisplex_snps(vcf_content: &str) -> Result<Vec<NormalizedVariant>, String> {
    parse_vcf_to_irisplex_variants(vcf_content)
}

pub fn parse_vcf_to_snp_data(vcf_content: &str) -> Result<Vec<NormalizedVariant>, String> {
    parse_vcf_to_irisplex_snps(vcf_content)
}

pub fn merkle_leaf_preimage(v: &NormalizedVariant) -> String {
    canonical_variant_leaf_preimage(v)
}
