use zeenome_core::variant::{
    self, canonical_variant_leaf_preimage, parse_genotype, GenomeBuild, NormalizedVariant,
    TargetVariant,
};

#[test]
fn target_variant_extraction_work_label_includes_chr_and_uppercase_alleles() {
    let t = TargetVariant::new("chr15", 28120472, "A", "g");
    assert_eq!(t.extraction_work_label(), "chr15_28120472_A_G");
    let y = TargetVariant::new("Y", 2786860, "t", "g");
    assert_eq!(y.extraction_work_label(), "chrY_2786860_T_G");
}

#[test]
fn genotype_phased_collapses_for_code_in_preimage() {
    let v = NormalizedVariant {
        genome_build: GenomeBuild::GRCh38,
        chrom: "chr1".to_string(),
        pos: 100,
        ref_allele: "A".to_string(),
        alt_allele: "G".to_string(),
        genotype: parse_genotype("1|0").unwrap(),
    };
    let p = canonical_variant_leaf_preimage(&v);
    assert!(
        p.ends_with("|0/1"),
        "preimage ends with canonical gt: {}",
        p
    );
}

#[test]
fn merkle_preimage_stable_case() {
    let v = NormalizedVariant {
        genome_build: GenomeBuild::GRCh38,
        chrom: "chr5".to_string(),
        pos: 33951588,
        ref_allele: "c".to_string(),
        alt_allele: "g".to_string(),
        genotype: parse_genotype("0/1").unwrap(),
    };
    assert_eq!(
        canonical_variant_leaf_preimage(&v),
        "ZV1|GRCh38|chr5|33951588|C|G|0/1"
    );
}

#[test]
fn multiallelic_alt_picks_panel_alt_and_maps_gt_hom_ref_het_hom_alt() {
    let panel = &[variant::TargetVariant::new("chr1", 1, "A", "G")];
    // Panel ALT is G (VCF ALT index 2 in C,G,T).
    let vcf_hom_ref = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tC,G,T\t.\t.\t.\tGT\t0/0\n";
    let vcf_het = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tC,G,T\t.\t.\t.\tGT\t0/2\n";
    let vcf_hom_alt = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tC,G,T\t.\t.\t.\tGT\t2/2\n";
    for (vcf, want) in [
        (vcf_hom_ref, parse_genotype("0/0").unwrap()),
        (vcf_het, parse_genotype("0/1").unwrap()),
        (vcf_hom_alt, parse_genotype("1/1").unwrap()),
    ] {
        let got = variant::parse_vcf_for_targets(vcf, panel, GenomeBuild::GRCh38, true).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ref_allele, "A");
        assert_eq!(got[0].alt_allele, "G");
        assert_eq!(got[0].genotype, want);
    }
}

#[test]
fn multiallelic_alt_1_2_maps_to_heterozygous_when_second_alt_is_panel() {
    // REF=A, panel ALT=T at VCF ALT index 2 (ALT=C,T).
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tC,T\t.\t.\t.\tGT\t1/2\n";
    let got = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr1", 1, "A", "T")],
        GenomeBuild::GRCh38,
        true,
    )
    .expect("parses");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].genotype, parse_genotype("0/1").unwrap());
}

#[test]
fn multiallelic_gt_with_only_other_alts_maps_to_unknown() {
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tC,G,T\t.\t.\t.\tGT\t2/3\n";
    let got = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr1", 1, "A", "G")],
        GenomeBuild::GRCh38,
        true,
    )
    .expect("parses");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].genotype, parse_genotype("./.").unwrap());
}

#[test]
fn multiallelic_duplicate_panel_alt_in_field_is_ambiguous_error() {
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\tG,G\t.\t.\t.\tGT\t0/1\n";
    let err = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr1", 1, "A", "G")],
        GenomeBuild::GRCh38,
        false,
    )
    .expect_err("ambiguous");
    assert!(
        err.contains("ambiguous") || err.contains("multiallelic"),
        "err={}",
        err
    );
}

#[test]
fn rejects_symbolic_alt_when_target_row_matches() {
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t1\t.\tA\t<DEL>\t.\t.\t.\tGT\t0/1\n";
    let err = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr1", 1, "A", "<DEL>")],
        GenomeBuild::GRCh38,
        false,
    )
    .expect_err("symbolic");
    assert!(err.contains("symbolic") || err.contains("SV"));
}

#[test]
fn ignores_symbolic_alt_lines_that_do_not_match_panel_alleles() {
    // Same coordinate as a panel site but a different ALT (e.g. bcftools `*`); must not fail parse.
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr6\t396321\t.\tC\t*\t.\t.\t.\tGT\t.\nchr6\t396321\t.\tC\tT\t.\t.\t.\tGT\t1/1\n";
    let got = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr6", 396321, "C", "T")],
        GenomeBuild::GRCh38,
        true,
    )
    .expect("parses");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ref_allele, "C");
    assert_eq!(got[0].alt_allele, "T");
}

#[test]
fn homozygous_ref_bcftools_dot_alt_matches_panel_row() {
    // bcftools call often outputs ALT `.` and GT 0/0 when the sample matches REF only.
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr6\t396321\t.\tC\t.\t.\t.\t.\tGT\t0/0\n";
    let got = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr6", 396321, "C", "T")],
        GenomeBuild::GRCh38,
        true,
    )
    .expect("parses");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ref_allele, "C");
    assert_eq!(got[0].alt_allele, "T");
    assert_eq!(got[0].genotype, parse_genotype("0/0").unwrap());
}

#[test]
fn homozygous_ref_truncated_ref_prefix_matches_multi_base_panel() {
    // Seen on PRS313 indels after per-locus mpileup: REF is first base only, ALT `.`, GT 0/0.
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\nchr1\t109655507\t.\tC\t.\t.\t.\t.\tGT\t0/0\n";
    let got = variant::parse_vcf_for_targets(
        vcf,
        &[variant::TargetVariant::new("chr1", 109655507, "CAAA", "C")],
        GenomeBuild::GRCh38,
        true,
    )
    .expect("parses");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ref_allele, "CAAA");
    assert_eq!(got[0].alt_allele, "C");
    assert_eq!(got[0].genotype, parse_genotype("0/0").unwrap());
}

#[test]
fn irisplex_panel_accepts_mixed_hom_ref_dot_and_standard_rows() {
    // Mirrors bcftools output shape seen on 1000G NA06986: some loci are REF-only rows (ALT `.`, GT 0/0).
    let vcf = r#"##fileformat=VCFv4.3
#CHROM	POS	ID	REF	ALT	QUAL	FILTER	INFO	FORMAT	SAMPLE
chr15	28120472	.	A	G	.	PASS	.	GT	0/1
chr15	27985172	.	C	.	.	PASS	.	GT	0/0
chr14	92307319	.	G	T	.	PASS	.	GT	0/1
chr5	33951588	.	C	G	.	PASS	.	GT	0/1
chr11	89277878	.	G	.	.	PASS	.	GT	0/0
chr6	396321	.	C	.	.	PASS	.	GT	0/0
"#;
    let got = variant::parse_vcf_to_irisplex_variants(vcf).expect("irisplex");
    assert_eq!(got.len(), 6);
}

#[test]
fn parse_vcf_for_sequencing_panel_rejects_unknown_panel() {
    let vcf = "##fileformat=VCFv4.3\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS\n";
    let err = variant::parse_vcf_for_sequencing_panel(vcf, "sex").expect_err("unknown panel");
    assert!(
        err.contains("unknown sequencing panel") || err.contains("irisplex"),
        "unexpected parse error: {}",
        err
    );
}

#[test]
fn duplicate_canonical_site_errors_on_sort() {
    let a = NormalizedVariant {
        genome_build: GenomeBuild::GRCh38,
        chrom: "chr1".to_string(),
        pos: 1,
        ref_allele: "A".to_string(),
        alt_allele: "G".to_string(),
        genotype: parse_genotype("0/0").unwrap(),
    };
    let b = NormalizedVariant {
        genome_build: GenomeBuild::GRCh38,
        chrom: "chr1".to_string(),
        pos: 1,
        ref_allele: "A".to_string(),
        alt_allele: "G".to_string(),
        genotype: parse_genotype("1/1").unwrap(),
    };
    let err = variant::sort_variants_for_merkle(vec![a, b]).expect_err("dup");
    assert!(err.contains("duplicate"));
}
