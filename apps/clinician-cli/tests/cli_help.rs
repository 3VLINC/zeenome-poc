use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn clinician_help_lists_stable_commands() {
    Command::cargo_bin("clinician")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("process-genome-sample"))
        .stdout(contains("process-phenopacket"))
        .stdout(contains("refresh-genomic-commitment"));
}

#[test]
fn clinician_process_genome_sample_help_mentions_catalog_id() {
    Command::cargo_bin("clinician")
        .expect("binary exists")
        .args(["process-genome-sample", "--help"])
        .assert()
        .success()
        .stdout(contains("--actor-id"))
        .stdout(contains("--catalog-sample-id"))
        .stdout(contains("--sequencing-panel"))
        .stdout(contains("--vcf-path"));
}
