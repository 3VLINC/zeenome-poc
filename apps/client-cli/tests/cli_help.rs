use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn client_help_lists_core_commands() {
    Command::cargo_bin("client")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("check-jobs"))
        .stdout(contains("execute-job"));
}

#[test]
fn client_execute_job_help_mentions_proof_mode() {
    Command::cargo_bin("client")
        .expect("binary exists")
        .args(["execute-job", "--help"])
        .assert()
        .success()
        .stdout(contains("--proof-mode"))
        .stdout(contains("run-only"))
        .stdout(contains("--bundle-elf-path"));
}
