use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn researcher_help_lists_job_and_whitelist_commands() {
    Command::cargo_bin("researcher")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("create-job"))
        .stdout(contains("publish-whitelist"))
        .stdout(contains("verify-response"));
}

#[test]
fn researcher_create_job_help_mentions_whitelist_epoch() {
    Command::cargo_bin("researcher")
        .expect("binary exists")
        .args(["create-job", "--help"])
        .assert()
        .success()
        .stdout(contains("--whitelist-epoch-id"))
        .stdout(contains("--manifest-path"));
}
