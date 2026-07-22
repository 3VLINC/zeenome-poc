use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn accreditor_help_lists_whitelist_commands() {
    Command::cargo_bin("accreditor")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("publish-whitelist"))
        .stdout(contains("get-pubkey"));
}
