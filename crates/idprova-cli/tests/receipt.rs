use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn idprova() -> Command {
    Command::cargo_bin("idprova").expect("binary built")
}

#[test]
fn receipt_verify_errors_on_missing_file() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist.jsonl");

    idprova()
        .args(["receipt", "verify"])
        .arg(&missing)
        .assert()
        .failure();
}

#[test]
fn receipt_verify_errors_on_malformed_jsonl() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("garbage.jsonl");
    fs::write(&file, "this is not json\n{also: not}\n").unwrap();

    idprova()
        .args(["receipt", "verify"])
        .arg(&file)
        .assert()
        .failure();
}

#[test]
fn receipt_verify_handles_empty_file_gracefully() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("empty.jsonl");
    fs::write(&file, "").unwrap();

    // An empty log has no entries to chain — integrity check should not panic.
    idprova()
        .args(["receipt", "verify"])
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("0").or(predicate::str::contains("Entries")));
}

#[test]
fn receipt_stats_errors_on_missing_file() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist.jsonl");

    idprova()
        .args(["receipt", "stats"])
        .arg(&missing)
        .assert()
        .failure();
}

#[test]
fn receipt_stats_reports_zero_entries_on_empty_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("empty.jsonl");
    fs::write(&file, "").unwrap();

    idprova()
        .args(["receipt", "stats"])
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Total entries: 0"));
}

#[test]
fn receipt_stats_errors_on_malformed_jsonl() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("garbage.jsonl");
    fs::write(&file, "{{not valid}}\n").unwrap();

    idprova()
        .args(["receipt", "stats"])
        .arg(&file)
        .assert()
        .failure();
}

#[test]
fn receipt_help_lists_subcommands() {
    idprova()
        .args(["receipt", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("stats"));
}
