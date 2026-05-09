use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn idprova() -> Command {
    Command::cargo_bin("idprova").expect("binary built")
}

#[test]
fn keygen_writes_private_and_public_key_files() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("agent.key");

    idprova()
        .args(["keygen", "--output"])
        .arg(&key_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated Ed25519 keypair"))
        .stdout(predicate::str::contains("Public key (multibase): z"));

    assert!(key_path.exists(), "private key file missing");
    assert!(
        key_path.with_extension("pub").exists(),
        "public key file missing — expected {}.pub",
        key_path.display()
    );
}

#[test]
fn keygen_private_key_is_64_hex_chars() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("agent.key");

    idprova()
        .args(["keygen", "--output"])
        .arg(&key_path)
        .assert()
        .success();

    let contents = fs::read_to_string(&key_path).unwrap();
    let trimmed = contents.trim();
    assert_eq!(
        trimmed.len(),
        64,
        "expected 64 hex chars (32 bytes), got {} chars: {:?}",
        trimmed.len(),
        trimmed
    );
    assert!(
        trimmed.chars().all(|c| c.is_ascii_hexdigit()),
        "private key file must be hex-only"
    );
}

#[test]
fn keygen_two_runs_produce_different_keys() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.key");
    let b = dir.path().join("b.key");

    idprova()
        .args(["keygen", "--output"])
        .arg(&a)
        .assert()
        .success();
    idprova()
        .args(["keygen", "--output"])
        .arg(&b)
        .assert()
        .success();

    let key_a = fs::read_to_string(&a).unwrap();
    let key_b = fs::read_to_string(&b).unwrap();
    assert_ne!(
        key_a.trim(),
        key_b.trim(),
        "two keygen runs produced the same private key — RNG broken"
    );
}

#[test]
fn keygen_help_lists_output_flag() {
    idprova()
        .args(["keygen", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--output"));
}
