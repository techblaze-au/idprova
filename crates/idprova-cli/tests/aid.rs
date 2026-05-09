use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn idprova() -> Command {
    Command::cargo_bin("idprova").expect("binary built")
}

fn keygen(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let key = dir.path().join(format!("{name}.key"));
    idprova()
        .args(["keygen", "--output"])
        .arg(&key)
        .assert()
        .success();
    key
}

#[test]
fn aid_create_succeeds_with_minimal_args() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:agent-min",
            "--name",
            "Minimal Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success()
        .stdout(predicate::str::contains("did:aid:example.com:agent-min"));

    let json_path = dir.path().join("did_aid_example.com_agent-min.json");
    assert!(
        json_path.exists(),
        "AID JSON not written to expected slugified path: {}",
        json_path.display()
    );
}

#[test]
fn aid_create_includes_optional_metadata_when_provided() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:agent-meta",
            "--name",
            "Meta Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--model",
            "claude-opus-4-7",
            "--runtime",
            "claude-code",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();

    let json_path = dir.path().join("did_aid_example.com_agent-meta.json");
    let body = fs::read_to_string(&json_path).unwrap();
    assert!(body.contains("claude-opus-4-7"), "model not embedded");
    assert!(body.contains("claude-code"), "runtime not embedded");
    assert!(
        body.contains("IdprovaAgentMetadata"),
        "expected IdprovaAgentMetadata service entry"
    );
}

#[test]
fn aid_create_fails_when_required_arg_missing() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .args([
            "aid",
            "create",
            "--name",
            "No-ID Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--id"));
}

#[test]
fn aid_verify_accepts_valid_document() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:agent-verify",
            "--name",
            "Verify Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();

    let json_path = dir.path().join("did_aid_example.com_agent-verify.json");

    idprova()
        .args(["aid", "verify"])
        .arg(&json_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn aid_verify_reports_failure_on_structurally_invalid_document() {
    // The AID document is not self-signed (its public key is part of the
    // doc, so a name change is not a meaningful tamper). What `aid verify`
    // *does* check is structure: valid DID id, valid controller, at least
    // one verification method, authentication refs that resolve. Break the
    // controller prefix so validate() fails.
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:agent-tamper",
            "--name",
            "Tamper Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();

    let json_path = dir.path().join("did_aid_example.com_agent-tamper.json");
    let original = fs::read_to_string(&json_path).unwrap();
    // Replace the controller's "did:" prefix to break validation
    let tampered = original.replace(
        "\"controller\": \"did:aid:example.com:controller\"",
        "\"controller\": \"http:aid:example.com:controller\"",
    );
    assert_ne!(original, tampered, "tamper did not modify controller");
    fs::write(&json_path, tampered).unwrap();

    idprova()
        .args(["aid", "verify"])
        .arg(&json_path)
        .assert()
        // Today the CLI prints "validation failed" but still exits 0
        // (see the regression test below). Assert on stdout, not exit code.
        .stdout(predicate::str::contains("validation failed"));
}

/// Regression for finding #3 (discovered during Phase 2 test write-up):
/// `aid verify` always returns Ok(()) from main, even when the document
/// fails validation. The CLI prints "AID document validation failed: ..."
/// to stdout but exits 0, so any caller relying on $? will think the
/// document is fine. See `commands/aid.rs::verify` — the inner Err is
/// matched and printed, never propagated.
#[test]
#[ignore = "regression: aid verify exits 0 even on validation failure — pre-existing bug"]
fn aid_verify_should_exit_nonzero_on_validation_failure() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:agent-exit-test",
            "--name",
            "Exit Test",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();

    let json_path = dir.path().join("did_aid_example.com_agent-exit-test.json");
    let original = fs::read_to_string(&json_path).unwrap();
    let tampered = original.replace("\"did:aid:example.com:controller\"", "\"not-a-did\"");
    fs::write(&json_path, tampered).unwrap();

    // Once fixed: should exit non-zero on validation failure.
    idprova()
        .args(["aid", "verify"])
        .arg(&json_path)
        .assert()
        .failure();
}

/// Regression for finding #2 in dry-run-baseline.md: `aid create` writes the
/// JSON to the *current working directory* under a slugified filename, with no
/// way to control the destination. This test pins that behavior so a future
/// fix (e.g. adding `--output`) is an explicit choice, not an accident.
#[test]
fn aid_create_writes_to_cwd_with_slugified_filename() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "agent");

    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            "did:aid:example.com:cwd-test",
            "--name",
            "CWD Test",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();

    let expected = dir.path().join("did_aid_example.com_cwd-test.json");
    assert!(
        expected.exists(),
        "regression: AID create no longer writes <slug>.json to CWD"
    );
}
