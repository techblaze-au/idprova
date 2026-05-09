use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn idprova() -> Command {
    Command::cargo_bin("idprova").expect("binary built")
}

fn keygen(dir: &TempDir, name: &str) -> PathBuf {
    let key = dir.path().join(format!("{name}.key"));
    idprova()
        .args(["keygen", "--output"])
        .arg(&key)
        .assert()
        .success();
    key
}

fn issue_dat(key: &PathBuf, scope: &str, expires_in: &str) -> String {
    let out = idprova()
        .args([
            "dat",
            "issue",
            "--issuer",
            "did:aid:example.com:issuer",
            "--subject",
            "did:aid:example.com:agent",
            "--scope",
            scope,
            "--expires-in",
            expires_in,
            "--key",
        ])
        .arg(key)
        .output()
        .expect("dat issue ran");
    assert!(out.status.success(), "dat issue failed: {:?}", out);
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn dat_issue_emits_three_segment_jws() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");
    let token = issue_dat(&key, "mcp:tool:filesystem:read", "1h");

    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(
        segments.len(),
        3,
        "JWS must be header.payload.signature, got {} segments",
        segments.len()
    );
    for (i, s) in segments.iter().enumerate() {
        assert!(!s.is_empty(), "segment {i} is empty in token: {token}");
    }
}

#[test]
fn dat_inspect_renders_decoded_claims() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");
    let token = issue_dat(&key, "mcp:tool:filesystem:read", "1h");

    idprova()
        .args(["dat", "inspect", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("Algorithm: EdDSA"))
        .stdout(predicate::str::contains("idprova-dat+jwt"))
        .stdout(predicate::str::contains("did:aid:example.com:issuer"))
        .stdout(predicate::str::contains("mcp:tool:filesystem:read"));
}

#[test]
fn dat_verify_offline_with_correct_key_and_scope_passes() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");
    let pub_key = key.with_extension("pub");
    let token = issue_dat(&key, "mcp:tool:filesystem:read", "1h");

    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(&pub_key)
        .args(["--scope", "mcp:tool:filesystem:read"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn dat_verify_with_wrong_public_key_fails() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");
    let attacker = keygen(&dir, "attacker");
    let token = issue_dat(&issuer, "mcp:tool:filesystem:read", "1h");

    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(attacker.with_extension("pub"))
        .args(["--scope", "mcp:tool:filesystem:read"])
        .assert()
        .failure();
}

#[test]
fn dat_verify_with_unrequested_scope_fails() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");
    let token = issue_dat(&key, "mcp:tool:filesystem:read", "1h");

    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(key.with_extension("pub"))
        .args(["--scope", "mcp:tool:network:write"])
        .assert()
        .failure();
}

/// Regression for finding #1 in dry-run-baseline.md: the issuer accepts a
/// 3-part scope (e.g. "mcp:tool:read") and produces a signed token, but the
/// verifier rejects that token because it requires 4 parts. The two sides
/// disagree on what "scope" means. This test pins the current broken
/// behavior so it can be turned into a green test (issuer rejects malformed
/// scope at issue time) once fixed.
#[test]
#[ignore = "regression: issuer/verifier scope-shape mismatch — pre-existing bug"]
fn dat_issue_rejects_malformed_three_part_scope() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");

    idprova()
        .args([
            "dat",
            "issue",
            "--issuer",
            "did:aid:example.com:issuer",
            "--subject",
            "did:aid:example.com:agent",
            "--scope",
            "mcp:tool:read",
            "--expires-in",
            "1h",
            "--key",
        ])
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("scope must have 4 parts"));
}

/// Pinned-down current behavior counterpart to the ignored test above:
/// today the issuer happily emits a token with a malformed scope, and only
/// the verifier rejects it later. Documents the bug.
#[test]
fn dat_issue_currently_accepts_three_part_scope_but_verifier_rejects_it() {
    let dir = TempDir::new().unwrap();
    let key = keygen(&dir, "issuer");

    let issue_out = idprova()
        .args([
            "dat",
            "issue",
            "--issuer",
            "did:aid:example.com:issuer",
            "--subject",
            "did:aid:example.com:agent",
            "--scope",
            "mcp:tool:read",
            "--expires-in",
            "1h",
            "--key",
        ])
        .arg(&key)
        .output()
        .expect("dat issue ran");
    assert!(
        issue_out.status.success(),
        "today: issuer accepts 3-part scope (regression marker — change when bug fixed)"
    );
    let token = String::from_utf8(issue_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(token.split('.').count(), 3);

    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(key.with_extension("pub"))
        .args(["--scope", "mcp:tool:read"])
        .assert()
        .failure()
        // The detailed reason lands on stdout (printed line by line),
        // and a top-level "Error: DAT verification failed" lands on stderr.
        .stdout(predicate::str::contains("scope must have 4 parts"));
}
