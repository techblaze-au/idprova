//! End-to-end scenario: delegation lifecycle.
//!
//! Issuer keys -> agent keys -> AID for issuer -> issue DAT -> verify -> expire ->
//! re-issue. Pure CLI flow, no registry involvement (offline verification path).

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

fn issue(issuer_key: &PathBuf, scope: &str, expires_in: &str) -> String {
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
        .arg(issuer_key)
        .output()
        .expect("dat issue ran");
    assert!(out.status.success(), "issue failed: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn issue_then_verify_offline_passes() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");
    let token = issue(&issuer, "mcp:tool:filesystem:read", "1h");

    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(issuer.with_extension("pub"))
        .args(["--scope", "mcp:tool:filesystem:read"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn re_issue_produces_a_new_jti() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");

    let token_a = issue(&issuer, "mcp:tool:filesystem:read", "1h");
    let token_b = issue(&issuer, "mcp:tool:filesystem:read", "1h");

    let inspect_a = idprova()
        .args(["dat", "inspect", &token_a])
        .output()
        .unwrap();
    let inspect_b = idprova()
        .args(["dat", "inspect", &token_b])
        .output()
        .unwrap();

    let stdout_a = String::from_utf8_lossy(&inspect_a.stdout);
    let stdout_b = String::from_utf8_lossy(&inspect_b.stdout);

    let jti_a = extract_jti(&stdout_a);
    let jti_b = extract_jti(&stdout_b);
    assert!(!jti_a.is_empty(), "no jti in inspect A");
    assert!(!jti_b.is_empty(), "no jti in inspect B");
    assert_ne!(jti_a, jti_b, "two issued DATs must have different JTIs");
}

fn extract_jti(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Some(rest) = line.split_once("JTI:") {
            return rest.1.trim().to_string();
        }
    }
    String::new()
}

/// The CLI's `--expires-in` flag only accepts hour/day/minute units, with a
/// minimum of "1m". That makes it hard to write a fast "wait for expiry"
/// test from the CLI alone, so this test pins the contract: 1m is the
/// minimum, and a 1m DAT inspects with a non-expired status when fresh.
/// A future enhancement should add seconds support so expiry can be
/// regression-tested without sleeping a full minute.
#[test]
fn one_minute_dat_inspects_as_active_when_fresh() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");
    let token = issue(&issuer, "mcp:tool:filesystem:read", "1m");

    let out = idprova().args(["dat", "inspect", &token]).output().unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("ACTIVE"),
        "fresh 1m DAT should inspect as ACTIVE; got: {body}"
    );
}

/// Pins the CLI duration grammar so we notice if it changes.
#[test]
fn dat_issue_rejects_sub_minute_durations() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");

    idprova()
        .args([
            "dat",
            "issue",
            "--issuer",
            "did:aid:example.com:issuer",
            "--subject",
            "did:aid:example.com:agent",
            "--scope",
            "mcp:tool:filesystem:read",
            "--expires-in",
            "1s",
            "--key",
        ])
        .arg(&issuer)
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid duration"));
}

#[test]
fn dat_signed_by_one_issuer_does_not_verify_against_another() {
    let dir = TempDir::new().unwrap();
    let issuer = keygen(&dir, "issuer");
    let attacker = keygen(&dir, "attacker");

    let token = issue(&issuer, "mcp:tool:filesystem:read", "1h");

    // Verifier given the attacker's public key — must reject.
    idprova()
        .args(["dat", "verify", &token, "--key"])
        .arg(attacker.with_extension("pub"))
        .args(["--scope", "mcp:tool:filesystem:read"])
        .assert()
        .failure();
}
