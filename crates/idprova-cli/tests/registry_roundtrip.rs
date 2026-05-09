//! End-to-end scenario: keygen -> aid create -> publish to registry -> resolve.
//!
//! Spins up the idprova-registry as an in-process axum server bound to a
//! random localhost port, then drives the actual `idprova` CLI binary
//! against it. This exercises the *real* HTTP wire path — no mocks.

use assert_cmd::Command as AssertCmd;
use idprova_registry::{build_app, store::AidStore, AppState};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn idprova() -> AssertCmd {
    AssertCmd::cargo_bin("idprova").expect("binary built")
}

/// Spawn the registry on a random port. Returns `(base_url, shutdown_handle)`.
async fn spawn_registry() -> String {
    let store = AidStore::new_in_memory().expect("in-memory store");
    let state = AppState::new(store, None); // open / dev mode
    let app = build_app(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .ok();
    });

    // Brief settle so the listener is accept()ing before the CLI fires off requests.
    tokio::time::sleep(Duration::from_millis(50)).await;

    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_roundtrip_keygen_aid_create_publish_resolve() {
    let base_url = spawn_registry().await;

    // Sanity: hit /health from this test, just to confirm the server is up.
    let health = reqwest::get(format!("{base_url}/health"))
        .await
        .expect("/health reachable");
    assert!(health.status().is_success(), "registry /health not OK");

    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("agent.key");

    // 1. keygen
    idprova()
        .args(["keygen", "--output"])
        .arg(&key_path)
        .assert()
        .success();

    // 2. aid create — note `aid create` writes the JSON to CWD with a slugified name.
    let aid_id = "did:aid:example.com:roundtrip-agent";
    idprova()
        .current_dir(dir.path())
        .args([
            "aid",
            "create",
            "--id",
            aid_id,
            "--name",
            "Roundtrip Agent",
            "--controller",
            "did:aid:example.com:controller",
            "--key",
        ])
        .arg(&key_path)
        .assert()
        .success();

    let aid_json_path = dir.path().join("did_aid_example.com_roundtrip-agent.json");
    let aid_body = std::fs::read_to_string(&aid_json_path).expect("aid json");

    // 3. PUT the AID document into the registry (CLI has no publish command yet).
    let aid_id_path = aid_id.strip_prefix("did:aid:").unwrap();
    let put_url = format!("{base_url}/v1/aid/{aid_id_path}");
    let resp = reqwest::Client::new()
        .put(&put_url)
        .header("Content-Type", "application/json")
        .body(aid_body.clone())
        .send()
        .await
        .expect("PUT /v1/aid/:id");
    assert!(
        resp.status().is_success(),
        "register failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // 4. CLI resolve against the running registry.
    let mut cli = Command::new(env!("CARGO_BIN_EXE_idprova"));
    let out = cli
        .args(["aid", "resolve", aid_id, "--registry", &base_url])
        .output()
        .expect("aid resolve ran");
    assert!(
        out.status.success(),
        "resolve failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let resolved = String::from_utf8_lossy(&out.stdout);
    assert!(
        resolved.contains(aid_id),
        "resolved doc missing AID id; got: {resolved}"
    );
    assert!(
        resolved.contains("Roundtrip Agent"),
        "resolved doc missing name; got: {resolved}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_unknown_aid_returns_error() {
    let base_url = spawn_registry().await;

    let mut cli = Command::new(env!("CARGO_BIN_EXE_idprova"));
    let out = cli
        .args([
            "aid",
            "resolve",
            "did:aid:example.com:does-not-exist",
            "--registry",
            &base_url,
        ])
        .output()
        .expect("aid resolve ran");

    assert!(!out.status.success(), "resolve of unknown AID should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("404"),
        "expected not-found error, got stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_against_unreachable_registry_errors_cleanly() {
    // Bind to a port, immediately drop the listener, then point the CLI at it.
    // The CLI should fail with a connection error, not panic.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let dead_url = format!("http://{addr}");

    let mut cli = Command::new(env!("CARGO_BIN_EXE_idprova"));
    let out = cli
        .args([
            "aid",
            "resolve",
            "did:aid:example.com:whatever",
            "--registry",
            &dead_url,
        ])
        .output()
        .expect("aid resolve ran");

    assert!(
        !out.status.success(),
        "should fail when registry is unreachable"
    );
}
