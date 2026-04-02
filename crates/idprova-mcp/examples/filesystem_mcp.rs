//! Filesystem MCP example — demonstrates DAT-scoped tool access with receipt chain.
//!
//! Scenario:
//! 1. Operator creates a keypair and issues a DAT scoped to `mcp:tool:filesystem:read`
//! 2. Worker agent verifies and succeeds on a read operation
//! 3. Worker agent attempts a write operation and gets blocked
//! 4. Full receipt chain is printed

use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::Dat;
use idprova_mcp::{McpAuth, McpReceiptLog};

fn main() {
    println!("=== IDProva MCP Filesystem Example ===\n");

    // --- Step 1: Operator creates identity and issues a read-only DAT ---
    let operator_kp = KeyPair::generate();
    let operator_did = "did:aid:example.com:operator";
    let agent_did = "did:aid:example.com:fs-worker";

    println!("Operator: {operator_did}");
    println!("Agent:    {agent_did}");
    println!("Scope:    mcp:tool:filesystem:read\n");

    let dat = Dat::issue(
        operator_did,
        agent_did,
        vec!["mcp:tool:filesystem:read".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &operator_kp,
    )
    .expect("failed to issue DAT");

    let dat_token = dat.to_compact().expect("failed to serialize DAT");
    let dat_jti = dat.claims.jti.clone();

    println!("DAT issued: {}\n", &dat_jti);

    // --- Step 2: Worker verifies read access (should succeed) ---
    let auth = McpAuth::offline();
    let mut receipts = McpReceiptLog::new();

    println!("--- Attempting: filesystem:read ---");
    match auth.verify_request(
        &dat_token,
        "mcp:tool:filesystem:read",
        &operator_kp.public_key_bytes(),
    ) {
        Ok(agent) => {
            println!(
                "  ALLOWED: agent={}, delegator={}",
                agent.aid, agent.delegator
            );
            receipts.log_tool_call(
                &agent.aid,
                &agent.jti,
                "filesystem:read",
                "blake3:input_abc",
                Some("blake3:output_def"),
            );
            println!("  Receipt logged (success)\n");
        }
        Err(e) => {
            println!("  DENIED: {e}");
            receipts.log_denial(agent_did, &dat_jti, "filesystem:read", &e.to_string());
            println!("  Receipt logged (denial)\n");
        }
    }

    // --- Step 3: Worker attempts write access (should fail) ---
    println!("--- Attempting: filesystem:write ---");
    match auth.verify_request(
        &dat_token,
        "mcp:tool:filesystem:write",
        &operator_kp.public_key_bytes(),
    ) {
        Ok(agent) => {
            println!("  ALLOWED: agent={}", agent.aid);
            receipts.log_tool_call(
                &agent.aid,
                &agent.jti,
                "filesystem:write",
                "blake3:input_xyz",
                None,
            );
        }
        Err(e) => {
            println!("  DENIED: {e}");
            receipts.log_denial(agent_did, &dat_jti, "filesystem:write", &e.to_string());
            println!("  Receipt logged (denial)\n");
        }
    }

    // --- Step 4: Print receipt chain ---
    println!("=== Receipt Chain ({} entries) ===\n", receipts.len());
    for (i, entry) in receipts.entries().iter().enumerate() {
        println!(
            "Receipt #{i}: seq={}, tool={}, status={}",
            entry.chain.sequence_number,
            entry.action.tool.as_deref().unwrap_or("n/a"),
            entry.action.status,
        );
        println!(
            "  prev_hash={}\n",
            &entry.chain.previous_hash[..20.min(entry.chain.previous_hash.len())]
        );
    }

    // Verify chain integrity
    match receipts.verify_integrity() {
        Ok(()) => println!("Chain integrity: VALID"),
        Err(e) => println!("Chain integrity: BROKEN ({e})"),
    }
}
