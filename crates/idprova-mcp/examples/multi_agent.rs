//! Multi-agent delegation chain example.
//!
//! Demonstrates a 4-agent delegation chain with progressive scope narrowing:
//!
//! 1. **Operator** issues DAT to Agent A with `mcp:tool:*:*` (all tools)
//! 2. **Agent A** re-delegates to Agent B with `mcp:tool:filesystem:*` (filesystem only)
//! 3. **Agent B** re-delegates to Agent C with `mcp:tool:filesystem:read` (read only)
//! 4. **Agent C** tries `filesystem:read` (succeeds) then `filesystem:write` (blocked)
//!
//! Full receipt chain is printed at the end.

use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::Dat;
use idprova_mcp::{McpAuth, McpReceiptLog};

/// Represents an agent in the delegation chain.
struct Agent {
    did: String,
    keypair: KeyPair,
}

impl Agent {
    fn new(name: &str) -> Self {
        Self {
            did: format!("did:aid:example.com:{name}"),
            keypair: KeyPair::generate(),
        }
    }
}

fn main() {
    println!("=== IDProva Multi-Agent Delegation Chain ===\n");

    // --- Create 4 agents ---
    let operator = Agent::new("operator");
    let agent_a = Agent::new("agent-a");
    let agent_b = Agent::new("agent-b");
    let agent_c = Agent::new("agent-c");

    let auth = McpAuth::offline();
    let mut receipts = McpReceiptLog::new();

    // --- Level 1: Operator -> Agent A (all MCP tools) ---
    println!("Level 1: {} -> {}", operator.did, agent_a.did);
    println!("  Scope: mcp:tool:*:*\n");

    let dat_a = Dat::issue(
        &operator.did,
        &agent_a.did,
        vec!["mcp:tool:*:*".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &operator.keypair,
    )
    .expect("failed to issue DAT for Agent A");
    let token_a = dat_a.to_compact().unwrap();

    // Verify Agent A can use any tool
    let verified_a = auth
        .verify_request(
            &token_a,
            "mcp:tool:search:execute",
            &operator.keypair.public_key_bytes(),
        )
        .expect("Agent A should have full tool access");
    println!(
        "  Agent A verified: aid={}, scope={:?}",
        verified_a.aid, verified_a.scope
    );
    receipts.log_tool_call(
        &verified_a.aid,
        &verified_a.jti,
        "search:execute",
        "blake3:search_input",
        Some("blake3:search_output"),
    );

    // --- Level 2: Agent A -> Agent B (filesystem only) ---
    println!("\nLevel 2: {} -> {}", agent_a.did, agent_b.did);
    println!("  Scope: mcp:tool:filesystem:* (narrowed from mcp:tool:*:*)\n");

    let dat_b = Dat::issue(
        &agent_a.did,
        &agent_b.did,
        vec!["mcp:tool:filesystem:*".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &agent_a.keypair,
    )
    .expect("failed to issue DAT for Agent B");
    let token_b = dat_b.to_compact().unwrap();

    // Verify Agent B can use filesystem tools
    let verified_b = auth
        .verify_request(
            &token_b,
            "mcp:tool:filesystem:read",
            &agent_a.keypair.public_key_bytes(),
        )
        .expect("Agent B should have filesystem access");
    println!(
        "  Agent B verified: aid={}, scope={:?}",
        verified_b.aid, verified_b.scope
    );
    receipts.log_tool_call(
        &verified_b.aid,
        &verified_b.jti,
        "filesystem:read",
        "blake3:fs_read_input",
        Some("blake3:fs_read_output"),
    );

    // --- Level 3: Agent B -> Agent C (filesystem read only) ---
    println!("\nLevel 3: {} -> {}", agent_b.did, agent_c.did);
    println!("  Scope: mcp:tool:filesystem:read (narrowed from mcp:tool:filesystem:*)\n");

    let dat_c = Dat::issue(
        &agent_b.did,
        &agent_c.did,
        vec!["mcp:tool:filesystem:read".to_string()],
        Utc::now() + Duration::hours(1),
        None,
        None,
        &agent_b.keypair,
    )
    .expect("failed to issue DAT for Agent C");
    let token_c = dat_c.to_compact().unwrap();
    let jti_c = dat_c.claims.jti.clone();

    // --- Agent C: filesystem:read (should succeed) ---
    println!("--- Agent C attempts: filesystem:read ---");
    match auth.verify_request(
        &token_c,
        "mcp:tool:filesystem:read",
        &agent_b.keypair.public_key_bytes(),
    ) {
        Ok(agent) => {
            println!("  ALLOWED: {}", agent.aid);
            receipts.log_tool_call(
                &agent.aid,
                &agent.jti,
                "filesystem:read",
                "blake3:c_read_input",
                Some("blake3:c_read_output"),
            );
        }
        Err(e) => {
            println!("  DENIED: {e}");
            receipts.log_denial(&agent_c.did, &jti_c, "filesystem:read", &e.to_string());
        }
    }

    // --- Agent C: filesystem:write (should FAIL — scope exceeded) ---
    println!("\n--- Agent C attempts: filesystem:write (exceeds scope) ---");
    match auth.verify_request(
        &token_c,
        "mcp:tool:filesystem:write",
        &agent_b.keypair.public_key_bytes(),
    ) {
        Ok(agent) => {
            println!("  ALLOWED: {} (unexpected!)", agent.aid);
            receipts.log_tool_call(
                &agent.aid,
                &agent.jti,
                "filesystem:write",
                "blake3:c_write_input",
                None,
            );
        }
        Err(e) => {
            println!("  BLOCKED: {e}");
            receipts.log_denial(&agent_c.did, &jti_c, "filesystem:write", &e.to_string());
        }
    }

    // --- Agent C: search:execute (should FAIL — not in scope at all) ---
    println!("\n--- Agent C attempts: search:execute (not in scope) ---");
    match auth.verify_request(
        &token_c,
        "mcp:tool:search:execute",
        &agent_b.keypair.public_key_bytes(),
    ) {
        Ok(agent) => {
            println!("  ALLOWED: {} (unexpected!)", agent.aid);
        }
        Err(e) => {
            println!("  BLOCKED: {e}");
            receipts.log_denial(&agent_c.did, &jti_c, "search:execute", &e.to_string());
        }
    }

    // --- Print full receipt chain ---
    println!(
        "\n=== Full Receipt Chain ({} entries) ===\n",
        receipts.len()
    );
    for (i, entry) in receipts.entries().iter().enumerate() {
        println!(
            "#{i} | agent={} | tool={} | status={}",
            entry.agent,
            entry.action.tool.as_deref().unwrap_or("n/a"),
            entry.action.status,
        );
    }

    println!();
    match receipts.verify_integrity() {
        Ok(()) => println!("Chain integrity: VALID"),
        Err(e) => println!("Chain integrity: BROKEN ({e})"),
    }

    println!("\n=== Delegation Summary ===");
    println!("Operator -> A: mcp:tool:*:*");
    println!("       A -> B: mcp:tool:filesystem:*");
    println!("       B -> C: mcp:tool:filesystem:read");
    println!("C tried write -> BLOCKED (scope narrowing enforced)");
}
