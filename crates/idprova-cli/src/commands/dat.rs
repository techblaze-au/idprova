use anyhow::{bail, Result};
use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::policy::EvaluationContext;
use idprova_core::dat::Dat;
use std::fs;

pub fn issue(
    issuer: &str,
    subject: &str,
    scope: &str,
    expires_in: &str,
    key_path: &str,
) -> Result<()> {
    let key_hex = fs::read_to_string(key_path)?.trim().to_string();
    let key_bytes: [u8; 32] = hex::decode(&key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    let kp = KeyPair::from_secret_bytes(&key_bytes);

    let scopes: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();
    let duration = parse_duration(expires_in)?;
    let expires_at = Utc::now() + duration;

    let dat = Dat::issue(issuer, subject, scopes, expires_at, None, None, &kp)?;
    println!("{}", dat.to_compact()?);

    Ok(())
}

/// Verify a DAT.
///
/// If `key_path` is provided the verification is fully offline:
///   sig + timing + scope + all constraint evaluators.
///
/// Without a key, timing and decode are checked and the signature
/// check is skipped (the user is told to pass `--key`).
pub fn verify(token: &str, registry: &str, key_path: Option<&str>, scope: &str) -> Result<()> {
    let dat = Dat::from_compact(token)?;

    println!("IDProva DAT Verification");
    println!("────────────────────────────────────────");
    println!("Issuer:  {}", dat.claims.iss);
    println!("Subject: {}", dat.claims.sub);
    println!("JTI:     {}", dat.claims.jti);
    println!("Scopes:  {}", dat.claims.scope.join(", "));

    let now = Utc::now().timestamp();
    let expires_in_secs = dat.claims.exp - now;
    if expires_in_secs > 0 {
        println!("Expires: in {}s", expires_in_secs);
    } else {
        println!("Expires: {} ago (EXPIRED)", -expires_in_secs);
    }

    if let Some(chain) = &dat.claims.delegation_chain {
        if !chain.is_empty() {
            println!("Chain depth: {} (parent JTIs: {})", chain.len(), chain.join(", "));
        }
    }

    println!();

    match key_path {
        Some(path) => {
            // ── Offline full verification ──────────────────────────────────
            // Accept hex (private key secret bytes) OR multibase public key (.pub file)
            let key_str = fs::read_to_string(path)?.trim().to_string();
            let key_bytes: [u8; 32] = if key_str.starts_with('z') {
                // multibase (base58btc) — this is the .pub file
                KeyPair::decode_multibase_pubkey(&key_str)
                    .map_err(|e| anyhow::anyhow!("invalid multibase public key: {e}"))?
            } else {
                hex::decode(&key_str)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?
            };

            // Build a default context — caller can extend via env vars in future
            let ctx = EvaluationContext::builder(scope).build();

            dat.verify_signature(&key_bytes)?;
            let evaluator = idprova_core::policy::PolicyEvaluator::new();
            let decision = evaluator.evaluate(&dat, &ctx);
            if decision.is_allowed() {
                println!("✓ Signature:  VALID");
                println!("✓ Timing:     VALID");
                if !scope.is_empty() {
                    println!("✓ Scope:      '{}' GRANTED", scope);
                }
                if dat.claims.constraints.is_some() {
                    println!("✓ Constraints: ALL PASS");
                }
                println!();
                println!("Result: VALID");
            } else {
                let reason = decision.denial_reason().map(|r| format!("{:?}", r)).unwrap_or_default();
                println!("✗ Verification FAILED: {reason}");
                bail!("DAT verification failed");
            }
        }
        None => {
            // ── Registry-assisted verification ────────────────────────────
            // Validate the registry URL before making any network call
            url::Url::parse(registry).map(|_| ())
                .map_err(|e| anyhow::anyhow!("invalid registry URL: {e}"))?;

            let base = registry.trim_end_matches('/');
            let issuer_did = &dat.claims.iss;
            let aid_id = issuer_did.strip_prefix("did:idprova:").unwrap_or(issuer_did);
            let key_url = format!("{base}/v1/aid/{aid_id}/key");

            eprintln!("No key supplied — resolving issuer public key from registry...");
            eprintln!("  GET {key_url}");

            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(format!("idprova-cli/{}", env!("CARGO_PKG_VERSION")))
                .build()?;

            let resp = client.get(&key_url).send()?;
            let status = resp.status();

            if !status.is_success() {
                if status.as_u16() == 404 {
                    bail!("issuer AID not found in registry: {issuer_did}");
                }
                bail!("registry returned {status} for key lookup");
            }

            #[derive(serde::Deserialize)]
            struct KeyEntry {
                #[serde(rename = "publicKeyMultibase")]
                public_key_multibase: String,
            }
            #[derive(serde::Deserialize)]
            struct KeyResp {
                keys: Vec<KeyEntry>,
            }

            let key_resp: KeyResp = resp.json()?;
            let key_entry = key_resp.keys.into_iter().next()
                .ok_or_else(|| anyhow::anyhow!("issuer AID has no verification keys"))?;

            let pub_key_bytes = KeyPair::decode_multibase_pubkey(&key_entry.public_key_multibase)
                .map_err(|e| anyhow::anyhow!("failed to decode issuer public key: {e}"))?;

            let ctx = EvaluationContext::builder(scope).build();
            dat.verify_signature(&pub_key_bytes).map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;
            let evaluator = idprova_core::policy::PolicyEvaluator::new();
            let decision = evaluator.evaluate(&dat, &ctx);
            if decision.is_allowed() {
                println!("✓ Signature:  VALID (verified via registry)");
                println!("✓ Timing:     VALID");
                if !scope.is_empty() {
                    println!("✓ Scope:      '{}' GRANTED", scope);
                }
                if dat.claims.constraints.is_some() {
                    println!("✓ Constraints: ALL PASS");
                }
                println!();
                println!("Result: VALID");
            } else {
                let reason = decision.denial_reason().map(|r| format!("{:?}", r)).unwrap_or_default();
                println!("✗ Verification FAILED: {reason}");
                bail!("DAT verification failed");
            }
        }
    }

    Ok(())
}

pub fn inspect(token: &str) -> Result<()> {
    let dat = Dat::from_compact(token)?;

    println!("┌─ Header ─────────────────────────────────────────────────────");
    println!("│  Algorithm: {}", dat.header.alg);
    println!("│  Type:      {}", dat.header.typ);
    println!("│  Key ID:    {}", dat.header.kid);

    println!("├─ Claims ─────────────────────────────────────────────────────");
    println!("│  Issuer:    {}", dat.claims.iss);
    println!("│  Subject:   {}", dat.claims.sub);
    println!("│  Issued At: {}", dat.claims.iat);
    println!("│  Expires:   {}", dat.claims.exp);
    println!("│  Not Before:{}", dat.claims.nbf);
    println!("│  JTI:       {}", dat.claims.jti);
    println!("│  Scopes:    {}", dat.claims.scope.join(", "));

    if let Some(ref chain) = dat.claims.delegation_chain {
        if chain.is_empty() {
            println!("│  Delegation: root (no parent chain)");
        } else {
            println!("│  Delegation depth: {}", chain.len());
            for (i, jti) in chain.iter().enumerate() {
                println!("│    [{}] {}", i, jti);
            }
        }
    }

    if let Some(ref attest) = dat.claims.config_attestation {
        println!("│  Config Attestation: {attest}");
    }

    if let Some(ref c) = dat.claims.constraints {
        println!("├─ Constraints ────────────────────────────────────────────────");

        if let Some(max) = c.max_actions {
            println!("│  Max Actions (lifetime):  {max}");
        }
        if let Some(max_hr) = c.max_calls_per_hour {
            println!("│  Max Calls/Hour:          {max_hr}");
        }
        if let Some(max_day) = c.max_calls_per_day {
            println!("│  Max Calls/Day:           {max_day}");
        }
        if let Some(max_conc) = c.max_concurrent {
            println!("│  Max Concurrent:          {max_conc}");
        }
        if let Some(ref servers) = c.allowed_servers {
            println!("│  Allowed Servers:         {:?}", servers);
        }
        if let Some(receipt) = c.require_receipt {
            println!("│  Require Receipt:         {receipt}");
        }
        if let Some(ref allowlist) = c.allowed_ips {
            println!("│  IP Allowlist (CIDR):     {:?}", allowlist);
        }
        if let Some(ref denylist) = c.denied_ips {
            println!("│  IP Denylist (CIDR):      {:?}", denylist);
        }
        if let Some(ref trust) = c.required_trust_level {
            println!("│  Required Trust Level:    {trust}");
        }
        if let Some(max_depth) = c.max_delegation_depth {
            println!("│  Max Delegation Depth:    {max_depth}");
        }
        if let Some(ref countries) = c.geofence {
            println!("│  Geofence (countries):    {:?}", countries);
        }
        if let Some(ref windows) = c.time_windows {
            println!("│  Time Windows (UTC):");
            for w in windows {
                let days = if w.days.is_empty() {
                    "every day".to_string()
                } else {
                    format!("{:?}", w.days)
                };
                println!(
                    "│    {:02}:00 – {:02}:00  ({})",
                    w.start_hour, w.end_hour, days
                );
            }
        }
        if let Some(ref hash) = c.required_config_attestation {
            println!("│  Required Config Hash:    {hash}");
        }
    }

    println!("└─ Status ─────────────────────────────────────────────────────");
    if dat.is_expired() {
        println!("   EXPIRED");
    } else if dat.is_not_yet_valid() {
        println!("   NOT YET VALID");
    } else {
        let secs = dat.claims.exp - Utc::now().timestamp();
        println!("   ACTIVE (expires in {}s)", secs);
    }

    Ok(())
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        Ok(Duration::hours(hours.parse()?))
    } else if let Some(days) = s.strip_suffix('d') {
        Ok(Duration::days(days.parse()?))
    } else if let Some(mins) = s.strip_suffix('m') {
        Ok(Duration::minutes(mins.parse()?))
    } else {
        Err(anyhow::anyhow!(
            "invalid duration format: {s}. Use '24h', '1d', or '30m'"
        ))
    }
}
