use anyhow::{bail, Result};
use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::constraints::EvaluationContext;
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
            let ctx = EvaluationContext::default();

            match dat.verify(&key_bytes, scope, &ctx) {
                Ok(()) => {
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
                }
                Err(e) => {
                    println!("✗ Verification FAILED: {e}");
                    bail!("DAT verification failed");
                }
            }
        }
        None => {
            // ── Registry-assisted verification ────────────────────────────
            // Validate the registry URL before making any network call
            idprova_core::http::validate_registry_url(registry)
                .map_err(|e| anyhow::anyhow!("invalid registry URL: {e}"))?;

            let base = registry.trim_end_matches('/');
            let issuer_did = &dat.claims.iss;
            let key_url = format!("{base}/v1/aid/{issuer_did}/key");

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

            let ctx = EvaluationContext::default();
            match dat.verify(&pub_key_bytes, scope, &ctx) {
                Ok(()) => {
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
                }
                Err(e) => {
                    println!("✗ Verification FAILED: {e}");
                    bail!("DAT verification failed");
                }
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
        if let Some(ref rl) = c.rate_limit {
            println!(
                "│  Rate Limit:              {} actions / {}s window",
                rl.max_actions, rl.window_secs
            );
        }
        if let Some(ref servers) = c.allowed_servers {
            println!("│  Allowed Servers:         {:?}", servers);
        }
        if let Some(receipt) = c.require_receipt {
            println!("│  Require Receipt:         {receipt}");
        }
        if let Some(ref allowlist) = c.ip_allowlist {
            println!("│  IP Allowlist (CIDR):     {:?}", allowlist);
        }
        if let Some(ref denylist) = c.ip_denylist {
            println!("│  IP Denylist (CIDR):      {:?}", denylist);
        }
        if let Some(min_trust) = c.min_trust_level {
            println!("│  Min Trust Level:         {min_trust}");
        }
        if let Some(max_depth) = c.max_delegation_depth {
            println!("│  Max Delegation Depth:    {max_depth}");
        }
        if let Some(ref countries) = c.allowed_countries {
            println!("│  Geofence (countries):    {:?}", countries);
        }
        if let Some(ref windows) = c.time_windows {
            println!("│  Time Windows (UTC):");
            for w in windows {
                let days = w
                    .days_of_week
                    .as_ref()
                    .map(|d| format!("{:?}", d))
                    .unwrap_or_else(|| "every day".to_string());
                println!(
                    "│    {:02}:00 – {:02}:00  ({})",
                    w.start_hour, w.end_hour, days
                );
            }
        }
        if let Some(ref hash) = c.required_config_hash {
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
