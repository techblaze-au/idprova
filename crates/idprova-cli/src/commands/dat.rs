use anyhow::Result;
use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::Dat;
use std::fs;

pub fn issue(
    issuer: &str,
    subject: &str,
    scope: &str,
    expires_in: &str,
    key_path: &str,
) -> Result<()> {
    // Load the signing key
    let key_hex = fs::read_to_string(key_path)?.trim().to_string();
    let key_bytes: [u8; 32] = hex::decode(&key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    let kp = KeyPair::from_secret_bytes(&key_bytes);

    // Parse scopes
    let scopes: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();

    // Parse expiry duration
    let duration = parse_duration(expires_in)?;
    let expires_at = Utc::now() + duration;

    // Issue the DAT
    let dat = Dat::issue(issuer, subject, scopes, expires_at, None, None, &kp)?;

    let compact = dat.to_compact()?;
    println!("{compact}");

    Ok(())
}

pub fn verify(token: &str, _registry: &str) -> Result<()> {
    let dat = Dat::from_compact(token)?;

    // Check timing
    match dat.validate_timing() {
        Ok(()) => println!("Timing: VALID"),
        Err(e) => println!("Timing: INVALID — {e}"),
    }

    println!("Issuer:  {}", dat.claims.iss);
    println!("Subject: {}", dat.claims.sub);
    println!("Scopes:  {}", dat.claims.scope.join(", "));
    println!("JTI:     {}", dat.claims.jti);

    // TODO: Resolve issuer's public key from registry and verify signature
    println!("\n(Signature verification requires registry client — coming in v0.1)");

    Ok(())
}

pub fn inspect(token: &str) -> Result<()> {
    let dat = Dat::from_compact(token)?;

    println!("Header:");
    println!("  Algorithm: {}", dat.header.alg);
    println!("  Type:      {}", dat.header.typ);
    println!("  Key ID:    {}", dat.header.kid);

    println!("\nClaims:");
    println!("  Issuer:    {}", dat.claims.iss);
    println!("  Subject:   {}", dat.claims.sub);
    println!("  Issued At: {}", dat.claims.iat);
    println!("  Expires:   {}", dat.claims.exp);
    println!("  Not Before:{}", dat.claims.nbf);
    println!("  JTI:       {}", dat.claims.jti);
    println!("  Scopes:    {:?}", dat.claims.scope);

    if let Some(ref c) = dat.claims.constraints {
        println!("\nConstraints:");
        if let Some(max) = c.max_actions {
            println!("  Max Actions:     {max}");
        }
        if let Some(ref servers) = c.allowed_servers {
            println!("  Allowed Servers: {:?}", servers);
        }
        if let Some(receipt) = c.require_receipt {
            println!("  Require Receipt: {receipt}");
        }
    }

    if dat.is_expired() {
        println!("\n  STATUS: EXPIRED");
    } else {
        println!("\n  STATUS: ACTIVE");
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
