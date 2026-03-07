use anyhow::Result;
use idprova_core::aid::AidBuilder;
use idprova_core::crypto::KeyPair;
use std::fs;

pub fn create(
    id: &str,
    name: &str,
    controller: &str,
    model: Option<&str>,
    runtime: Option<&str>,
    key_path: &str,
) -> Result<()> {
    // Load the signing key
    let key_hex = fs::read_to_string(key_path)?.trim().to_string();
    let key_bytes: [u8; 32] = hex::decode(&key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    let kp = KeyPair::from_secret_bytes(&key_bytes);

    // Build the AID
    let mut builder = AidBuilder::new()
        .id(id)
        .controller(controller)
        .name(name)
        .add_ed25519_key(&kp);

    if let Some(m) = model {
        builder = builder.model(m);
    }
    if let Some(r) = runtime {
        builder = builder.runtime(r);
    }

    let doc = builder.build()?;

    let json = serde_json::to_string_pretty(&doc)?;
    println!("{json}");

    // Save to file
    let filename = format!("{}.json", id.replace(':', "_"));
    fs::write(&filename, &json)?;
    println!("\nSaved to: {filename}");

    Ok(())
}

pub fn resolve(id: &str, registry: &str) -> Result<()> {
    // Validate the registry URL for SSRF safety before any network call
    url::Url::parse(registry).map(|_| ())
        .map_err(|e| anyhow::anyhow!("invalid registry URL: {e}"))?;

    // Strip trailing slash, build endpoint URL
    let base = registry.trim_end_matches('/');
    // The DID path segment is the part after "did:idprova:" — use the full id as path param
    let url = format!("{base}/v1/aid/{id}");

    eprintln!("Resolving {id} from {base}...");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("idprova-cli/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let resp = client.get(&url).send()?;
    let status = resp.status();

    if status.is_success() {
        let doc: idprova_core::aid::AidDocument = resp.json()?;
        let json = serde_json::to_string_pretty(&doc)?;
        println!("{json}");
    } else if status.as_u16() == 404 {
        anyhow::bail!("AID not found: {id}");
    } else {
        let body = resp.text().unwrap_or_default();
        anyhow::bail!("registry returned {status}: {body}");
    }

    Ok(())
}

pub fn verify(file: &str) -> Result<()> {
    let json = fs::read_to_string(file)?;
    let doc: idprova_core::aid::AidDocument = serde_json::from_str(&json)?;

    match doc.validate() {
        Ok(()) => println!("AID document is valid."),
        Err(e) => println!("AID document validation failed: {e}"),
    }

    Ok(())
}
