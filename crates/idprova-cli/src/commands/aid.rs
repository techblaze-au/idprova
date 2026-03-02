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

pub fn resolve(id: &str, _registry: &str) -> Result<()> {
    // TODO: Implement registry client resolution
    println!("Resolving {id} from registry...");
    println!("(Registry client not yet implemented — coming in v0.1)");
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
