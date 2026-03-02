use anyhow::Result;
use idprova_core::crypto::KeyPair;
use std::fs;
use std::path::PathBuf;

pub fn run(output: &str) -> Result<()> {
    // Expand ~ to home directory
    let path = if output.starts_with('~') {
        let home = dirs_path();
        PathBuf::from(output.replacen('~', &home, 1))
    } else {
        PathBuf::from(output)
    };

    // Create parent directories
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let kp = KeyPair::generate();

    // Save secret key (raw 32 bytes, hex-encoded for simplicity in MVP)
    let secret_hex = hex::encode(kp.secret_bytes());
    fs::write(&path, &secret_hex)?;

    // Save public key alongside
    let pub_path = path.with_extension("pub");
    let pub_multibase = kp.public_key_multibase();
    fs::write(&pub_path, &pub_multibase)?;

    println!("Generated Ed25519 keypair:");
    println!("  Private key: {}", path.display());
    println!("  Public key:  {}", pub_path.display());
    println!("  Public key (multibase): {pub_multibase}");

    // Set restrictive permissions on the private key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn dirs_path() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string())
}
