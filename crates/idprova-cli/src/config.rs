use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

/// CLI configuration loaded from ~/.idprova/config.toml.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    /// Registry URL for AID resolution and DAT verification.
    #[serde(default = "default_registry")]
    pub registry_url: String,

    /// Default path to the signing key file.
    #[serde(default = "default_key_path")]
    pub default_key: String,

    /// Output format: "json" or "table".
    #[serde(default = "default_output_format")]
    pub output_format: String,
}

fn default_registry() -> String {
    "https://registry.idprova.dev".to_string()
}
fn default_key_path() -> String {
    "~/.idprova/keys/agent.key".to_string()
}
fn default_output_format() -> String {
    "json".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registry_url: default_registry(),
            default_key: default_key_path(),
            output_format: default_output_format(),
        }
    }
}

impl Config {
    /// Load config from ~/.idprova/config.toml, falling back to defaults.
    pub fn load() -> Result<Self> {
        let path = config_path();
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            let config: Config = toml::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".idprova").join("config.toml")
}
