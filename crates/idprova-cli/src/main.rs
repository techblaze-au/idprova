use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod config;

/// IDProva CLI — manage AI agent identities, delegation tokens, and receipts.
#[derive(Parser)]
#[command(name = "idprova", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair.
    Keygen {
        /// Output path for the key file.
        #[arg(short, long, default_value = "~/.idprova/keys/agent.key")]
        output: String,
    },

    /// Agent Identity Document operations.
    Aid {
        #[command(subcommand)]
        action: AidCommands,
    },

    /// Delegation Attestation Token operations.
    Dat {
        #[command(subcommand)]
        action: DatCommands,
    },

    /// Action receipt operations.
    Receipt {
        #[command(subcommand)]
        action: ReceiptCommands,
    },
}

#[derive(Subcommand)]
enum AidCommands {
    /// Create a new Agent Identity Document.
    Create {
        /// The DID identifier (e.g., "did:aid:example.com:my-agent").
        #[arg(long)]
        id: String,
        /// Human-readable agent name.
        #[arg(long)]
        name: String,
        /// Controller DID.
        #[arg(long)]
        controller: String,
        /// AI model identifier.
        #[arg(long)]
        model: Option<String>,
        /// Runtime environment.
        #[arg(long)]
        runtime: Option<String>,
        /// Path to the signing key.
        #[arg(long)]
        key: String,
    },

    /// Resolve an AID from the registry.
    Resolve {
        /// The DID to resolve.
        id: String,
        /// Registry URL (overrides config.toml).
        #[arg(long)]
        registry: Option<String>,
    },

    /// Verify an AID document.
    Verify {
        /// Path to the AID document JSON file.
        file: String,
    },
}

#[derive(Subcommand)]
enum DatCommands {
    /// Issue a new Delegation Attestation Token.
    Issue {
        /// Issuer DID.
        #[arg(long)]
        issuer: String,
        /// Subject (agent) DID.
        #[arg(long)]
        subject: String,
        /// Scope grants (comma-separated).
        #[arg(long)]
        scope: String,
        /// Expiry duration (e.g., "24h", "1d", "30m").
        #[arg(long, default_value = "24h")]
        expires_in: String,
        /// Path to the issuer's signing key.
        #[arg(long)]
        key: String,
    },

    /// Verify a DAT.
    Verify {
        /// The compact JWS token to verify.
        token: String,
        /// Registry URL for AID resolution (overrides config.toml).
        #[arg(long)]
        registry: Option<String>,
        /// Path to the issuer's public key file (hex-encoded, for offline verification).
        #[arg(long)]
        key: Option<String>,
        /// Required scope to check against the DAT's grants (e.g. "mcp:tool:read").
        #[arg(long, default_value = "")]
        scope: String,
    },

    /// Inspect a DAT (decode without verifying).
    Inspect {
        /// The compact JWS token to inspect.
        token: String,
    },
}

#[derive(Subcommand)]
enum ReceiptCommands {
    /// Verify the integrity of a receipt log.
    Verify {
        /// Path to the receipt log file (JSONL).
        file: String,
    },

    /// Show receipt log statistics.
    Stats {
        /// Path to the receipt log file (JSONL).
        file: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::load().unwrap_or_default();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            commands::keygen::run(&output)?;
        }
        Commands::Aid { action } => match action {
            AidCommands::Create {
                id,
                name,
                controller,
                model,
                runtime,
                key,
            } => {
                commands::aid::create(
                    &id,
                    &name,
                    &controller,
                    model.as_deref(),
                    runtime.as_deref(),
                    &key,
                )?;
            }
            AidCommands::Resolve { id, registry } => {
                let reg = registry.unwrap_or_else(|| cfg.registry_url.clone());
                commands::aid::resolve(&id, &reg)?;
            }
            AidCommands::Verify { file } => {
                commands::aid::verify(&file)?;
            }
        },
        Commands::Dat { action } => match action {
            DatCommands::Issue {
                issuer,
                subject,
                scope,
                expires_in,
                key,
            } => {
                commands::dat::issue(&issuer, &subject, &scope, &expires_in, &key)?;
            }
            DatCommands::Verify {
                token,
                registry,
                key,
                scope,
            } => {
                let reg = registry.unwrap_or_else(|| cfg.registry_url.clone());
                commands::dat::verify(&token, &reg, key.as_deref(), &scope)?;
            }
            DatCommands::Inspect { token } => {
                commands::dat::inspect(&token)?;
            }
        },
        Commands::Receipt { action } => match action {
            ReceiptCommands::Verify { file } => {
                commands::receipt::verify(&file)?;
            }
            ReceiptCommands::Stats { file } => {
                commands::receipt::stats(&file)?;
            }
        },
    }

    Ok(())
}
