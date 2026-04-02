//! # idprova-mcp
//!
//! Drop-in identity verification middleware for MCP (Model Context Protocol) servers.
//!
//! Provides [`McpAuth`] for verifying DAT bearer tokens against required scopes,
//! and [`McpReceiptLog`] for building hash-chained audit trails of MCP tool calls.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use idprova_mcp::{McpAuth, McpAuthError};
//!
//! // Create an auth verifier (offline mode — no registry lookup)
//! let auth = McpAuth::offline();
//!
//! // Verify a DAT token against a required scope
//! // let agent = auth.verify_request(&dat_token, "mcp:tool:filesystem:read", &pub_key)?;
//! ```
//!
//! ## Modules
//!
//! - [`auth`] — Core authentication: `McpAuth`, `VerifiedAgent`
//! - [`error`] — Error types: `McpAuthError`
//! - [`scope`] — Scope matching (delegates to `idprova-core`)
//! - [`receipt`] — Receipt logging for MCP tool calls

pub mod auth;
pub mod error;
pub mod receipt;
pub mod scope;

pub use auth::{McpAuth, VerifiedAgent};
pub use error::McpAuthError;
pub use receipt::McpReceiptLog;
pub use scope::scope_covers;
