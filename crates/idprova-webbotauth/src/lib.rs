//! # IDProva Web Bot Auth
//!
//! Implementation of **RFC 9421 HTTP Message Signatures** and **IETF Web Bot Auth**.
//!
//! This crate allows IDProva agents to:
//! - Sign outbound HTTP requests using Ed25519.
//! - Serve a standard JWKS directory and Signature Agent Card.
//! - Verify inbound signed requests deterministically.
//!
//! ## Modules
//!
//! - [`request`]: Abstractions for HTTP requests (`SignableRequest`).
//! - [`components`]: Component definitions and signature base construction.
//! - [`sfv`]: Helpers for RFC 8941 Structured Fields.
//! - [`signer`]: Logic for creating HTTP signatures.
//! - [`verifier`]: Logic for verifying HTTP signatures.
//! - [`directory`]: Types for JWKS and Signature Agent Cards.
//! - [`binding`]: Integration logic binding Web Bot Auth keys to `did:aid:`.

#![forbid(unsafe_code)]

pub mod binding;
pub mod components;
pub mod directory;
pub mod request;
pub mod sfv;
pub mod signer;
pub mod verifier;

/// Common result type for webbotauth operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors specific to Web Bot Auth operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid structured field value in header.
    #[error("Invalid structured field: {0}")]
    InvalidStructuredField(String),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Timing error (e.g., expired signature).
    #[error("Signature expired or invalid timestamp")]
    InvalidTime,

    /// Required component missing from signature coverage.
    #[error("Missing required component in signature: {0}")]
    MissingComponent(String),

    /// Key ID not found in resolver.
    #[error("Key ID not found: {0}")]
    KeyNotFound(String),

    /// Serialization/Deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 encoding/decoding error.
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}
