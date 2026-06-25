//! Framework-agnostic HTTP request abstraction.
//!
//! Defines [`SignableRequest`] which captures the essential components of an HTTP
//! request needed to generate or verify a signature base.

use std::collections::HashMap;

/// A framework-agnostic representation of an HTTP request suitable for signing.
///
/// This struct extracts only the data relevant to RFC 9421 signatures, avoiding
/// ties to specific HTTP client libraries like `reqwest` or `hyper`.
#[derive(Debug, Clone)]
pub struct SignableRequest {
    /// The HTTP method (e.g., "GET", "POST").
    pub method: String,

    /// The authority (host and port), usually from the `Host` header or the URL.
    /// Example: `example.com` or `example.com:8080`.
    pub authority: String,

    /// The path component of the URI, including the leading `/`.
    /// Example: `/foo/bar`.
    pub path: String,

    /// The query string, *without* the leading `?`. Empty if no query.
    /// Example: `a=1&b=2`.
    pub query: Option<String>,

    /// Headers relevant to signing (e.g., `content-digest`, `content-type`).
    /// The signature base generator pulls from this map.
    pub headers: HashMap<String, String>,
}

impl SignableRequest {
    /// Create a new `SignableRequest` from raw components.
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
        query: Option<impl Into<String>>,
    ) -> Self {
        Self {
            method: method.into(),
            authority: authority.into(),
            path: path.into(),
            query: query.map(|q| q.into()),
            headers: HashMap::new(),
        }
    }

    /// Add a header to be used in signature generation.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_lowercase(), value.into());
        self
    }
}

/// Trait to convert specific HTTP request types into [`SignableRequest`].
///
/// Implement this for `reqwest::Request`, `hyper::Request`, etc.
pub trait IntoSignable {
    /// Convert the request into a [`SignableRequest`].
    fn into_signable(self) -> SignableRequest;
}

// Stub implementation for tests
#[cfg(test)]
impl IntoSignable for SignableRequest {
    fn into_signable(self) -> SignableRequest {
        self
    }
}
