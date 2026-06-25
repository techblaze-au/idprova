//! HTTP Message Signature components and base construction.
//!
//! Implements RFC 9421 §2.5: creation of the signature base string.
//! Defines the [`Component`] enum and the deterministic builder.

use super::request::SignableRequest;
use super::Error;
use super::Result;

/// Represents a part of the HTTP message that can be covered by a signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    /// The `@method` derived component.
    Method,
    /// The `@authority` derived component.
    Authority,
    /// The `@path` derived component.
    Path,
    /// The `@query` derived component.
    Query,
    /// A specific HTTP header field (lowercase name).
    Header(String),
    /// The `@signature-params` derived component (always covered implicitly).
    SignatureParams,
}

impl Component {
    /// Returns the string identifier for this component used in the signature base.
    pub fn name(&self) -> &str {
        match self {
            Component::Method => "@method",
            Component::Authority => "@authority",
            Component::Path => "@path",
            Component::Query => "@query",
            Component::Header(name) => name,
            Component::SignatureParams => "@signature-params",
        }
    }

    /// Extracts the value for this component from the request.
    ///
    /// Returns an error if the component is required but missing from the request.
    pub fn extract_value(&self, req: &SignableRequest) -> Result<String> {
        match self {
            Component::Method => Ok(req.method.clone()),
            Component::Authority => Ok(req.authority.clone()),
            Component::Path => Ok(req.path.clone()),
            Component::Query => Ok(req.query.clone().unwrap_or_else(String::new)),
            Component::Header(name) => req
                .headers
                .get(name)
                .cloned()
                .ok_or_else(|| Error::MissingComponent(format!("header: {}", name))),
            Component::SignatureParams => {
                // This is handled by `build_signature_base` which generates the param string.
                // But we must return the *value* string, which is the param line.
                // However, the `@signature-params` line is defined *by* the params list.
                // This function is usually called inside the loop of covered components.
                // We handle this special case in `build_signature_base`.
                Ok(String::new())
            }
        }
    }
}

/// Parameters included in the `@signature-params` line.
#[derive(Debug, Clone)]
pub struct SignatureParams {
    /// Key ID (RFC 7638 JWK Thumbprint).
    pub keyid: String,
    /// Creation time (Unix timestamp).
    pub created: i64,
    /// Expiration time (Unix timestamp).
    pub expires: Option<i64>,
    /// Algorithm identifier (must be `ed25519` for IDProva).
    pub alg: String,
    /// Optional nonce.
    pub nonce: Option<String>,
    /// Application-specific tag.
    pub tag: Option<String>,
}

impl SignatureParams {
    /// Serialize the parameters into the string format used in the `@signature-params` value.
    /// e.g. `created=1618884473;keyid="...";alg="ed25519"`
    pub fn to_param_string(&self) -> String {
        let mut parts = vec![
            format!("created={}", self.created),
            format!("keyid=\"{}\"", self.keyid),
            format!("alg=\"{}\"", self.alg),
        ];

        if let Some(exp) = self.expires {
            parts.push(format!("expires={}", exp));
        }
        if let Some(nonce) = &self.nonce {
            parts.push(format!("nonce=\"{}\"", nonce));
        }
        if let Some(tag) = &self.tag {
            parts.push(format!("tag=\"{}\"", tag));
        }

        parts.join(";")
    }
}

/// Builds the deterministic signature base string as defined in RFC 9421 §2.5.
///
/// The base is constructed by appending lines in the order of `covered_components`.
/// Each line is `"<name>": <value>`. The final line is always `@signature-params`.
///
/// # Arguments
///
/// * `req` - The request being signed.
/// * `covered_components` - The list of components to include (order matters).
/// * `params` - The signature parameters (created, expires, keyid, etc.).
///
/// # Example
///
/// ```text
/// "@method": POST
/// "@authority": example.com
/// "@path": /foo
/// "@signature-params": ("@method" "@authority" "@path");created=...
/// ```
pub fn build_signature_base(
    req: &SignableRequest,
    covered_components: &[Component],
    params: &SignatureParams,
) -> Result<String> {
    if covered_components.is_empty() {
        return Err(Error::MissingComponent(
            "covered components list cannot be empty".into(),
        ));
    }

    let mut lines = Vec::new();

    // Add covered components in order
    for component in covered_components {
        if component == &Component::SignatureParams {
            continue; // We add this manually at the end
        }
        let name = component.name();
        let value = component.extract_value(req)?;
        lines.push(format!("{}: {}", name, value));
    }

    // Construct the @signature-params line
    // Format: ("name1" "name2");key=...
    let covered_names = covered_components
        .iter()
        .filter_map(|c| {
            if c == &Component::SignatureParams {
                None
            } else {
                Some(format!("\"{}\"", c.name()))
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let param_string = params.to_param_string();
    lines.push(format!(
        "@signature-params: ({});{}",
        covered_names, param_string
    ));

    // RFC 9421 says lines are joined by \n (no trailing \n explicitly requested,
    // but base string usually acts as the signed payload. \n is standard).
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_names() {
        assert_eq!(Component::Method.name(), "@method");
        assert_eq!(Component::Query.name(), "@query");
        assert_eq!(
            Component::Header("content-type".to_string()).name(),
            "content-type"
        );
    }

    #[test]
    fn test_build_base_simple() {
        let req = SignableRequest::new("GET", "example.com", "/path", None::<&str>);
        let covered = vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::SignatureParams,
        ];

        let params = SignatureParams {
            keyid: "test-key".into(),
            created: 1234567890,
            expires: None,
            alg: "ed25519".into(),
            nonce: None,
            tag: None,
        };

        let base = build_signature_base(&req, &covered, &params).unwrap();
        assert!(base.contains("@method: GET"));
        assert!(base.contains("@authority: example.com"));
        assert!(base.contains("@path: /path"));
        assert!(base.contains("@signature-params:"));
    }
}
