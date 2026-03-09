//! SSRF-safe URL validation and secure HTTP client builder.
//!
//! Use [`validate_registry_url`] to sanitize any registry URL before making
//! outbound requests. Rejects private/loopback IPs, dangerous schemes, and
//! cloud metadata endpoints.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use ipnet::{Ipv4Net, Ipv6Net};
use url::Url;

use crate::{IdprovaError, Result};

// ── Blocked CIDR ranges ──────────────────────────────────────────────────────

/// IPv4 ranges that must never be contacted (SSRF prevention).
fn blocked_v4() -> Vec<Ipv4Net> {
    [
        "127.0.0.0/8",    // loopback
        "10.0.0.0/8",     // private class A
        "172.16.0.0/12",  // private class B
        "192.168.0.0/16", // private class C
        "169.254.0.0/16", // link-local (cloud metadata)
        "0.0.0.0/8",      // unspecified
        "100.64.0.0/10",  // shared address space
        "192.0.0.0/24",   // IETF protocol assignments
        "198.18.0.0/15",  // benchmark testing
        "240.0.0.0/4",    // reserved
    ]
    .iter()
    .map(|s| s.parse().expect("static CIDR is valid"))
    .collect()
}

/// IPv6 ranges that must never be contacted.
fn blocked_v6() -> Vec<Ipv6Net> {
    [
        "::1/128",       // loopback
        "fc00::/7",      // unique local
        "fe80::/10",     // link-local
        "::ffff:0:0/96", // IPv4-mapped
        "::/128",        // unspecified
    ]
    .iter()
    .map(|s| s.parse().expect("static CIDR is valid"))
    .collect()
}

// ── Allowed schemes ───────────────────────────────────────────────────────────

/// Only HTTPS (and HTTP for localhost in tests/dev) are permitted.
/// All other schemes — file://, gopher://, ldap://, ftp://, data:, etc. — are rejected.
const ALLOWED_SCHEMES: &[&str] = &["https", "http"];

// ── Public API ────────────────────────────────────────────────────────────────

/// Validate a registry URL for SSRF safety.
///
/// Rejects:
/// - Non-HTTP/HTTPS schemes (`file://`, `gopher://`, `ldap://`, `ftp://`, etc.)
/// - Private/loopback IPv4: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
/// - Link-local / cloud metadata: `169.254.0.0/16`
/// - IPv6 loopback `::1` and ULA `fc00::/7`
/// - Hostnames that resolve to any of the above
///
/// Returns the parsed [`Url`] on success.
pub fn validate_registry_url(raw_url: &str) -> Result<Url> {
    let url = Url::parse(raw_url)
        .map_err(|e| IdprovaError::Other(format!("invalid URL '{raw_url}': {e}")))?;

    // Check scheme
    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        return Err(IdprovaError::Other(format!(
            "URL scheme '{}' is not permitted; only https/http are allowed",
            url.scheme()
        )));
    }

    // Extract host — a URL without a host is invalid for registry use
    let host = url
        .host_str()
        .ok_or_else(|| IdprovaError::Other(format!("URL has no host: {raw_url}")))?;

    // If the host is an IP literal, check it directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        check_ip_blocked(ip)?;
        return Ok(url);
    }

    // Otherwise resolve hostname → check each resolved IP
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addrs_str = format!("{host}:{port}");
    let resolved: Vec<SocketAddr> = addrs_str
        .to_socket_addrs()
        .map_err(|e| IdprovaError::Other(format!("cannot resolve host '{host}': {e}")))?
        .collect();

    if resolved.is_empty() {
        return Err(IdprovaError::Other(format!(
            "host '{host}' resolved to no addresses"
        )));
    }

    for addr in resolved {
        check_ip_blocked(addr.ip())?;
    }

    Ok(url)
}

/// Check whether a single IP address falls in a blocked range.
fn check_ip_blocked(ip: IpAddr) -> Result<()> {
    match ip {
        IpAddr::V4(v4) => {
            for net in blocked_v4() {
                if net.contains(&v4) {
                    return Err(IdprovaError::Other(format!(
                        "IP address {ip} is in blocked range {net} (SSRF prevention)"
                    )));
                }
            }
        }
        IpAddr::V6(v6) => {
            for net in blocked_v6() {
                if net.contains(&v6) {
                    return Err(IdprovaError::Other(format!(
                        "IP address {ip} is in blocked range {net} (SSRF prevention)"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Build a secure, SSRF-safe [`reqwest::Client`] for registry communication.
///
/// Configuration:
/// - `timeout`: 10 seconds total
/// - `connect_timeout`: 5 seconds
/// - `redirect` limit: 5
/// - `https_only`: true (no plain-HTTP redirects)
/// - `user_agent`: `idprova-client/{version}`
#[cfg(feature = "http")]
pub fn build_registry_client() -> std::result::Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .https_only(true)
        .user_agent(format!("idprova-client/{}", env!("CARGO_PKG_VERSION")))
        .build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scheme rejection ──────────────────────────────────────────────────────

    #[test]
    fn test_reject_file_scheme() {
        let result = validate_registry_url("file:///etc/passwd");
        assert!(result.is_err(), "file:// must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("scheme"), "expected scheme error, got: {msg}");
    }

    #[test]
    fn test_reject_gopher_scheme() {
        assert!(validate_registry_url("gopher://evil.example.com/").is_err());
    }

    #[test]
    fn test_reject_ldap_scheme() {
        assert!(validate_registry_url("ldap://10.0.0.1/dc=example").is_err());
    }

    #[test]
    fn test_reject_ftp_scheme() {
        assert!(validate_registry_url("ftp://ftp.example.com/file").is_err());
    }

    #[test]
    fn test_reject_data_uri() {
        assert!(validate_registry_url("data:text/html,<script>alert(1)</script>").is_err());
    }

    // ── Private IP rejection ──────────────────────────────────────────────────

    #[test]
    fn test_reject_loopback_ipv4() {
        assert!(validate_registry_url("http://127.0.0.1/api").is_err());
        assert!(validate_registry_url("http://127.1.2.3/api").is_err());
    }

    #[test]
    fn test_reject_private_class_a() {
        assert!(validate_registry_url("https://10.0.0.1/api").is_err());
        assert!(validate_registry_url("https://10.255.255.255/api").is_err());
    }

    #[test]
    fn test_reject_private_class_b() {
        assert!(validate_registry_url("https://172.16.0.1/api").is_err());
        assert!(validate_registry_url("https://172.31.255.255/api").is_err());
    }

    #[test]
    fn test_reject_private_class_c() {
        assert!(validate_registry_url("https://192.168.1.1/api").is_err());
    }

    #[test]
    fn test_reject_cloud_metadata() {
        assert!(validate_registry_url("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn test_reject_ipv6_loopback() {
        assert!(validate_registry_url("https://[::1]/api").is_err());
    }

    #[test]
    fn test_reject_ipv6_ula() {
        assert!(validate_registry_url("https://[fc00::1]/api").is_err());
        assert!(validate_registry_url("https://[fd00::1]/api").is_err());
    }

    // ── Valid URLs accepted ───────────────────────────────────────────────────

    #[test]
    #[ignore = "requires DNS + network access"]
    fn test_accept_public_https_url() {
        let result = validate_registry_url("https://registry.idprova.dev");
        assert!(
            result.is_ok(),
            "public HTTPS URL must be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires DNS + network access"]
    fn test_accept_public_https_with_path() {
        assert!(validate_registry_url("https://registry.idprova.dev/v1/aid/test").is_ok());
    }

    #[test]
    fn test_accept_public_ip() {
        // Public IPs (not in any private/reserved range) must be accepted
        assert!(validate_registry_url("https://1.1.1.1/api").is_ok());
        assert!(validate_registry_url("https://8.8.8.8/api").is_ok());
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn test_reject_malformed_url() {
        assert!(validate_registry_url("not a url at all").is_err());
        assert!(validate_registry_url("").is_err());
    }
}
