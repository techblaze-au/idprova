//! Scope matching — delegates to `idprova_core::dat::scope`.

use idprova_core::dat::scope::Scope;

/// Check whether the `granted` scope string covers the `required` scope string.
///
/// Both must be 4-part colon-separated strings (namespace:protocol:resource:action).
/// Wildcards (`*`) in the granted scope match any value in that position.
///
/// Returns `true` if the granted scope permits the required scope.
///
/// # Examples
///
/// ```
/// use idprova_mcp::scope_covers;
///
/// assert!(scope_covers("mcp:tool:filesystem:read", "mcp:tool:filesystem:read"));
/// assert!(scope_covers("mcp:tool:*:*", "mcp:tool:filesystem:read"));
/// assert!(!scope_covers("mcp:tool:filesystem:read", "mcp:tool:filesystem:write"));
/// ```
pub fn scope_covers(granted: &str, required: &str) -> bool {
    let Ok(granted_scope) = Scope::parse(granted) else {
        return false;
    };
    let Ok(required_scope) = Scope::parse(required) else {
        return false;
    };
    granted_scope.covers(&required_scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(scope_covers(
            "mcp:tool:filesystem:read",
            "mcp:tool:filesystem:read"
        ));
    }

    #[test]
    fn test_wildcard_action() {
        assert!(scope_covers(
            "mcp:tool:filesystem:*",
            "mcp:tool:filesystem:read"
        ));
        assert!(scope_covers(
            "mcp:tool:filesystem:*",
            "mcp:tool:filesystem:write"
        ));
    }

    #[test]
    fn test_wildcard_resource_and_action() {
        assert!(scope_covers("mcp:tool:*:*", "mcp:tool:filesystem:read"));
        assert!(scope_covers("mcp:tool:*:*", "mcp:tool:search:execute"));
    }

    #[test]
    fn test_full_wildcard() {
        assert!(scope_covers("*:*:*:*", "mcp:tool:filesystem:read"));
    }

    #[test]
    fn test_no_match() {
        assert!(!scope_covers(
            "mcp:tool:filesystem:read",
            "mcp:tool:filesystem:write"
        ));
    }

    #[test]
    fn test_namespace_mismatch() {
        assert!(!scope_covers(
            "a2a:tool:filesystem:read",
            "mcp:tool:filesystem:read"
        ));
    }

    #[test]
    fn test_invalid_scope_returns_false() {
        assert!(!scope_covers("invalid", "mcp:tool:filesystem:read"));
        assert!(!scope_covers("mcp:tool:filesystem:read", "invalid"));
    }
}
