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
