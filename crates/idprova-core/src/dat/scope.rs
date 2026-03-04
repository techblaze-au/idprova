use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{IdprovaError, Result};

/// A single permission scope in the format `namespace:protocol:resource:action`.
///
/// ## Grammar (4-part)
///
/// ```text
/// scope = namespace ":" protocol ":" resource ":" action
/// ```
///
/// Each component may be a literal value or `"*"` (wildcard, matches anything).
///
/// ## Fields
///
/// | Field       | Description                                      | Examples                      |
/// |-------------|--------------------------------------------------|-------------------------------|
/// | `namespace` | Protocol family                                  | `mcp`, `a2a`, `idprova`, `http` |
/// | `protocol`  | Sub-protocol or category within the namespace    | `tool`, `prompt`, `resource`, `agent` |
/// | `resource`  | Specific resource (tool name, endpoint, etc.)    | `filesystem`, `search`, `billing` |
/// | `action`    | Operation being requested                        | `read`, `write`, `execute`, `call` |
///
/// ## Examples
///
/// ```text
/// mcp:tool:filesystem:read     — read access to the filesystem MCP tool
/// mcp:tool:*:*                 — all tools, any action
/// mcp:tool:filesystem:*        — all actions on the filesystem tool
/// a2a:agent:billing:execute    — execute on the billing A2A agent
/// idprova:registry:aid:write   — write AIDs to the IDProva registry
/// *:*:*:*                      — unrestricted (root delegation only)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Scope {
    /// Protocol family (e.g., "mcp", "a2a", "idprova").
    pub namespace: String,
    /// Sub-protocol within the namespace (e.g., "tool", "prompt", "agent").
    pub protocol: String,
    /// Specific resource targeted (e.g., "filesystem", "billing").
    pub resource: String,
    /// Action being requested (e.g., "read", "write", "execute").
    pub action: String,
}

impl Scope {
    /// Parse a 4-part scope string `namespace:protocol:resource:action`.
    ///
    /// Returns an error if the string does not contain exactly 4 colon-separated parts.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(5, ':').collect();
        if parts.len() != 4 {
            return Err(IdprovaError::ScopeNotPermitted(format!(
                "scope must have 4 parts (namespace:protocol:resource:action), got: {s}"
            )));
        }

        Ok(Self {
            namespace: parts[0].to_string(),
            protocol: parts[1].to_string(),
            resource: parts[2].to_string(),
            action: parts[3].to_string(),
        })
    }

    /// Check if this scope covers (permits) the requested scope.
    ///
    /// A scope covers another if each component either matches exactly
    /// or this scope's component is the wildcard `"*"`.
    pub fn covers(&self, requested: &Scope) -> bool {
        (self.namespace == "*" || self.namespace == requested.namespace)
            && (self.protocol == "*" || self.protocol == requested.protocol)
            && (self.resource == "*" || self.resource == requested.resource)
            && (self.action == "*" || self.action == requested.action)
    }

    /// Convert to the canonical string representation.
    pub fn to_string_repr(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.namespace, self.protocol, self.resource, self.action
        )
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

/// A set of scopes that can be checked for permission coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSet {
    scopes: Vec<Scope>,
}

impl ScopeSet {
    pub fn new(scopes: Vec<Scope>) -> Self {
        Self { scopes }
    }

    /// Parse a list of scope strings.
    pub fn parse(scope_strings: &[String]) -> Result<Self> {
        let scopes: Result<Vec<Scope>> = scope_strings.iter().map(|s| Scope::parse(s)).collect();
        Ok(Self { scopes: scopes? })
    }

    /// Check if the scope set permits the requested scope.
    pub fn permits(&self, requested: &Scope) -> bool {
        self.scopes.iter().any(|s| s.covers(requested))
    }

    /// Check if this scope set is a subset of (narrower than or equal to) another.
    /// Used to enforce scope narrowing in delegation chains.
    pub fn is_subset_of(&self, parent: &ScopeSet) -> bool {
        self.scopes.iter().all(|s| parent.permits(s))
    }

    /// Get the scopes as strings.
    pub fn to_strings(&self) -> Vec<String> {
        self.scopes.iter().map(|s| s.to_string_repr()).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter()
    }

    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope() {
        let s = Scope::parse("mcp:tool:filesystem:read").unwrap();
        assert_eq!(s.namespace, "mcp");
        assert_eq!(s.protocol, "tool");
        assert_eq!(s.resource, "filesystem");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn test_parse_scope_rejects_3_parts() {
        assert!(
            Scope::parse("mcp:tool:read").is_err(),
            "3-part scopes must be rejected — use 4 parts: mcp:tool:*:read"
        );
    }

    #[test]
    fn test_parse_scope_rejects_2_parts() {
        assert!(Scope::parse("mcp:tool").is_err());
    }

    #[test]
    fn test_scope_covers_exact() {
        let parent = Scope::parse("mcp:tool:filesystem:read").unwrap();
        let child = Scope::parse("mcp:tool:filesystem:read").unwrap();
        assert!(parent.covers(&child));
    }

    #[test]
    fn test_scope_wildcard_covers() {
        // Wildcard on all fields
        let parent = Scope::parse("mcp:*:*:*").unwrap();
        let child = Scope::parse("mcp:tool:filesystem:read").unwrap();
        assert!(parent.covers(&child));

        // Wildcard on resource + action only
        let partial = Scope::parse("mcp:tool:*:*").unwrap();
        assert!(partial.covers(&child));
        assert!(!partial.covers(&Scope::parse("a2a:agent:billing:execute").unwrap()));
    }

    #[test]
    fn test_scope_wildcard_action_only() {
        let parent = Scope::parse("mcp:tool:filesystem:*").unwrap();
        assert!(parent.covers(&Scope::parse("mcp:tool:filesystem:read").unwrap()));
        assert!(parent.covers(&Scope::parse("mcp:tool:filesystem:write").unwrap()));
        assert!(!parent.covers(&Scope::parse("mcp:tool:search:read").unwrap()));
    }

    #[test]
    fn test_scope_does_not_cover() {
        let parent = Scope::parse("mcp:tool:filesystem:read").unwrap();
        let child = Scope::parse("mcp:tool:filesystem:write").unwrap();
        assert!(!parent.covers(&child));
    }

    #[test]
    fn test_scope_set_permits() {
        let set = ScopeSet::parse(&[
            "mcp:tool:filesystem:read".to_string(),
            "mcp:resource:data:read".to_string(),
        ])
        .unwrap();

        assert!(set.permits(&Scope::parse("mcp:tool:filesystem:read").unwrap()));
        assert!(set.permits(&Scope::parse("mcp:resource:data:read").unwrap()));
        assert!(!set.permits(&Scope::parse("mcp:tool:filesystem:write").unwrap()));
        assert!(!set.permits(&Scope::parse("a2a:agent:billing:execute").unwrap()));
    }

    #[test]
    fn test_scope_set_narrowing() {
        let parent = ScopeSet::parse(&["mcp:*:*:*".to_string()]).unwrap();
        let child = ScopeSet::parse(&["mcp:tool:filesystem:read".to_string()]).unwrap();
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn test_scope_set_narrowing_partial_wildcard() {
        let parent = ScopeSet::parse(&["mcp:tool:*:read".to_string()]).unwrap();
        let child = ScopeSet::parse(&["mcp:tool:filesystem:read".to_string()]).unwrap();
        assert!(child.is_subset_of(&parent));

        // Cannot expand resource wildcard
        let wider = ScopeSet::parse(&["mcp:tool:*:*".to_string()]).unwrap();
        assert!(!wider.is_subset_of(&parent));
    }

    #[test]
    fn test_scope_display() {
        let s = Scope::parse("mcp:tool:filesystem:read").unwrap();
        assert_eq!(s.to_string(), "mcp:tool:filesystem:read");
    }
}
