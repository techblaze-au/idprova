use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{IdprovaError, Result};

/// A single permission scope in the format `namespace:resource:action`.
///
/// Examples:
/// - `mcp:tool:filesystem:read`
/// - `mcp:tool:*:*`
/// - `a2a:agent:billing:execute`
/// - `idprova:delegate:L0`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Scope {
    pub namespace: String,
    pub resource: String,
    pub action: String,
}

impl Scope {
    /// Parse a scope string.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(IdprovaError::ScopeNotPermitted(format!(
                "scope must have 3 parts (namespace:resource:action), got: {s}"
            )));
        }

        Ok(Self {
            namespace: parts[0].to_string(),
            resource: parts[1].to_string(),
            action: parts[2].to_string(),
        })
    }

    /// Check if this scope covers (permits) the requested scope.
    ///
    /// A scope covers another if each component either matches exactly
    /// or is a wildcard "*".
    pub fn covers(&self, requested: &Scope) -> bool {
        (self.namespace == "*" || self.namespace == requested.namespace)
            && (self.resource == "*" || self.resource == requested.resource)
            && (self.action == "*" || self.action == requested.action)
    }

    /// Convert to the canonical string representation.
    pub fn to_string_repr(&self) -> String {
        format!("{}:{}:{}", self.namespace, self.resource, self.action)
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
        // Note: scope grammar has 3 parts — namespace:resource:action
        // "tool:filesystem" is the resource part (MCP tool name with namespace)
        assert_eq!(s.namespace, "mcp");
        assert_eq!(s.resource, "tool");
        assert_eq!(s.action, "filesystem:read");
    }

    #[test]
    fn test_scope_covers_exact() {
        let parent = Scope::parse("mcp:tool:read").unwrap();
        let child = Scope::parse("mcp:tool:read").unwrap();
        assert!(parent.covers(&child));
    }

    #[test]
    fn test_scope_wildcard_covers() {
        let parent = Scope::parse("mcp:*:*").unwrap();
        let child = Scope::parse("mcp:tool:read").unwrap();
        assert!(parent.covers(&child));
    }

    #[test]
    fn test_scope_does_not_cover() {
        let parent = Scope::parse("mcp:tool:read").unwrap();
        let child = Scope::parse("mcp:tool:write").unwrap();
        assert!(!parent.covers(&child));
    }

    #[test]
    fn test_scope_set_permits() {
        let set = ScopeSet::parse(&["mcp:tool:read".to_string(), "mcp:resource:read".to_string()])
            .unwrap();

        assert!(set.permits(&Scope::parse("mcp:tool:read").unwrap()));
        assert!(set.permits(&Scope::parse("mcp:resource:read").unwrap()));
        assert!(!set.permits(&Scope::parse("mcp:tool:write").unwrap()));
    }

    #[test]
    fn test_scope_set_narrowing() {
        let parent = ScopeSet::parse(&["mcp:*:*".to_string()]).unwrap();
        let child = ScopeSet::parse(&["mcp:tool:read".to_string()]).unwrap();
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }
}
