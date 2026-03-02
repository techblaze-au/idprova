use serde::{Deserialize, Serialize};
use std::fmt;

/// Trust levels for IDProva agent identities.
///
/// Higher levels require more verification and provide stronger guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Self-declared identity. No verification. Any agent can claim L0.
    L0,
    /// Domain-verified. DNS TXT record proves domain ownership.
    L1,
    /// Organization-verified. CA-like verification of the controlling organization.
    L2,
    /// Audited. Third-party security audit of the agent and its environment.
    L3,
    /// Continuously monitored. Real-time behavior analysis and compliance checking.
    L4,
}

impl TrustLevel {
    /// Parse from string (e.g., "L0", "L1", "L2", "L3", "L4").
    pub fn from_str_repr(s: &str) -> Option<Self> {
        match s {
            "L0" => Some(Self::L0),
            "L1" => Some(Self::L1),
            "L2" => Some(Self::L2),
            "L3" => Some(Self::L3),
            "L4" => Some(Self::L4),
            _ => None,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L4 => "L4",
        }
    }

    /// Human-readable description of the trust level.
    pub fn description(&self) -> &'static str {
        match self {
            Self::L0 => "Self-declared — unverified identity claim",
            Self::L1 => "Domain-verified — DNS TXT record confirms domain ownership",
            Self::L2 => "Organization-verified — CA-like verification of controlling entity",
            Self::L3 => "Audited — third-party security audit completed",
            Self::L4 => "Continuously monitored — real-time behavior and compliance analysis",
        }
    }

    /// Check if this trust level meets a minimum requirement.
    pub fn meets_minimum(&self, required: TrustLevel) -> bool {
        *self >= required
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_ordering() {
        assert!(TrustLevel::L0 < TrustLevel::L1);
        assert!(TrustLevel::L1 < TrustLevel::L2);
        assert!(TrustLevel::L2 < TrustLevel::L3);
        assert!(TrustLevel::L3 < TrustLevel::L4);
    }

    #[test]
    fn test_meets_minimum() {
        assert!(TrustLevel::L2.meets_minimum(TrustLevel::L1));
        assert!(TrustLevel::L1.meets_minimum(TrustLevel::L1));
        assert!(!TrustLevel::L0.meets_minimum(TrustLevel::L1));
    }

    #[test]
    fn test_parse_roundtrip() {
        for level in [
            TrustLevel::L0,
            TrustLevel::L1,
            TrustLevel::L2,
            TrustLevel::L3,
            TrustLevel::L4,
        ] {
            let s = level.as_str();
            let parsed = TrustLevel::from_str_repr(s).unwrap();
            assert_eq!(parsed, level);
        }
    }
}
