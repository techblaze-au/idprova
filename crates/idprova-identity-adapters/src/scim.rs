//! `ScimProvisioner` — port for SCIM 2.0 user/group lifecycle.
//!
//! IDProva exposes SCIM 2.0 endpoints (per RFC 0001 §6.2 / RFC 7644)
//! so IdPs like Okta and Entra can drive agent provisioning into the
//! registry. This trait is the seam between the registry's HTTP
//! handlers and the per-tenant business logic that translates SCIM
//! resources into IDProva AIDs.
//!
//! IANA-pending URN for the IDProva agent extension:
//! `urn:ietf:params:scim:schemas:extension:idprova:2.0:Agent`.

use serde::{Deserialize, Serialize};

use crate::error::AdapterResult;

/// SCIM 2.0 user resource — the subset IDProva consumes during
/// provisioning. Adapters MAY persist additional fields via the
/// [`ScimUser::extra`] map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    /// SCIM `id` — the canonical identifier in the IdP's directory.
    pub id: String,
    /// SCIM `userName` (typically the IdP-side login).
    #[serde(rename = "userName")]
    pub user_name: String,
    /// SCIM `active` flag. `false` means the user has been deprovisioned
    /// at the IdP and IDProva MUST revoke all AIDs they control.
    #[serde(default = "ScimUser::default_active")]
    pub active: bool,
    /// Display name (`displayName`), if present.
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    /// Email addresses (`emails`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    /// IDProva agent extension claims under URN
    /// `urn:ietf:params:scim:schemas:extension:idprova:2.0:Agent`.
    #[serde(rename = "agent", default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<ScimAgentExtension>,
    /// Vendor-specific or unstandardised SCIM attributes.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl ScimUser {
    fn default_active() -> bool {
        true
    }
}

/// SCIM email subresource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    /// Email address string (`value`).
    pub value: String,
    /// `true` if this is the user's primary email.
    #[serde(default)]
    pub primary: bool,
    /// Optional SCIM `type` tag (`"work"`, `"home"`, etc.).
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
}

/// IDProva-specific SCIM extension claims. The IANA-pending URN is
/// `urn:ietf:params:scim:schemas:extension:idprova:2.0:Agent`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScimAgentExtension {
    /// IDProva DID for this agent (if pre-allocated by the IdP).
    #[serde(rename = "did", default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// AI model identifier (e.g. `"acme-ai/agent-v1"`).
    #[serde(rename = "model", default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Runtime environment identifier (e.g. `"agents.acme.io"`).
    #[serde(rename = "runtime", default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Controller DID — the human or service principal responsible
    /// for this agent.
    #[serde(
        rename = "controller",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub controller: Option<String>,
}

/// SCIM 2.0 group resource — the subset IDProva consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    /// SCIM `id` — canonical group identifier in the IdP directory.
    pub id: String,
    /// Human-readable group name (`displayName`).
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Member references (users + nested groups).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMember>,
    /// Vendor-specific or unstandardised group attributes.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// A member reference inside a [`ScimGroup`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMember {
    /// SCIM `id` of the referenced user or group.
    pub value: String,
    /// Optional SCIM `type` tag (`"User"` or `"Group"`).
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub member_type: Option<String>,
}

/// SCIM 2.0 provisioning port.
///
/// Implementations sit between the registry's SCIM HTTP handlers and
/// the per-tenant store. They translate SCIM resources into IDProva
/// AIDs (via [`provision_user`]) and respect SCIM's hard-/soft-delete
/// semantics on deprovisioning.
///
/// [`provision_user`]: Self::provision_user
pub trait ScimProvisioner: Send + Sync {
    /// Create a new agent identity for the supplied SCIM user.
    ///
    /// Returns the IDProva DID assigned to the agent. Implementations
    /// MUST be idempotent on `(user.id, user.user_name)` — repeated
    /// calls with the same input MUST return the same DID.
    fn provision_user<'a>(
        &'a self,
        user: &'a ScimUser,
    ) -> impl std::future::Future<Output = AdapterResult<String>> + Send + 'a;

    /// Update an existing user's SCIM attributes. Adapters MAY refuse
    /// updates that would change the underlying DID; in that case
    /// they MUST return [`crate::error::AdapterError::InvalidInput`].
    fn update_user<'a>(
        &'a self,
        id: &'a str,
        user: &'a ScimUser,
    ) -> impl std::future::Future<Output = AdapterResult<()>> + Send + 'a;

    /// Deprovision a user. `hard_delete` distinguishes soft-delete
    /// (DAT revocation + AID deactivation) from hard-delete
    /// (record removed entirely). Per RFC 7644 §3.6 SCIM defaults to
    /// soft-delete on `active: false`; hard-delete on `DELETE`.
    fn deprovision_user<'a>(
        &'a self,
        id: &'a str,
        hard_delete: bool,
    ) -> impl std::future::Future<Output = AdapterResult<()>> + Send + 'a;

    /// Create or update a SCIM group. Group membership is reflected
    /// in IDProva by re-evaluating each member's scope set against
    /// the [`crate::attributes::AttributeMapper`] (the implementation
    /// is responsible for triggering re-evaluation).
    fn upsert_group<'a>(
        &'a self,
        group: &'a ScimGroup,
    ) -> impl std::future::Future<Output = AdapterResult<()>> + Send + 'a;

    /// Delete a group. Member AIDs are NOT deleted; their scope sets
    /// are recomputed by the registry.
    fn delete_group<'a>(
        &'a self,
        id: &'a str,
    ) -> impl std::future::Future<Output = AdapterResult<()>> + Send + 'a;
}
