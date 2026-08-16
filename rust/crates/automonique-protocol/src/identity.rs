// SPDX-License-Identifier: Elastic-2.0

//! Tenant-scoped actors, policy evaluation and credential records.
//!
//! This is the layer everything else is authorized against, so its job is to
//! make an unauthorized state unrepresentable rather than merely rejected.
//!
//! A secret value cannot be stored in any type here. A credential is a record
//! naming one, and a record is not usable as the thing it names. First the
//! construction that does compile, so the two failures below are attributable
//! to the thing each rejects:
//!
//! ```
//! use automonique_protocol::identity::CredentialRecord;
//! let record = CredentialRecord::new(
//!     "database", 3, "platform", "read replica", "daemon", None,
//! ).unwrap();
//! assert_eq!(record.name(), "database");
//! assert_eq!(record.version(), 3);
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::identity::CredentialRecord;
//! // There is no constructor that accepts a secret value.
//! let record = CredentialRecord::new(
//!     "database", 3, "platform", "read replica", "daemon", None, "s3cret",
//! ).unwrap();
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::identity::CredentialRecord;
//! let record = CredentialRecord::new(
//!     "database", 3, "platform", "read replica", "daemon", None,
//! ).unwrap();
//! // Nor any accessor that returns one.
//! let value: String = record.secret();
//! ```
//!
//! Nothing here authenticates, resolves a credential, contacts an identity
//! provider, reads a store or grants a session.

use core::fmt;
use std::error::Error;

use crate::primitives::{EpochMillis, Revision, ValueError};

/// Maximum UTF-8 byte length of an identity field.
pub const MAX_IDENTITY_FIELD_BYTES: usize = 128;

/// Why an identity or policy operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Two actors from different tenants were compared.
    ///
    /// Returned rather than `false`, because silently answering "not equal" is
    /// how a cross-tenant check becomes a no-op.
    CrossTenantComparison {
        /// The left operand's tenant.
        left: String,
        /// The right operand's tenant.
        right: String,
    },
    /// A mutable platform attribute was offered as an identity key.
    MutableAttributeAsKey {
        /// The attribute that was refused.
        attribute: &'static str,
    },
    /// A break-glass grant carried no expiry.
    BreakGlassNeedsExpiry,
    /// A bounded identity field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl IdentityError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::CrossTenantComparison { .. } => "cross_tenant_comparison",
            Self::MutableAttributeAsKey { .. } => "mutable_attribute_as_key",
            Self::BreakGlassNeedsExpiry => "break_glass_needs_expiry",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossTenantComparison { left, right } => write!(
                formatter,
                "actors from tenants {left} and {right} are not comparable"
            ),
            Self::MutableAttributeAsKey { attribute } => write!(
                formatter,
                "{attribute} is a mutable attribute and cannot key an identity"
            ),
            Self::BreakGlassNeedsExpiry => {
                formatter.write_str("a break-glass grant must carry an expiry")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for IdentityError {}

/// A tenant-scoped principal.
///
/// There is no constructor without a tenant, so a tenant-free actor cannot
/// exist.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Actor {
    tenant: String,
    id: String,
}

impl Actor {
    /// Name an actor within a tenant.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Field`] for an invalid component.
    pub fn new(tenant: &str, id: &str) -> Result<Self, IdentityError> {
        bounded(tenant, "tenant")?;
        bounded(id, "actor_id")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            id: id.to_owned(),
        })
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The actor identity within its tenant.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether two actors are the same principal.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CrossTenantComparison`] when the operands come
    /// from different tenants. Answering `false` there would let a
    /// cross-tenant check pass as a successful comparison.
    pub fn is_same_as(&self, other: &Self) -> Result<bool, IdentityError> {
        if self.tenant != other.tenant {
            return Err(IdentityError::CrossTenantComparison {
                left: self.tenant.clone(),
                right: other.tenant.clone(),
            });
        }
        Ok(self.id == other.id)
    }
}

/// A platform attribute that may never key an identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MutableAttribute {
    /// Microsoft user principal name.
    UserPrincipalName,
    /// Email address.
    Email,
    /// Display name.
    DisplayName,
    /// Platform username or handle.
    Username,
    /// Platform role membership.
    Roles,
}

impl MutableAttribute {
    /// Every attribute, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::UserPrincipalName,
        Self::Email,
        Self::DisplayName,
        Self::Username,
        Self::Roles,
    ];

    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserPrincipalName => "user_principal_name",
            Self::Email => "email",
            Self::DisplayName => "display_name",
            Self::Username => "username",
            Self::Roles => "roles",
        }
    }
}

/// The immutable coordinates that identify an external user.
///
/// Only these four fields exist. A mutable attribute is not a field of this
/// type at all, which is why it cannot become a key by accident.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExternalIdentityKey {
    platform: String,
    application: String,
    external_tenant: String,
    immutable_user_id: String,
}

impl ExternalIdentityKey {
    /// Build an external identity key from immutable coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Field`] for an invalid component.
    pub fn new(
        platform: &str,
        application: &str,
        external_tenant: &str,
        immutable_user_id: &str,
    ) -> Result<Self, IdentityError> {
        bounded(platform, "platform")?;
        bounded(application, "application")?;
        bounded(external_tenant, "external_tenant")?;
        bounded(immutable_user_id, "immutable_user_id")?;
        Ok(Self {
            platform: platform.to_owned(),
            application: application.to_owned(),
            external_tenant: external_tenant.to_owned(),
            immutable_user_id: immutable_user_id.to_owned(),
        })
    }

    /// Refuse an attempt to key an identity on a mutable attribute.
    ///
    /// # Errors
    ///
    /// Always returns [`IdentityError::MutableAttributeAsKey`]. It exists so a
    /// caller reaching for the wrong thing gets a named refusal rather than a
    /// missing method.
    pub const fn keyed_on(attribute: MutableAttribute) -> Result<Self, IdentityError> {
        Err(IdentityError::MutableAttributeAsKey {
            attribute: attribute.as_str(),
        })
    }

    /// The platform.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// The platform's immutable user identifier.
    #[must_use]
    pub fn immutable_user_id(&self) -> &str {
        &self.immutable_user_id
    }
}

/// A grant of a role to an actor, recorded historically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleGrant {
    actor: Actor,
    role: String,
    granted_by: Actor,
    effective_from: Revision,
    effective_to: Option<Revision>,
    reason: String,
}

impl RoleGrant {
    /// Record a grant effective from one policy revision.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Field`] for an invalid role or reason.
    pub fn new(
        actor: Actor,
        role: &str,
        granted_by: Actor,
        effective_from: Revision,
        effective_to: Option<Revision>,
        reason: &str,
    ) -> Result<Self, IdentityError> {
        bounded(role, "role")?;
        bounded(reason, "reason")?;
        Ok(Self {
            actor,
            role: role.to_owned(),
            granted_by,
            effective_from,
            effective_to,
            reason: reason.to_owned(),
        })
    }

    /// The granted role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Who granted it.
    #[must_use]
    pub const fn granted_by(&self) -> &Actor {
        &self.granted_by
    }

    /// Why it was granted.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Whether the grant was in force at a policy revision.
    #[must_use]
    pub fn in_force_at(&self, revision: Revision) -> bool {
        revision.get() >= self.effective_from.get()
            && self
                .effective_to
                .is_none_or(|end| revision.get() < end.get())
    }
}

/// Why a request was denied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DenyReason {
    /// No grant matched the request.
    NoMatchingGrant,
    /// A grant exists but was not in force at the evaluated revision.
    GrantNotInForce,
    /// The actor belongs to another tenant.
    WrongTenant,
}

impl DenyReason {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingGrant => "no_matching_grant",
            Self::GrantNotInForce => "grant_not_in_force",
            Self::WrongTenant => "wrong_tenant",
        }
    }
}

/// The outcome of one authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionOutcome {
    /// Permitted by a named grant.
    Allow {
        /// The role that permitted it.
        role: String,
    },
    /// Refused, with exactly one reason.
    Deny {
        /// Why.
        reason: DenyReason,
    },
}

/// An authorization decision and the evidence that explains it.
///
/// Every field is required, so a decision without evidence cannot be
/// constructed and an allow can always be explained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    actor: Actor,
    permission: String,
    policy_revision: Revision,
    outcome: DecisionOutcome,
}

impl Decision {
    /// The actor the decision was made for.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The permission that was requested.
    #[must_use]
    pub fn permission(&self) -> &str {
        &self.permission
    }

    /// The policy revision it was evaluated against.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> &DecisionOutcome {
        &self.outcome
    }

    /// Whether the request was permitted.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self.outcome, DecisionOutcome::Allow { .. })
    }
}

/// Historical role grants and the permissions each role carries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyLedger {
    grants: Vec<RoleGrant>,
    role_permissions: Vec<(String, String)>,
}

impl PolicyLedger {
    /// Start an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            grants: Vec::new(),
            role_permissions: Vec::new(),
        }
    }

    /// Record a grant.
    pub fn grant(&mut self, grant: RoleGrant) {
        self.grants.push(grant);
    }

    /// Declare that a role carries a permission.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Field`] for an invalid identifier. There is no
    /// wildcard: a role carries the permissions it names and no others.
    pub fn allow_role(&mut self, role: &str, permission: &str) -> Result<(), IdentityError> {
        bounded(role, "role")?;
        bounded(permission, "permission")?;
        self.role_permissions
            .push((role.to_owned(), permission.to_owned()));
        Ok(())
    }

    /// Decide one request against one policy revision.
    ///
    /// Deny by default and total: an unmatched request is denied with a named
    /// reason, and there is no path on which an error yields permission.
    #[must_use]
    pub fn evaluate(&self, actor: &Actor, permission: &str, revision: Revision) -> Decision {
        let mut saw_expired_grant = false;
        for grant in &self.grants {
            // A grant for another tenant is not merely unmatched; it is the
            // wrong tenant, and the evidence says so.
            let Ok(same) = grant.actor.is_same_as(actor) else {
                continue;
            };
            if !same {
                continue;
            }
            let carries = self
                .role_permissions
                .iter()
                .any(|(role, allowed)| role == &grant.role && allowed == permission);
            if !carries {
                continue;
            }
            if grant.in_force_at(revision) {
                return Decision {
                    actor: actor.clone(),
                    permission: permission.to_owned(),
                    policy_revision: revision,
                    outcome: DecisionOutcome::Allow {
                        role: grant.role.clone(),
                    },
                };
            }
            saw_expired_grant = true;
        }

        let wrong_tenant = self
            .grants
            .iter()
            .any(|grant| grant.actor.id == actor.id && grant.actor.tenant != actor.tenant);
        let reason = if wrong_tenant {
            DenyReason::WrongTenant
        } else if saw_expired_grant {
            DenyReason::GrantNotInForce
        } else {
            DenyReason::NoMatchingGrant
        };
        Decision {
            actor: actor.clone(),
            permission: permission.to_owned(),
            policy_revision: revision,
            outcome: DecisionOutcome::Deny { reason },
        }
    }
}

/// The health of a credential, without its value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialHealth {
    /// Usable.
    Active,
    /// Usable, and a replacement is also active.
    RotationOverlap,
    /// Not usable; derived capabilities are invalid.
    Revoked,
    /// Past its expiry.
    Expired,
}

/// An operational record naming a credential.
///
/// This is the operational half of the descriptor a release manifest declares
/// in [`crate::release::CredentialDescriptor`]: that one says which credential
/// and version a release expects, this one records owner, purpose, audience and
/// health. Neither can hold a value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecord {
    name: String,
    version: u32,
    owner: String,
    purpose: String,
    audience: String,
    expires_at: Option<EpochMillis>,
    health: CredentialHealth,
}

impl CredentialRecord {
    /// Record a credential by name and version.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Field`] for an invalid component.
    pub fn new(
        name: &str,
        version: u32,
        owner: &str,
        purpose: &str,
        audience: &str,
        expires_at: Option<EpochMillis>,
    ) -> Result<Self, IdentityError> {
        bounded(name, "credential_name")?;
        bounded(owner, "owner")?;
        bounded(purpose, "purpose")?;
        bounded(audience, "audience")?;
        Ok(Self {
            name: name.to_owned(),
            version,
            owner: owner.to_owned(),
            purpose: purpose.to_owned(),
            audience: audience.to_owned(),
            expires_at,
            health: CredentialHealth::Active,
        })
    }

    /// Credential name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Credential version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Who owns it.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Current health.
    #[must_use]
    pub const fn health(&self) -> CredentialHealth {
        self.health
    }

    /// Begin a rotation, leaving both versions usable for an overlap window.
    #[must_use]
    pub fn rotating_to(&self, next_version: u32) -> (Self, Self) {
        let mut outgoing = self.clone();
        outgoing.health = CredentialHealth::RotationOverlap;
        let mut incoming = self.clone();
        incoming.version = next_version;
        incoming.health = CredentialHealth::RotationOverlap;
        (outgoing, incoming)
    }

    /// Revoke the credential.
    ///
    /// Derived capabilities are invalid immediately: `grants_capability`
    /// answers `false` from this point, with no grace period to opt into.
    #[must_use]
    pub fn revoked(&self) -> Self {
        let mut revoked = self.clone();
        revoked.health = CredentialHealth::Revoked;
        revoked
    }

    /// Whether a capability derived from this credential is still valid.
    #[must_use]
    pub fn grants_capability(&self, now: EpochMillis) -> bool {
        if matches!(
            self.health,
            CredentialHealth::Revoked | CredentialHealth::Expired
        ) {
            return false;
        }
        self.expires_at
            .is_none_or(|expiry| now.as_millis() < expiry.as_millis())
    }
}

/// A recorded emergency elevation.
///
/// Cannot be silent and cannot be unbounded in time. It is a durable value, so
/// restarting does not clear it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BreakGlassGrant {
    actor: Actor,
    reason: String,
    role: String,
    expires_at: EpochMillis,
}

impl BreakGlassGrant {
    /// Record an emergency elevation.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::BreakGlassNeedsExpiry`] when `expires_at` is
    /// absent, and [`IdentityError::Field`] for an invalid reason or role. A
    /// reason is required, so the grant cannot be silent.
    pub fn new(
        actor: Actor,
        reason: &str,
        role: &str,
        expires_at: Option<EpochMillis>,
    ) -> Result<Self, IdentityError> {
        bounded(reason, "reason")?;
        bounded(role, "role")?;
        let expires_at = expires_at.ok_or(IdentityError::BreakGlassNeedsExpiry)?;
        Ok(Self {
            actor,
            reason: reason.to_owned(),
            role: role.to_owned(),
            expires_at,
        })
    }

    /// Who invoked it.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Why.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The elevated role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Whether the elevation is still in force.
    #[must_use]
    pub fn is_active_at(&self, now: EpochMillis) -> bool {
        now.as_millis() < self.expires_at.as_millis()
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), IdentityError> {
    crate::primitives::bounded_value(value, MAX_IDENTITY_FIELD_BYTES)
        .map_err(|error| IdentityError::Field { field, error })
}
