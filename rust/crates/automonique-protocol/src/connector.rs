// SPDX-License-Identifier: Elastic-2.0

//! The platform-neutral connector vocabulary.
//!
//! Teams Activities, Adaptive Cards, Discord Interactions and Components stay
//! in their platform packages. Nothing here names them, and
//! `tests/connector.rs` scans this crate's sources to keep it that way — a
//! boundary that is only documented is a boundary that leaks.
//!
//! Outbound content is a typed [`RenderIntent`] derived from durable events,
//! never a platform model string or pre-rendered markup, so a connector cannot
//! invent state a platform user then believes.
//!
//! Nothing here speaks to a platform, verifies a webhook signature, holds a bot
//! token, renders a card or sends a message.

use core::fmt;
use std::error::Error;

use crate::identity::Actor;
use crate::primitives::{EpochMillis, Revision, ValueError};
use crate::release::ArtifactDigest;

/// Maximum UTF-8 byte length of a connector identifier.
pub const MAX_CONNECTOR_FIELD_BYTES: usize = 256;

/// Maximum UTF-8 byte length of rendered intent text.
pub const MAX_INTENT_TEXT_BYTES: usize = 4_096;

/// Why a connector operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectorError {
    /// An action token no longer matches its target's revision.
    TargetRevisionChanged {
        /// The revision the token was bound to.
        bound_to: u64,
        /// The revision the target is at now.
        current: u64,
    },
    /// An action token has passed its expiry.
    TokenExpired,
    /// The acting user is not eligible for this action.
    ActorNotEligible,
    /// A grant was requested for more bytes than may be transferred.
    GrantTooLarge {
        /// Maximum grantable bytes.
        max_bytes: u64,
        /// Bytes requested.
        requested: u64,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl ConnectorError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::TargetRevisionChanged { .. } => "target_revision_changed",
            Self::TokenExpired => "token_expired",
            Self::ActorNotEligible => "actor_not_eligible",
            Self::GrantTooLarge { .. } => "grant_too_large",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetRevisionChanged { bound_to, current } => write!(
                formatter,
                "action was bound to revision {bound_to}; the target is at {current}"
            ),
            Self::TokenExpired => formatter.write_str("action token has expired"),
            Self::ActorNotEligible => {
                formatter.write_str("the acting user is not eligible for this action")
            }
            Self::GrantTooLarge {
                max_bytes,
                requested,
            } => write!(
                formatter,
                "grant of {requested} bytes exceeds the maximum of {max_bytes}"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ConnectorError {}

/// One platform application installation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationKey {
    platform: String,
    application: String,
    installation_owner: String,
}

impl InstallationKey {
    /// Identify an installation.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid component.
    pub fn new(
        platform: &str,
        application: &str,
        installation_owner: &str,
    ) -> Result<Self, ConnectorError> {
        bounded(platform, "platform")?;
        bounded(application, "application")?;
        bounded(installation_owner, "installation_owner")?;
        Ok(Self {
            platform: platform.to_owned(),
            application: application.to_owned(),
            installation_owner: installation_owner.to_owned(),
        })
    }

    /// The platform.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }
}

/// What an installation lookup found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantResolution {
    /// The installation is bound to exactly one tenant.
    Resolved {
        /// The bound tenant.
        tenant: String,
    },
    /// The installation is unknown.
    ///
    /// There is no fallback tenant variant, so an unrecognized installation
    /// cannot resolve to a default.
    InstallationRequired,
}

/// Installations bound to tenants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstallationRegistry {
    bindings: Vec<(InstallationKey, String)>,
}

impl InstallationRegistry {
    /// Start an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// Bind one installation to one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid tenant.
    pub fn bind(&mut self, key: InstallationKey, tenant: &str) -> Result<(), ConnectorError> {
        bounded(tenant, "tenant")?;
        self.bindings.retain(|(existing, _)| existing != &key);
        self.bindings.push((key, tenant.to_owned()));
        Ok(())
    }

    /// Resolve an installation.
    #[must_use]
    pub fn resolve(&self, key: &InstallationKey) -> TenantResolution {
        self.bindings
            .iter()
            .find(|(existing, _)| existing == key)
            .map_or(TenantResolution::InstallationRequired, |(_, tenant)| {
                TenantResolution::Resolved {
                    tenant: tenant.clone(),
                }
            })
    }
}

/// What an external identity lookup found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityResolution {
    /// Mapped to a durable actor.
    Linked {
        /// The mapped actor.
        actor: Actor,
    },
    /// Not mapped. A first-class outcome, never an anonymous actor.
    Unlinked {
        /// What the platform user must be told to do.
        link_prompt: String,
    },
}

/// A stable key for one platform event.
///
/// Derived from the platform, the installation and the platform's own immutable
/// event identity. Nothing else is accepted, so a key cannot absorb a
/// timestamp, a random value or a connector process identity, and the same
/// event yields the same key across restarts and instances.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceKey(String);

impl SourceKey {
    /// Derive a source key.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid component.
    pub fn derive(
        installation: &InstallationKey,
        platform_event_id: &str,
    ) -> Result<Self, ConnectorError> {
        bounded(platform_event_id, "platform_event_id")?;
        Ok(Self(format!(
            "{}:{}:{}:{platform_event_id}",
            installation.platform, installation.application, installation.installation_owner
        )))
    }

    /// The derived key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A platform-level acknowledgement.
///
/// Says only that the platform's deadline was met. Deliberately not
/// convertible into a [`BusinessAcceptance`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    deferred: bool,
}

impl Acknowledgement {
    /// Acknowledge immediately.
    #[must_use]
    pub const fn immediate() -> Self {
        Self { deferred: false }
    }

    /// Acknowledge with a deferred response.
    #[must_use]
    pub const fn deferred() -> Self {
        Self { deferred: true }
    }

    /// Whether the acknowledgement deferred its response.
    #[must_use]
    pub const fn is_deferred(self) -> bool {
        self.deferred
    }
}

/// Confirmation that Automonique durably accepted the work.
///
/// Constructible only from a durable input identity, so `accepted` cannot be
/// reported before one exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessAcceptance {
    input_id: String,
}

impl BusinessAcceptance {
    /// Record acceptance against a durable input.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid input identity.
    pub fn for_input(input_id: &str) -> Result<Self, ConnectorError> {
        bounded(input_id, "input_id")?;
        Ok(Self {
            input_id: input_id.to_owned(),
        })
    }

    /// The durable input this acceptance refers to.
    #[must_use]
    pub fn input_id(&self) -> &str {
        &self.input_id
    }
}

/// Outbound content, expressed as intent rather than presentation.
///
/// Every variant carries structured fields and bounded text. There is no
/// variant and no field carrying platform markup, a card payload or a
/// pre-rendered body, so a connector renders from these rather than being
/// handed something to display.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenderIntent {
    /// Work is progressing.
    Progress {
        /// Bounded human-readable summary.
        summary: String,
        /// Completed steps.
        completed: u32,
        /// Total steps, when known.
        total: Option<u32>,
    },
    /// Automonique needs an answer before continuing.
    Clarification {
        /// Bounded question.
        question: String,
    },
    /// A decision is required.
    Approval {
        /// Bounded description of what is being approved.
        summary: String,
        /// The revision the decision applies to.
        target_revision: Revision,
    },
    /// The work reached its end.
    Terminal {
        /// Bounded outcome summary.
        summary: String,
        /// Whether the work succeeded.
        succeeded: bool,
    },
}

impl RenderIntent {
    /// Build a progress intent.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] when the summary is unbounded.
    pub fn progress(
        summary: &str,
        completed: u32,
        total: Option<u32>,
    ) -> Result<Self, ConnectorError> {
        bounded_text(summary, "summary")?;
        Ok(Self::Progress {
            summary: summary.to_owned(),
            completed,
            total,
        })
    }

    /// Build a terminal intent.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] when the summary is unbounded.
    pub fn terminal(summary: &str, succeeded: bool) -> Result<Self, ConnectorError> {
        bounded_text(summary, "summary")?;
        Ok(Self::Terminal {
            summary: summary.to_owned(),
            succeeded,
        })
    }

    /// Stable lowercase kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Progress { .. } => "progress",
            Self::Clarification { .. } => "clarification",
            Self::Approval { .. } => "approval",
            Self::Terminal { .. } => "terminal",
        }
    }
}

/// An opaque token binding an interactive control to an exact target.
///
/// The token is opaque to the platform and stored as a hash. A changed target
/// revision is a conflict rather than a re-targeted action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionToken {
    opaque: String,
    target: String,
    target_revision: Revision,
    eligible_actor: Actor,
    expires_at: EpochMillis,
}

impl ActionToken {
    /// Mint a token bound to a target revision and an eligible actor.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid component.
    pub fn mint(
        opaque: &str,
        target: &str,
        target_revision: Revision,
        eligible_actor: Actor,
        expires_at: EpochMillis,
    ) -> Result<Self, ConnectorError> {
        bounded(opaque, "opaque_token")?;
        bounded(target, "target")?;
        Ok(Self {
            opaque: opaque.to_owned(),
            target: target.to_owned(),
            target_revision,
            eligible_actor,
            expires_at,
        })
    }

    /// The form kept in storage.
    ///
    /// A non-cryptographic stand-in for the real digest, which needs a hash
    /// implementation this crate does not carry. What matters here is that the
    /// stored form is not the token: a store leak does not yield usable
    /// tokens.
    #[must_use]
    pub fn stored_form(&self) -> String {
        let mut folded: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.opaque.as_bytes() {
            folded ^= u64::from(*byte);
            folded = folded.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("h:{folded:016x}")
    }

    /// The target this token acts on.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Resolve the token against the target's current revision.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::TokenExpired`],
    /// [`ConnectorError::ActorNotEligible`] or
    /// [`ConnectorError::TargetRevisionChanged`] — three distinct outcomes, so
    /// a caller can tell "too late" from "not yours" from "it moved".
    pub fn resolve(
        &self,
        now: EpochMillis,
        acting_actor: &Actor,
        current_revision: Revision,
    ) -> Result<(), ConnectorError> {
        if now.as_millis() >= self.expires_at.as_millis() {
            return Err(ConnectorError::TokenExpired);
        }
        if !acting_actor
            .is_same_as(&self.eligible_actor)
            .unwrap_or(false)
        {
            return Err(ConnectorError::ActorNotEligible);
        }
        if current_revision != self.target_revision {
            return Err(ConnectorError::TargetRevisionChanged {
                bound_to: self.target_revision.get(),
                current: current_revision.get(),
            });
        }
        Ok(())
    }
}

/// Which way bytes move under a grant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GrantDirection {
    /// The platform sends bytes to Automonique.
    Upload,
    /// Automonique sends bytes to the platform.
    Download,
}

/// A bounded permission to move one artifact.
///
/// Names a digest and a ceiling. There is no path, no URL and no inline
/// payload, so attachments cannot travel as anything else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactGrant {
    direction: GrantDirection,
    digest: ArtifactDigest,
    max_bytes: u64,
    expires_at: EpochMillis,
}

impl ArtifactGrant {
    /// Maximum bytes any single grant may cover.
    pub const MAX_GRANT_BYTES: u64 = 512 * 1024 * 1024;

    /// Issue a grant.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::GrantTooLarge`] above the ceiling.
    pub fn issue(
        direction: GrantDirection,
        digest: ArtifactDigest,
        max_bytes: u64,
        expires_at: EpochMillis,
    ) -> Result<Self, ConnectorError> {
        if max_bytes > Self::MAX_GRANT_BYTES {
            return Err(ConnectorError::GrantTooLarge {
                max_bytes: Self::MAX_GRANT_BYTES,
                requested: max_bytes,
            });
        }
        Ok(Self {
            direction,
            digest,
            max_bytes,
            expires_at,
        })
    }

    /// Which way bytes move.
    #[must_use]
    pub const fn direction(&self) -> GrantDirection {
        self.direction
    }

    /// The artifact this grant covers.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// The byte ceiling.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Whether the grant is still usable.
    #[must_use]
    pub const fn is_valid_at(&self, now: EpochMillis) -> bool {
        now.as_millis() < self.expires_at.as_millis()
    }
}

/// Where a platform message sits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationCoordinates {
    installation: InstallationKey,
    conversation: String,
    thread: Option<String>,
    message: String,
    locale: Option<String>,
    mentioned: bool,
}

impl ConversationCoordinates {
    /// Record where a message came from.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid component.
    pub fn new(
        installation: InstallationKey,
        conversation: &str,
        thread: Option<&str>,
        message: &str,
        locale: Option<&str>,
        mentioned: bool,
    ) -> Result<Self, ConnectorError> {
        bounded(conversation, "conversation")?;
        bounded(message, "message")?;
        if let Some(thread) = thread {
            bounded(thread, "thread")?;
        }
        if let Some(locale) = locale {
            bounded(locale, "locale")?;
        }
        Ok(Self {
            installation,
            conversation: conversation.to_owned(),
            thread: thread.map(str::to_owned),
            message: message.to_owned(),
            locale: locale.map(str::to_owned),
            mentioned,
        })
    }

    /// The conversation scope.
    #[must_use]
    pub fn conversation(&self) -> &str {
        &self.conversation
    }

    /// The thread or reply key, when the platform has one.
    #[must_use]
    pub fn thread(&self) -> Option<&str> {
        self.thread.as_deref()
    }

    /// The platform message identity.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether Automonique was mentioned.
    #[must_use]
    pub const fn was_mentioned(&self) -> bool {
        self.mentioned
    }
}

/// What happened to a source message after it arrived.
///
/// An edit produces a revision and a deletion produces a tombstone. Neither
/// rewrites an approved action, because neither variant carries one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceMessageEvent {
    /// The platform user edited the message.
    Revised {
        /// The new revision of the source message.
        revision: Revision,
    },
    /// The platform user deleted the message.
    Tombstoned {
        /// When the deletion was observed.
        at: EpochMillis,
    },
}

fn bounded(value: &str, field: &'static str) -> Result<(), ConnectorError> {
    check(value, field, MAX_CONNECTOR_FIELD_BYTES)
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), ConnectorError> {
    check(value, field, MAX_INTENT_TEXT_BYTES)
}

fn check(value: &str, field: &'static str, max_bytes: usize) -> Result<(), ConnectorError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > max_bytes {
        Some(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ConnectorError::Field { field, error }),
        None => Ok(()),
    }
}
