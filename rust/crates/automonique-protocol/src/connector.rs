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
//! invent state a platform user then believes. Wording enters through
//! [`IntentPhrase::parse`] and nowhere else, so no value of that type carries
//! markup — the boundary is a property of the type, not a check a caller might
//! skip:
//!
//! ```
//! use automonique_protocol::connector::IntentPhrase;
//! let phrase: IntentPhrase = IntentPhrase::parse("deployment finished").unwrap();
//! assert_eq!(phrase.as_str(), "deployment finished");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::connector::IntentPhrase;
//! let phrase: IntentPhrase = IntentPhrase("deployment finished".to_owned());
//! ```
//!
//! An intent is *derived*; it cannot be assembled. The only constructor takes a
//! [`DurableEvent`], so an outcome a connector invented on its own has nowhere
//! to go:
//!
//! ```
//! use automonique_protocol::connector::{DurableEvent, EventOutcome, IntentPhrase, RenderIntent};
//! use automonique_protocol::primitives::Revision;
//! let outcome = EventOutcome::Finished {
//!     summary: IntentPhrase::parse("deployment finished").unwrap(),
//!     succeeded: true,
//! };
//! let event = DurableEvent::record("evt-1", Revision::new(3).unwrap(), outcome).unwrap();
//! let intent = RenderIntent::derived_from(&event);
//! assert_eq!(intent.kind(), "terminal");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::connector::{EventOutcome, IntentPhrase, RenderIntent};
//! let outcome = EventOutcome::Finished {
//!     summary: IntentPhrase::parse("deployment finished").unwrap(),
//!     succeeded: true,
//! };
//! let intent = RenderIntent::derived_from(&outcome);
//! ```
//!
//! A deletion is recorded beside the history rather than in place of it. The
//! log hands out a shared slice and owns no removal method, so a tombstone
//! cannot erase an audit record or rewrite an approved action:
//!
//! ```
//! use automonique_protocol::connector::{
//!     ConversationCoordinates, InstallationKey, SourceMessageEvent, SourceMessageLog,
//! };
//! use automonique_protocol::primitives::EpochMillis;
//! let installation = InstallationKey::new("teams", "app-1", "ext-tenant-1").unwrap();
//! let coordinates =
//!     ConversationCoordinates::new(installation, "conv-1", None, "msg-1", None, false).unwrap();
//! let mut log = SourceMessageLog::opened(coordinates);
//! log.record(SourceMessageEvent::Tombstoned { at: EpochMillis::from_millis(1_000) });
//! assert_eq!(log.events().len(), 1);
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::connector::{
//!     ConversationCoordinates, InstallationKey, SourceMessageEvent, SourceMessageLog,
//! };
//! use automonique_protocol::primitives::EpochMillis;
//! let installation = InstallationKey::new("teams", "app-1", "ext-tenant-1").unwrap();
//! let coordinates =
//!     ConversationCoordinates::new(installation, "conv-1", None, "msg-1", None, false).unwrap();
//! let mut log = SourceMessageLog::opened(coordinates);
//! log.record(SourceMessageEvent::Tombstoned { at: EpochMillis::from_millis(1_000) });
//! log.events().clear();
//! ```
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

/// Characters an [`IntentPhrase`] cannot contain.
///
/// The set covers the ways a platform payload arrives dressed as text: XML and
/// HTML markup (`<`, `>`, `&`), a serialized card or component body (`{`, `}`,
/// `[`, `]`, `"`), and a fenced or escaped literal (`` ` ``, `\`). Wording that
/// needs one of these is presentation, and presentation belongs to the platform
/// package.
pub const MARKUP_CHARACTERS: [char; 10] = ['<', '>', '&', '{', '}', '[', ']', '"', '`', '\\'];

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
    /// Wording would have carried markup or a serialized platform payload.
    MarkupRejected {
        /// The rejected field.
        field: &'static str,
        /// The first [`MARKUP_CHARACTERS`] character found.
        character: char,
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
            Self::MarkupRejected { .. } => "markup_rejected",
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
            Self::MarkupRejected { field, character } => write!(
                formatter,
                "field {field}: {character:?} would carry markup or a platform payload"
            ),
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

    /// The platform application identity.
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// The external tenant, guild or installation owner.
    #[must_use]
    pub fn installation_owner(&self) -> &str {
        &self.installation_owner
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

/// Plain outbound wording, parsed once at the only door in.
///
/// The type has no public field, no `From<String>` and no `Deref`, and
/// [`parse`](Self::parse) refuses every [`MARKUP_CHARACTERS`] character, so a
/// value of this type carrying markup or a serialized platform model does not
/// exist. A [`RenderIntent`] holds these rather than `String`s, which is what
/// turns "must not be markup" from a rule a caller follows into a state the
/// program cannot reach.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntentPhrase(String);

impl IntentPhrase {
    /// Parse outbound wording.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] when the wording is empty, longer than
    /// [`MAX_INTENT_TEXT_BYTES`] or carries a control character, and
    /// [`ConnectorError::MarkupRejected`] naming the offending character when
    /// the wording is presentation rather than prose.
    pub fn parse(wording: &str) -> Result<Self, ConnectorError> {
        bounded_text(wording, "phrase")?;
        if let Some(character) = wording
            .chars()
            .find(|candidate| MARKUP_CHARACTERS.contains(candidate))
        {
            return Err(ConnectorError::MarkupRejected {
                field: "phrase",
                character,
            });
        }
        Ok(Self(wording.to_owned()))
    }

    /// The parsed wording.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IntentPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What a durable Automonique event recorded.
///
/// Every variant is structured: counts, a flag and parsed [`IntentPhrase`]
/// wording. No variant carries a body to display.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventOutcome {
    /// Work advanced.
    Progressed {
        /// Parsed summary of the step.
        summary: IntentPhrase,
        /// Completed steps.
        completed: u32,
        /// Total steps, when known.
        total: Option<u32>,
    },
    /// Automonique needs an answer before continuing.
    ClarificationRequested {
        /// Parsed question.
        question: IntentPhrase,
    },
    /// A decision is required.
    ApprovalRequired {
        /// Parsed description of what is being approved.
        summary: IntentPhrase,
    },
    /// The work reached its end.
    Finished {
        /// Parsed outcome summary.
        summary: IntentPhrase,
        /// Whether the work succeeded.
        succeeded: bool,
    },
}

impl EventOutcome {
    /// Stable lowercase kind of the intent this outcome renders as.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Progressed { .. } => "progress",
            Self::ClarificationRequested { .. } => "clarification",
            Self::ApprovalRequired { .. } => "approval",
            Self::Finished { .. } => "terminal",
        }
    }
}

/// A durable Automonique event.
///
/// Carries its own identity and the revision it was recorded at. This is the
/// only thing a [`RenderIntent`] can be derived from, so an outcome a connector
/// assembled for itself has nowhere to go.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEvent {
    event_id: String,
    revision: Revision,
    outcome: EventOutcome,
}

impl DurableEvent {
    /// Record a durable event.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Field`] for an invalid event identity.
    pub fn record(
        event_id: &str,
        revision: Revision,
        outcome: EventOutcome,
    ) -> Result<Self, ConnectorError> {
        bounded(event_id, "event_id")?;
        Ok(Self {
            event_id: event_id.to_owned(),
            revision,
            outcome,
        })
    }

    /// The durable event identity.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// The revision the event was recorded at.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// What the event recorded.
    #[must_use]
    pub const fn outcome(&self) -> &EventOutcome {
        &self.outcome
    }
}

/// Outbound content, expressed as intent rather than presentation.
///
/// Built only by [`RenderIntent::derived_from`], so every intent names the
/// durable event it came from and the revision that event was recorded at. Its
/// text is the bounded identity of that source event plus [`IntentPhrase`]
/// wording that was parsed; there is no content field, no field of any platform
/// type and no constructor accepting a body, so a platform model string and
/// pre-rendered markup are not values this type can hold. A connector renders
/// from the structure rather than being handed something to display.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderIntent {
    source_event: String,
    target_revision: Revision,
    outcome: EventOutcome,
}

impl RenderIntent {
    /// Derive an intent from a durable event.
    #[must_use]
    pub fn derived_from(event: &DurableEvent) -> Self {
        Self {
            source_event: event.event_id.clone(),
            target_revision: event.revision,
            outcome: event.outcome.clone(),
        }
    }

    /// The durable event this intent was derived from.
    #[must_use]
    pub fn source_event(&self) -> &str {
        &self.source_event
    }

    /// The revision the source event was recorded at.
    #[must_use]
    pub const fn target_revision(&self) -> Revision {
        self.target_revision
    }

    /// What the source event recorded.
    #[must_use]
    pub const fn outcome(&self) -> &EventOutcome {
        &self.outcome
    }

    /// Stable lowercase kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.outcome.kind()
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

    /// The installation the message arrived through.
    ///
    /// Every coordinate that goes in comes back out; a coordinate that cannot
    /// be read back was not preserved, it was discarded.
    #[must_use]
    pub const fn installation(&self) -> &InstallationKey {
        &self.installation
    }

    /// The platform.
    #[must_use]
    pub fn platform(&self) -> &str {
        self.installation.platform()
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

    /// The locale the platform reported, when it reported one.
    #[must_use]
    pub fn locale(&self) -> Option<&str> {
        self.locale.as_deref()
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

/// The audit record of what happened to one source message.
///
/// Append-only by construction: [`record`](Self::record) is the only mutator,
/// [`events`](Self::events) hands out a shared slice, and there is no removal,
/// truncation or replacement method. A tombstone therefore lands *beside* the
/// history rather than in place of it, so a deletion cannot erase an audit
/// record. Nothing here holds an approved action either — an approval lives on
/// an [`ActionToken`] bound to its own target revision — so a source-message
/// event has no route by which to rewrite one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMessageLog {
    coordinates: ConversationCoordinates,
    events: Vec<SourceMessageEvent>,
}

impl SourceMessageLog {
    /// Open a log for a message at known coordinates.
    #[must_use]
    pub const fn opened(coordinates: ConversationCoordinates) -> Self {
        Self {
            coordinates,
            events: Vec::new(),
        }
    }

    /// Append what happened.
    pub fn record(&mut self, event: SourceMessageEvent) {
        self.events.push(event);
    }

    /// Where the message sits.
    #[must_use]
    pub const fn coordinates(&self) -> &ConversationCoordinates {
        &self.coordinates
    }

    /// Everything recorded, in arrival order.
    #[must_use]
    pub fn events(&self) -> &[SourceMessageEvent] {
        &self.events
    }

    /// Whether a deletion was observed.
    #[must_use]
    pub fn is_tombstoned(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, SourceMessageEvent::Tombstoned { .. }))
    }
}

/// One obligation a connector must satisfy to conform, whatever it bridges.
///
/// Declared as a list so a Teams bridge and a Discord bridge are judged against
/// the same contract rather than each against its own platform's habits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConformanceObligation {
    /// Resolve an installation to one tenant or return `installation_required`.
    ResolveInstallationOrRequire,
    /// Report an unlinked identity rather than acting as an anonymous actor.
    ReportUnlinkedIdentity,
    /// Derive a source key deterministically from immutable platform identity.
    DeriveStableSourceKeys,
    /// Keep platform acknowledgement separate from business acceptance.
    SeparateAcknowledgementFromAcceptance,
    /// Render only from a [`RenderIntent`] derived from a durable event.
    RenderOnlyFromDerivedIntents,
    /// Bind every interactive control to an [`ActionToken`].
    BindControlsToActionTokens,
    /// Move every attachment through an [`ArtifactGrant`].
    MoveAttachmentsThroughGrants,
    /// Preserve conversation coordinates and hand them back unchanged.
    PreserveConversationCoordinates,
    /// Resume after a restart without replaying an external effect.
    ResumeWithoutReplayingExternalEffects,
}

impl ConformanceObligation {
    /// Every obligation, so a conformance run cannot silently skip one.
    pub const ALL: [Self; 9] = [
        Self::ResolveInstallationOrRequire,
        Self::ReportUnlinkedIdentity,
        Self::DeriveStableSourceKeys,
        Self::SeparateAcknowledgementFromAcceptance,
        Self::RenderOnlyFromDerivedIntents,
        Self::BindControlsToActionTokens,
        Self::MoveAttachmentsThroughGrants,
        Self::PreserveConversationCoordinates,
        Self::ResumeWithoutReplayingExternalEffects,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolveInstallationOrRequire => "resolve_installation_or_require",
            Self::ReportUnlinkedIdentity => "report_unlinked_identity",
            Self::DeriveStableSourceKeys => "derive_stable_source_keys",
            Self::SeparateAcknowledgementFromAcceptance => {
                "separate_acknowledgement_from_acceptance"
            }
            Self::RenderOnlyFromDerivedIntents => "render_only_from_derived_intents",
            Self::BindControlsToActionTokens => "bind_controls_to_action_tokens",
            Self::MoveAttachmentsThroughGrants => "move_attachments_through_grants",
            Self::PreserveConversationCoordinates => "preserve_conversation_coordinates",
            Self::ResumeWithoutReplayingExternalEffects => {
                "resume_without_replaying_external_effects"
            }
        }
    }

    /// What a connector must demonstrate to satisfy this obligation.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ResolveInstallationOrRequire => {
                "an unrecognized installation yields installation_required, never a default tenant"
            }
            Self::ReportUnlinkedIdentity => {
                "an unmapped external identity yields unlinked with a link prompt, never an anonymous actor"
            }
            Self::DeriveStableSourceKeys => {
                "the same platform event yields the same source key across restarts and instances"
            }
            Self::SeparateAcknowledgementFromAcceptance => {
                "an acknowledgement is never returned where a business acceptance is required"
            }
            Self::RenderOnlyFromDerivedIntents => {
                "every outbound message renders a render intent derived from a durable event"
            }
            Self::BindControlsToActionTokens => {
                "a control resolved against a changed target revision conflicts rather than retargeting"
            }
            Self::MoveAttachmentsThroughGrants => {
                "no attachment moves by filesystem path, credential-bearing URL or inline payload"
            }
            Self::PreserveConversationCoordinates => {
                "platform, installation, conversation, thread, message, locale and mention coordinates survive a round trip"
            }
            Self::ResumeWithoutReplayingExternalEffects => {
                "a restart resumes from the recorded source keys without re-sending a message already sent"
            }
        }
    }
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
