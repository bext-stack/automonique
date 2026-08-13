// SPDX-License-Identifier: Elastic-2.0

//! Shared composer semantics.
//!
//! One typed composition model serves every client surface. R12-01 names it
//! "multiline/history, command/reference completion, queue editing,
//! retry/undo/stop/compress and context meter across clients"
//! (`docs/product-plan/reference/work-breakdown.md`); the capability ledger
//! records the same row as "Shared command registry, composer history and
//! generated completion" (`docs/product-plan/requirements/external-capability-ledger.md`).
//!
//! # What this module is, and is not
//!
//! It is **semantics**: values describing what was composed and what the
//! composition is addressed to. It is not UI, not delivery, and not intake.
//! Nothing here renders a widget, opens a socket, sends a message, enqueues a
//! durable item, reads a clock or performs I/O. A [`Draft`] is inert; producing
//! one has no effect anywhere.
//!
//! The parts that already exist elsewhere are not restated here:
//!
//! * the durable queue, retry lineage, stop/undo idempotence, checkpoints,
//!   compression lineage and per-turn context meter live in
//!   [`crate::interaction`];
//! * typed context references (`@file`, folder, diff, URL, session…) live in
//!   [`crate::context`];
//! * command identity, fields, authorization and approval policy live in
//!   [`crate::command_registry`].
//!
//! This module composes those vocabularies; it does not fork them.
//!
//! # The explicit-operation rule
//!
//! `docs/product-plan/requirements/operator-tui.md` is exact about the one
//! thing a composer must never do: "Sending text chooses an explicit
//! operation — new follow-up, queued input, active-turn steering, or
//! provider-request answer — based on advertised capabilities and current
//! state. The TUI shows that choice before submission; it never guesses from
//! timing or silently starts a replacement session." The same document adds
//! that "nearby text or the currently highlighted row must never imply
//! conversational context on its own".
//!
//! [`ComposerTarget`] is that rule as a type. Every variant carries its own
//! coordinates as typed identities, so there is no representation of "whatever
//! session was highlighted". The one variant without a session,
//! [`ComposerTarget::NewRequest`], says so by name rather than by an absent
//! field.
//!
//! ```
//! use automonique_protocol::composer::{BodyFit, ComposerBody, ComposerTarget, ComposerTransport, Draft};
//! use automonique_protocol::interaction::{SessionRef, SurfaceKind};
//!
//! let draft = Draft::new(
//!     SurfaceKind::Tui,
//!     ComposerTarget::FollowUp {
//!         session: SessionRef::new("s-1").unwrap(),
//!     },
//!     ComposerBody::new("first line\nsecond line").unwrap(),
//!     Vec::new(),
//! )
//! .unwrap();
//! assert!(matches!(
//!     draft.fit(ComposerTransport::Telegram),
//!     BodyFit::Fits { .. }
//! ));
//! ```
//!
//! A body is a validated value, never a borrowed editor buffer:
//!
//! ```compile_fail
//! use automonique_protocol::composer::ComposerBody;
//! let body: ComposerBody = String::from("send it");
//! ```
//!
//! and a surface cannot declare itself submitted, because [`Submission`] has no
//! public constructor and only [`ComposerState::submit`] returns one:
//!
//! ```compile_fail
//! use automonique_protocol::composer::{ComposerState, Submission};
//! let state = ComposerState::Submitted(Submission::new());
//! ```
//!
//! # Bounds and the transports that must carry a body
//!
//! [`MAX_COMPOSER_BODY_BYTES`] is defined as half of
//! [`crate::admin::MAX_ADMIN_CANONICAL_BYTES`], the canonical frame a
//! composition must ride to reach the daemon, so the relationship cannot drift
//! into a body no admin frame could hold.
//!
//! That ceiling is deliberately **wider** than the narrowest messaging
//! transport, which is why [`BodyFit`] exists. A composer that silently
//! accepted text no transport could carry would be lying to the operator, and
//! one clamped to the narrowest chat limit would make the dashboard and TUI
//! pay a Telegram bound they never touch. The honest shape is a wide ceiling
//! plus a typed per-transport answer: see [`Draft::fit`] and
//! [`TRANSPORT_BOUNDS`].
//!
//! [`BodyFit::Fits`] is **necessary, not sufficient**. It answers exactly one
//! question — does the composed body fit this transport's documented byte
//! bound — and says nothing about attachment carriage, encoding or markup
//! expansion, envelope overhead, or whether delivery would succeed.
//!
//! # An honest gap in the bound table
//!
//! `automonique-protocol` is dependency-free by design and cannot import
//! `automonique-transports` to read its constants. Two of the three rows in
//! [`TRANSPORT_BOUNDS`] therefore carry a *copy* of a foreign value and name
//! the symbol that owns it — see [`BoundAuthority::Foreign`], which mirrors
//! [`crate::compat::VersionAuthority`]'s distinction. A test in the owning
//! crate pinning [`TRANSPORT_BOUNDS`] would close the loop; none exists yet,
//! and [`BoundAuthority::is_checkable_here`] reports `false` for those rows
//! rather than implying the claim was verified.
//!
//! # Seams this module refuses to paper over
//!
//! * [`crate::interaction::SteerText`] is single-line and bounded to
//!   [`crate::interaction::MAX_INTERACTION_TEXT_BYTES`], so a multiline or
//!   long body is not expressible as a steer. [`Draft::steer_request`] refuses
//!   with [`ComposerError::NotExpressibleAsSteer`] instead of flattening or
//!   truncating the operator's text.
//! * [`crate::interaction::RequestKind`] has no variant carrying a fresh
//!   prompt; it models control requests. A [`ComposerTarget::NewRequest`] or
//!   [`ComposerTarget::FollowUp`] draft therefore has no bridge into that
//!   queue here, and none is invented: durable intake is another slice's
//!   value.
//! * A [`CommandMention`] carries a [`CommandId`], so a hyphenated alias such
//!   as `run-submit` is not expressible as a mention: `-` belongs to
//!   [`crate::command_registry::CommandAlias`]'s grammar, not the identifier's.
//!   An alias whose spelling also satisfies the identifier grammar — `submit`,
//!   for `submit_synthetic` — does resolve, to the command's canonical
//!   identifier. Widening a mention to accept either spelling is a registry
//!   decision, and it is recorded here rather than worked around.

use core::fmt;
use std::error::Error;

use crate::command_registry::{CommandId, CommandRegistry};
use crate::context::ContextReference;
use crate::interaction::{
    ContentDigest, RequestRef, RequiredAuthority, SessionRef, SteerRequest, SteerText, SurfaceKind,
    TurnRef,
};
use crate::primitives::{BoundedString, ValueError};

/// Stable schema identifier for the composer value shape.
pub const COMPOSER_SCHEMA_V1: &str = "automonique.composer/v1";

/// Maximum UTF-8 byte length of a composed body.
///
/// Half of [`crate::admin::MAX_ADMIN_CANONICAL_BYTES`]: a composition must fit
/// one canonical admin frame together with its target coordinates, references
/// and envelope, so the body may claim at most half of it.
pub const MAX_COMPOSER_BODY_BYTES: usize = crate::admin::MAX_ADMIN_CANONICAL_BYTES / 2;

/// Maximum UTF-8 byte length of an attachment's display name.
pub const MAX_ATTACHMENT_NAME_BYTES: usize = 256;

/// Maximum number of references one draft may carry.
pub const MAX_DRAFT_REFERENCES: usize = 32;

/// Maximum number of drafts one composer history window retains.
pub const MAX_COMPOSER_HISTORY: usize = 64;

/// Bounded, single-line attachment name.
pub type AttachmentName = BoundedString<MAX_ATTACHMENT_NAME_BYTES>;

/// Why a body cannot be expressed as an [`crate::interaction::SteerRequest`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SteerRefusal {
    /// The body spans more than one line; steering text is single-line.
    Multiline,
    /// The body exceeds the steering text ceiling.
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
        /// Supplied UTF-8 byte length.
        actual_bytes: usize,
    },
}

impl SteerRefusal {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Multiline => "multiline",
            Self::TooLong { .. } => "too_long",
        }
    }
}

/// Why a composer value was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposerError {
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A body carried a carriage return.
    ///
    /// Refused rather than normalized. Rewriting `\r\n` to `\n` would silently
    /// change what the operator typed, and leaving both spellings admissible
    /// would make two visually identical bodies render to different bytes.
    CarriageReturn,
    /// A bounded collection exceeded its ceiling.
    TooMany {
        /// The rejected collection.
        field: &'static str,
        /// Maximum accepted count.
        max: usize,
        /// Supplied count.
        actual: usize,
    },
    /// One draft named the same reference twice.
    DuplicateReference {
        /// The repeated reference identity.
        reference: String,
    },
    /// A submission still carried a reference that resolves to nothing.
    ///
    /// The reference is named, not dropped: an unknown `/command` survives
    /// composition so the operator is told which one failed.
    UnresolvedReference {
        /// The unresolved reference identity.
        reference: String,
    },
    /// An operation was asked of a draft addressed to a different target.
    TargetMismatch {
        /// The target the operation requires.
        expected: &'static str,
        /// The target the draft actually carries.
        actual: &'static str,
    },
    /// A composition event was not legal in the current state.
    IllegalTransition {
        /// The state the composer was in.
        from: &'static str,
        /// The event that was offered.
        event: &'static str,
    },
    /// A submission was attempted without the authority its target names.
    AuthorityRequired {
        /// The authority the target requires.
        authority: RequiredAuthority,
    },
    /// A body cannot become steering text.
    NotExpressibleAsSteer {
        /// Which rule the body broke.
        reason: SteerRefusal,
    },
    /// A recall addressed a slot the history window does not hold.
    HistoryOutOfRange {
        /// How many drafts the window holds.
        length: usize,
        /// The requested slot.
        requested: usize,
    },
}

impl ComposerError {
    /// Every stable category this module can produce.
    ///
    /// Published as a constant so generated SDK fixtures can enforce the same
    /// edges without duplicating hidden policy.
    pub const CATEGORIES: [&'static str; 10] = [
        "field_invalid",
        "carriage_return",
        "too_many",
        "duplicate_reference",
        "unresolved_reference",
        "target_mismatch",
        "illegal_transition",
        "authority_required",
        "not_expressible_as_steer",
        "history_out_of_range",
    ];

    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field_invalid",
            Self::CarriageReturn => "carriage_return",
            Self::TooMany { .. } => "too_many",
            Self::DuplicateReference { .. } => "duplicate_reference",
            Self::UnresolvedReference { .. } => "unresolved_reference",
            Self::TargetMismatch { .. } => "target_mismatch",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::AuthorityRequired { .. } => "authority_required",
            Self::NotExpressibleAsSteer { .. } => "not_expressible_as_steer",
            Self::HistoryOutOfRange { .. } => "history_out_of_range",
        }
    }
}

impl fmt::Display for ComposerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::CarriageReturn => formatter.write_str(
                "a composed body carries a carriage return; it is refused rather \
                 than normalized",
            ),
            Self::TooMany { field, max, actual } => write!(
                formatter,
                "{field} holds {actual} entries; maximum is {max}"
            ),
            Self::DuplicateReference { reference } => {
                write!(formatter, "the draft repeats the reference {reference}")
            }
            Self::UnresolvedReference { reference } => write!(
                formatter,
                "the reference {reference} resolves to nothing; it is refused, not dropped"
            ),
            Self::TargetMismatch { expected, actual } => write!(
                formatter,
                "the operation requires a {expected} draft; this one targets {actual}"
            ),
            Self::IllegalTransition { from, event } => {
                write!(formatter, "a {from} composer cannot accept {event}")
            }
            Self::AuthorityRequired { authority } => write!(
                formatter,
                "submitting this draft requires the {} authority",
                authority.as_str()
            ),
            Self::NotExpressibleAsSteer { reason } => match reason {
                SteerRefusal::Multiline => formatter.write_str(
                    "steering text is single-line; a multiline body is refused rather \
                     than flattened",
                ),
                SteerRefusal::TooLong {
                    max_bytes,
                    actual_bytes,
                } => write!(
                    formatter,
                    "steering text accepts {max_bytes} UTF-8 bytes; the body is \
                     {actual_bytes} and is refused rather than truncated"
                ),
            },
            Self::HistoryOutOfRange { length, requested } => write!(
                formatter,
                "slot {requested} is outside a history window of {length} drafts"
            ),
        }
    }
}

impl Error for ComposerError {}

/// A bounded, multiline composed body.
///
/// Unlike [`crate::primitives::BoundedString`], a body admits `\n` and `\t`,
/// because R12-01 ships a multiline editor and operators paste indented text
/// into it. Every other control character is refused, and `\r` has its own
/// category so the refusal is never mistaken for a normalization that happened
/// quietly. The type never truncates and never normalizes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComposerBody(String);

impl ComposerBody {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_COMPOSER_BODY_BYTES;

    /// Validate and construct a body.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::Field`] when the value is empty, over
    /// [`MAX_COMPOSER_BODY_BYTES`], or carries a control character other than
    /// `\n` or `\t`, and [`ComposerError::CarriageReturn`] for `\r`.
    pub fn new(value: impl Into<String>) -> Result<Self, ComposerError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ComposerError::Field {
                field: "body",
                error: ValueError::Empty,
            });
        }
        if value.len() > MAX_COMPOSER_BODY_BYTES {
            return Err(ComposerError::Field {
                field: "body",
                error: ValueError::TooLong {
                    max_bytes: MAX_COMPOSER_BODY_BYTES,
                    actual_bytes: value.len(),
                },
            });
        }
        for character in value.chars() {
            if character == '\r' {
                return Err(ComposerError::CarriageReturn);
            }
            if character == '\n' || character == '\t' {
                continue;
            }
            if character.is_control() {
                return Err(ComposerError::Field {
                    field: "body",
                    error: ValueError::ControlCharacter,
                });
            }
        }
        Ok(Self(value))
    }

    /// Return the validated body exactly as it was accepted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The body's UTF-8 byte length.
    #[must_use]
    pub fn len_bytes(&self) -> usize {
        self.0.len()
    }

    /// How many lines the body spans.
    ///
    /// Lines are `\n`-separated; a trailing `\n` therefore opens a final empty
    /// line, which is what an editor shows.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.0.split('\n').count()
    }

    /// Whether the body is a single line.
    #[must_use]
    pub fn is_single_line(&self) -> bool {
        !self.0.contains('\n')
    }
}

impl fmt::Display for ComposerBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A reference to stored bytes, carried by digest.
///
/// The draft holds the digest and a display name; it never holds the payload.
/// Composition therefore costs the same whatever was attached, and an
/// attachment cannot become an unbounded field on a value type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentRef {
    digest: ContentDigest,
    name: AttachmentName,
}

impl AttachmentRef {
    /// Reference stored bytes by digest.
    #[must_use]
    pub const fn new(digest: ContentDigest, name: AttachmentName) -> Self {
        Self { digest, name }
    }

    /// The content-addressed digest.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// The display name, which is not an identity.
    #[must_use]
    pub const fn name(&self) -> &AttachmentName {
        &self.name
    }
}

/// Why a command mention resolves to nothing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnresolvedReason {
    /// No registry was consulted, so the mention has not been checked at all.
    NoRegistryConsulted,
    /// A registry was consulted and does not hold the name.
    NotInRegistry,
}

impl UnresolvedReason {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRegistryConsulted => "no_registry_consulted",
            Self::NotInRegistry => "not_in_registry",
        }
    }
}

/// What a registry said about a command mention.
///
/// "Not yet checked" and "checked and absent" are different facts, so they are
/// different values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MentionResolution {
    /// The registry holds the name, under this canonical identifier.
    Resolved {
        /// The command's own identifier, which an alias mention resolves to.
        canonical: CommandId,
    },
    /// The mention resolves to nothing.
    Unresolved {
        /// Which of the two absences this is.
        reason: UnresolvedReason,
    },
}

impl MentionResolution {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Resolved { .. } => "resolved",
            Self::Unresolved { .. } => "unresolved",
        }
    }

    /// Whether the mention names a command that exists.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved { .. })
    }
}

/// A command named inside a composition.
///
/// The name is a [`CommandId`], so it has already passed the registry's dotted
/// grammar before a mention can exist. Whether the registry *holds* it is a
/// separate, explicit fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandMention {
    named: CommandId,
    resolution: MentionResolution,
}

impl CommandMention {
    /// Record a mention that has not been checked against any registry.
    #[must_use]
    pub const fn unchecked(named: CommandId) -> Self {
        Self {
            named,
            resolution: MentionResolution::Unresolved {
                reason: UnresolvedReason::NoRegistryConsulted,
            },
        }
    }

    /// Record a mention checked against a registry.
    ///
    /// Resolution is a lookup, not a guess: the registry resolves an
    /// identifier or one of its aliases to exactly one command, and an unknown
    /// name resolves to [`UnresolvedReason::NotInRegistry`] rather than to the
    /// nearest match.
    #[must_use]
    pub fn resolved_against(named: CommandId, registry: &CommandRegistry) -> Self {
        let resolution = registry.lookup(named.as_str()).map_or(
            MentionResolution::Unresolved {
                reason: UnresolvedReason::NotInRegistry,
            },
            |command| MentionResolution::Resolved {
                canonical: command.id().clone(),
            },
        );
        Self { named, resolution }
    }

    /// The name as it was composed.
    #[must_use]
    pub const fn named(&self) -> &CommandId {
        &self.named
    }

    /// What a registry said about it.
    #[must_use]
    pub const fn resolution(&self) -> &MentionResolution {
        &self.resolution
    }
}

/// Anything a composition can point at.
///
/// Three families, each validated by the grammar that owns it: typed context
/// references from [`crate::context`], registry commands from
/// [`crate::command_registry`], and digest-bound attachments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposerReference {
    /// A typed, already-validated context reference.
    Context(ContextReference),
    /// A registry command named in the composition.
    Command(CommandMention),
    /// Stored bytes, carried by digest.
    Attachment(AttachmentRef),
}

impl ComposerReference {
    /// Every family's stable spelling, for coverage checks.
    pub const KINDS: [&'static str; 3] = ["attachment", "command", "context"];

    /// Stable lowercase family.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Context(_) => "context",
            Self::Command(_) => "command",
            Self::Attachment(_) => "attachment",
        }
    }

    /// Whether the reference points at something that exists.
    ///
    /// A context reference and an attachment are already bound to a path,
    /// digest or URL by their own constructors; only a command mention can be
    /// unresolved at composition time.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        match self {
            Self::Context(_) | Self::Attachment(_) => true,
            Self::Command(mention) => mention.resolution.is_resolved(),
        }
    }

    /// The identity two references are the same reference by.
    ///
    /// Deliberately excludes a command mention's resolution state and an
    /// attachment's display name: mentioning one command twice is a duplicate
    /// whether or not both mentions were checked, and one digest under two
    /// names is one attachment.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Context(reference) => context_identity(reference),
            Self::Command(mention) => format!("command {}", mention.named),
            Self::Attachment(attachment) => format!("attachment {}", attachment.digest),
        }
    }

    /// The reference's line in a [`Draft::canonical_form`].
    ///
    /// The identity, plus the resolution state a command mention carries.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Context(_) | Self::Attachment(_) => self.identity(),
            Self::Command(mention) => {
                let mut line = self.identity();
                match &mention.resolution {
                    MentionResolution::Resolved { canonical } => {
                        line.push_str(" resolved=");
                        line.push_str(canonical.as_str());
                    }
                    MentionResolution::Unresolved { reason } => {
                        line.push_str(" unresolved=");
                        line.push_str(reason.as_str());
                    }
                }
                line
            }
        }
    }
}

/// Render a context reference as a stable, fully qualified identity line.
fn context_identity(reference: &ContextReference) -> String {
    let mut line = String::from("context ");
    line.push_str(reference.kind());
    match reference {
        ContextReference::File {
            path,
            digest,
            lines,
        } => {
            line.push(' ');
            line.push_str(path.as_str());
            line.push(' ');
            line.push_str(digest.as_str());
            match lines {
                Some(range) => {
                    line.push_str(&format!(" {}-{}", range.first(), range.last()));
                }
                None => line.push_str(" whole"),
            }
        }
        ContextReference::Folder {
            path,
            depth,
            filter,
        } => {
            line.push(' ');
            line.push_str(path.as_str());
            line.push_str(&format!(" depth={}", depth.get()));
            match filter.pattern() {
                Some(pattern) => {
                    line.push_str(" filter=");
                    line.push_str(pattern);
                }
                None => line.push_str(" filter=all"),
            }
        }
        ContextReference::Diff { revision } => push_field(&mut line, revision.as_str()),
        ContextReference::Staged => {}
        ContextReference::Commit { commit } => push_field(&mut line, commit.as_str()),
        ContextReference::Branch { branch } => push_field(&mut line, branch.as_str()),
        ContextReference::Url { url } => push_field(&mut line, url.as_str()),
        ContextReference::Session { session } => push_field(&mut line, session.as_str()),
        ContextReference::Turn { session, turn } => {
            push_field(&mut line, session.as_str());
            push_field(&mut line, turn.as_str());
        }
        ContextReference::Run { run } => push_field(&mut line, run.as_str()),
        ContextReference::Ticket { ticket } => push_field(&mut line, ticket.as_str()),
        ContextReference::Artifact { digest } => push_field(&mut line, digest.as_str()),
        ContextReference::Workspace { workspace } => push_field(&mut line, workspace.as_str()),
    }
    line
}

fn push_field(line: &mut String, value: &str) {
    line.push(' ');
    line.push_str(value);
}

/// The explicit operation a composition is addressed to.
///
/// Each variant carries the coordinates that operation needs, as typed
/// identities. There is no variant meaning "the selected row", and no field
/// that could be filled in from focus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposerTarget {
    /// Free-form intake with no session: a new durable request.
    ///
    /// `operator-tui.md`: "Free-form requests enter the same durable
    /// inbox/router as Slack and Telegram with origin `tui` and the
    /// authenticated local operator identity."
    NewRequest,
    /// A new turn on one explicitly selected session.
    FollowUp {
        /// The session the follow-up starts a turn on.
        session: SessionRef,
    },
    /// A durable queued item for one session.
    ///
    /// `operator-tui.md` bounds what may still be edited: "`queue/edit/withdraw`
    /// changes only provider-unaccepted input by expected revision." The
    /// acceptance boundary and the revision live with the durable item in
    /// [`crate::interaction`]; this target names only what the composition is
    /// for.
    Queue {
        /// The session the item is queued on.
        session: SessionRef,
    },
    /// Steering for one active turn.
    Steer {
        /// The session that owns the turn.
        session: SessionRef,
        /// The exact turn being steered.
        turn: TurnRef,
    },
    /// An answer to one provider user-input or permission request.
    Answer {
        /// The session that raised the request.
        session: SessionRef,
        /// The exact request being answered.
        request: RequestRef,
    },
}

impl ComposerTarget {
    /// Every target's stable spelling, for coverage checks.
    pub const KINDS: [&'static str; 5] = ["new_request", "follow_up", "queue", "steer", "answer"];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NewRequest => "new_request",
            Self::FollowUp { .. } => "follow_up",
            Self::Queue { .. } => "queue",
            Self::Steer { .. } => "steer",
            Self::Answer { .. } => "answer",
        }
    }

    /// The session the target names, when it names one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionRef> {
        match self {
            Self::NewRequest => None,
            Self::FollowUp { session }
            | Self::Queue { session }
            | Self::Steer { session, .. }
            | Self::Answer { session, .. } => Some(session),
        }
    }

    /// The authority a surface must hold before submitting to this target.
    ///
    /// Composing text — a new request, a follow-up, a queued item or steering —
    /// requires [`RequiredAuthority::Compose`]. Steering is not
    /// [`RequiredAuthority::Interrupt`]: it does not stop work, and stopping is
    /// [`crate::interaction::CancelRequest`], an intent this module does not
    /// compose. Answering a provider request goes "through the typed approval
    /// bridge" (`operator-tui.md`), so it requires
    /// [`RequiredAuthority::Approve`].
    #[must_use]
    pub const fn authority(&self) -> RequiredAuthority {
        match self {
            Self::NewRequest | Self::FollowUp { .. } | Self::Queue { .. } | Self::Steer { .. } => {
                RequiredAuthority::Compose
            }
            Self::Answer { .. } => RequiredAuthority::Approve,
        }
    }

    /// The target's line in a [`Draft::canonical_form`].
    #[must_use]
    pub fn line(&self) -> String {
        let mut line = String::from("target ");
        line.push_str(self.kind());
        match self {
            Self::NewRequest => {}
            Self::FollowUp { session } | Self::Queue { session } => {
                line.push_str(&format!(" session={session}"));
            }
            Self::Steer { session, turn } => {
                line.push_str(&format!(" session={session} turn={turn}"));
            }
            Self::Answer { session, request } => {
                line.push_str(&format!(" session={session} request={request}"));
            }
        }
        line
    }
}

/// What a transport's byte ceiling actually bounds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundKind {
    /// The ceiling bounds message text, so a fitting body is fully accounted.
    Text,
    /// The ceiling bounds a whole frame, so a fitting body still shares the
    /// budget with its envelope.
    Frame,
}

impl BoundKind {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Frame => "frame",
        }
    }
}

/// Where a transport bound's authoritative constant lives, relative to this
/// crate.
///
/// The distinction is the honest part of the table, and mirrors
/// [`crate::compat::VersionAuthority`]. A local claim is checkable by a test
/// here; a foreign one is an assertion this dependency-free crate cannot
/// verify.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundAuthority {
    /// The constant is visible from this crate and is used directly.
    Local {
        /// Path of the authoritative symbol.
        symbol: &'static str,
    },
    /// The constant lives in a crate this one cannot depend on.
    ///
    /// The table carries a copy of the value and names the symbol; a test in
    /// the owning crate pinning [`TRANSPORT_BOUNDS`] would close the loop, and
    /// none exists yet.
    Foreign {
        /// Path of the authoritative symbol.
        symbol: &'static str,
    },
}

impl BoundAuthority {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::Foreign { .. } => "foreign",
        }
    }

    /// The authoritative symbol's path.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Local { symbol } | Self::Foreign { symbol } => symbol,
        }
    }

    /// Whether a test in this crate can compare the carried value against its
    /// source.
    #[must_use]
    pub const fn is_checkable_here(self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

/// A transport a composed body may have to travel over.
///
/// Not a delivery channel: nothing in this module opens one. The enum exists so
/// [`Draft::fit`] can answer per transport instead of pretending one ceiling
/// serves them all.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComposerTransport {
    /// The local daemon administration socket every operator client uses.
    AdminSocket,
    /// The Slack connector.
    Slack,
    /// The Telegram connector.
    Telegram,
}

impl ComposerTransport {
    /// Every transport, in the order [`Draft::fit_table`] reports.
    pub const ALL: [Self; 3] = [Self::AdminSocket, Self::Slack, Self::Telegram];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdminSocket => "admin_socket",
            Self::Slack => "slack",
            Self::Telegram => "telegram",
        }
    }

    /// The transport's declared bound.
    #[must_use]
    pub const fn bound(self) -> TransportBound {
        match self {
            Self::AdminSocket => TransportBound {
                transport: self,
                kind: BoundKind::Frame,
                max_bytes: crate::admin::MAX_ADMIN_CANONICAL_BYTES,
                authority: BoundAuthority::Local {
                    symbol: "automonique_protocol::admin::MAX_ADMIN_CANONICAL_BYTES",
                },
            },
            Self::Slack => TransportBound {
                transport: self,
                kind: BoundKind::Text,
                max_bytes: 16 * 1024,
                authority: BoundAuthority::Foreign {
                    symbol: "automonique_transports::MAX_SLACK_TEXT_BYTES",
                },
            },
            Self::Telegram => TransportBound {
                transport: self,
                kind: BoundKind::Text,
                max_bytes: 16 * 1024,
                authority: BoundAuthority::Foreign {
                    symbol: "automonique_transports::MAX_TELEGRAM_INPUT_BYTES",
                },
            },
        }
    }
}

/// One transport's declared byte ceiling, with the authority for the number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransportBound {
    transport: ComposerTransport,
    kind: BoundKind,
    max_bytes: usize,
    authority: BoundAuthority,
}

impl TransportBound {
    /// The transport this bounds.
    #[must_use]
    pub const fn transport(self) -> ComposerTransport {
        self.transport
    }

    /// What the ceiling bounds.
    #[must_use]
    pub const fn kind(self) -> BoundKind {
        self.kind
    }

    /// The ceiling in UTF-8 bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Where the authoritative constant lives.
    #[must_use]
    pub const fn authority(self) -> BoundAuthority {
        self.authority
    }
}

/// Every transport bound this build declares, in [`ComposerTransport::ALL`]
/// order.
pub const TRANSPORT_BOUNDS: [TransportBound; 3] = [
    ComposerTransport::AdminSocket.bound(),
    ComposerTransport::Slack.bound(),
    ComposerTransport::Telegram.bound(),
];

/// Whether a composed body fits one transport's declared bound.
///
/// [`BodyFit::Fits`] is necessary, not sufficient: it accounts for the body's
/// bytes and nothing else — not attachments, not encoding or markup expansion,
/// not envelope overhead, and not whether delivery would succeed. Against a
/// [`BoundKind::Frame`] bound the remaining budget is shared with the envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyFit {
    /// The body is within the bound.
    Fits {
        /// Which transport was measured.
        transport: ComposerTransport,
        /// Bytes remaining under the ceiling.
        headroom_bytes: usize,
    },
    /// The body exceeds the bound and this transport cannot carry it.
    TooLarge {
        /// Which transport refused.
        transport: ComposerTransport,
        /// The transport's ceiling.
        limit_bytes: usize,
        /// The body's UTF-8 byte length.
        actual_bytes: usize,
    },
}

impl BodyFit {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fits { .. } => "fits",
            Self::TooLarge { .. } => "too_large",
        }
    }

    /// The transport measured.
    #[must_use]
    pub const fn transport(self) -> ComposerTransport {
        match self {
            Self::Fits { transport, .. } | Self::TooLarge { transport, .. } => transport,
        }
    }

    /// Whether the body fits.
    #[must_use]
    pub const fn fits(self) -> bool {
        matches!(self, Self::Fits { .. })
    }
}

/// One composition: what was written, what it points at, and what it is for.
///
/// A draft has **no durable identity**. It is a local composition, and durable
/// identity appears only when it becomes something else — a queued item's
/// [`crate::interaction::QueueItemId`] or a submission's
/// [`crate::interaction::RequestRef`]. `plan/contracts/R1-25.md` puts the
/// durable identity on the queued item, and this type does not compete with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Draft {
    surface: SurfaceKind,
    target: ComposerTarget,
    body: ComposerBody,
    references: Vec<ComposerReference>,
}

impl Draft {
    /// Validate and construct a draft.
    ///
    /// References keep the order they were composed in: the type never sorts,
    /// deduplicates or otherwise rewrites what the operator assembled.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::TooMany`] above [`MAX_DRAFT_REFERENCES`] and
    /// [`ComposerError::DuplicateReference`] when one reference identity
    /// occurs twice.
    pub fn new(
        surface: SurfaceKind,
        target: ComposerTarget,
        body: ComposerBody,
        references: Vec<ComposerReference>,
    ) -> Result<Self, ComposerError> {
        if references.len() > MAX_DRAFT_REFERENCES {
            return Err(ComposerError::TooMany {
                field: "references",
                max: MAX_DRAFT_REFERENCES,
                actual: references.len(),
            });
        }
        for (index, reference) in references.iter().enumerate() {
            let identity = reference.identity();
            if references[..index]
                .iter()
                .any(|earlier| earlier.identity() == identity)
            {
                return Err(ComposerError::DuplicateReference {
                    reference: identity,
                });
            }
        }
        Ok(Self {
            surface,
            target,
            body,
            references,
        })
    }

    /// The surface the composition was made on.
    #[must_use]
    pub const fn surface(&self) -> SurfaceKind {
        self.surface
    }

    /// The explicit operation the composition is addressed to.
    #[must_use]
    pub const fn target(&self) -> &ComposerTarget {
        &self.target
    }

    /// The composed body.
    #[must_use]
    pub const fn body(&self) -> &ComposerBody {
        &self.body
    }

    /// The references, in composition order.
    #[must_use]
    pub fn references(&self) -> &[ComposerReference] {
        &self.references
    }

    /// The references that resolve to nothing, in composition order.
    ///
    /// Refuse, don't drop: an unknown reference stays in the draft and is
    /// reported, so a surface can show which one failed instead of quietly
    /// composing a message that lost it.
    #[must_use]
    pub fn unresolved(&self) -> Vec<&ComposerReference> {
        self.references
            .iter()
            .filter(|reference| !reference.is_resolved())
            .collect()
    }

    /// Whether every reference resolves.
    #[must_use]
    pub fn is_fully_resolved(&self) -> bool {
        self.references.iter().all(ComposerReference::is_resolved)
    }

    /// Whether the body fits one transport's declared bound.
    #[must_use]
    pub fn fit(&self, transport: ComposerTransport) -> BodyFit {
        let bound = transport.bound();
        let actual_bytes = self.body.len_bytes();
        match bound.max_bytes().checked_sub(actual_bytes) {
            Some(headroom_bytes) => BodyFit::Fits {
                transport,
                headroom_bytes,
            },
            None => BodyFit::TooLarge {
                transport,
                limit_bytes: bound.max_bytes(),
                actual_bytes,
            },
        }
    }

    /// The fit against every declared transport, in [`ComposerTransport::ALL`]
    /// order.
    #[must_use]
    pub fn fit_table(&self) -> [BodyFit; 3] {
        [
            self.fit(ComposerTransport::AdminSocket),
            self.fit(ComposerTransport::Slack),
            self.fit(ComposerTransport::Telegram),
        ]
    }

    /// Express the draft as an [`crate::interaction::SteerRequest`].
    ///
    /// The only bridge this module offers into [`crate::interaction`], because
    /// steering is the only [`crate::interaction::RequestKind`] that carries
    /// composed text.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::TargetMismatch`] for a draft addressed
    /// elsewhere, and [`ComposerError::NotExpressibleAsSteer`] when the body is
    /// multiline or exceeds
    /// [`crate::interaction::MAX_INTERACTION_TEXT_BYTES`]. A body carrying a
    /// tab is refused as [`ComposerError::Field`], because steering text admits
    /// no control character. Nothing is flattened and nothing is truncated.
    pub fn steer_request(&self) -> Result<SteerRequest, ComposerError> {
        if !matches!(self.target, ComposerTarget::Steer { .. }) {
            return Err(ComposerError::TargetMismatch {
                expected: "steer",
                actual: self.target.kind(),
            });
        }
        if !self.body.is_single_line() {
            return Err(ComposerError::NotExpressibleAsSteer {
                reason: SteerRefusal::Multiline,
            });
        }
        match SteerText::new(self.body.as_str()) {
            Ok(text) => Ok(SteerRequest::new(text)),
            Err(ValueError::TooLong {
                max_bytes,
                actual_bytes,
            }) => Err(ComposerError::NotExpressibleAsSteer {
                reason: SteerRefusal::TooLong {
                    max_bytes,
                    actual_bytes,
                },
            }),
            Err(error) => Err(ComposerError::Field {
                field: "steer_text",
                error,
            }),
        }
    }

    /// A deterministic canonical rendering of the draft.
    ///
    /// A pure function of the draft's values: no clock, no locale, no hash
    /// iteration order and no terminal width, so two equal drafts render to
    /// identical bytes and one draft renders identically every time.
    ///
    /// The body is length-prefixed and written last, so no line inside it can
    /// be mistaken for a header and nothing needs escaping. This is a form for
    /// digesting and comparison — it is not a wire format, not a display, and
    /// nothing parses it back.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        let mut out = String::from(COMPOSER_SCHEMA_V1);
        out.push('\n');
        out.push_str("surface ");
        out.push_str(self.surface.as_str());
        out.push('\n');
        out.push_str(&self.target.line());
        out.push('\n');
        out.push_str(&format!("references {}\n", self.references.len()));
        for reference in &self.references {
            out.push_str(&reference.line());
            out.push('\n');
        }
        out.push_str(&format!("body {}\n", self.body.len_bytes()));
        out.push_str(self.body.as_str());
        out.push('\n');
        out
    }
}

/// A draft that was submitted, with the identity and authority that carried it.
///
/// Only [`ComposerState::submit`] produces one, so a surface cannot present
/// itself as having submitted anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Submission {
    draft: Draft,
    request: RequestRef,
    authority: RequiredAuthority,
}

impl Submission {
    /// The draft exactly as it was submitted.
    #[must_use]
    pub const fn draft(&self) -> &Draft {
        &self.draft
    }

    /// The request identity the submission is keyed by.
    ///
    /// The same identity [`crate::interaction`] uses for idempotent intents, so
    /// a reconnecting client reconciles one key rather than guessing whether to
    /// send again.
    #[must_use]
    pub const fn request(&self) -> &RequestRef {
        &self.request
    }

    /// The authority that permitted the submission.
    #[must_use]
    pub const fn authority(&self) -> RequiredAuthority {
        self.authority
    }
}

/// The composer's state.
///
/// Three states and five events. Every transition returns a new value, so a
/// state is a fact rather than a buffer two surfaces can race on, and an event
/// that is not legal in the current state is refused with
/// [`ComposerError::IllegalTransition`] rather than quietly ignored.
///
/// ```text
/// Empty     --begin-->    Drafting
/// Drafting  --edit-->     Drafting
/// Drafting  --discard-->  Empty
/// Drafting  --submit-->   Submitted
/// Submitted --clear-->    Empty
/// ```
///
/// Nothing here is durable and nothing here is delivery: `Submitted` records
/// that a draft was handed over under a named authority, not that anything
/// arrived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposerState {
    /// Nothing is composed.
    Empty,
    /// A draft is being composed.
    Drafting(Draft),
    /// A draft was submitted and the composition is frozen.
    Submitted(Submission),
}

impl ComposerState {
    /// Every state's stable spelling, for coverage checks.
    pub const STATES: [&'static str; 3] = ["empty", "drafting", "submitted"];

    /// Every event's stable spelling, for coverage checks.
    pub const EVENTS: [&'static str; 5] = ["begin", "edit", "discard", "submit", "clear"];

    /// Stable lowercase state.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Drafting(_) => "drafting",
            Self::Submitted(_) => "submitted",
        }
    }

    /// The draft being composed, if any.
    #[must_use]
    pub const fn draft(&self) -> Option<&Draft> {
        match self {
            Self::Drafting(draft) => Some(draft),
            Self::Empty | Self::Submitted(_) => None,
        }
    }

    /// The submission, if the composition was submitted.
    #[must_use]
    pub const fn submission(&self) -> Option<&Submission> {
        match self {
            Self::Submitted(submission) => Some(submission),
            Self::Empty | Self::Drafting(_) => None,
        }
    }

    /// Begin composing.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::IllegalTransition`] unless the composer is
    /// empty. Replacing an in-progress draft is [`ComposerState::edit`], which
    /// names what it is doing.
    pub fn begin(&self, draft: Draft) -> Result<Self, ComposerError> {
        match self {
            Self::Empty => Ok(Self::Drafting(draft)),
            Self::Drafting(_) | Self::Submitted(_) => Err(ComposerError::IllegalTransition {
                from: self.state(),
                event: "begin",
            }),
        }
    }

    /// Replace the draft being composed.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::IllegalTransition`] unless a draft is being
    /// composed. A submitted composition is frozen: editing it would change
    /// what a recorded request identity refers to.
    pub fn edit(&self, draft: Draft) -> Result<Self, ComposerError> {
        match self {
            Self::Drafting(_) => Ok(Self::Drafting(draft)),
            Self::Empty | Self::Submitted(_) => Err(ComposerError::IllegalTransition {
                from: self.state(),
                event: "edit",
            }),
        }
    }

    /// Discard the draft being composed.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::IllegalTransition`] unless a draft is being
    /// composed. Discarding an empty composer would report having thrown away
    /// something that never existed.
    pub fn discard(&self) -> Result<Self, ComposerError> {
        match self {
            Self::Drafting(_) => Ok(Self::Empty),
            Self::Empty | Self::Submitted(_) => Err(ComposerError::IllegalTransition {
                from: self.state(),
                event: "discard",
            }),
        }
    }

    /// Submit the draft under a request identity and the authorities granted.
    ///
    /// Three refusals, checked in order: the state, then every reference, then
    /// the authority. Nothing is sent — the result records that a draft was
    /// handed over, and delivery is another layer's concern.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::IllegalTransition`] unless a draft is being
    /// composed, [`ComposerError::UnresolvedReference`] naming the first
    /// reference that resolves to nothing, and
    /// [`ComposerError::AuthorityRequired`] when the target's authority was not
    /// granted.
    pub fn submit(
        &self,
        request: RequestRef,
        granted: &[RequiredAuthority],
    ) -> Result<Self, ComposerError> {
        let Self::Drafting(draft) = self else {
            return Err(ComposerError::IllegalTransition {
                from: self.state(),
                event: "submit",
            });
        };
        if let Some(unresolved) = draft.unresolved().first() {
            return Err(ComposerError::UnresolvedReference {
                reference: unresolved.identity(),
            });
        }
        let authority = draft.target.authority();
        if !granted.contains(&authority) {
            return Err(ComposerError::AuthorityRequired { authority });
        }
        Ok(Self::Submitted(Submission {
            draft: draft.clone(),
            request,
            authority,
        }))
    }

    /// Return an empty composer after a submission.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::IllegalTransition`] unless a draft was
    /// submitted.
    pub fn clear(&self) -> Result<Self, ComposerError> {
        match self {
            Self::Submitted(_) => Ok(Self::Empty),
            Self::Empty | Self::Drafting(_) => Err(ComposerError::IllegalTransition {
                from: self.state(),
                event: "clear",
            }),
        }
    }
}

/// A bounded window of previously composed drafts, most recent first.
///
/// R12-01 names composer history alongside the multiline editor. The window is
/// bounded, and eviction is **returned** rather than performed silently: a
/// history that dropped its oldest entry without saying so would be a claim
/// the type cannot keep.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposerHistory {
    entries: Vec<Draft>,
}

impl ComposerHistory {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many drafts the window holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the window holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The drafts, most recent first.
    #[must_use]
    pub fn entries(&self) -> &[Draft] {
        &self.entries
    }

    /// Record a draft as the most recent entry.
    ///
    /// Returns the new window and the draft evicted from the far end, if the
    /// window was already full at [`MAX_COMPOSER_HISTORY`]. The caller receives
    /// what left; nothing disappears.
    #[must_use]
    pub fn push(&self, draft: Draft) -> (Self, Option<Draft>) {
        let mut entries = Vec::with_capacity(self.entries.len() + 1);
        entries.push(draft);
        entries.extend(self.entries.iter().cloned());
        let evicted = if entries.len() > MAX_COMPOSER_HISTORY {
            entries.pop()
        } else {
            None
        };
        (Self { entries }, evicted)
    }

    /// The draft at one slot, counting from the most recent.
    ///
    /// # Errors
    ///
    /// Returns [`ComposerError::HistoryOutOfRange`] for a slot the window does
    /// not hold, rather than the nearest entry.
    pub fn recall(&self, slot: usize) -> Result<&Draft, ComposerError> {
        self.entries
            .get(slot)
            .ok_or(ComposerError::HistoryOutOfRange {
                length: self.entries.len(),
                requested: slot,
            })
    }
}
