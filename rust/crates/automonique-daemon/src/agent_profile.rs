// SPDX-License-Identifier: Elastic-2.0

//! Transport-independent conversation identity and agent-profile context.
//!
//! A conversation belongs to a room, not to whichever participant happened to
//! speak most recently. [`ConversationKey`] therefore contains tenant,
//! installation, surface and room coordinates only. [`ActorTurn`] carries the
//! actor beside that key, allowing a Slack thread or Telegram topic to retain
//! one shared transcript without weakening actor-scoped authorization or
//! private-memory filtering.
//!
//! Persona and security policy are deliberately different types. A
//! [`PersonaBundle`] can describe identity and voice; it has no field through
//! which tools, credentials, roles or authority can be granted. Those decisions
//! remain outside this module and are represented here only by the digest and
//! revision of the independently reviewed [`SecurityPolicyRevision`] and
//! toolset.

use std::error::Error;
use std::fmt;

use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::primitives::Revision;

/// Maximum bytes in a tenant, installation, surface or actor coordinate.
pub const MAX_PROFILE_COORDINATE_BYTES: usize = 256;
/// Maximum bytes in a transport room coordinate.
pub const MAX_CONVERSATION_ROOM_BYTES: usize = 512;
/// Maximum bytes in a transport source key.
pub const MAX_TURN_SOURCE_KEY_BYTES: usize = 512;
/// Maximum bytes retained in one transcript turn.
pub const MAX_ACTOR_TURN_BYTES: usize = 16 * 1024;
/// Maximum bytes in the display name of a persona.
pub const MAX_PERSONA_NAME_BYTES: usize = 128;
/// Maximum bytes in a persona's stable identity statement.
pub const MAX_PERSONA_IDENTITY_BYTES: usize = 2 * 1024;
/// Maximum bytes in a persona's voice and interaction guidance.
pub const MAX_PERSONA_VOICE_BYTES: usize = 8 * 1024;
/// Maximum turns one manifest may claim were supplied to a provider.
pub const MAX_MANIFEST_TRANSCRIPT_TURNS: u32 = 64;
/// Maximum transcript bytes one manifest may claim were supplied.
pub const MAX_MANIFEST_TRANSCRIPT_BYTES: u32 = 64 * 1024;
/// Maximum evidence items one manifest may claim were supplied.
pub const MAX_MANIFEST_EVIDENCE_ITEMS: u32 = 128;
/// Maximum evidence bytes one manifest may claim were supplied.
pub const MAX_MANIFEST_EVIDENCE_BYTES: u32 = 256 * 1024;

const CONVERSATION_KEY_SCHEMA: &[u8] = b"automonique.conversation-key.v1";
const PERSONA_SCHEMA: &[u8] = b"automonique.persona-bundle.v1";
const CONTEXT_MANIFEST_SCHEMA: &[u8] = b"automonique.agent-context-manifest.v1";

/// A rejected conversation/profile value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentProfileError {
    /// A required field was empty or only whitespace.
    Empty(&'static str),
    /// A field exceeded its byte ceiling.
    TooLong {
        /// Stable field name.
        field: &'static str,
        /// Maximum accepted UTF-8 bytes.
        max_bytes: usize,
    },
    /// A coordinate or text field contained a disallowed character.
    Character(&'static str),
    /// A timestamp was before the Unix epoch.
    Time,
    /// Bounded transcript or evidence metadata was inconsistent or oversized.
    Metadata(&'static str),
}

impl fmt::Display for AgentProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "agent profile field is empty: {field}"),
            Self::TooLong { field, max_bytes } => {
                write!(
                    formatter,
                    "agent profile field exceeds {max_bytes} bytes: {field}"
                )
            }
            Self::Character(field) => {
                write!(
                    formatter,
                    "agent profile field has an invalid character: {field}"
                )
            }
            Self::Time => formatter.write_str("agent profile turn time is before the Unix epoch"),
            Self::Metadata(field) => {
                write!(formatter, "agent profile metadata is invalid: {field}")
            }
        }
    }
}

impl Error for AgentProfileError {}

/// The durable identity of one shared transport room.
///
/// `room` is the normalized transport coordinate, for example a Slack
/// `channel/thread_ts` pair or Telegram `chat/topic` pair. An actor is
/// intentionally absent: participants in one room resolve to the same key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationKey {
    tenant: String,
    installation: String,
    surface: String,
    room: String,
}

impl ConversationKey {
    /// Construct one shared-room key.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError`] for an empty, oversized, non-ASCII or
    /// separator-bearing coordinate outside the conservative coordinate
    /// grammar.
    pub fn new(
        tenant: impl Into<String>,
        installation: impl Into<String>,
        surface: impl Into<String>,
        room: impl Into<String>,
    ) -> Result<Self, AgentProfileError> {
        let tenant = tenant.into();
        let installation = installation.into();
        let surface = surface.into();
        let room = room.into();
        validate_coordinate(&tenant, "tenant", MAX_PROFILE_COORDINATE_BYTES, false)?;
        validate_coordinate(
            &installation,
            "installation",
            MAX_PROFILE_COORDINATE_BYTES,
            false,
        )?;
        validate_coordinate(&surface, "surface", MAX_PROFILE_COORDINATE_BYTES, true)?;
        validate_coordinate(&room, "room", MAX_CONVERSATION_ROOM_BYTES, false)?;
        Ok(Self {
            tenant,
            installation,
            surface,
            room,
        })
    }

    /// Tenant that owns the conversation.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Connector or bot installation that received the conversation.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.installation
    }

    /// Normalized transport surface, such as `slack` or `telegram`.
    #[must_use]
    pub fn surface(&self) -> &str {
        &self.surface
    }

    /// Normalized room/thread/topic coordinate.
    #[must_use]
    pub fn room(&self) -> &str {
        &self.room
    }

    /// Stable content digest of the normalized room key.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, CONVERSATION_KEY_SCHEMA);
        push_text(&mut bytes, &self.tenant);
        push_text(&mut bytes, &self.installation);
        push_text(&mut bytes, &self.surface);
        push_text(&mut bytes, &self.room);
        Sha256::digest(&bytes)
    }
}

/// Role of an actor-authored conversation turn.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActorTurnRole {
    /// A human or authenticated external actor.
    User,
    /// Monique's successfully delivered response.
    Assistant,
}

impl ActorTurnRole {
    const fn canonical(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Assistant => 2,
        }
    }
}

/// One actor's immutable turn within a shared conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorTurn {
    conversation: ConversationKey,
    actor: String,
    role: ActorTurnRole,
    source_key: String,
    content: String,
    created_at_ms: i64,
}

impl ActorTurn {
    /// Validate and construct one transcript turn.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError`] when the actor or source coordinate is
    /// malformed, content is empty/oversized/control-bearing, or the time is
    /// negative.
    pub fn new(
        conversation: ConversationKey,
        actor: impl Into<String>,
        role: ActorTurnRole,
        source_key: impl Into<String>,
        content: impl Into<String>,
        created_at_ms: i64,
    ) -> Result<Self, AgentProfileError> {
        let actor = actor.into();
        let source_key = source_key.into();
        let content = content.into();
        validate_coordinate(&actor, "actor", MAX_PROFILE_COORDINATE_BYTES, false)?;
        validate_coordinate(&source_key, "source_key", MAX_TURN_SOURCE_KEY_BYTES, false)?;
        validate_multiline_text(&content, "content", MAX_ACTOR_TURN_BYTES, false)?;
        if created_at_ms < 0 {
            return Err(AgentProfileError::Time);
        }
        Ok(Self {
            conversation,
            actor,
            role,
            source_key,
            content,
            created_at_ms,
        })
    }

    /// Shared conversation this turn belongs to.
    #[must_use]
    pub const fn conversation(&self) -> &ConversationKey {
        &self.conversation
    }

    /// Authenticated actor responsible for this turn.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// User or assistant role.
    #[must_use]
    pub const fn role(&self) -> ActorTurnRole {
        self.role
    }

    /// Idempotent external transport coordinate for this turn.
    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Redacted transcript content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Source timestamp in Unix milliseconds.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// Stable digest of this exact room-bound actor turn.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, b"automonique.actor-turn.v1");
        push_digest(&mut bytes, self.conversation.digest());
        push_text(&mut bytes, &self.actor);
        bytes.push(self.role.canonical());
        push_text(&mut bytes, &self.source_key);
        push_text(&mut bytes, &self.content);
        bytes.extend_from_slice(&self.created_at_ms.to_be_bytes());
        Sha256::digest(&bytes)
    }
}

/// Versioned presentation-only personality content.
///
/// The private representation contains only a name, identity and voice. Tools,
/// roles, approval policy and credentials have no representation in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonaBundle {
    revision: Revision,
    name: String,
    identity: String,
    voice: String,
    digest: Sha256Digest,
}

impl PersonaBundle {
    /// Construct one immutable persona revision.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError`] when presentation text is empty,
    /// oversized, padded with ambiguous outer whitespace, or contains control
    /// characters other than line-feed and tab inside multiline fields.
    pub fn new(
        revision: Revision,
        name: impl Into<String>,
        identity: impl Into<String>,
        voice: impl Into<String>,
    ) -> Result<Self, AgentProfileError> {
        let name = name.into();
        let identity = identity.into();
        let voice = voice.into();
        validate_single_line_text(&name, "persona_name", MAX_PERSONA_NAME_BYTES)?;
        validate_multiline_text(
            &identity,
            "persona_identity",
            MAX_PERSONA_IDENTITY_BYTES,
            true,
        )?;
        validate_multiline_text(&voice, "persona_voice", MAX_PERSONA_VOICE_BYTES, true)?;
        let digest = persona_digest(revision, &name, &identity, &voice);
        Ok(Self {
            revision,
            name,
            identity,
            voice,
            digest,
        })
    }

    /// Monotonic persona revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Display name of the persona.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Stable identity statement.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Voice and interaction guidance.
    #[must_use]
    pub fn voice(&self) -> &str {
        &self.voice
    }

    /// Digest binding content to its declared revision.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Revision and digest of independently enforced security policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPolicyRevision {
    revision: Revision,
    digest: Sha256Digest,
}

impl SecurityPolicyRevision {
    /// Bind one policy revision to its reviewed content digest.
    #[must_use]
    pub const fn new(revision: Revision, digest: Sha256Digest) -> Self {
        Self { revision, digest }
    }

    /// Monotonic policy revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Reviewed policy digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

/// Bounded metadata for the transcript projection supplied to one turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptMetadata {
    turns: u32,
    bytes: u32,
    digest: Sha256Digest,
    truncated: bool,
}

impl TranscriptMetadata {
    /// Describe a bounded transcript projection.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::Metadata`] when counts exceed their caps,
    /// zero/non-zero counts disagree, or an empty projection claims truncation.
    pub const fn new(
        turns: u32,
        bytes: u32,
        digest: Sha256Digest,
        truncated: bool,
    ) -> Result<Self, AgentProfileError> {
        if turns > MAX_MANIFEST_TRANSCRIPT_TURNS || bytes > MAX_MANIFEST_TRANSCRIPT_BYTES {
            return Err(AgentProfileError::Metadata("transcript_bounds"));
        }
        if (turns == 0) != (bytes == 0) || (turns == 0 && truncated) {
            return Err(AgentProfileError::Metadata("transcript_shape"));
        }
        Ok(Self {
            turns,
            bytes,
            digest,
            truncated,
        })
    }

    /// Number of ordered turns supplied.
    #[must_use]
    pub const fn turns(self) -> u32 {
        self.turns
    }

    /// UTF-8 bytes supplied across those turns.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }

    /// Digest of the ordered transcript projection.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }

    /// Whether older transcript material was omitted.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.truncated
    }
}

/// Bounded metadata for tool, memory and retrieved evidence supplied to a turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceMetadata {
    items: u32,
    bytes: u32,
    digest: Sha256Digest,
    truncated: bool,
}

impl EvidenceMetadata {
    /// Describe a bounded ordered evidence projection.
    ///
    /// # Errors
    ///
    /// Returns [`AgentProfileError::Metadata`] when counts exceed their caps,
    /// zero/non-zero counts disagree, or an empty projection claims truncation.
    pub const fn new(
        items: u32,
        bytes: u32,
        digest: Sha256Digest,
        truncated: bool,
    ) -> Result<Self, AgentProfileError> {
        if items > MAX_MANIFEST_EVIDENCE_ITEMS || bytes > MAX_MANIFEST_EVIDENCE_BYTES {
            return Err(AgentProfileError::Metadata("evidence_bounds"));
        }
        if (items == 0) != (bytes == 0) || (items == 0 && truncated) {
            return Err(AgentProfileError::Metadata("evidence_shape"));
        }
        Ok(Self {
            items,
            bytes,
            digest,
            truncated,
        })
    }

    /// Number of ordered evidence items supplied.
    #[must_use]
    pub const fn items(self) -> u32 {
        self.items
    }

    /// UTF-8/encoded bytes supplied across those items.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }

    /// Digest of the ordered evidence projection.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }

    /// Whether lower-ranked evidence was omitted.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.truncated
    }
}

/// Ordered, content-addressed identity of the context supplied to one turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextManifest {
    conversation: ConversationKey,
    persona_revision: Revision,
    persona_digest: Sha256Digest,
    security_policy: SecurityPolicyRevision,
    toolset_revision: Revision,
    toolset_digest: Sha256Digest,
    model_revision: Revision,
    model_digest: Sha256Digest,
    transcript: TranscriptMetadata,
    evidence: EvidenceMetadata,
    digest: Sha256Digest,
}

impl ContextManifest {
    /// Assemble one context identity from separately typed profile and policy.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        conversation: ConversationKey,
        persona: &PersonaBundle,
        security_policy: SecurityPolicyRevision,
        toolset_revision: Revision,
        toolset_digest: Sha256Digest,
        model_revision: Revision,
        model_digest: Sha256Digest,
        transcript: TranscriptMetadata,
        evidence: EvidenceMetadata,
    ) -> Self {
        let mut manifest = Self {
            conversation,
            persona_revision: persona.revision(),
            persona_digest: persona.digest(),
            security_policy,
            toolset_revision,
            toolset_digest,
            model_revision,
            model_digest,
            transcript,
            evidence,
            digest: Sha256::digest(&[]),
        };
        manifest.digest = manifest.compute_digest();
        manifest
    }

    /// Shared conversation whose provider context this describes.
    #[must_use]
    pub const fn conversation(&self) -> &ConversationKey {
        &self.conversation
    }

    /// Persona revision supplied to the turn.
    #[must_use]
    pub const fn persona_revision(&self) -> Revision {
        self.persona_revision
    }

    /// Persona content digest supplied to the turn.
    #[must_use]
    pub const fn persona_digest(&self) -> Sha256Digest {
        self.persona_digest
    }

    /// Independently enforced security policy revision and digest.
    #[must_use]
    pub const fn security_policy(&self) -> SecurityPolicyRevision {
        self.security_policy
    }

    /// Tool catalog/policy revision exposed to the harness.
    #[must_use]
    pub const fn toolset_revision(&self) -> Revision {
        self.toolset_revision
    }

    /// Digest of the exact ordered tool catalog and schemas.
    #[must_use]
    pub const fn toolset_digest(&self) -> Sha256Digest {
        self.toolset_digest
    }

    /// Model-route revision selected for the turn.
    #[must_use]
    pub const fn model_revision(&self) -> Revision {
        self.model_revision
    }

    /// Digest of the resolved provider/model configuration.
    #[must_use]
    pub const fn model_digest(&self) -> Sha256Digest {
        self.model_digest
    }

    /// Bounded transcript projection metadata.
    #[must_use]
    pub const fn transcript(&self) -> TranscriptMetadata {
        self.transcript
    }

    /// Bounded evidence projection metadata.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceMetadata {
        self.evidence
    }

    /// Stable digest of every field in the manifest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, CONTEXT_MANIFEST_SCHEMA);
        push_digest(&mut bytes, self.conversation.digest());
        push_revision(&mut bytes, self.persona_revision);
        push_digest(&mut bytes, self.persona_digest);
        push_revision(&mut bytes, self.security_policy.revision());
        push_digest(&mut bytes, self.security_policy.digest());
        push_revision(&mut bytes, self.toolset_revision);
        push_digest(&mut bytes, self.toolset_digest);
        push_revision(&mut bytes, self.model_revision);
        push_digest(&mut bytes, self.model_digest);
        push_projection(
            &mut bytes,
            self.transcript.turns,
            self.transcript.bytes,
            self.transcript.digest,
            self.transcript.truncated,
        );
        push_projection(
            &mut bytes,
            self.evidence.items,
            self.evidence.bytes,
            self.evidence.digest,
            self.evidence.truncated,
        );
        Sha256::digest(&bytes)
    }
}

fn persona_digest(revision: Revision, name: &str, identity: &str, voice: &str) -> Sha256Digest {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, PERSONA_SCHEMA);
    push_revision(&mut bytes, revision);
    push_text(&mut bytes, name);
    push_text(&mut bytes, identity);
    push_text(&mut bytes, voice);
    Sha256::digest(&bytes)
}

fn validate_coordinate(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    surface: bool,
) -> Result<(), AgentProfileError> {
    if value.is_empty() {
        return Err(AgentProfileError::Empty(field));
    }
    if value.len() > max_bytes {
        return Err(AgentProfileError::TooLong { field, max_bytes });
    }
    let valid = if surface {
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    } else {
        value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    };
    if !valid {
        return Err(AgentProfileError::Character(field));
    }
    Ok(())
}

fn validate_single_line_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), AgentProfileError> {
    if value.trim().is_empty() {
        return Err(AgentProfileError::Empty(field));
    }
    if value.len() > max_bytes {
        return Err(AgentProfileError::TooLong { field, max_bytes });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(AgentProfileError::Character(field));
    }
    Ok(())
}

fn validate_multiline_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    canonical_outer_whitespace: bool,
) -> Result<(), AgentProfileError> {
    if value.trim().is_empty() {
        return Err(AgentProfileError::Empty(field));
    }
    if value.len() > max_bytes {
        return Err(AgentProfileError::TooLong { field, max_bytes });
    }
    if (canonical_outer_whitespace && value.trim() != value)
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(AgentProfileError::Character(field));
    }
    Ok(())
}

fn push_revision(bytes: &mut Vec<u8>, revision: Revision) {
    bytes.extend_from_slice(&revision.get().to_be_bytes());
}

fn push_digest(bytes: &mut Vec<u8>, digest: Sha256Digest) {
    bytes.extend_from_slice(digest.as_bytes());
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    push_bytes(bytes, value.as_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("bounded profile value length fits u64");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
}

fn push_projection(
    bytes: &mut Vec<u8>,
    count: u32,
    size: u32,
    digest: Sha256Digest,
    truncated: bool,
) {
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&size.to_be_bytes());
    push_digest(bytes, digest);
    bytes.push(u8::from(truncated));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(value: u64) -> Revision {
        Revision::new(value).expect("non-zero fixture revision")
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256::digest(value.as_bytes())
    }

    fn persona(at: u64) -> PersonaBundle {
        PersonaBundle::new(
            revision(at),
            "Monique",
            "Automonique's operational assistant.",
            "Warm, direct, curious, and concise.",
        )
        .expect("persona")
    }

    fn transcript() -> TranscriptMetadata {
        TranscriptMetadata::new(2, 42, digest("two ordered turns"), false).expect("transcript")
    }

    fn evidence() -> EvidenceMetadata {
        EvidenceMetadata::new(1, 19, digest("one evidence item"), false).expect("evidence")
    }

    fn manifest(
        conversation: ConversationKey,
        persona: &PersonaBundle,
        toolset_revision: u64,
    ) -> ContextManifest {
        ContextManifest::new(
            conversation,
            persona,
            SecurityPolicyRevision::new(revision(7), digest("security-policy-v7")),
            revision(toolset_revision),
            digest("toolset"),
            revision(3),
            digest("model-route-v3"),
            transcript(),
            evidence(),
        )
    }

    #[test]
    fn same_room_across_actors_shares_one_conversation_key() {
        let room = ConversationKey::new(
            "primary",
            "automonique-slack",
            "slack",
            "channel:C0RESERVED/thread:1723542000.000100",
        )
        .expect("room");
        let alice = ActorTurn::new(
            room.clone(),
            "slack:T0RESERVED:UALICE",
            ActorTurnRole::User,
            "slack:A0:T0:C0:1723542001.000100",
            "What was completed?",
            1,
        )
        .expect("Alice turn");
        let bob = ActorTurn::new(
            room,
            "slack:T0RESERVED:UBOB",
            ActorTurnRole::User,
            "slack:A0:T0:C0:1723542002.000100",
            "And yesterday?",
            2,
        )
        .expect("Bob turn");

        assert_eq!(alice.conversation(), bob.conversation());
        assert_ne!(alice.actor(), bob.actor());
    }

    #[test]
    fn tenant_thread_and_topic_coordinates_isolate_rooms() {
        let slack_one = ConversationKey::new(
            "primary",
            "automonique-slack",
            "slack",
            "channel:C0/thread:1.000100",
        )
        .expect("Slack thread one");
        let slack_two = ConversationKey::new(
            "primary",
            "automonique-slack",
            "slack",
            "channel:C0/thread:2.000100",
        )
        .expect("Slack thread two");
        let telegram_one = ConversationKey::new(
            "primary",
            "telegram-bot-42",
            "telegram",
            "chat:-100/topic:7",
        )
        .expect("Telegram topic one");
        let telegram_two = ConversationKey::new(
            "primary",
            "telegram-bot-42",
            "telegram",
            "chat:-100/topic:8",
        )
        .expect("Telegram topic two");
        let other_tenant =
            ConversationKey::new("other", "telegram-bot-42", "telegram", "chat:-100/topic:7")
                .expect("other tenant");

        assert_ne!(slack_one, slack_two);
        assert_ne!(telegram_one, telegram_two);
        assert_ne!(telegram_one, other_tenant);
    }

    #[test]
    fn persona_is_presentation_only_and_cannot_supply_tools_or_authority() {
        let persona = persona(4);
        let room =
            ConversationKey::new("primary", "bot", "telegram", "chat:7").expect("conversation");
        let first = manifest(room.clone(), &persona, 1);
        let changed_toolset = manifest(room, &persona, 2);

        assert_eq!(persona.name(), "Monique");
        assert_eq!(persona.identity(), "Automonique's operational assistant.");
        assert_eq!(persona.voice(), "Warm, direct, curious, and concise.");
        assert_eq!(first.persona_digest(), persona.digest());
        assert_eq!(first.security_policy().revision(), revision(7));
        assert_eq!(first.toolset_revision(), revision(1));
        assert_eq!(changed_toolset.toolset_revision(), revision(2));
        assert_eq!(first.persona_digest(), changed_toolset.persona_digest());
        assert_ne!(first.digest(), changed_toolset.digest());
    }

    #[test]
    fn stable_manifest_digest_changes_on_meaningful_revision() {
        let room = ConversationKey::new("primary", "bot", "telegram", "chat:7/topic:3")
            .expect("conversation");
        let persona_one = persona(1);
        let persona_two = persona(2);
        let first = manifest(room.clone(), &persona_one, 5);
        let replay = manifest(room.clone(), &persona_one, 5);
        let persona_changed = manifest(room.clone(), &persona_two, 5);
        let toolset_changed = manifest(room, &persona_one, 6);

        assert_eq!(first.digest(), replay.digest());
        assert_ne!(first.digest(), persona_changed.digest());
        assert_ne!(first.digest(), toolset_changed.digest());
    }

    #[test]
    fn validation_rejects_ambiguous_coordinates_controls_and_false_metadata() {
        assert!(ConversationKey::new("primary", "bot", "Slack", "room:1").is_err());
        assert!(ConversationKey::new("primary", "bot", "slack", "room 1").is_err());
        assert!(PersonaBundle::new(revision(1), " Monique", "identity", "voice").is_err());
        assert!(
            ActorTurn::new(
                ConversationKey::new("primary", "bot", "telegram", "chat:1").expect("room"),
                "actor:1",
                ActorTurnRole::User,
                "telegram:bot:update:1",
                "unsafe\u{7}content",
                1,
            )
            .is_err()
        );
        assert!(TranscriptMetadata::new(0, 1, digest("invalid"), false).is_err());
        assert!(EvidenceMetadata::new(0, 0, digest("empty"), true).is_err());
    }
}
