// SPDX-License-Identifier: Elastic-2.0

//! Hash-chained audit records: the typed record, its canonical bytes, and the
//! chain verifier.
//!
//! One audit record says that a named actor, on a named surface, did a named
//! thing to a named subject, and that it came out one of five ways. Records are
//! linked: each carries the SHA-256 of the record before it, so a reader who
//! trusts only the newest hash can tell whether any earlier record was altered,
//! reordered or removed. That is the whole property. It is *tamper-evidence*,
//! not tamper-proofing — see [what a verified chain does not
//! establish](#what-a-verified-chain-does-not-establish).
//!
//! # Where the pieces live, and why
//!
//! The hashing and the canonicalization are here, in the protocol crate,
//! because both already are: [`crate::digest::Sha256`] is this crate's
//! from-scratch FIPS 180-4 implementation and [`crate::wire`] is its canonical
//! JSON. The durable table is [`automonique-store`]'s `audit_chain`, which
//! stores what this module produces and checks linkage structurally without
//! computing a hash of its own. That split is deliberate: the store's library
//! modules take no protocol dependency, so one implementation of SHA-256 covers
//! the whole chain and there is no second one to disagree with it.
//!
//! # `prev_hash` is inside the body, not beside it
//!
//! `record_hash` is `SHA-256` over the record's canonical bytes, and the
//! `prev_hash` field is one of the keys *in* those bytes. So the hash covers
//! the link as well as the content, and an attacker who rewrites history has to
//! rewrite every record after the one they touched rather than only re-pointing
//! it. The genesis record's `prev_hash` is [`GENESIS_PREV_HASH`], 64 zeros —
//! a value no SHA-256 output will practically collide with, and one that makes
//! "this is the first record" a property of the record rather than of the row
//! it happens to occupy.
//!
//! `seq` is likewise inside the body. Two rows that swap places therefore fail
//! verification on their own contents, before their links are even considered.
//!
//! # The canonicalization profile, stated exactly
//!
//! Records are canonicalized under **`automonique.wire/v1`**
//! ([`CANONICALIZATION_PROFILE`]), which is [`crate::wire`]'s encoding and is
//! **not** RFC 8785 (JCS). The three divergences are:
//!
//! 1. **Integers only.** `wire` admits no floating point at all, where JCS
//!    mandates ECMAScript number serialization for every number.
//! 2. **Keys sort by raw UTF-8 bytes**, where JCS sorts by UTF-16 code units.
//!    The two orderings differ for keys containing characters above U+FFFF.
//! 3. **`i64` range**, where JCS numbers are IEEE-754 doubles and lose
//!    precision above 2^53.
//!
//! An audit record makes all three unreachable rather than merely unlikely.
//! Its key set is fixed by this module and every key is ASCII, so divergence 2
//! cannot arise: over U+0000..U+007F, UTF-8 byte order, UTF-16 code-unit order
//! and code-point order are the same order. Its only integer is `seq`, bounded
//! by [`MAX_AUDIT_SEQ`] at 2^53 - 1, so divergence 3 cannot arise either, and
//! there is no number that is not `seq`, so neither can divergence 1.
//!
//! **Within that subset — ASCII keys, `i64` integers below 2^53, and strings —
//! this encoder's output is byte-for-byte what a JCS encoder produces**, for
//! the reasons above plus RFC 8785 §3.2.2.1's string escaping, which is
//! `JSON.stringify`'s and which [`crate::wire`] implements exactly: the seven
//! two-character escapes and lowercase `\u00xx` for the remaining C0 controls.
//! [`crate::wire::JsonValue::to_canonical_bytes`] is asserted against that
//! subset by test. **This is a statement about the subset and nothing wider.**
//! Nothing in this crate implements JCS, and no caller should describe it as
//! doing so.
//!
//! # `record_id` is derived, and that is a deviation
//!
//! The IETF Agent Audit Trail draft this schema follows gives each record a
//! UUIDv4. This workspace has no random number generator and declares no
//! dependency that could supply one, so a v4 identifier is not available and a
//! counterfeit one — a counter or a clock dressed as random — would be worse
//! than an honest deviation.
//!
//! Instead [`AuditRecord::record_id`] is derived: a domain-separated SHA-256 of
//! the record's own `record_hash`, rendered as [`RECORD_ID_PREFIX`] followed by
//! 32 hexadecimal digits. This buys back more than it gives up:
//!
//! - **Unique by construction.** Two records with different content have
//!   different `record_hash`es, so they have different identifiers. A UUIDv4
//!   only makes collision unlikely.
//! - **Verifiable.** Anyone holding the record can recompute the identifier and
//!   check it, which is exactly what [`verify_chain`] does. A random identifier
//!   is unverifiable by definition, so a tampered one is undetectable.
//! - **Reproducible.** The same logical record hashed twice yields the same
//!   identifier, which is what lets an append be replayed rather than
//!   duplicated.
//!
//! What it gives up is unlinkability: the identifier is a function of the
//! content, so publishing an identifier tells a holder of a candidate record
//! whether that record is the one. Audit records are not published, and the
//! chain's whole purpose is to bind identity to content, so this is not a cost
//! here. It would be one in a different application, and that is why it is
//! written down.
//!
//! # What a verified chain does not establish
//!
//! - **It does not establish that a record is true.** A chain proves that what
//!   was written has not changed since it was written. An actor who writes a
//!   false record writes it into the chain exactly as durably as a true one.
//! - **It does not establish that no record is missing from the front.** A
//!   holder of the whole file can delete a *suffix* and re-verify successfully;
//!   what they cannot do is remove or alter anything in the middle. Detecting
//!   truncation needs an external witness to the head hash, which this module
//!   does not provide and does not pretend to.
//! - **It does not establish that the event happened before the record.** The
//!   record's `recorded_at` is supplied by the caller, like every other time in
//!   this workspace, so retries stay deterministic and tests do not depend on
//!   an ambient clock. It is a claim, not an observation.
//! - **It is not authorization and it is not a decision.** A record describes
//!   what a decision was; nothing gates on one.

use core::fmt;
use std::error::Error;

use crate::digest::Sha256;
use crate::wire::JsonValue;

/// Schema identifier every audit record carries in its body.
pub const AUDIT_RECORD_SCHEMA_V1: &str = "automonique.audit-record/v1";

/// The canonicalization profile audit records are hashed under.
///
/// Named rather than assumed, because it is not RFC 8785; see the module
/// documentation for the exact divergences and the exact subset over which the
/// two agree.
pub const CANONICALIZATION_PROFILE: &str = "automonique.wire/v1";

/// The `prev_hash` of the first record in a chain: 64 zeros.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Hexadecimal digits in one chain hash.
pub const HASH_HEX_BYTES: usize = 64;

/// The fixed prefix of every derived record identifier.
pub const RECORD_ID_PREFIX: &str = "aud-";

/// Hexadecimal digits following [`RECORD_ID_PREFIX`] in a record identifier.
pub const RECORD_ID_HEX_BYTES: usize = 32;

/// Total byte length of a record identifier.
pub const RECORD_ID_BYTES: usize = RECORD_ID_PREFIX.len() + RECORD_ID_HEX_BYTES;

/// Maximum UTF-8 byte length of `actor`, `surface`, `subject` and
/// `recorded_at`.
pub const MAX_AUDIT_FIELD_BYTES: usize = 256;

/// Highest admissible `seq`.
///
/// 2^53 - 1 rather than [`i64::MAX`]: it is the largest integer RFC 8785's
/// number serialization represents exactly, so bounding here is what makes the
/// module's subset-equivalence claim true rather than approximately true. A
/// chain reaching it has recorded nine quadrillion events.
pub const MAX_AUDIT_SEQ: u64 = (1 << 53) - 1;

/// The domain separator that keeps a record identifier from colliding with a
/// record hash.
///
/// Without it `record_id` would be a plain re-hash and a reader holding one
/// value could not tell which of the two it had. With it, the identifier is
/// reachable only from this construction.
const RECORD_ID_DOMAIN: &[u8] = b"automonique.audit-record/v1/record-id\0";

/// What one audit record is about.
///
/// Closed, and fail-closed on decode: an unrecognized spelling is refused
/// rather than folded into a neighbouring one, because "we could not tell what
/// this record was" and "this record was an action" are different answers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuditCategory {
    /// A decision was asked for, granted, denied or expired.
    Approval,
    /// Something was done: a run started, a message sent, a row written.
    Override,
    /// An operator set aside a gate that would otherwise have refused.
    Action,
    /// Work in flight was stopped.
    Cancellation,
    /// A policy was composed, tightened or consulted.
    Policy,
    /// A decision was raised to a second approver.
    ///
    /// Reserved. This product has no second approver identity, so nothing
    /// emits it today. It is declared so the vocabulary is complete on the day
    /// one exists, rather than migrated in under deadline.
    Escalation,
}

impl AuditCategory {
    /// Every category, in canonical order.
    pub const ALL: [Self; 6] = [
        Self::Approval,
        Self::Action,
        Self::Override,
        Self::Cancellation,
        Self::Policy,
        Self::Escalation,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Action => "action",
            Self::Override => "override",
            Self::Cancellation => "cancellation",
            Self::Policy => "policy",
            Self::Escalation => "escalation",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.as_str() == value)
    }
}

impl fmt::Display for AuditCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How the thing a record describes came out.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuditOutcome {
    /// It was done, or the decision was to permit.
    Success,
    /// It was attempted and did not succeed.
    Failure,
    /// A deadline passed before an answer arrived.
    Timeout,
    /// The decision was to refuse.
    Denied,
    /// It was raised to a second approver.
    ///
    /// Reserved for the same reason [`AuditCategory::Escalation`] is, and
    /// asserted by test to have no emitter in this build.
    Escalated,
}

impl AuditOutcome {
    /// Every outcome, in canonical order.
    pub const ALL: [Self; 5] = [
        Self::Success,
        Self::Failure,
        Self::Timeout,
        Self::Denied,
        Self::Escalated,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
            Self::Denied => "denied",
            Self::Escalated => "escalated",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A field this module would not have written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    /// A field is empty, over-long, or carries a control character.
    InvalidField(&'static str),
    /// `seq` is zero or above [`MAX_AUDIT_SEQ`].
    SeqOutOfRange,
    /// A hash is not 64 lowercase hexadecimal digits.
    InvalidHash(&'static str),
}

impl AuditError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "audit_invalid_field",
            Self::SeqOutOfRange => "audit_seq_out_of_range",
            Self::InvalidHash(_) => "audit_invalid_hash",
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid audit field: {field}"),
            Self::SeqOutOfRange => write!(
                formatter,
                "audit seq must be between 1 and {MAX_AUDIT_SEQ} inclusive"
            ),
            Self::InvalidHash(field) => write!(
                formatter,
                "audit {field} must be {HASH_HEX_BYTES} lowercase hexadecimal digits"
            ),
        }
    }
}

impl Error for AuditError {}

/// One event presented for recording, before it has a place in a chain.
///
/// Separate from [`AuditRecord`] because an event is what a caller knows and a
/// record is what the chain makes of it: the caller supplies the six fields
/// here, and `seq` and `prev_hash` come from the chain's head, which the caller
/// does not choose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent<'a> {
    /// Caller-supplied RFC 3339 UTC timestamp. A claim, not an observation.
    pub recorded_at: &'a str,
    /// Who did the thing.
    pub actor: &'a str,
    /// Where they did it: the transport, lane or command surface.
    pub surface: &'a str,
    /// What kind of event this is.
    pub category: AuditCategory,
    /// What it was done to.
    pub subject: &'a str,
    /// How it came out.
    pub outcome: AuditOutcome,
}

/// One audit record, validated on construction.
///
/// Every field is checked by [`AuditRecord::link`], so a value of this type
/// always has canonical bytes and a well-formed hash. There is no way to build
/// one that does not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    seq: u64,
    recorded_at: String,
    actor: String,
    surface: String,
    category: AuditCategory,
    subject: String,
    outcome: AuditOutcome,
    prev_hash: String,
}

impl AuditRecord {
    /// Validate one event's fields and bind it into a chain at `seq`, after
    /// `prev_hash`.
    ///
    /// `prev_hash` is the previous record's `record_hash`, or
    /// [`GENESIS_PREV_HASH`] for the first record in a chain.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::SeqOutOfRange`] for a `seq` outside 1..=
    /// [`MAX_AUDIT_SEQ`], [`AuditError::InvalidHash`] for a `prev_hash` that is
    /// not 64 lowercase hexadecimal digits, and
    /// [`AuditError::InvalidField`] for any text field that is empty, longer
    /// than [`MAX_AUDIT_FIELD_BYTES`], or carries a control character.
    pub fn link(seq: u64, prev_hash: &str, event: AuditEvent<'_>) -> Result<Self, AuditError> {
        if seq == 0 || seq > MAX_AUDIT_SEQ {
            return Err(AuditError::SeqOutOfRange);
        }
        if !is_chain_hash(prev_hash) {
            return Err(AuditError::InvalidHash("prev_hash"));
        }
        Ok(Self {
            seq,
            recorded_at: checked_field(event.recorded_at, "recorded_at")?,
            actor: checked_field(event.actor, "actor")?,
            surface: checked_field(event.surface, "surface")?,
            category: event.category,
            subject: checked_field(event.subject, "subject")?,
            outcome: event.outcome,
            prev_hash: prev_hash.to_owned(),
        })
    }

    /// Position in the chain, counting from one.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Caller-supplied RFC 3339 UTC timestamp.
    #[must_use]
    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }

    /// Who did the thing.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Where they did it: the transport, lane or command surface.
    #[must_use]
    pub fn surface(&self) -> &str {
        &self.surface
    }

    /// What kind of event this is.
    #[must_use]
    pub const fn category(&self) -> AuditCategory {
        self.category
    }

    /// What it was done to.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// How it came out.
    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// The previous record's `record_hash`, or [`GENESIS_PREV_HASH`].
    #[must_use]
    pub fn prev_hash(&self) -> &str {
        &self.prev_hash
    }

    /// The record as a canonical JSON value.
    ///
    /// Every key is ASCII and the only number is `seq`, which is why the
    /// module's subset-equivalence claim holds. Key order here is irrelevant —
    /// [`JsonValue::to_canonical_bytes`] sorts — but the literal is kept sorted
    /// so a reader can see the encoded order without running the encoder.
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("actor".to_owned(), JsonValue::String(self.actor.clone())),
            (
                "category".to_owned(),
                JsonValue::String(self.category.as_str().to_owned()),
            ),
            (
                "outcome".to_owned(),
                JsonValue::String(self.outcome.as_str().to_owned()),
            ),
            (
                "prev_hash".to_owned(),
                JsonValue::String(self.prev_hash.clone()),
            ),
            (
                "recorded_at".to_owned(),
                JsonValue::String(self.recorded_at.clone()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String(AUDIT_RECORD_SCHEMA_V1.to_owned()),
            ),
            ("seq".to_owned(), JsonValue::Integer(self.seq_as_integer())),
            (
                "subject".to_owned(),
                JsonValue::String(self.subject.clone()),
            ),
            (
                "surface".to_owned(),
                JsonValue::String(self.surface.clone()),
            ),
        ])
    }

    /// The exact bytes this record is hashed over and stored as.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_json().to_canonical_bytes()
    }

    /// SHA-256 of [`AuditRecord::to_canonical_bytes`], as 64 lowercase
    /// hexadecimal digits.
    ///
    /// The bytes include `prev_hash` and `seq`, so this covers the record's
    /// place in the chain as well as its content.
    #[must_use]
    pub fn record_hash(&self) -> String {
        Sha256::digest(&self.to_canonical_bytes()).to_hex()
    }

    /// The derived record identifier.
    ///
    /// See the module documentation for why this is derived rather than random
    /// and what that trades away.
    #[must_use]
    pub fn record_id(&self) -> String {
        derive_record_id(&self.record_hash())
    }

    /// `seq` as the canonical encoder's integer type.
    ///
    /// Infallible: [`AuditRecord::new`] bounds `seq` at [`MAX_AUDIT_SEQ`],
    /// which is far below [`i64::MAX`], so the conversion cannot fail and a
    /// fallible signature here would be a refusal nobody could reach.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "seq is bounded at 2^53 - 1 by AuditRecord::new"
    )]
    const fn seq_as_integer(&self) -> i64 {
        self.seq as i64
    }
}

/// Derive the record identifier one chain hash names.
///
/// Public so a verifier that holds only stored columns can recompute it without
/// rebuilding the record.
#[must_use]
pub fn derive_record_id(record_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_ID_DOMAIN);
    hasher.update(record_hash.as_bytes());
    let hex = hasher.finish().to_hex();
    let mut identifier = String::with_capacity(RECORD_ID_BYTES);
    identifier.push_str(RECORD_ID_PREFIX);
    identifier.push_str(&hex[..RECORD_ID_HEX_BYTES]);
    identifier
}

/// Whether a value is exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is refused rather than folded, so one hash has exactly one
/// spelling and comparing two of them by bytes means what it looks like.
#[must_use]
pub fn is_chain_hash(value: &str) -> bool {
    value.len() == HASH_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_field(value: &str, field: &'static str) -> Result<String, AuditError> {
    if value.is_empty()
        || value.len() > MAX_AUDIT_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(AuditError::InvalidField(field));
    }
    Ok(value.to_owned())
}

/// One stored record, as a verifier sees it: the persisted columns and nothing
/// derived.
///
/// Borrowed rather than owned so a verifier can walk a large chain without
/// copying every body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditLink<'a> {
    /// Position the row claims.
    pub seq: u64,
    /// Identifier the row claims.
    pub record_id: &'a str,
    /// The canonical bytes as stored.
    pub body: &'a [u8],
    /// Link the row claims to its predecessor.
    pub prev_hash: &'a str,
    /// Hash the row claims for itself.
    pub record_hash: &'a str,
}

/// The exact way one record failed verification.
///
/// Each variant names a different lie, because which one it is says what
/// happened: a body that does not hash to its column was edited, a `seq` that
/// does not match its body was moved, and a gap in `seq` is a deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainFault {
    /// `seq` is not one more than its predecessor's — a record was removed,
    /// inserted, or reordered.
    SeqNotContiguous,
    /// The stored body is not canonical JSON this module could have written.
    BodyMalformed,
    /// The body decodes, but a field it carries is not one this module admits.
    BodyFieldInvalid,
    /// The `seq` inside the body is not the `seq` of the row holding it — two
    /// rows were swapped.
    BodySeqMismatch,
    /// The `prev_hash` inside the body is not the `prev_hash` column beside it.
    BodyPrevHashMismatch,
    /// The first record's `prev_hash` is not [`GENESIS_PREV_HASH`].
    GenesisNotZero,
    /// This record's `prev_hash` is not its predecessor's `record_hash` — the
    /// link is cut.
    PrevHashMismatch,
    /// The body does not hash to the stored `record_hash` — the body was
    /// edited, or the hash was.
    RecordHashMismatch,
    /// The stored `record_id` is not the one this `record_hash` derives.
    RecordIdMismatch,
}

impl ChainFault {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SeqNotContiguous => "seq_not_contiguous",
            Self::BodyMalformed => "body_malformed",
            Self::BodyFieldInvalid => "body_field_invalid",
            Self::BodySeqMismatch => "body_seq_mismatch",
            Self::BodyPrevHashMismatch => "body_prev_hash_mismatch",
            Self::GenesisNotZero => "genesis_not_zero",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::RecordHashMismatch => "record_hash_mismatch",
            Self::RecordIdMismatch => "record_id_mismatch",
        }
    }
}

impl fmt::Display for ChainFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The first record at which a chain stopped verifying.
///
/// One break, not a list: everything after the first bad record is unverifiable
/// rather than known-bad, and reporting the rest as failures would be claiming
/// to know something the chain no longer says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainBreak {
    /// `seq` of the first record that did not verify.
    pub seq: u64,
    /// What was wrong with it.
    pub fault: ChainFault,
}

impl fmt::Display for ChainBreak {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "audit chain breaks at seq {}: {}",
            self.seq, self.fault
        )
    }
}

impl Error for ChainBreak {}

/// Recompute every hash in a chain and report the first record that does not
/// verify.
///
/// The links must be presented in ascending `seq` order starting at 1; a
/// caller that presents them in another order is told so as
/// [`ChainFault::SeqNotContiguous`] rather than silently sorted, because a
/// verifier that repaired its input would be verifying something other than
/// what it was given.
///
/// For each record this recomputes the body's hash, the derived identifier, and
/// the link to the predecessor, and it re-reads `seq` and `prev_hash` out of
/// the body to check them against the columns beside it. Every one of those is
/// a separate way to be wrong and each has its own [`ChainFault`].
///
/// # Errors
///
/// Returns the first [`ChainBreak`]. An empty chain verifies: a chain with no
/// records makes no claim that could be false.
pub fn verify_chain<'a>(links: impl IntoIterator<Item = AuditLink<'a>>) -> Result<u64, ChainBreak> {
    let mut expected_seq = 1_u64;
    let mut expected_prev = GENESIS_PREV_HASH.to_owned();
    let mut verified = 0_u64;
    for link in links {
        let fault = verify_link(&link, expected_seq, &expected_prev);
        if let Some(fault) = fault {
            return Err(ChainBreak {
                seq: link.seq,
                fault,
            });
        }
        expected_prev = link.record_hash.to_owned();
        expected_seq = expected_seq.saturating_add(1);
        verified = verified.saturating_add(1);
    }
    Ok(verified)
}

/// Judge one link against the position and predecessor the walk expects.
///
/// Ordered cheapest-and-most-specific first: a `seq` gap is reported as a gap
/// rather than as the hash mismatch it also produces, because "a record was
/// deleted" is what the reader needs to be told.
fn verify_link(link: &AuditLink<'_>, expected_seq: u64, expected_prev: &str) -> Option<ChainFault> {
    if link.seq != expected_seq {
        return Some(ChainFault::SeqNotContiguous);
    }
    if expected_seq == 1 && link.prev_hash != GENESIS_PREV_HASH {
        return Some(ChainFault::GenesisNotZero);
    }
    if link.prev_hash != expected_prev {
        return Some(ChainFault::PrevHashMismatch);
    }
    let Ok(body) = crate::wire::parse_canonical(link.body) else {
        return Some(ChainFault::BodyMalformed);
    };
    let record = match decode_body(&body) {
        Ok(record) => record,
        Err(fault) => return Some(fault),
    };
    if record.seq() != link.seq {
        return Some(ChainFault::BodySeqMismatch);
    }
    if record.prev_hash() != link.prev_hash {
        return Some(ChainFault::BodyPrevHashMismatch);
    }
    // The record was rebuilt from the stored bytes, so re-encoding it also
    // proves the bytes were canonical for these fields and carried no key this
    // module does not write.
    let record_hash = record.record_hash();
    if record.to_canonical_bytes() != link.body || record_hash != link.record_hash {
        return Some(ChainFault::RecordHashMismatch);
    }
    if derive_record_id(&record_hash) != link.record_id {
        return Some(ChainFault::RecordIdMismatch);
    }
    None
}

/// Rebuild a record from its stored canonical bytes.
fn decode_body(body: &JsonValue) -> Result<AuditRecord, ChainFault> {
    let JsonValue::Object(entries) = body else {
        return Err(ChainFault::BodyMalformed);
    };
    if entries.len() != BODY_KEYS.len()
        || !BODY_KEYS
            .iter()
            .all(|key| entries.iter().any(|(name, _)| name == key))
    {
        return Err(ChainFault::BodyMalformed);
    }
    if body.get("schema").and_then(JsonValue::as_str) != Some(AUDIT_RECORD_SCHEMA_V1) {
        return Err(ChainFault::BodyFieldInvalid);
    }
    let seq = body
        .get("seq")
        .and_then(JsonValue::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ChainFault::BodyFieldInvalid)?;
    let category = text(body, "category")
        .and_then(AuditCategory::from_spelling)
        .ok_or(ChainFault::BodyFieldInvalid)?;
    let outcome = text(body, "outcome")
        .and_then(AuditOutcome::from_spelling)
        .ok_or(ChainFault::BodyFieldInvalid)?;
    AuditRecord::link(
        seq,
        text(body, "prev_hash").ok_or(ChainFault::BodyFieldInvalid)?,
        AuditEvent {
            recorded_at: text(body, "recorded_at").ok_or(ChainFault::BodyFieldInvalid)?,
            actor: text(body, "actor").ok_or(ChainFault::BodyFieldInvalid)?,
            surface: text(body, "surface").ok_or(ChainFault::BodyFieldInvalid)?,
            category,
            subject: text(body, "subject").ok_or(ChainFault::BodyFieldInvalid)?,
            outcome,
        },
    )
    .map_err(|_| ChainFault::BodyFieldInvalid)
}

/// Every key an audit record body carries, and the only ones it admits.
const BODY_KEYS: [&str; 9] = [
    "actor",
    "category",
    "outcome",
    "prev_hash",
    "recorded_at",
    "schema",
    "seq",
    "subject",
    "surface",
];

fn text<'a>(body: &'a JsonValue, key: &str) -> Option<&'a str> {
    body.get(key).and_then(JsonValue::as_str)
}
