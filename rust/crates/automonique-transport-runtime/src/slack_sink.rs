// SPDX-License-Identifier: Elastic-2.0

//! Durable binding between a parsed Slack frame and the product's ingress log.
//!
//! `automonique-transports` turns one Socket Mode frame into a
//! [`SlackEnvelope`] carrying a disposition and an acknowledgement plan, and
//! states plainly that the disposition must be durable *before* the plan is
//! executed. This module is the durable half of that contract: it maps one
//! parsed envelope onto one [`SlackIngressLog`] row and hands back a receipt.
//!
//! # What the receipt proves, and what it does not
//!
//! A [`SlackDurableReceipt`] proves the disposition is **recorded**. It does not
//! prove an acknowledgement was sent, attempted, or accepted — nothing in this
//! module performs one, and the socket layer that does is the only thing that
//! can observe it.
//!
//! The receipt reports whether the row was [`SlackRecordOutcome::Recorded`] or
//! [`SlackRecordOutcome::AlreadyRecorded`], and that distinction must not change
//! the acknowledgement. Both answers mean the same durable fact holds, and Slack
//! redelivers precisely because an earlier acknowledgement did not arrive; a
//! caller that acknowledged only fresh recordings would leave every redelivery
//! unacknowledged and keep the redelivery storm alive. The outcome is reported
//! for logging and reconciliation, not for branching an ack on.
//!
//! # Seam
//!
//! This crate already depends on `automonique-transports`, so the sink consumes
//! [`SlackEnvelope`] directly rather than restating its fields as a local input
//! struct the way [`super::DurableTelegramUpdate`] does. That local struct
//! exists for Telegram because a batch is assembled and digested by this crate
//! before it reaches the store; a Slack frame is not assembled from anything, so
//! an intermediate type here would only add a mapping the caller could get
//! wrong. `SlackEnvelope` has no public constructor, so an envelope reaching
//! this sink was necessarily produced by `parse_slack_envelope`.
//!
//! The sink is bound to exactly one [`SlackAppId`] at construction, because a
//! Socket Mode connection serves one app. Every recorded `source_key` is checked
//! to carry that app's prefix, so an envelope parsed under another app's policy
//! is refused rather than filed under the wrong app.
//!
//! Today's parser pairs an ingress only with [`SlackDisposition::Admitted`] and
//! [`SlackDisposition::Denied`], so this sink cannot presently produce an
//! `ignored_unsupported` row. The mapping for it is kept because the durable
//! vocabulary admits it: an unsupported frame that did carry a
//! `(team, channel, ts)` triple would have a deduplication identity and belong
//! in the log. Every other frame reaches [`SlackSinkFailure::NotRecordable`].
//!
//! # Content
//!
//! The log stores a digest, never the admitted text (see
//! `automonique_store::slack_ingress` for why, and for the ordering duty that
//! follows). This module computes that digest with
//! [`slack_content_digest`] over a domain-separated preimage, so a digest from
//! this crate cannot collide with a digest of the same bytes taken in another
//! context.

use automonique_store::slack_ingress::{
    CONTENT_DIGEST_CHARS, MAX_DISPOSITION_PAGE, SlackDispositionEntry, SlackDispositionKind,
    SlackDispositionRecord, SlackIngressError, SlackIngressLog, SlackRecordOutcome,
    SlackStoreDisposition,
};
use automonique_transports::{SlackAppId, SlackDisposition, SlackEnvelope};
use sha2::{Digest, Sha256};

use super::Clock;

/// Domain separator prefixed to admitted content before hashing.
const SLACK_CONTENT_DOMAIN: &[u8] = b"automonique.slack.content/v1\0";

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Bind admitted Slack content to a stable lowercase hex SHA-256 name.
///
/// The preimage is exactly `"automonique.slack.content/v1\0"` followed by the
/// admitted text's UTF-8 bytes. It is stated here because a durable row keeps
/// only the digest: anyone reconciling a row against a message must be able to
/// reproduce this value byte for byte.
#[must_use]
pub fn slack_content_digest(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SLACK_CONTENT_DOMAIN);
    hasher.update(content.as_bytes());
    let mut digest = String::with_capacity(CONTENT_DIGEST_CHARS);
    for byte in hasher.finalize() {
        digest.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        digest.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    digest
}

/// Closed durable-sink failures for one Slack frame.
///
/// Only [`SlackSinkFailure::NotRecordable`] is an ordinary outcome. Every other
/// member means nothing was recorded, so a caller must not acknowledge on one
/// without an explicit policy: an unacknowledged frame is redelivered, which is
/// the recoverable direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackSinkFailure {
    /// The frame carries no deduplication identity, so there is no row to write.
    ///
    /// Ordinary and expected: control frames, refusals, slash commands and
    /// interactive frames, and every `events_api` frame outside the admitted
    /// input surface reach this. Such a frame creates no durable work, so
    /// acknowledging it per [`automonique_transports::SlackAckPlan`] loses
    /// nothing — but that decision is the caller's, not this module's.
    NotRecordable,
    /// The envelope pairs a disposition and content the durable vocabulary
    /// cannot represent, or names an app this sink was not bound to.
    ///
    /// The app mismatch is reachable: it is an envelope parsed under a
    /// different policy. The disposition/content mismatches are not reachable
    /// from today's parser and are typed rather than panicked so that a future
    /// parser change is refused here instead of being filed under a
    /// neighbouring spelling.
    Inconsistent,
    /// A redelivery disagreed with the recorded history. Nothing was written.
    Conflict,
    /// The log holds its capacity. Nothing was written.
    LogFull,
    /// The clock or the durable log was unavailable. Nothing was written.
    Unavailable,
    /// A stored row failed validation on read.
    Corrupt,
}

/// Durable proof that one Slack disposition was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackDurableReceipt {
    /// Row identity of the durable disposition.
    pub entry_id: i64,
    /// The disposition that is durable, which on a replay is the one recorded
    /// by the first delivery rather than the one just presented.
    pub disposition: SlackDispositionKind,
    /// Whether this call created the row or found it.
    pub outcome: SlackRecordOutcome,
}

impl SlackDurableReceipt {
    /// Whether the row already existed. Never a reason to skip an ack.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.outcome.is_replay()
    }
}

/// Concrete adapter from one Slack app's frames to its private ingress log.
pub struct StoreSlackDurableSink<C> {
    log: SlackIngressLog,
    clock: C,
    app_id: SlackAppId,
    source_prefix: String,
}

impl<C> StoreSlackDurableSink<C>
where
    C: Clock,
{
    /// Bind a log, a trusted clock and exactly one Slack app.
    #[must_use]
    pub fn new(log: SlackIngressLog, clock: C, app_id: SlackAppId) -> Self {
        let source_prefix = format!("slack:{}:", app_id.as_str());
        Self {
            log,
            clock,
            app_id,
            source_prefix,
        }
    }

    /// App this sink records for.
    #[must_use]
    pub const fn app_id(&self) -> &SlackAppId {
        &self.app_id
    }

    /// Recover the owned log and clock for controlled host shutdown or tests.
    #[must_use]
    pub fn into_parts(self) -> (SlackIngressLog, C) {
        (self.log, self.clock)
    }

    /// Record one parsed frame's disposition before its acknowledgement.
    ///
    /// The recording instant comes from this sink's clock, not from the caller,
    /// so a host cannot backdate history. On a replay the stored instant,
    /// `envelope_id` and `retry_attempt` remain those of the first delivery.
    pub fn record_disposition(
        &mut self,
        envelope: &SlackEnvelope,
    ) -> Result<SlackDurableReceipt, SlackSinkFailure> {
        let ingress = envelope.ingress().ok_or(SlackSinkFailure::NotRecordable)?;
        let envelope_id = envelope
            .envelope_id()
            .ok_or(SlackSinkFailure::NotRecordable)?;
        if !ingress.source_key().starts_with(&self.source_prefix) {
            return Err(SlackSinkFailure::Inconsistent);
        }
        let content_digest = match (envelope.disposition(), ingress.content()) {
            (SlackDisposition::Admitted, Some(content)) => Some(slack_content_digest(content)),
            (SlackDisposition::Denied | SlackDisposition::IgnoredUnsupported, None) => None,
            _ => return Err(SlackSinkFailure::Inconsistent),
        };
        // The pairing is restated rather than assumed: the digest above is an
        // owned `String`, and the store's disposition borrows it.
        let disposition = match (envelope.disposition(), content_digest.as_deref()) {
            (SlackDisposition::Admitted, Some(content_digest)) => {
                SlackStoreDisposition::Admitted { content_digest }
            }
            (SlackDisposition::Denied, None) => SlackStoreDisposition::Denied,
            (SlackDisposition::IgnoredUnsupported, None) => {
                SlackStoreDisposition::IgnoredUnsupported
            }
            _ => return Err(SlackSinkFailure::Inconsistent),
        };

        let recorded_at_ms = self.observed_now()?;
        let receipt = self
            .log
            .record(SlackDispositionRecord {
                source_key: ingress.source_key(),
                app_id: self.app_id.as_str(),
                envelope_id: envelope_id.as_str(),
                retry_attempt: envelope.retry().attempt(),
                disposition,
                recorded_at_ms,
            })
            .map_err(map_record_error)?;
        Ok(SlackDurableReceipt {
            entry_id: receipt.entry_id,
            disposition: disposition.kind(),
            outcome: receipt.outcome,
        })
    }

    /// Read back one recorded disposition by its deduplication identity.
    pub fn recorded(
        &self,
        source_key: &str,
    ) -> Result<Option<SlackDispositionEntry>, SlackSinkFailure> {
        self.log.disposition(source_key).map_err(map_read_error)
    }

    /// Bounded recovery page of this app's dispositions since an instant.
    ///
    /// `limit` is bounded by `MAX_DISPOSITION_PAGE`; a wider request is refused
    /// rather than silently truncated.
    pub fn recorded_since(
        &self,
        since_ms: i64,
        limit: usize,
    ) -> Result<Vec<SlackDispositionEntry>, SlackSinkFailure> {
        if limit == 0 || limit > MAX_DISPOSITION_PAGE {
            return Err(SlackSinkFailure::Inconsistent);
        }
        self.log
            .app_dispositions(self.app_id.as_str(), since_ms, limit)
            .map_err(map_read_error)
    }

    fn observed_now(&mut self) -> Result<i64, SlackSinkFailure> {
        self.clock
            .now_ms()
            .map_err(|_| SlackSinkFailure::Unavailable)
            .and_then(|now_ms| {
                if now_ms < 0 {
                    Err(SlackSinkFailure::Unavailable)
                } else {
                    Ok(now_ms)
                }
            })
    }
}

/// Map a write refusal onto the closed sink vocabulary.
///
/// `InvalidField` becomes [`SlackSinkFailure::Inconsistent`] rather than a
/// conflict: the transport's identifier grammar is strictly tighter than the
/// log's, so reaching it means the two boundaries disagree, not that a caller
/// presented a competing binding.
fn map_record_error(error: SlackIngressError) -> SlackSinkFailure {
    match error {
        SlackIngressError::Conflict { .. } => SlackSinkFailure::Conflict,
        SlackIngressError::LogFull { .. } => SlackSinkFailure::LogFull,
        SlackIngressError::InvalidField(_) => SlackSinkFailure::Inconsistent,
        SlackIngressError::Corrupt(_) => SlackSinkFailure::Corrupt,
        SlackIngressError::InsecurePath(_)
        | SlackIngressError::SchemaVersion { .. }
        | SlackIngressError::Io(_)
        | SlackIngressError::Sqlite(_) => SlackSinkFailure::Unavailable,
    }
}

/// Map a read refusal onto the closed sink vocabulary.
///
/// A read cannot conflict and cannot fill the log, so those spellings are
/// unreachable here and are mapped to the same classes a write would use only
/// because the error type is shared.
fn map_read_error(error: SlackIngressError) -> SlackSinkFailure {
    match error {
        SlackIngressError::Corrupt(_) => SlackSinkFailure::Corrupt,
        SlackIngressError::InvalidField(_) | SlackIngressError::Conflict { .. } => {
            SlackSinkFailure::Inconsistent
        }
        SlackIngressError::LogFull { .. }
        | SlackIngressError::InsecurePath(_)
        | SlackIngressError::SchemaVersion { .. }
        | SlackIngressError::Io(_)
        | SlackIngressError::Sqlite(_) => SlackSinkFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_refusal_classes_are_contextual_and_closed() {
        assert_eq!(
            map_record_error(SlackIngressError::LogFull { capacity: 1 }),
            SlackSinkFailure::LogFull
        );
        assert_eq!(
            map_record_error(SlackIngressError::InvalidField("source_key")),
            SlackSinkFailure::Inconsistent
        );
        assert_eq!(
            map_record_error(SlackIngressError::Corrupt("content_digest")),
            SlackSinkFailure::Corrupt
        );
        assert_eq!(
            map_read_error(SlackIngressError::Corrupt("source_key")),
            SlackSinkFailure::Corrupt
        );
        assert_eq!(
            map_read_error(SlackIngressError::LogFull { capacity: 1 }),
            SlackSinkFailure::Unavailable
        );
    }

    #[test]
    fn the_content_digest_is_domain_separated_and_lowercase_hex() {
        let digest = slack_content_digest("hello");
        assert_eq!(digest.len(), CONTENT_DIGEST_CHARS);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );

        let mut bare = Sha256::new();
        bare.update(b"hello");
        let bare: String = bare
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_ne!(digest, bare, "the domain separator must change the digest");
        assert_ne!(slack_content_digest("hello"), slack_content_digest("hell"));
    }
}
