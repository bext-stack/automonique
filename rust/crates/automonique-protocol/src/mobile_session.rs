// SPDX-License-Identifier: Elastic-2.0

//! Sanitized, session-scoped history values for remote mobile clients.
//!
//! This contract deliberately cannot represent provider records, tool input or
//! output, credentials, or prompts. Producers must project those richer local
//! values into one of the small public variants below before persistence.

use core::fmt;

use crate::event::{EventKind, StepStatus};
use crate::primitives::{BoundedString, EpochMillis, ValueError};
use crate::progress_api::ProgressFrame;
use crate::tools::RunId;

pub const MOBILE_SESSION_PROTOCOL: &str = "automonique.mobile-session";
pub const MOBILE_SESSION_SCHEMA_V1: &str = "automonique.mobile-session/v1";
pub const MOBILE_SESSION_MEDIA_TYPE: &str = "application/vnd.automonique.mobile-session.v1+json";
pub const MAX_MOBILE_HISTORY_EVENTS: usize = 512;
pub const MAX_MOBILE_HISTORY_MESSAGE_BYTES: usize = 32 * 1024;
pub const MAX_MOBILE_HISTORY_KIND_BYTES: usize = 64;
/// Largest cursor or epoch value carried as a decimal string. This remains
/// above JavaScript's safe-integer ceiling while fitting every durable store.
pub const MAX_MOBILE_HISTORY_DECIMAL: u64 = 9_999_999_999_999_999;

pub type MobileUnknownEventKind = BoundedString<MAX_MOBILE_HISTORY_KIND_BYTES>;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MobileHistoryMessage(String);

impl MobileHistoryMessage {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > MAX_MOBILE_HISTORY_MESSAGE_BYTES {
            return Err(ValueError::TooLong {
                max_bytes: MAX_MOBILE_HISTORY_MESSAGE_BYTES,
                actual_bytes: value.len(),
            });
        }
        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ValueError::ControlCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// A lossless wire cursor. JSON carries its canonical decimal spelling rather
/// than a number, so positions above JavaScript's safe-integer ceiling survive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MobileHistoryCursor(u64);

impl MobileHistoryCursor {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn parse(value: &str) -> Result<Self, MobileSessionError> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(MobileSessionError::InvalidCursor);
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= MAX_MOBILE_HISTORY_DECIMAL)
            .map(Self)
            .ok_or(MobileSessionError::InvalidCursor)
    }
}

impl fmt::Display for MobileHistoryCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileMessageRole {
    Assistant,
}

impl MobileMessageRole {
    pub const ALL: [Self; 1] = [Self::Assistant];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assistant => "assistant",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileToolState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl MobileToolState {
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Running,
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileRunState {
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl MobileRunState {
    pub const ALL: [Self; 5] = [
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

/// The only bodies permitted in the remotely serialized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MobileHistoryBody {
    Message {
        role: MobileMessageRole,
        text: MobileHistoryMessage,
    },
    ToolState {
        state: MobileToolState,
    },
    RunState {
        state: MobileRunState,
    },
    /// A future or deliberately unprojected event. Only its bounded public
    /// vocabulary word survives; its payload never crosses this boundary.
    Unknown {
        event_kind: MobileUnknownEventKind,
    },
}

impl MobileHistoryBody {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Message { .. } => "message",
            Self::ToolState { .. } => "tool_state",
            Self::RunState { .. } => "run_state",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Project a sanitized progress frame into the deliberately smaller mobile
    /// vocabulary. Text survives only for a final assistant message; tool and
    /// unknown events discard every payload member.
    #[must_use]
    pub fn from_progress_frame(frame: &ProgressFrame) -> Option<Self> {
        match frame.kind() {
            EventKind::AssistantMessageCompleted => Some(Self::Message {
                role: MobileMessageRole::Assistant,
                text: MobileHistoryMessage::new(frame.body().text()?.as_str()).ok()?,
            }),
            EventKind::ToolCallStarted
            | EventKind::ToolCallUpdated
            | EventKind::ToolCallCompleted => Some(Self::ToolState {
                state: match frame.body().step()? {
                    StepStatus::Pending => MobileToolState::Pending,
                    StepStatus::InProgress => MobileToolState::Running,
                    StepStatus::Completed => MobileToolState::Succeeded,
                    StepStatus::Error => MobileToolState::Failed,
                },
            }),
            kind => MobileUnknownEventKind::new(kind.as_str())
                .ok()
                .map(|event_kind| Self::Unknown { event_kind }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileHistoryEvent {
    pub cursor: MobileHistoryCursor,
    pub at_ms: EpochMillis,
    pub run_id: RunId,
    pub body: MobileHistoryBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileHistoryPage {
    pub schema: &'static str,
    pub session_id: String,
    pub requested_limit: usize,
    pub applied_limit: usize,
    pub exclusive_cursor: MobileHistoryCursor,
    pub terminal_cursor: MobileHistoryCursor,
    pub has_more: bool,
    pub events: Vec<MobileHistoryEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileHistoryResyncReason {
    RetentionExpired,
    CursorGap,
}

impl MobileHistoryResyncReason {
    pub const ALL: [Self; 2] = [Self::RetentionExpired, Self::CursorGap];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetentionExpired => "retention_expired",
            Self::CursorGap => "cursor_gap",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileHistoryResync {
    pub schema: &'static str,
    pub session_id: String,
    pub reason: MobileHistoryResyncReason,
    pub requested_cursor: MobileHistoryCursor,
    pub earliest_cursor: MobileHistoryCursor,
    pub terminal_cursor: MobileHistoryCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MobileSessionError {
    InvalidCursor,
    InvalidLimit,
    InvalidField(ValueError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_canonical_and_lossless_above_javascript_safe_integer() {
        let cursor = MobileHistoryCursor::new(9_007_199_254_740_992);
        assert_eq!(cursor.to_string(), "9007199254740992");
        assert_eq!(MobileHistoryCursor::parse(&cursor.to_string()), Ok(cursor));
        for refused in ["", "01", "+1", "-1", "18446744073709551616"] {
            assert_eq!(
                MobileHistoryCursor::parse(refused),
                Err(MobileSessionError::InvalidCursor)
            );
        }
    }
}
