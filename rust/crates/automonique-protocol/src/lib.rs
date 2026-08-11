// SPDX-License-Identifier: Elastic-2.0

//! Stable, dependency-free product protocol primitives.
//!
//! The crate contains values only. It performs no process, filesystem, network,
//! credential, or provider operations.

pub mod automation;
pub mod codec;
pub mod codegen;
pub mod compat;
pub mod connector;
pub mod context;
pub mod digest;
pub mod event;
pub mod host;
pub mod identity;
pub mod interaction;
pub mod journal;
pub mod models;
pub mod namespace;
pub mod primitives;
pub mod protocols;
pub mod provider;
pub mod release;
pub mod sandbox;
pub mod schema;
pub mod tools;
pub mod wire;
pub mod workspace;

use std::error::Error;
use std::fmt;

/// Stable schema identifier for [`DoctorReportV1`].
pub const DOCTOR_REPORT_SCHEMA_V1: &str = "automonique.doctor/v1";

/// Maximum UTF-8 byte length of a finding code.
pub const MAX_FINDING_CODE_BYTES: usize = 64;

/// Maximum UTF-8 byte length of a human-readable finding message.
pub const MAX_FINDING_MESSAGE_BYTES: usize = 512;

/// Maximum number of checks in one doctor report.
pub const MAX_DOCTOR_CHECKS: usize = 256;

/// Product-facing health status, ordered from least to most severe.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReportStatus {
    /// All applicable checks passed.
    #[default]
    Healthy,
    /// At least one check needs attention, but operation may continue.
    Degraded,
    /// At least one check failed and the inspected operation must stop.
    Failed,
}

impl ReportStatus {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

/// Outcome of one doctor check.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CheckStatus {
    /// The check ran and passed.
    Healthy,
    /// The check ran and found a condition that blocks healthy operation.
    Finding,
    /// The check could not determine the condition truthfully.
    Unavailable,
}

impl CheckStatus {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Finding => "finding",
            Self::Unavailable => "unavailable",
        }
    }

    const fn report_status(self) -> ReportStatus {
        match self {
            Self::Healthy => ReportStatus::Healthy,
            Self::Finding => ReportStatus::Failed,
            Self::Unavailable => ReportStatus::Degraded,
        }
    }
}

/// Why a bounded protocol string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedTextError {
    /// The value was empty.
    Empty,
    /// The UTF-8 representation exceeded the field's fixed bound.
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
        /// Supplied UTF-8 byte length.
        actual_bytes: usize,
    },
    /// The value contained a character outside the field's grammar.
    InvalidCharacter,
}

impl fmt::Display for BoundedTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value is empty"),
            Self::TooLong {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "value is {actual_bytes} UTF-8 bytes; maximum is {max_bytes}"
            ),
            Self::InvalidCharacter => formatter.write_str("value contains an invalid character"),
        }
    }
}

impl Error for BoundedTextError {}

/// Stable machine-readable finding code.
///
/// Codes begin with an ASCII lowercase letter and otherwise contain only
/// lowercase letters, digits, `.`, `_`, or `-`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FindingCode(String);

impl FindingCode {
    /// Validate and construct a finding code.
    pub fn new(value: impl Into<String>) -> Result<Self, BoundedTextError> {
        let value = value.into();
        validate_length(&value, MAX_FINDING_CODE_BYTES)?;
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(BoundedTextError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Return the stable code spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded, single-line, human-readable finding message.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FindingMessage(String);

impl FindingMessage {
    /// Validate and construct a finding message.
    pub fn new(value: impl Into<String>) -> Result<Self, BoundedTextError> {
        let value = value.into();
        validate_length(&value, MAX_FINDING_MESSAGE_BYTES)?;
        if value.chars().any(char::is_control) {
            return Err(BoundedTextError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Return the message text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a doctor check could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorCheckError {
    /// A finding or unavailable check did not include a reason.
    ReasonRequired,
    /// A healthy check included a contradictory reason.
    HealthyReasonForbidden,
}

impl fmt::Display for DoctorCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReasonRequired => formatter.write_str("non-healthy check requires a reason"),
            Self::HealthyReasonForbidden => {
                formatter.write_str("healthy check cannot include a reason")
            }
        }
    }
}

impl Error for DoctorCheckError {}

/// Stable machine-readable reason paired with a bounded explanation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DoctorReason {
    code: FindingCode,
    message: FindingMessage,
}

impl DoctorReason {
    /// Construct a typed, bounded reason.
    #[must_use]
    pub const fn new(code: FindingCode, message: FindingMessage) -> Self {
        Self { code, message }
    }

    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn code(&self) -> &FindingCode {
        &self.code
    }

    /// Bounded human-readable explanation.
    #[must_use]
    pub const fn message(&self) -> &FindingMessage {
        &self.message
    }
}

/// One immutable doctor check.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DoctorCheck {
    code: FindingCode,
    status: CheckStatus,
    reason: Option<DoctorReason>,
}

impl DoctorCheck {
    /// Construct a check while enforcing truthful reason presence.
    pub fn new(
        code: FindingCode,
        status: CheckStatus,
        reason: Option<DoctorReason>,
    ) -> Result<Self, DoctorCheckError> {
        match (status, &reason) {
            (CheckStatus::Healthy, Some(_)) => {
                return Err(DoctorCheckError::HealthyReasonForbidden);
            }
            (CheckStatus::Finding | CheckStatus::Unavailable, None) => {
                return Err(DoctorCheckError::ReasonRequired);
            }
            (CheckStatus::Healthy, None)
            | (CheckStatus::Finding | CheckStatus::Unavailable, Some(_)) => {}
        }
        Ok(Self {
            code,
            status,
            reason,
        })
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &FindingCode {
        &self.code
    }

    /// Finding severity.
    #[must_use]
    pub const fn status(&self) -> CheckStatus {
        self.status
    }

    /// Bounded reason for a finding or unavailable result.
    #[must_use]
    pub const fn reason(&self) -> Option<&DoctorReason> {
        self.reason.as_ref()
    }
}

/// Why a doctor report could not be constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorReportError {
    /// No check was performed, so health cannot be claimed.
    NoChecks,
    /// The report exceeded [`MAX_DOCTOR_CHECKS`].
    TooManyChecks,
    /// A stable check code occurred more than once.
    DuplicateCode(FindingCode),
}

impl fmt::Display for DoctorReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChecks => formatter.write_str("doctor report contains no checks"),
            Self::TooManyChecks => write!(
                formatter,
                "doctor report exceeds {MAX_DOCTOR_CHECKS} checks"
            ),
            Self::DuplicateCode(code) => write!(formatter, "duplicate check code: {code}"),
        }
    }
}

impl Error for DoctorReportError {}

/// Version-one deterministic doctor report.
///
/// Checks are sorted by code, then status and reason. Empty reports and
/// duplicate codes are rejected so consumers never infer health from absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorReportV1 {
    checks: Vec<DoctorCheck>,
    status: ReportStatus,
}

impl DoctorReportV1 {
    /// Validate, sort, and construct a report.
    pub fn new(checks: impl IntoIterator<Item = DoctorCheck>) -> Result<Self, DoctorReportError> {
        let mut ordered = Vec::new();
        for check in checks {
            if ordered.len() == MAX_DOCTOR_CHECKS {
                return Err(DoctorReportError::TooManyChecks);
            }
            ordered.push(check);
        }
        if ordered.is_empty() {
            return Err(DoctorReportError::NoChecks);
        }
        ordered.sort_unstable();
        if let Some(duplicate) = ordered.windows(2).find(|pair| pair[0].code == pair[1].code) {
            return Err(DoctorReportError::DuplicateCode(duplicate[0].code.clone()));
        }
        let status = ordered
            .iter()
            .map(|check| check.status().report_status())
            .max()
            .unwrap_or_default();
        Ok(Self {
            checks: ordered,
            status,
        })
    }

    /// Stable schema identifier for this report version.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        DOCTOR_REPORT_SCHEMA_V1
    }

    /// Aggregate status derived from the most severe check outcome.
    #[must_use]
    pub const fn status(&self) -> ReportStatus {
        self.status
    }

    /// Checks in deterministic code order.
    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }
}

fn validate_length(value: &str, max_bytes: usize) -> Result<(), BoundedTextError> {
    if value.is_empty() {
        Err(BoundedTextError::Empty)
    } else if value.len() > max_bytes {
        Err(BoundedTextError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        })
    } else {
        Ok(())
    }
}
