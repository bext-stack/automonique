// SPDX-License-Identifier: Elastic-2.0

//! Bounded identifiers for following one input through work and effects.

use core::fmt;
use std::error::Error;

use crate::digest::Sha256;

/// Largest provenance identifier accepted on a durable boundary.
pub const MAX_PROVENANCE_ID_BYTES: usize = 256;

/// Why a provenance identifier was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "provenance identifier is empty",
            Self::TooLong => "provenance identifier is too long",
            Self::InvalidCharacter => "provenance identifier contains a forbidden character",
        })
    }
}

impl Error for ProvenanceError {}

fn validate(value: &str) -> Result<(), ProvenanceError> {
    if value.is_empty() {
        return Err(ProvenanceError::Empty);
    }
    if value.len() > MAX_PROVENANCE_ID_BYTES {
        return Err(ProvenanceError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ProvenanceError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! provenance_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validate and own one identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
                let value = value.into();
                validate(&value)?;
                Ok(Self(value))
            }

            /// Borrow the canonical spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

provenance_id!(
    TraceId,
    "Identity shared by every record descended from one ingress."
);
provenance_id!(
    CorrelationId,
    "Identity shared by records in the current unit of work."
);
provenance_id!(
    CausationId,
    "Identity of the durable record that directly caused this record."
);

impl TraceId {
    /// Mint the stable trace for a transport delivery.
    ///
    /// The first 128 bits of SHA-256 over `transport || NUL || transport_key`
    /// are sufficient for an operational identifier and make replay mint the
    /// same trace without a random-number source.
    #[must_use]
    pub fn for_ingress(transport: &str, transport_key: &str) -> Self {
        let mut input = Vec::with_capacity(transport.len() + 1 + transport_key.len());
        input.extend_from_slice(transport.as_bytes());
        input.push(0);
        input.extend_from_slice(transport_key.as_bytes());
        let digest = Sha256::digest(&input);
        let mut value = String::with_capacity(32);
        for byte in &digest.as_bytes()[..16] {
            use core::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(value)
    }
}

/// The explicit provenance carried by a durable child record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    trace_id: TraceId,
    correlation_id: CorrelationId,
    causation_id: CausationId,
}

impl Provenance {
    #[must_use]
    pub const fn new(
        trace_id: TraceId,
        correlation_id: CorrelationId,
        causation_id: CausationId,
    ) -> Self {
        Self {
            trace_id,
            correlation_id,
            causation_id,
        }
    }

    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    #[must_use]
    pub const fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }

    #[must_use]
    pub const fn causation_id(&self) -> &CausationId {
        &self.causation_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_trace_is_deterministic_and_coordinate_safe() {
        let first = TraceId::for_ingress("slack", "slack:A:T:C:123.4");
        let second = TraceId::for_ingress("slack", "slack:A:T:C:123.4");
        assert_eq!(first, second);
        assert_eq!(first.as_str().len(), 32);
        assert!(first.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, TraceId::for_ingress("telegram", "slack:A:T:C:123.4"));
    }

    #[test]
    fn every_id_uses_the_header_safe_coordinate_alphabet() {
        for value in ["a.b_c:d-9", "trace:01"] {
            assert!(TraceId::new(value).is_ok());
            assert!(CorrelationId::new(value).is_ok());
            assert!(CausationId::new(value).is_ok());
        }
        for value in ["", "has space", "line\nbreak", "é"] {
            assert!(TraceId::new(value).is_err());
            assert!(CorrelationId::new(value).is_err());
            assert!(CausationId::new(value).is_err());
        }
    }
}
