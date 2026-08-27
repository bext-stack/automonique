// SPDX-License-Identifier: Elastic-2.0

//! Length-delimited local protocol framing, envelopes and version negotiation.
//!
//! Frames carry a fixed-width big-endian length prefix. Newline framing is
//! deliberately absent: local messages carry arbitrary model text, and a
//! delimiter that can appear inside a payload is not a delimiter.
//!
//! Every limit is enforced before the payload is interpreted, and no decode
//! path allocates a buffer sized by an untrusted length prefix. Errors name a
//! field and a violation class and never echo payload bytes, so a rejection is
//! safe to log.

use core::num::NonZeroU32;
use core::num::NonZeroUsize;
use std::error::Error;
use std::fmt;

use crate::primitives::ValueError;

/// Width of the big-endian frame length prefix.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Maximum payload bytes in one frame.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024 + 512;

/// Maximum structural nesting depth accepted during decode.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Maximum UTF-8 byte length of a protocol name.
pub const MAX_PROTOCOL_NAME_BYTES: usize = 64;

/// Maximum UTF-8 byte length of a request correlation identifier.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a message kind.
pub const MAX_MESSAGE_KIND_BYTES: usize = 64;

/// Maximum UTF-8 byte length of an enum value spelling retained as unknown.
pub const MAX_ENUM_VALUE_BYTES: usize = 64;

/// Why a frame, envelope or negotiation was rejected.
///
/// No variant carries payload bytes or a peer-supplied spelling, so a rejection
/// may be logged even when the frame that produced it is hostile or secret.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CodecError {
    /// The frame declared a zero-length payload, which carries no envelope.
    EmptyFrame,
    /// The declared payload length exceeded [`MAX_FRAME_BYTES`].
    FrameTooLarge {
        /// Maximum accepted payload length.
        max_bytes: usize,
        /// Length the prefix declared.
        declared_bytes: usize,
    },
    /// Structural nesting exceeded [`MAX_NESTING_DEPTH`].
    NestingTooDeep {
        /// Maximum accepted depth.
        max_depth: usize,
    },
    /// A bounded field violated the shared value rules.
    Field {
        /// Field that was rejected.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A bounded field violated its own grammar.
    Grammar {
        /// Field that was rejected.
        field: &'static str,
    },
    /// The envelope named a protocol this peer does not implement.
    UnknownProtocol,
    /// The envelope's major version lies outside the supported range.
    UnsupportedVersion {
        /// Lowest supported major version.
        supported_min: u32,
        /// Highest supported major version.
        supported_max: u32,
        /// Major version the envelope offered.
        offered: u32,
    },
    /// Two supported ranges share no major version.
    NoVersionOverlap {
        /// Local lowest supported major version.
        local_min: u32,
        /// Local highest supported major version.
        local_max: u32,
        /// Peer lowest supported major version.
        peer_min: u32,
        /// Peer highest supported major version.
        peer_max: u32,
    },
    /// A supported range was constructed with its maximum below its minimum.
    InvertedVersionRange {
        /// Supplied minimum.
        min: u32,
        /// Supplied maximum.
        max: u32,
    },
    /// A security-sensitive enum received a value this build does not define.
    UnknownEnumValue {
        /// Field that was rejected.
        field: &'static str,
    },
    /// The payload is not syntactically valid JSON, or not valid UTF-8.
    MalformedJson,
    /// The payload parses but is not in canonical form.
    ///
    /// Refused rather than normalized, so one message has exactly one accepted
    /// byte spelling.
    NonCanonicalJson,
    /// A value is the wrong JSON type for its field, or a non-integer number.
    InvalidJsonValue {
        /// Field that was rejected.
        field: &'static str,
    },
    /// An object contained the same key twice.
    DuplicateKey,
    /// Bytes remained after a complete value.
    TrailingData,
    /// An integer is outside the signed 64-bit range.
    IntegerOutOfRange,
    /// An array or object exceeded the entry ceiling.
    TooManyEntries {
        /// Maximum accepted entries.
        max: usize,
    },
    /// A required field was absent.
    MissingField {
        /// The absent field.
        field: &'static str,
    },
}

impl CodecError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::EmptyFrame => "empty_frame",
            Self::FrameTooLarge { .. } => "frame_too_large",
            Self::NestingTooDeep { .. } => "nesting_too_deep",
            Self::Field { .. } => "field_invalid",
            Self::Grammar { .. } => "field_grammar",
            Self::UnknownProtocol => "unknown_protocol",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::NoVersionOverlap { .. } => "no_version_overlap",
            Self::InvertedVersionRange { .. } => "inverted_version_range",
            Self::UnknownEnumValue { .. } => "unknown_enum_value",
            Self::MalformedJson => "malformed_json",
            Self::NonCanonicalJson => "non_canonical_json",
            Self::InvalidJsonValue { .. } => "invalid_json_value",
            Self::DuplicateKey => "duplicate_key",
            Self::TrailingData => "trailing_data",
            Self::IntegerOutOfRange => "integer_out_of_range",
            Self::TooManyEntries { .. } => "too_many_entries",
            Self::MissingField { .. } => "missing_field",
        }
    }

    /// Stable wire code a peer receives for this rejection.
    ///
    /// The mapping is total and each code is used by exactly one category, so a
    /// peer's classification matches a local caller's.
    #[must_use]
    pub const fn wire_code(&self) -> u16 {
        match self {
            Self::EmptyFrame => 1000,
            Self::FrameTooLarge { .. } => 1001,
            Self::NestingTooDeep { .. } => 1002,
            Self::Field { .. } => 1003,
            Self::Grammar { .. } => 1004,
            Self::UnknownProtocol => 1005,
            Self::UnsupportedVersion { .. } => 1006,
            Self::NoVersionOverlap { .. } => 1007,
            Self::InvertedVersionRange { .. } => 1008,
            Self::UnknownEnumValue { .. } => 1009,
            Self::MalformedJson => 1010,
            Self::NonCanonicalJson => 1011,
            Self::InvalidJsonValue { .. } => 1012,
            Self::DuplicateKey => 1013,
            Self::TrailingData => 1014,
            Self::IntegerOutOfRange => 1015,
            Self::TooManyEntries { .. } => 1016,
            Self::MissingField { .. } => 1017,
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => formatter.write_str("frame declares a zero-length payload"),
            Self::FrameTooLarge {
                max_bytes,
                declared_bytes,
            } => write!(
                formatter,
                "frame declares {declared_bytes} payload bytes; maximum is {max_bytes}"
            ),
            Self::NestingTooDeep { max_depth } => {
                write!(
                    formatter,
                    "nesting exceeds the maximum depth of {max_depth}"
                )
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Grammar { field } => {
                write!(formatter, "field {field} violates its grammar")
            }
            Self::UnknownProtocol => formatter.write_str("protocol name is not implemented"),
            Self::UnsupportedVersion {
                supported_min,
                supported_max,
                offered,
            } => write!(
                formatter,
                "major version {offered} is outside the supported range \
                 {supported_min}..={supported_max}"
            ),
            Self::NoVersionOverlap {
                local_min,
                local_max,
                peer_min,
                peer_max,
            } => write!(
                formatter,
                "supported ranges {local_min}..={local_max} and \
                 {peer_min}..={peer_max} share no major version"
            ),
            Self::InvertedVersionRange { min, max } => {
                write!(formatter, "version range {min}..={max} is inverted")
            }
            Self::UnknownEnumValue { field } => {
                write!(formatter, "field {field} has an undefined enum value")
            }
            Self::MalformedJson => formatter.write_str("payload is not valid canonical JSON text"),
            Self::NonCanonicalJson => {
                formatter.write_str("payload parses but is not in canonical form")
            }
            Self::InvalidJsonValue { field } => {
                write!(formatter, "field {field} has the wrong JSON type")
            }
            Self::DuplicateKey => formatter.write_str("object contains a duplicate key"),
            Self::TrailingData => formatter.write_str("bytes remain after a complete value"),
            Self::IntegerOutOfRange => {
                formatter.write_str("integer is outside the signed 64-bit range")
            }
            Self::TooManyEntries { max } => {
                write!(formatter, "container exceeds {max} entries")
            }
            Self::MissingField { field } => {
                write!(formatter, "required field {field} is absent")
            }
        }
    }
}

impl Error for CodecError {}

/// Outcome of decoding one frame from a byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDecode<'a> {
    /// A complete frame was available.
    Frame {
        /// Payload bytes, borrowed from the input.
        payload: &'a [u8],
        /// Bytes the caller should consume, including the length prefix.
        consumed: usize,
    },
    /// The frame is incomplete; nothing was consumed.
    NeedMore {
        /// Further bytes required before the frame can be decoded.
        additional: NonZeroUsize,
    },
}

/// Append a length-delimited frame to `out`.
///
/// # Errors
///
/// Returns [`CodecError::EmptyFrame`] for an empty payload and
/// [`CodecError::FrameTooLarge`] above [`MAX_FRAME_BYTES`].
pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
    if payload.is_empty() {
        return Err(CodecError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES,
            declared_bytes: payload.len(),
        });
    }
    // The bound above keeps this conversion exact on every supported target.
    let length = u32::try_from(payload.len()).map_err(|_| CodecError::FrameTooLarge {
        max_bytes: MAX_FRAME_BYTES,
        declared_bytes: payload.len(),
    })?;
    out.reserve(LENGTH_PREFIX_BYTES + payload.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Decode the first frame in `input` without consuming a partial frame.
///
/// The declared length is validated against [`MAX_FRAME_BYTES`] before it is
/// used for anything, and the payload is borrowed rather than copied, so an
/// oversized prefix can never drive an allocation.
///
/// # Errors
///
/// Returns [`CodecError::EmptyFrame`] or [`CodecError::FrameTooLarge`] when the
/// prefix declares a length outside the accepted range.
pub fn decode_frame(input: &[u8]) -> Result<FrameDecode<'_>, CodecError> {
    let Some(prefix) = input.get(..LENGTH_PREFIX_BYTES) else {
        return Ok(need_more(LENGTH_PREFIX_BYTES - input.len()));
    };
    let mut raw = [0_u8; LENGTH_PREFIX_BYTES];
    raw.copy_from_slice(prefix);
    let declared = u32::from_be_bytes(raw);
    if declared == 0 {
        return Err(CodecError::EmptyFrame);
    }
    let declared = usize::try_from(declared).map_err(|_| CodecError::FrameTooLarge {
        max_bytes: MAX_FRAME_BYTES,
        declared_bytes: MAX_FRAME_BYTES.saturating_add(1),
    })?;
    if declared > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES,
            declared_bytes: declared,
        });
    }
    let total = LENGTH_PREFIX_BYTES + declared;
    match input.get(LENGTH_PREFIX_BYTES..total) {
        Some(payload) => Ok(FrameDecode::Frame {
            payload,
            consumed: total,
        }),
        None => Ok(need_more(total - input.len())),
    }
}

fn need_more(additional: usize) -> FrameDecode<'static> {
    // Only reached when at least one byte is outstanding.
    let additional = NonZeroUsize::new(additional).unwrap_or(NonZeroUsize::MIN);
    FrameDecode::NeedMore { additional }
}

/// Guard that bounds structural nesting during decode.
///
/// The guard counts depth rather than recursing, so a deeply nested body fails
/// at a known depth instead of exhausting the stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepthGuard {
    max_depth: usize,
    depth: usize,
}

impl DepthGuard {
    /// Create a guard bounded by [`MAX_NESTING_DEPTH`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: MAX_NESTING_DEPTH,
            depth: 0,
        }
    }

    /// Create a guard with an explicit ceiling.
    #[must_use]
    pub const fn with_max_depth(max_depth: usize) -> Self {
        Self {
            max_depth,
            depth: 0,
        }
    }

    /// Current nesting depth.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth
    }

    /// Enter one nesting level.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NestingTooDeep`] at one level beyond the ceiling.
    pub const fn enter(&mut self) -> Result<(), CodecError> {
        if self.depth == self.max_depth {
            return Err(CodecError::NestingTooDeep {
                max_depth: self.max_depth,
            });
        }
        self.depth += 1;
        Ok(())
    }

    /// Leave one nesting level. Leaving the outermost level is a no-op.
    pub const fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl Default for DepthGuard {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! bounded_field {
    ($name:ident, $max:expr, $field:literal, $doc:literal, $grammar:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Maximum accepted UTF-8 byte length.
            pub const MAX_BYTES: usize = $max;

            /// Validate and construct the value.
            ///
            /// # Errors
            ///
            /// Returns [`CodecError::Field`] when the shared bounded-value rules
            /// are violated and [`CodecError::Grammar`] when the field's own
            /// grammar is.
            pub fn new(value: impl Into<String>) -> Result<Self, CodecError> {
                let value = value.into();
                validate_bounded_field(&value, $max, $field)?;
                #[allow(clippy::redundant_closure_call)]
                if !($grammar)(value.as_str()) {
                    return Err(CodecError::Grammar { field: $field });
                }
                Ok(Self(value))
            }

            /// Return the validated spelling.
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

bounded_field!(
    ProtocolName,
    MAX_PROTOCOL_NAME_BYTES,
    "protocol",
    "Dotted lowercase protocol name, such as `automonique.runner`.",
    |value: &str| {
        let mut bytes = value.bytes();
        bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
            && !value.ends_with('.')
            && !value.contains("..")
    }
);

bounded_field!(
    RequestId,
    MAX_REQUEST_ID_BYTES,
    "request_id",
    "Opaque request correlation identifier.",
    |value: &str| value
        .bytes()
        .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':') })
);

bounded_field!(
    MessageKind,
    MAX_MESSAGE_KIND_BYTES,
    "kind",
    "Lowercase message kind, such as `subscribe`.",
    |value: &str| {
        value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }
);

fn validate_bounded_field(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), CodecError> {
    let error = if max_bytes == 0 {
        Some(ValueError::ZeroBound)
    } else if value.is_empty() {
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
        Some(error) => Err(CodecError::Field { field, error }),
        None => Ok(()),
    }
}

/// Major protocol version. Zero is not a version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MajorVersion(NonZeroU32);

impl MajorVersion {
    /// The first major version.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Construct a major version.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Field`] when `value` is zero.
    pub const fn new(value: u32) -> Result<Self, CodecError> {
        match NonZeroU32::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(CodecError::Field {
                field: "version",
                error: ValueError::Empty,
            }),
        }
    }

    /// Return the version number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for MajorVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.get())
    }
}

/// Inclusive range of supported major versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VersionRange {
    min: MajorVersion,
    max: MajorVersion,
}

impl VersionRange {
    /// Construct an inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::InvertedVersionRange`] when `max` is below `min`.
    /// An empty range is unrepresentable: both bounds are non-zero and
    /// inclusive.
    pub const fn new(min: MajorVersion, max: MajorVersion) -> Result<Self, CodecError> {
        if max.get() < min.get() {
            return Err(CodecError::InvertedVersionRange {
                min: min.get(),
                max: max.get(),
            });
        }
        Ok(Self { min, max })
    }

    /// Construct a range accepting exactly one version.
    #[must_use]
    pub const fn exact(version: MajorVersion) -> Self {
        Self {
            min: version,
            max: version,
        }
    }

    /// Lowest supported version.
    #[must_use]
    pub const fn min(self) -> MajorVersion {
        self.min
    }

    /// Highest supported version.
    #[must_use]
    pub const fn max(self) -> MajorVersion {
        self.max
    }

    /// Whether the range accepts `version`.
    #[must_use]
    pub const fn accepts(self, version: MajorVersion) -> bool {
        self.min.get() <= version.get() && version.get() <= self.max.get()
    }

    /// Select the highest version both ranges support.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NoVersionOverlap`] naming both ranges when they
    /// share no version.
    pub const fn negotiate(self, peer: Self) -> Result<MajorVersion, CodecError> {
        let low = if self.min.get() >= peer.min.get() {
            self.min.get()
        } else {
            peer.min.get()
        };
        let high = if self.max.get() <= peer.max.get() {
            self.max.get()
        } else {
            peer.max.get()
        };
        if high < low {
            return Err(CodecError::NoVersionOverlap {
                local_min: self.min.get(),
                local_max: self.max.get(),
                peer_min: peer.min.get(),
                peer_max: peer.max.get(),
            });
        }
        MajorVersion::new(high)
    }
}

/// Decoded message envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    protocol: ProtocolName,
    version: MajorVersion,
    request_id: RequestId,
    kind: MessageKind,
}

impl Envelope {
    /// Construct an envelope from validated parts.
    #[must_use]
    pub const fn new(
        protocol: ProtocolName,
        version: MajorVersion,
        request_id: RequestId,
        kind: MessageKind,
    ) -> Self {
        Self {
            protocol,
            version,
            request_id,
            kind,
        }
    }

    /// Protocol name.
    #[must_use]
    pub const fn protocol(&self) -> &ProtocolName {
        &self.protocol
    }

    /// Major version.
    #[must_use]
    pub const fn version(&self) -> MajorVersion {
        self.version
    }

    /// Request correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Message kind.
    #[must_use]
    pub const fn kind(&self) -> &MessageKind {
        &self.kind
    }
}

/// One protocol this peer implements, with its supported version range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedProtocol {
    name: ProtocolName,
    versions: VersionRange,
}

impl SupportedProtocol {
    /// Declare a supported protocol.
    #[must_use]
    pub const fn new(name: ProtocolName, versions: VersionRange) -> Self {
        Self { name, versions }
    }

    /// Supported version range.
    #[must_use]
    pub const fn versions(&self) -> VersionRange {
        self.versions
    }

    /// Admit an envelope, failing closed on either axis.
    ///
    /// An unimplemented protocol and an unsupported major version are distinct
    /// errors; neither is downgraded, guessed or defaulted.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnknownProtocol`] or
    /// [`CodecError::UnsupportedVersion`].
    pub fn admit(&self, envelope: &Envelope) -> Result<(), CodecError> {
        if envelope.protocol() != &self.name {
            return Err(CodecError::UnknownProtocol);
        }
        if !self.versions.accepts(envelope.version()) {
            return Err(CodecError::UnsupportedVersion {
                supported_min: self.versions.min().get(),
                supported_max: self.versions.max().get(),
                offered: envelope.version().get(),
            });
        }
        Ok(())
    }
}

/// A closed enum whose unknown values must be rejected.
///
/// Implement this for any enum whose value selects behavior with a security
/// consequence. Decoding refuses a value this build does not define rather than
/// guessing a default.
pub trait SecuritySensitiveEnum: Sized {
    /// Field name reported when a value is refused.
    const FIELD: &'static str;

    /// Map a wire spelling to a defined value.
    fn from_wire(value: &str) -> Option<Self>;
}

/// Decode a security-sensitive enum, failing closed on an unknown value.
///
/// # Errors
///
/// Returns [`CodecError::UnknownEnumValue`] when the value is not defined.
pub fn decode_security_enum<T: SecuritySensitiveEnum>(value: &str) -> Result<T, CodecError> {
    T::from_wire(value).ok_or(CodecError::UnknownEnumValue { field: T::FIELD })
}

/// A read-only enum that tolerates values added by an adjacent release.
pub trait ReadOnlyEnum: Sized {
    /// Field name used when retaining an unknown spelling.
    const FIELD: &'static str;

    /// Map a wire spelling to a defined value.
    fn from_wire(value: &str) -> Option<Self>;
}

/// A read-only enum value, which may be one this build does not define.
///
/// An unknown value keeps its original spelling for display and logging without
/// acquiring meaning: no method converts [`ReadOnly::Unknown`] into a known
/// variant.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ReadOnly<T> {
    /// A value this build defines.
    Known(T),
    /// A value this build does not define, with its spelling preserved.
    Unknown(String),
}

impl<T> ReadOnly<T> {
    /// The defined value, if this build understands it.
    #[must_use]
    pub const fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// The preserved spelling of an unrecognized value.
    #[must_use]
    pub fn unknown_spelling(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(spelling) => Some(spelling),
        }
    }
}

/// Decode a read-only enum, retaining an unknown spelling rather than failing.
///
/// # Errors
///
/// Returns [`CodecError::Field`] when an unknown spelling violates the shared
/// bounded-value rules, so an unbounded value cannot be retained.
pub fn decode_read_only_enum<T: ReadOnlyEnum>(value: &str) -> Result<ReadOnly<T>, CodecError> {
    match T::from_wire(value) {
        Some(known) => Ok(ReadOnly::Known(known)),
        None => {
            validate_bounded_field(value, MAX_ENUM_VALUE_BYTES, T::FIELD)?;
            Ok(ReadOnly::Unknown(value.to_owned()))
        }
    }
}

/// Reference to a body held in the spool rather than copied through a frame.
///
/// The reference is carried opaquely. This layer neither resolves, opens nor
/// validates the spool it names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpoolReference {
    sequence: u64,
    offset: u64,
}

impl SpoolReference {
    /// Construct a spool reference.
    #[must_use]
    pub const fn new(sequence: u64, offset: u64) -> Self {
        Self { sequence, offset }
    }

    /// Event sequence the body belongs to.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Byte offset within that sequence.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }
}
