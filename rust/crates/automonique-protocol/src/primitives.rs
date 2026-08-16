// SPDX-License-Identifier: Elastic-2.0

//! Bounded domain primitives shared by later protocol and policy work.
//!
//! Every value in this module validates at construction and exposes no
//! mutation that can break its invariant. The module performs no I/O, reads no
//! clock, resolves no name, and generates no identifier.

use std::fmt;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

/// Largest DNS name accepted in the host position, in ASCII bytes.
pub const MAX_DNS_NAME_BYTES: usize = 253;

/// Largest single DNS label accepted in the host position, in ASCII bytes.
pub const MAX_DNS_LABEL_BYTES: usize = 63;

/// Why a bounded value was rejected.
///
/// No variant carries the submitted value, so an error may be logged or
/// displayed even when the value it describes is a secret.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ValueError {
    /// The type was instantiated with a zero byte ceiling, which can accept
    /// nothing.
    ZeroBound,
    /// The value was empty.
    Empty,
    /// The UTF-8 representation exceeded the fixed ceiling.
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
        /// Supplied UTF-8 byte length.
        actual_bytes: usize,
    },
    /// The value contained a Unicode control character.
    ControlCharacter,
}

impl ValueError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::ZeroBound => "zero_bound",
            Self::Empty => "empty",
            Self::TooLong { .. } => "too_long",
            Self::ControlCharacter => "control_character",
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBound => formatter.write_str("byte ceiling is zero"),
            Self::Empty => formatter.write_str("value is empty"),
            Self::TooLong {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "value is {actual_bytes} UTF-8 bytes; maximum is {max_bytes}"
            ),
            Self::ControlCharacter => formatter.write_str("value contains a control character"),
        }
    }
}

impl std::error::Error for ValueError {}

/// Why a public HTTP(S) URL was rejected.
///
/// The URL itself never appears in a variant, so the category is safe to
/// report even when the URL embeds a caller-supplied path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UrlError {
    /// The bound or length rule was violated.
    Value(ValueError),
    /// The value contained a byte outside ASCII.
    NonAscii,
    /// The value contained ASCII whitespace.
    Whitespace,
    /// The scheme was not exactly `http` or `https`.
    Scheme,
    /// The authority carried user information.
    UserInfo,
    /// The value carried a fragment.
    Fragment,
    /// The value contained a backslash.
    Backslash,
    /// The host was empty, including a port-only authority.
    EmptyHost,
    /// The host was not a DNS name, IPv4 address or bracketed IPv6 address.
    Host,
    /// The port was absent after its separator, non-decimal, or outside
    /// `1..=65535`.
    Port,
}

impl UrlError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Value(inner) => inner.category(),
            Self::NonAscii => "non_ascii",
            Self::Whitespace => "whitespace",
            Self::Scheme => "scheme",
            Self::UserInfo => "user_info",
            Self::Fragment => "fragment",
            Self::Backslash => "backslash",
            Self::EmptyHost => "empty_host",
            Self::Host => "host",
            Self::Port => "port",
        }
    }
}

impl From<ValueError> for UrlError {
    fn from(value: ValueError) -> Self {
        Self::Value(value)
    }
}

impl fmt::Display for UrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(inner) => inner.fmt(formatter),
            Self::NonAscii => formatter.write_str("URL contains a non-ASCII byte"),
            Self::Whitespace => formatter.write_str("URL contains whitespace"),
            Self::Scheme => formatter.write_str("URL scheme is not http or https"),
            Self::UserInfo => formatter.write_str("URL authority carries user information"),
            Self::Fragment => formatter.write_str("URL carries a fragment"),
            Self::Backslash => formatter.write_str("URL contains a backslash"),
            Self::EmptyHost => formatter.write_str("URL host is empty"),
            Self::Host => formatter.write_str("URL host is not a valid name or address"),
            Self::Port => formatter.write_str("URL port is not a decimal number in 1..=65535"),
        }
    }
}

impl std::error::Error for UrlError {}

/// Why a timestamp operation was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeError {
    /// The millisecond remainder was outside `0..=999`.
    MillisecondOutOfRange,
    /// Checked arithmetic overflowed the representable range.
    Overflow,
}

impl TimeError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MillisecondOutOfRange => "millisecond_out_of_range",
            Self::Overflow => "overflow",
        }
    }
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MillisecondOutOfRange => {
                formatter.write_str("millisecond remainder is outside 0..=999")
            }
            Self::Overflow => formatter.write_str("checked arithmetic overflowed"),
        }
    }
}

impl std::error::Error for TimeError {}

/// Why a revision operation was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RevisionError {
    /// Zero is not a revision.
    Zero,
    /// The successor would overflow the representable range.
    Overflow,
}

impl RevisionError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Zero => "zero_revision",
            Self::Overflow => "overflow",
        }
    }
}

impl fmt::Display for RevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("revision is zero"),
            Self::Overflow => formatter.write_str("revision successor overflowed"),
        }
    }
}

impl std::error::Error for RevisionError {}

/// Marker trait implemented by identifier domain types.
///
/// A domain narrows what an identifier means without weakening the shared
/// bound enforced by [`OpaqueId`].
pub trait IdDomain {}

/// Validate a non-empty, control-free UTF-8 value against a byte ceiling.
///
/// The one implementation of the rule every bounded field in this crate is
/// checked against. It used to be twenty: each module carried its own
/// `bounded()` differing only in which constant it read and which error it
/// built, which meant "what counts as a control character" had twenty places to
/// drift and no test that would notice if one did.
///
/// The ceiling stays an argument. The modules' ceilings differ on purpose — an
/// interaction's text and a host's identifier are not the same size of thing —
/// so each keeps its own constant and passes it here.
///
/// # Errors
///
/// Returns [`ValueError::ZeroBound`] for a ceiling of zero, and otherwise
/// [`ValueError::Empty`], [`ValueError::TooLong`] or
/// [`ValueError::ControlCharacter`] for the first rule the value breaks.
pub fn bounded_value(value: &str, max_bytes: usize) -> Result<(), ValueError> {
    if max_bytes == 0 {
        return Err(ValueError::ZeroBound);
    }
    if value.is_empty() {
        return Err(ValueError::Empty);
    }
    if value.len() > max_bytes {
        return Err(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValueError::ControlCharacter);
    }
    Ok(())
}

/// Opaque, domain-distinct identifier bounded to `MAX_BYTES` UTF-8 bytes.
///
/// The identifier's contents are not interpreted beyond the shared rules:
/// non-empty, within the ceiling, and free of control characters. Two
/// identifiers with different domains are different types.
///
/// ```compile_fail
/// use automonique_protocol::primitives::{IdDomain, OpaqueId};
/// # #[derive(Clone, Copy, Debug)] pub struct Tenant;
/// # impl IdDomain for Tenant {}
/// # #[derive(Clone, Copy, Debug)] pub struct Actor;
/// # impl IdDomain for Actor {}
/// let tenant: OpaqueId<Tenant, 64> = OpaqueId::new("t-1").unwrap();
/// // A tenant identifier is not an actor identifier.
/// let actor: OpaqueId<Actor, 64> = tenant;
/// ```
pub struct OpaqueId<D: IdDomain, const MAX_BYTES: usize> {
    value: String,
    domain: PhantomData<fn() -> D>,
}

impl<D: IdDomain, const MAX_BYTES: usize> OpaqueId<D, MAX_BYTES> {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_BYTES;

    /// Validate and construct an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the ceiling is zero, or the value is empty,
    /// over the ceiling, or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        bounded_value(&value, MAX_BYTES)?;
        Ok(Self {
            value,
            domain: PhantomData,
        })
    }

    /// Return the validated opaque spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consume the identifier and return its validated spelling.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> Clone for OpaqueId<D, MAX_BYTES> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            domain: PhantomData,
        }
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> fmt::Debug for OpaqueId<D, MAX_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueId")
            .field(&self.value)
            .finish()
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> fmt::Display for OpaqueId<D, MAX_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> PartialEq for OpaqueId<D, MAX_BYTES> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> Eq for OpaqueId<D, MAX_BYTES> {}

impl<D: IdDomain, const MAX_BYTES: usize> std::hash::Hash for OpaqueId<D, MAX_BYTES> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> PartialOrd for OpaqueId<D, MAX_BYTES> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<D: IdDomain, const MAX_BYTES: usize> Ord for OpaqueId<D, MAX_BYTES> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

/// Non-empty, control-free UTF-8 text bounded to `MAX_BYTES` UTF-8 bytes.
///
/// Accepted Unicode is preserved exactly. The type never truncates and never
/// normalizes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedString<const MAX_BYTES: usize>(String);

impl<const MAX_BYTES: usize> BoundedString<MAX_BYTES> {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_BYTES;

    /// Validate and construct bounded text.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the ceiling is zero, or the value is empty,
    /// over the ceiling, or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        bounded_value(&value, MAX_BYTES)?;
        Ok(Self(value))
    }

    /// Return the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the value and return its validated text.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const MAX_BYTES: usize> fmt::Display for BoundedString<MAX_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A UTC instant as signed Unix epoch milliseconds.
///
/// The type reads no clock and assumes no timezone. Every arithmetic and
/// decomposition operation is checked.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EpochMillis(i64);

impl EpochMillis {
    /// The Unix epoch itself.
    pub const EPOCH: Self = Self(0);

    /// Build a timestamp from signed epoch milliseconds.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Return signed epoch milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Build a timestamp from whole seconds plus a `0..=999` remainder.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::MillisecondOutOfRange`] when the remainder exceeds
    /// 999, and [`TimeError::Overflow`] when the combination is not
    /// representable.
    pub const fn from_parts(seconds: i64, millis: u16) -> Result<Self, TimeError> {
        if millis > 999 {
            return Err(TimeError::MillisecondOutOfRange);
        }
        match seconds.checked_mul(1000) {
            Some(scaled) => match scaled.checked_add(millis as i64) {
                Some(total) => Ok(Self(total)),
                None => Err(TimeError::Overflow),
            },
            None => Err(TimeError::Overflow),
        }
    }

    /// Decompose into whole seconds and a non-negative `0..=999` remainder.
    ///
    /// The remainder is non-negative for negative instants too, so
    /// `-1` millisecond decomposes to `(-1, 999)`.
    #[must_use]
    pub const fn to_parts(self) -> (i64, u16) {
        let seconds = self.0.div_euclid(1000);
        let millis = self.0.rem_euclid(1000) as u16;
        (seconds, millis)
    }

    /// Add a signed millisecond delta.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::Overflow`] when the result is not representable.
    pub const fn checked_add_millis(self, delta: i64) -> Result<Self, TimeError> {
        match self.0.checked_add(delta) {
            Some(total) => Ok(Self(total)),
            None => Err(TimeError::Overflow),
        }
    }

    /// Signed millisecond difference between two instants.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::Overflow`] when the difference is not
    /// representable.
    pub const fn checked_difference_millis(self, earlier: Self) -> Result<i64, TimeError> {
        match self.0.checked_sub(earlier.0) {
            Some(difference) => Ok(difference),
            None => Err(TimeError::Overflow),
        }
    }
}

/// A non-zero, monotonically increasing revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(NonZeroU64);

impl Revision {
    /// The first revision of any aggregate.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Build a revision from a non-zero value.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionError::Zero`] when the value is zero.
    pub const fn new(value: u64) -> Result<Self, RevisionError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RevisionError::Zero),
        }
    }

    /// Return the revision as a primitive.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Return the next revision.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionError::Overflow`] rather than wrapping.
    pub const fn checked_next(self) -> Result<Self, RevisionError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(RevisionError::Overflow),
        }
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.get())
    }
}

/// Accept a decimal port with no sign, no leading zero and a `1..=65535` range.
fn validate_port(port: &str) -> Result<(), UrlError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UrlError::Port);
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(UrlError::Port);
    }
    match port.parse::<u32>() {
        Ok(value) if (1..=65535).contains(&value) => Ok(()),
        _ => Err(UrlError::Port),
    }
}

/// Accept an ASCII DNS name of non-empty labels.
fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_DNS_NAME_BYTES {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DNS_LABEL_BYTES
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Validate the authority component, which is the host plus an optional port.
fn validate_authority(authority: &str) -> Result<(), UrlError> {
    if authority.contains('@') {
        return Err(UrlError::UserInfo);
    }
    if authority.is_empty() {
        return Err(UrlError::EmptyHost);
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inside, tail)) = rest.split_once(']') else {
            return Err(UrlError::Host);
        };
        if inside.is_empty() {
            return Err(UrlError::EmptyHost);
        }
        if inside.parse::<Ipv6Addr>().is_err() {
            return Err(UrlError::Host);
        }
        return match tail {
            "" => Ok(()),
            _ => match tail.strip_prefix(':') {
                Some(port) => validate_port(port),
                None => Err(UrlError::Host),
            },
        };
    }
    if authority.contains(']') {
        return Err(UrlError::Host);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(UrlError::EmptyHost);
    }
    if host.contains(':') {
        return Err(UrlError::Host);
    }
    if !is_dns_name(host) && host.parse::<Ipv4Addr>().is_err() {
        return Err(UrlError::Host);
    }
    match port {
        Some(port) => validate_port(port),
        None => Ok(()),
    }
}

/// A bounded public `http` or `https` URL.
///
/// Validation is offline and syntactic. The type performs no DNS lookup, no
/// network access, and no egress authorization; a value proves only that the
/// spelling is a well-formed public HTTP(S) URL within the ceiling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicHttpUrl<const MAX_BYTES: usize>(String);

impl<const MAX_BYTES: usize> PublicHttpUrl<MAX_BYTES> {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_BYTES;

    /// Validate and construct a public HTTP(S) URL.
    ///
    /// The scheme must be exactly `http` or `https` in lowercase; the type
    /// never case-folds, so it never normalizes a value silently.
    ///
    /// # Errors
    ///
    /// Returns [`UrlError`] for a zero ceiling, an empty or over-long value, a
    /// non-ASCII byte, whitespace, a control character, a wrong scheme, user
    /// information, a fragment, a backslash, an empty or invalid host, or an
    /// invalid port.
    pub fn new(value: impl Into<String>) -> Result<Self, UrlError> {
        let value = value.into();
        bounded_value(&value, MAX_BYTES)?;
        if !value.is_ascii() {
            return Err(UrlError::NonAscii);
        }
        if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(UrlError::Whitespace);
        }
        if value.contains('\\') {
            return Err(UrlError::Backslash);
        }
        if value.contains('#') {
            return Err(UrlError::Fragment);
        }
        let rest = if let Some(rest) = value.strip_prefix("https://") {
            rest
        } else if let Some(rest) = value.strip_prefix("http://") {
            rest
        } else {
            return Err(UrlError::Scheme);
        };
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        validate_authority(&rest[..authority_end])?;
        Ok(Self(value))
    }

    /// Return the validated URL spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the URL and return its validated spelling.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const MAX_BYTES: usize> fmt::Display for PublicHttpUrl<MAX_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A bounded secret-bearing value.
///
/// `Debug` is a constant redaction and no `Display` implementation exists, so
/// the value cannot reach a log through ordinary formatting. Reading the
/// secret is explicit, and extraction consumes the wrapper.
///
/// `Display` is unavailable:
///
/// ```compile_fail
/// use automonique_protocol::primitives::SecretText;
/// let secret: SecretText<32> = SecretText::new("synthetic-value").unwrap();
/// println!("{secret}");
/// ```
///
/// so `to_string` is unavailable too:
///
/// ```compile_fail
/// use automonique_protocol::primitives::SecretText;
/// let secret: SecretText<32> = SecretText::new("synthetic-value").unwrap();
/// let leaked = secret.to_string();
/// ```
///
/// and the inner value is unreachable without the explicit accessor:
///
/// ```compile_fail
/// use automonique_protocol::primitives::SecretText;
/// let secret: SecretText<32> = SecretText::new("synthetic-value").unwrap();
/// let leaked = secret.0;
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SecretText<const MAX_BYTES: usize>(String);

impl<const MAX_BYTES: usize> SecretText<MAX_BYTES> {
    /// Constant substituted for the secret in `Debug` output.
    pub const REDACTION: &'static str = "<redacted>";

    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_BYTES;

    /// Validate and construct a secret.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the ceiling is zero, or the value is empty,
    /// over the ceiling, or contains a control character. No variant carries
    /// the submitted value.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        bounded_value(&value, MAX_BYTES)?;
        Ok(Self(value))
    }

    /// Borrow the secret explicitly.
    ///
    /// Every call site that reads a secret names this method, so reads are
    /// greppable.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the secret.
    #[must_use]
    pub fn into_exposed(self) -> String {
        self.0
    }
}

impl<const MAX_BYTES: usize> fmt::Debug for SecretText<MAX_BYTES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretText")
            .field(&Self::REDACTION)
            .finish()
    }
}
