// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical JSON for the local protocol, without a dependency.
//!
//! JSON is preferred initially because it is inspectable during migration. The
//! encoding here is *canonical*: object keys are sorted, there is no
//! insignificant whitespace, and escaping is minimal and fixed. One value has
//! exactly one byte representation, which is what lets a Rust encoder and a
//! non-Rust decoder be compared byte-for-byte.
//!
//! Decoding is strict by the same rule: input that parses but is not already
//! canonical is refused rather than silently normalized, so a peer cannot send
//! two spellings of one message and have both accepted.
//!
//! Numbers are integers only. The local protocol carries epoch milliseconds,
//! revisions, versions and counts; admitting floating point would add a class
//! of precision and round-trip disagreement for no expressive gain.

use crate::codec::{
    CodecError, DepthGuard, Envelope, MAX_MESSAGE_KIND_BYTES, MAX_PROTOCOL_NAME_BYTES,
    MAX_REQUEST_ID_BYTES, MajorVersion, MessageKind, ProtocolName, RequestId, SupportedProtocol,
};

/// Maximum UTF-8 byte length of one JSON string.
pub const MAX_JSON_STRING_BYTES: usize = 64 * 1024;

/// Maximum number of entries in one array or object.
pub const MAX_JSON_ENTRIES: usize = 4096;

/// A JSON value the local protocol can carry.
///
/// Floating point is deliberately absent; see the module documentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A bounded UTF-8 string.
    String(String),
    /// A bounded array.
    Array(Vec<JsonValue>),
    /// A bounded object whose keys are unique and sorted.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Look up a key in an object value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Borrow a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Copy an integer value.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Serialize to canonical bytes.
    ///
    /// Object keys are sorted by byte order before writing, so a value built in
    /// any order encodes identically.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(true) => out.extend_from_slice(b"true"),
            Self::Bool(false) => out.extend_from_slice(b"false"),
            Self::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Self::String(value) => write_canonical_string(value, out),
            Self::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write_canonical(out);
                }
                out.push(b']');
            }
            Self::Object(entries) => {
                let mut ordered: Vec<&(String, Self)> = entries.iter().collect();
                ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                out.push(b'{');
                for (index, (key, value)) in ordered.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_canonical_string(key, out);
                    out.push(b':');
                    value.write_canonical(out);
                }
                out.push(b'}');
            }
        }
    }
}

fn write_canonical_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in value.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Parse canonical JSON from a frame payload.
///
/// The input must be valid UTF-8, syntactically valid, within the depth and
/// size ceilings, and already canonical. Anything else is a typed refusal.
///
/// # Errors
///
/// Returns [`CodecError::MalformedJson`], [`CodecError::InvalidJsonValue`],
/// [`CodecError::DuplicateKey`], [`CodecError::TrailingData`],
/// [`CodecError::IntegerOutOfRange`], [`CodecError::NestingTooDeep`],
/// [`CodecError::Field`] or [`CodecError::NonCanonicalJson`].
pub fn parse_canonical(payload: &[u8]) -> Result<JsonValue, CodecError> {
    let text = core::str::from_utf8(payload).map_err(|_| CodecError::MalformedJson)?;
    let mut parser = Parser {
        input: text.as_bytes(),
        position: 0,
        depth: DepthGuard::new(),
    };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.position != parser.input.len() {
        return Err(CodecError::TrailingData);
    }
    // Canonicality is proved by re-encoding: a value that does not round-trip
    // to the exact input bytes was not canonical to begin with.
    if value.to_canonical_bytes() != payload {
        return Err(CodecError::NonCanonicalJson);
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    depth: DepthGuard,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    /// Consume insignificant whitespace.
    ///
    /// Whitespace is accepted here and rejected by the canonical round-trip
    /// comparison, so `{"a": 1}` is refused as non-canonical rather than as a
    /// syntax error. Conflating the two would tell a peer its JSON is broken
    /// when its spelling is merely not the one this wire accepts.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.peek() == Some(byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(CodecError::MalformedJson)
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), CodecError> {
        if self.input[self.position..].starts_with(word) {
            self.position += word.len();
            Ok(())
        } else {
            Err(CodecError::MalformedJson)
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, CodecError> {
        match self.peek().ok_or(CodecError::MalformedJson)? {
            b'n' => {
                self.literal(b"null")?;
                Ok(JsonValue::Null)
            }
            b't' => {
                self.literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            b'f' => {
                self.literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            b'"' => Ok(JsonValue::String(self.parse_string()?)),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_integer(),
            _ => Err(CodecError::MalformedJson),
        }
    }

    fn parse_string(&mut self) -> Result<String, CodecError> {
        self.expect(b'"')?;
        let mut value = String::new();
        loop {
            let byte = self.peek().ok_or(CodecError::MalformedJson)?;
            self.position += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = self.peek().ok_or(CodecError::MalformedJson)?;
                    self.position += 1;
                    let decoded = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.parse_unicode_escape()?,
                        _ => return Err(CodecError::MalformedJson),
                    };
                    value.push(decoded);
                }
                control if control < 0x20 => return Err(CodecError::MalformedJson),
                ascii if ascii < 0x80 => value.push(char::from(ascii)),
                _ => {
                    // Re-read the character as UTF-8 rather than a raw byte.
                    let start = self.position - 1;
                    let remainder = core::str::from_utf8(&self.input[start..])
                        .map_err(|_| CodecError::MalformedJson)?;
                    let character = remainder.chars().next().ok_or(CodecError::MalformedJson)?;
                    self.position = start + character.len_utf8();
                    value.push(character);
                }
            }
            if value.len() > MAX_JSON_STRING_BYTES {
                return Err(CodecError::Field {
                    field: "json_string",
                    error: crate::primitives::ValueError::TooLong {
                        max_bytes: MAX_JSON_STRING_BYTES,
                        actual_bytes: value.len(),
                    },
                });
            }
        }
        Ok(value)
    }

    fn parse_unicode_escape(&mut self) -> Result<char, CodecError> {
        let hex = self
            .input
            .get(self.position..self.position + 4)
            .ok_or(CodecError::MalformedJson)?;
        let text = core::str::from_utf8(hex).map_err(|_| CodecError::MalformedJson)?;
        let code = u32::from_str_radix(text, 16).map_err(|_| CodecError::MalformedJson)?;
        self.position += 4;
        char::from_u32(code).ok_or(CodecError::MalformedJson)
    }

    fn parse_integer(&mut self) -> Result<JsonValue, CodecError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        let digits_start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if self.position == digits_start {
            return Err(CodecError::MalformedJson);
        }
        // A float, an exponent or a leading zero is a non-integer spelling.
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(CodecError::InvalidJsonValue {
                field: "json_number",
            });
        }
        let digits = &self.input[digits_start..self.position];
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(CodecError::NonCanonicalJson);
        }
        let text = core::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| CodecError::MalformedJson)?;
        // "-0" has a second spelling of zero and is refused for canonicality.
        if text == "-0" {
            return Err(CodecError::NonCanonicalJson);
        }
        text.parse::<i64>()
            .map(JsonValue::Integer)
            .map_err(|_| CodecError::IntegerOutOfRange)
    }

    fn parse_array(&mut self) -> Result<JsonValue, CodecError> {
        self.depth.enter()?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            self.depth.exit();
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value()?);
            self.skip_whitespace();
            if items.len() > MAX_JSON_ENTRIES {
                return Err(CodecError::TooManyEntries {
                    max: MAX_JSON_ENTRIES,
                });
            }
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(CodecError::MalformedJson),
            }
        }
        self.depth.exit();
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, CodecError> {
        self.depth.enter()?;
        self.expect(b'{')?;
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            self.depth.exit();
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if entries.iter().any(|(existing, _)| *existing == key) {
                return Err(CodecError::DuplicateKey);
            }
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value()?;
            self.skip_whitespace();
            entries.push((key, value));
            if entries.len() > MAX_JSON_ENTRIES {
                return Err(CodecError::TooManyEntries {
                    max: MAX_JSON_ENTRIES,
                });
            }
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(CodecError::MalformedJson),
            }
        }
        self.depth.exit();
        Ok(JsonValue::Object(entries))
    }
}

/// A decoded envelope together with its body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    envelope: Envelope,
    body: JsonValue,
}

impl Message {
    /// Pair an envelope with its body.
    #[must_use]
    pub const fn new(envelope: Envelope, body: JsonValue) -> Self {
        Self { envelope, body }
    }

    /// The envelope.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &JsonValue {
        &self.body
    }

    /// Encode to canonical frame-payload bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        JsonValue::Object(vec![
            ("body".to_owned(), self.body.clone()),
            (
                "kind".to_owned(),
                JsonValue::String(self.envelope.kind().as_str().to_owned()),
            ),
            (
                "protocol".to_owned(),
                JsonValue::String(self.envelope.protocol().as_str().to_owned()),
            ),
            (
                "request_id".to_owned(),
                JsonValue::String(self.envelope.request_id().as_str().to_owned()),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(self.envelope.version().get())),
            ),
        ])
        .to_canonical_bytes()
    }

    /// Decode an envelope and body from canonical frame-payload bytes.
    ///
    /// # Errors
    ///
    /// Returns the parse refusal, or [`CodecError::MissingField`] and
    /// [`CodecError::InvalidJsonValue`] when a required envelope field is
    /// absent or of the wrong type.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, CodecError> {
        let value = parse_canonical(payload)?;
        let protocol = required_string(&value, "protocol", MAX_PROTOCOL_NAME_BYTES)?;
        let request_id = required_string(&value, "request_id", MAX_REQUEST_ID_BYTES)?;
        let kind = required_string(&value, "kind", MAX_MESSAGE_KIND_BYTES)?;
        let version = value
            .get("version")
            .ok_or(CodecError::MissingField { field: "version" })?
            .as_integer()
            .ok_or(CodecError::InvalidJsonValue { field: "version" })?;
        let version = u32::try_from(version)
            .map_err(|_| CodecError::InvalidJsonValue { field: "version" })?;
        let body = value
            .get("body")
            .ok_or(CodecError::MissingField { field: "body" })?
            .clone();

        Ok(Self {
            envelope: Envelope::new(
                ProtocolName::new(protocol)?,
                MajorVersion::new(version)?,
                RequestId::new(request_id)?,
                MessageKind::new(kind)?,
            ),
            body,
        })
    }

    /// Decode a message and admit it against the protocols this peer implements.
    ///
    /// Shape is settled first: a payload that is not a well-formed envelope is
    /// refused with its own category, so a peer is never told its protocol is
    /// unimplemented when its JSON is what is broken. Negotiation then fails
    /// closed on either axis, and the two axes stay distinct: an unimplemented
    /// name and an out-of-range major version are different refusals and
    /// neither is downgraded, guessed or defaulted into the other.
    ///
    /// `supported` carries one entry per implemented protocol name. When two
    /// entries share a name the first that admits the envelope wins and the
    /// first version refusal is the one reported.
    ///
    /// # Errors
    ///
    /// Returns the decode refusal, [`CodecError::UnknownProtocol`] when no
    /// declared protocol carries the envelope's name, or
    /// [`CodecError::UnsupportedVersion`] when one does and the major version
    /// lies outside its range. An empty `supported` slice implements nothing
    /// and admits nothing.
    pub fn from_canonical_bytes_admitted(
        payload: &[u8],
        supported: &[SupportedProtocol],
    ) -> Result<Self, CodecError> {
        let message = Self::from_canonical_bytes(payload)?;
        let mut refusal = CodecError::UnknownProtocol;
        for protocol in supported {
            match protocol.admit(message.envelope()) {
                Ok(()) => return Ok(message),
                // A name mismatch leaves the default refusal in place; a
                // version refusal came from the entry that owns this name, so
                // it outranks it and is kept.
                Err(CodecError::UnknownProtocol) => {}
                Err(version) => {
                    if refusal == CodecError::UnknownProtocol {
                        refusal = version;
                    }
                }
            }
        }
        Err(refusal)
    }
}

fn required_string(
    value: &JsonValue,
    field: &'static str,
    max_bytes: usize,
) -> Result<String, CodecError> {
    let text = value
        .get(field)
        .ok_or(CodecError::MissingField { field })?
        .as_str()
        .ok_or(CodecError::InvalidJsonValue { field })?;
    if text.len() > max_bytes {
        return Err(CodecError::Field {
            field,
            error: crate::primitives::ValueError::TooLong {
                max_bytes,
                actual_bytes: text.len(),
            },
        });
    }
    Ok(text.to_owned())
}
