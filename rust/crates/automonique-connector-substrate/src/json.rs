// SPDX-License-Identifier: Elastic-2.0

//! Writing one JSON string, and reading a whole document strictly.

/// Append one JSON string literal, escaping everything RFC 8259 requires.
///
/// Written out rather than delegated to a serializer so a body's field order is
/// exactly the one each connector documents; a map-backed serializer would
/// reorder it. `DEL` is escaped as well, so no C0/C1-adjacent byte reaches a
/// captured request verbatim.
pub fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < '\u{20}' || control == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            plain => out.push(plain),
        }
    }
    out.push('"');
}

pub use strict::{StrictJsonError, strict_json};

mod strict {
    use std::fmt;

    use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Value};

    /// A document was not JSON, or not JSON this project will act on.
    ///
    /// Deliberately opaque and deliberately singular. Every caller of
    /// [`strict_json`] collapses the failure into one variant of its own enum
    /// — `InvalidResponse`, `InvalidJson` — because the distinction that
    /// matters to a connector is "this response cannot be trusted", not which
    /// byte offended. Carrying serde's message across this boundary would also
    /// carry fragments of a response body into a log line.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StrictJsonError;

    impl fmt::Display for StrictJsonError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("response was not strictly valid JSON")
        }
    }

    impl std::error::Error for StrictJsonError {}

    /// Parse JSON refusing duplicate object keys, non-finite numbers and
    /// trailing bytes.
    ///
    /// Duplicate keys matter most: without this, two `state` fields would let
    /// the decoder and a reviewer reading the same bytes disagree about which
    /// one counted. Trailing bytes are the same problem from the other end — a
    /// document followed by a second one is two answers to a question that has
    /// one — and a non-finite number has no JSON spelling to agree on at all.
    ///
    /// # Errors
    ///
    /// Returns [`StrictJsonError`] for any of the above and for ordinary syntax
    /// errors, without distinguishing them.
    pub fn strict_json(bytes: &[u8]) -> Result<Value, StrictJsonError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = StrictJson
            .deserialize(&mut deserializer)
            .map_err(|_| StrictJsonError)?;
        deserializer.end().map_err(|_| StrictJsonError)?;
        Ok(value)
    }

    struct StrictJson;

    impl<'de> DeserializeSeed<'de> for StrictJson {
        type Value = Value;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(StrictJsonVisitor)
        }
    }

    struct StrictJsonVisitor;

    impl<'de> Visitor<'de> for StrictJsonVisitor {
        type Value = Value;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("JSON without duplicate object keys or non-finite numbers")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(Value::Bool(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
            Ok(Value::Number(value.into()))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(Value::Number(value.into()))
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite floating-point value"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(Value::String(value.to_owned()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(Value::String(value))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(Value::Null)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Value::Null)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element_seed(StrictJson)? {
                values.push(value);
            }
            Ok(Value::Array(values))
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate object key"));
                }
                values.insert(key, map.next_value_seed(StrictJson)?);
            }
            Ok(Value::Object(values))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod escaping {
        use super::*;

        fn rendered(value: &str) -> String {
            let mut out = String::new();
            push_json_string(&mut out, value);
            out
        }

        #[test]
        fn the_two_mandatory_escapes_are_applied() {
            assert_eq!(rendered(r#"a"b"#), r#""a\"b""#);
            assert_eq!(rendered(r"a\b"), r#""a\\b""#);
        }

        #[test]
        fn the_named_control_escapes_are_used_where_they_exist() {
            assert_eq!(rendered("\n\r\t\u{08}\u{0c}"), r#""\n\r\t\b\f""#);
        }

        #[test]
        fn a_control_without_a_name_gets_a_lowercase_hex_escape() {
            assert_eq!(rendered("\u{00}\u{01}\u{1f}"), r#""\u0000\u0001\u001f""#);
        }

        /// `DEL` is escaped even though RFC 8259 does not require it.
        ///
        /// It is not a C0 control, so a bare-minimum escaper emits it raw; a
        /// captured request then carries a byte that terminals and log viewers
        /// treat as a command rather than as text.
        #[test]
        fn delete_is_escaped_although_the_grammar_permits_it_raw() {
            assert_eq!(rendered("\u{7f}"), r#""\u007f""#);
        }

        #[test]
        fn ordinary_text_passes_through_including_non_ascii() {
            assert_eq!(rendered("plain text"), r#""plain text""#);
            assert_eq!(rendered("héllo ☃"), "\"héllo ☃\"");
            assert_eq!(rendered(""), r#""""#);
        }

        /// The solidus is *not* escaped: `\/` is optional in JSON, and emitting
        /// it would give one string two spellings for no benefit.
        #[test]
        fn the_optional_solidus_escape_is_not_used() {
            assert_eq!(rendered("a/b"), r#""a/b""#);
        }

        #[test]
        fn it_appends_rather_than_replacing() {
            let mut out = String::from("{\"key\":");
            push_json_string(&mut out, "value");
            assert_eq!(out, r#"{"key":"value""#);
        }

        /// Whatever it writes, `serde_json` reads back unchanged.
        ///
        /// The escaper is hand-written so a body's field order is fixed; this
        /// is the check that hand-writing it did not also change what the bytes
        /// mean.
        #[test]
        fn everything_it_writes_parses_back_to_the_same_string() {
            for value in [
                "",
                "plain",
                r#"quote " and backslash \"#,
                "controls \u{00}\u{01}\u{1f}\u{7f}",
                "named \n\r\t\u{08}\u{0c}",
                "héllo ☃ 𝄞",
                "solidus / and colon :",
            ] {
                let rendered = rendered(value);
                let parsed: serde_json::Value =
                    serde_json::from_str(&rendered).expect("valid JSON");
                assert_eq!(parsed.as_str(), Some(value), "round trip of {value:?}");
            }
        }
    }

    mod strict_reading {
        use super::*;

        #[test]
        fn an_ordinary_document_parses() {
            let value = strict_json(br#"{"ok":true,"count":2}"#).expect("valid");
            assert_eq!(value["ok"], serde_json::Value::Bool(true));
            assert_eq!(value["count"], serde_json::Value::from(2));
        }

        #[test]
        fn a_duplicate_object_key_is_refused() {
            assert_eq!(
                strict_json(br#"{"ok":true,"ok":false}"#),
                Err(StrictJsonError)
            );
        }

        /// The refusal reaches duplicates nested anywhere, not just at the top.
        #[test]
        fn a_duplicate_key_inside_a_nested_value_is_refused() {
            assert_eq!(
                strict_json(br#"{"outer":{"a":1,"a":2}}"#),
                Err(StrictJsonError)
            );
            assert_eq!(
                strict_json(br#"{"rows":[{"a":1,"a":2}]}"#),
                Err(StrictJsonError)
            );
        }

        #[test]
        fn trailing_bytes_after_a_complete_document_are_refused() {
            assert_eq!(strict_json(br#"{"ok":true} {}"#), Err(StrictJsonError));
            assert_eq!(strict_json(br#"{"ok":true}junk"#), Err(StrictJsonError));
        }

        /// Trailing *whitespace* is not trailing data; a server is entitled to
        /// end its body with a newline.
        #[test]
        fn trailing_whitespace_is_accepted() {
            assert!(strict_json(b"{\"ok\":true}\n  \t").is_ok());
        }

        #[test]
        fn a_non_finite_number_is_refused() {
            // JSON has no spelling for these, so they arrive only as an
            // out-of-range literal that overflows to infinity.
            assert_eq!(strict_json(b"1e400").ok(), None);
            assert_eq!(strict_json(br#"{"n":-1e400}"#).ok(), None);
        }

        #[test]
        fn syntax_errors_are_refused() {
            for bytes in [
                b"".as_slice(),
                b"{",
                b"{\"a\"}",
                b"[1,]",
                b"'single'",
                b"\xff\xfe",
            ] {
                assert_eq!(strict_json(bytes), Err(StrictJsonError), "{bytes:?}");
            }
        }

        #[test]
        fn every_scalar_shape_is_carried_through() {
            assert_eq!(
                strict_json(b"null").expect("valid"),
                serde_json::Value::Null
            );
            assert_eq!(
                strict_json(b"true").expect("valid"),
                serde_json::Value::Bool(true)
            );
            assert_eq!(
                strict_json(b"-7").expect("valid"),
                serde_json::Value::from(-7)
            );
            assert_eq!(
                strict_json(b"1.5").expect("valid"),
                serde_json::Value::from(1.5)
            );
            assert_eq!(
                strict_json(br#""text""#).expect("valid"),
                serde_json::Value::from("text")
            );
            assert_eq!(
                strict_json(b"[]").expect("valid"),
                serde_json::Value::Array(vec![])
            );
        }

        /// An integer past `u64` is a float to serde, and stays finite, so it is
        /// admitted rather than refused. Recorded because it is the boundary a
        /// reader is most likely to guess wrong about.
        #[test]
        fn an_integer_beyond_sixty_four_bits_becomes_a_finite_float() {
            let value = strict_json(b"123456789012345678901234567890").expect("valid");
            assert!(value.as_f64().is_some_and(f64::is_finite));
        }
    }
}
