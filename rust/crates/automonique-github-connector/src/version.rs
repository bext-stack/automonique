// SPDX-License-Identifier: Elastic-2.0

//! Typed HTTP validators used for optimistic concurrency.

use crate::GitHubRefusal;

/// Longest entity tag accepted from GitHub or a caller.
pub const MAX_ENTITY_TAG_BYTES: usize = 256;

/// One bounded, syntactically valid HTTP entity tag.
///
/// Both strong (`"abc"`) and weak (`W/"abc"`) tags are retained byte for
/// byte. The connector does not invent or normalize validators: an update
/// sends exactly the value returned by the versioned read that preceded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityTag(String);

impl EntityTag {
    /// Validate one quoted entity tag.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::EntityTag`] for an empty, over-long,
    /// control-bearing or unquoted value.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if value.is_empty()
            || value.len() > MAX_ENTITY_TAG_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GitHubRefusal::EntityTag);
        }
        let quoted = value.strip_prefix("W/").unwrap_or(value);
        if quoted.len() < 2
            || !quoted.starts_with('"')
            || !quoted.ends_with('"')
            || quoted[1..quoted.len() - 1]
                .bytes()
                .any(|byte| !matches!(byte, 0x21 | 0x23..=0x7e))
        {
            return Err(GitHubRefusal::EntityTag);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A decoded GitHub resource and the validator returned with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Versioned<T> {
    value: T,
    etag: EntityTag,
}

impl<T> Versioned<T> {
    /// Bind a decoded resource to its response validator.
    #[must_use]
    pub const fn new(value: T, etag: EntityTag) -> Self {
        Self { value, etag }
    }

    /// The decoded resource.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// The validator to use for a subsequent conditional update.
    #[must_use]
    pub const fn etag(&self) -> &EntityTag {
        &self.etag
    }

    /// Take the decoded resource and discard its validator.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Take both parts.
    #[must_use]
    pub fn into_parts(self) -> (T, EntityTag) {
        (self.value, self.etag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_tags_are_bounded_quoted_and_retained_exactly() {
        for accepted in ["\"abc\"", "W/\"abc-123\"", "\"\""] {
            assert_eq!(EntityTag::new(accepted).expect("etag").as_str(), accepted);
        }
        for refused in [
            "",
            "abc",
            "\"unterminated",
            "unterminated\"",
            "\"a\"b\"",
            "w/\"lowercase-weak\"",
            "\"space is invalid\"",
            "\"a\n\"",
        ] {
            assert_eq!(
                EntityTag::new(refused).err(),
                Some(GitHubRefusal::EntityTag),
                "must refuse {refused:?}"
            );
        }
        assert_eq!(
            EntityTag::new(&format!("\"{}\"", "x".repeat(MAX_ENTITY_TAG_BYTES))).err(),
            Some(GitHubRefusal::EntityTag)
        );
    }
}
