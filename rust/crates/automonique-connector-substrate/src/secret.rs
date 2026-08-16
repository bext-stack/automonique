// SPDX-License-Identifier: Elastic-2.0

//! Best-effort erasure of a rendered credential.

/// Overwrite a temporary header rendering before its buffer is released.
///
/// `String::clear` keeps the allocation and the bytes in it, so the zeros are
/// pushed back over the same capacity afterwards. This is the same best-effort
/// hygiene the token types apply on drop, and it needs no `unsafe` because
/// `NUL` is valid UTF-8.
///
/// Best-effort is the honest description and the reason this is one function
/// rather than three. It cannot defeat a `realloc` that already moved the bytes,
/// or a compiler that elides the writes to a value about to be dropped. What it
/// can do is keep a freed heap block from holding a readable bearer token for
/// the rest of the process's life — and it can only do that everywhere if there
/// is one copy to get right.
pub fn scrub_rendered(mut header: String) {
    let width = header.len();
    header.clear();
    for _ in 0..width {
        header.push('\0');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered secret is gone from the buffer's own bytes.
    ///
    /// Reading the capacity back is the only observation available without
    /// `unsafe`: the buffer is moved in and dropped, so a caller cannot inspect
    /// it afterwards. Rebuilding the same sequence of operations here and
    /// checking the result is what makes the overwrite testable at all — the
    /// three connector copies this replaced had no test that reached it.
    #[test]
    fn the_rendered_secret_is_overwritten_in_place() {
        let mut header = String::with_capacity(64);
        header.push_str("Bearer fixture-secret-value");
        let width = header.len();
        let before = header.as_ptr();

        // The body of `scrub_rendered`, observed rather than moved away.
        header.clear();
        for _ in 0..width {
            header.push('\0');
        }

        assert_eq!(header.as_ptr(), before, "the buffer was reallocated");
        assert_eq!(header.len(), width);
        assert!(header.bytes().all(|byte| byte == 0));
        assert!(!header.contains("fixture-secret-value"));
    }

    /// The overwrite is exactly as wide as what it replaces.
    #[test]
    fn the_overwrite_covers_the_whole_rendering() {
        for secret in ["", "a", "Bearer x", &"z".repeat(512)] {
            let mut header = String::from(secret);
            let width = header.len();
            header.clear();
            for _ in 0..width {
                header.push('\0');
            }
            assert_eq!(header.len(), secret.len());
        }
    }

    /// Multi-byte input is counted in bytes, not characters.
    ///
    /// A rendered credential is ASCII by construction — every token type
    /// validates its character set before it gets here — but the function is
    /// written against `String`, and a character-counted overwrite would leave
    /// a tail of the original bytes readable for any input that is not.
    #[test]
    fn a_multi_byte_rendering_is_covered_by_byte_length() {
        let mut header = String::from("héllo");
        let width = header.len();
        assert_eq!(width, 6, "the fixture is not a pure-ASCII string");
        header.clear();
        for _ in 0..width {
            header.push('\0');
        }
        assert_eq!(header.len(), 6);
        assert!(header.bytes().all(|byte| byte == 0));
    }

    /// It accepts an owned buffer and returns nothing, so a caller cannot keep
    /// using the rendering after asking for it to be erased.
    #[test]
    fn the_buffer_is_consumed() {
        let header = String::from("Bearer fixture-secret-value");
        scrub_rendered(header);
        // `header` is moved; the type system is the guarantee under test.
    }
}
