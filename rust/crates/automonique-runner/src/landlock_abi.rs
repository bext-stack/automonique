// SPDX-License-Identifier: Elastic-2.0

//! Single source of the Landlock ABI levels this build can name.
//!
//! `landlock::ABI` is `#[non_exhaustive]`, so both the capability probe and
//! the enforcement reporters need a closed table of the versions this build
//! understands. Keeping the ascending table and the reverse mapping in one
//! module means a new crate ABI is added in exactly one place, and the two
//! spellings are pinned to each other by a test rather than by discipline.

use landlock::ABI;

/// Every Landlock ABI level this build can name, ascending.
pub(crate) const KNOWN: [(u8, ABI); 9] = [
    (1, ABI::V1),
    (2, ABI::V2),
    (3, ABI::V3),
    (4, ABI::V4),
    (5, ABI::V5),
    (6, ABI::V6),
    (7, ABI::V7),
    (8, ABI::V8),
    (9, ABI::V9),
];

/// The numeric level of `abi`, or `None` for a version this build cannot name.
///
/// Returning `None` rather than guessing keeps every reported ABI honest; the
/// callers turn it into a typed refusal instead of inventing a number.
pub(crate) fn ordinal(abi: ABI) -> Option<u8> {
    match abi {
        ABI::Unsupported => Some(0),
        ABI::V1 => Some(1),
        ABI::V2 => Some(2),
        ABI::V3 => Some(3),
        ABI::V4 => Some(4),
        ABI::V5 => Some(5),
        ABI::V6 => Some(6),
        ABI::V7 => Some(7),
        ABI::V8 => Some(8),
        ABI::V9 => Some(9),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{KNOWN, ordinal};

    /// The table and the match arm are two spellings of one fact; a version
    /// added to only one of them fails here instead of drifting silently.
    #[test]
    fn the_table_and_the_reverse_mapping_agree() {
        for (index, (level, abi)) in KNOWN.into_iter().enumerate() {
            assert_eq!(ordinal(abi), Some(level));
            assert_eq!(usize::from(level), index + 1, "table must ascend from 1");
        }
        assert_eq!(ordinal(landlock::ABI::Unsupported), Some(0));
    }
}
