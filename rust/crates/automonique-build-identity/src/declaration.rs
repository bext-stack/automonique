// SPDX-License-Identifier: Elastic-2.0

// The one spelling of the variable a build pipeline declares a revision in.
//
// Included by both `build.rs`, which reads the variable, and `lib.rs`, which
// publishes it to the code that sets it. A build script cannot link the crate
// it belongs to, so without this file the reader and the writers would each
// carry their own string literal — and a variable renamed in one place and not
// the others fails silently, by falling back to guessing a revision from the
// build host. That is the exact failure this crate exists to prevent, so the
// spelling is shared rather than restated.
//
// Written with ordinary comments rather than module documentation because
// `include!` places this text in the middle of another file, where an inner doc
// comment is a compile error.

/// Environment variable through which a build is told the revision it is building.
///
/// Its value must be a full lowercase-hexadecimal git object name. A malformed
/// value stops the build rather than falling back to whatever the build host
/// happens to have checked out.
pub const DECLARED_REVISION_VARIABLE: &str = "AUTOMONIQUE_SOURCE_REVISION";
