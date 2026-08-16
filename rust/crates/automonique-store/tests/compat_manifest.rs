// SPDX-License-Identifier: Elastic-2.0

//! Store-side pin for the protocol crate's compatibility matrix.
//!
//! `automonique-protocol` ships a tree-level compatibility matrix whose rows
//! for this crate's schema versions are assertions it cannot verify: neither
//! crate depends on the other, so no compile-time link exists. This test is
//! the closing half the matrix's manifest was designed for — it pins each
//! schema constant this crate owns to the exact value the matrix records.
//!
//! When a version bump fails this test, update BOTH places: the constant's
//! row in `automonique-protocol/src/compat.rs`'s shipped matrix, and the
//! expectation here. The failure message names the matrix so the second half
//! of the update cannot be forgotten silently.

use automonique_store::cancel_ledger::CANCEL_LEDGER_SCHEMA_VERSION;
use automonique_store::generation_audit::GENERATION_AUDIT_SCHEMA_VERSION;
use automonique_store::provider_journal::PROVIDER_JOURNAL_SCHEMA_VERSION;
use automonique_store::run_submissions::RUN_SUBMISSIONS_SCHEMA_VERSION;
use automonique_store::slack_ingress::SLACK_INGRESS_SCHEMA_VERSION;

#[test]
fn the_schema_versions_this_crate_owns_match_the_compat_matrix_rows() {
    // Values as recorded in automonique-protocol's shipped compatibility
    // matrix (compat.rs). A mismatch here means the matrix's foreign row has
    // drifted from the authoritative constant — update both together.
    assert_eq!(
        automonique_store::SCHEMA_VERSION,
        10,
        "store SCHEMA_VERSION moved: update the compat matrix's store_schema \
         row in automonique-protocol/src/compat.rs together with this pin"
    );
    assert_eq!(
        CANCEL_LEDGER_SCHEMA_VERSION, 1,
        "cancel ledger schema moved: update the compat matrix row and this pin"
    );
    assert_eq!(
        GENERATION_AUDIT_SCHEMA_VERSION, 1,
        "generation audit schema moved: update the compat matrix row and this pin"
    );
    assert_eq!(
        SLACK_INGRESS_SCHEMA_VERSION, 2,
        "slack ingress schema moved: update the compat matrix row and this pin"
    );
    assert_eq!(
        PROVIDER_JOURNAL_SCHEMA_VERSION, 3,
        "provider journal schema moved: update the compat matrix row and this pin"
    );
    assert_eq!(
        RUN_SUBMISSIONS_SCHEMA_VERSION, 1,
        "run submissions schema moved: update the compat matrix row and this pin"
    );
}
