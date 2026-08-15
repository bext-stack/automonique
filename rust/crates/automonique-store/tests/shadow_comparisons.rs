// SPDX-License-Identifier: Elastic-2.0

//! Durable custody of shadow-comparison evidence.
//!
//! The properties under test are the ones a parity gate rests on: a recorded
//! envelope is never rewritten, a re-decided gate is a conflict rather than an
//! update, retention refuses rather than evicts, and the schema ladder replays
//! to the same place on a database opened twice.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use automonique_store::shadow_comparisons::{
    ComparisonRecord, GateCounts, GateDecisionRecord, IntendedActionRecord, MAX_BODY_BYTES,
    MAX_SOURCE_KEY_BYTES, Retention, SHADOW_COMPARISONS_SCHEMA_VERSION, ShadowComparisonStore,
    ShadowDisposition, ShadowError,
};
use tempfile::TempDir;

const SHADOW: &str = "shadow-candidate";
const LEGACY: &str = "legacy-observed";
const SCOPE: &str = "slack-ticket-routing";
const SOURCE: &str = "slack:T0TEAM:event:Ev0000000001";
const DIGEST_A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const DIGEST_B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// A private temporary directory, which is what the store's path check demands.
fn private_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    directory
}

fn database(directory: &TempDir) -> PathBuf {
    directory.path().join("shadow-comparisons.sqlite3")
}

fn store(directory: &TempDir) -> ShadowComparisonStore {
    ShadowComparisonStore::open(database(directory)).expect("opens")
}

fn action<'a>(engine: &'a str, sequence: i64, envelope: &'a [u8]) -> IntendedActionRecord<'a> {
    IntendedActionRecord {
        scope: SCOPE,
        source_key: SOURCE,
        engine,
        sequence,
        envelope,
        envelope_digest: DIGEST_A,
        observed_at_ms: 1_700_000_000_000,
    }
}

fn comparison<'a>(sequence: i64, classification: &'a str) -> ComparisonRecord<'a> {
    ComparisonRecord {
        scope: SCOPE,
        source_key: SOURCE,
        sequence,
        verdict: "match",
        classification,
        deviation_id: None,
        category: "happy",
        diff: b"{\"differences\":[],\"verdict\":\"match\"}",
        diff_digest: DIGEST_A,
        compared_at_ms: 1_700_000_000_000,
    }
}

fn decision(key: &str) -> GateDecisionRecord<'_> {
    GateDecisionRecord {
        decision_key: key,
        scope: SCOPE,
        score: 87,
        band: "cutover-ready",
        happy: GateCounts {
            total: 4,
            accounted: 4,
        },
        error: GateCounts::default(),
        edge: GateCounts::default(),
        variety: GateCounts::default(),
        production: GateCounts {
            total: 2,
            accounted: 1,
        },
        registry_digest: DIGEST_A,
        evidence_digest: DIGEST_B,
        decided_at_ms: 1_700_000_000_000,
        decider: "owner",
    }
}

mod schema_ladder {
    use super::*;

    #[test]
    fn a_fresh_database_lands_on_the_supported_version() {
        let directory = private_directory();
        let store = store(&directory);
        let version: u32 = rusqlite_version(store.path());
        assert_eq!(version, SHADOW_COMPARISONS_SCHEMA_VERSION);
    }

    #[test]
    fn replaying_the_ladder_is_idempotent() {
        let directory = private_directory();
        {
            let mut first = store(&directory);
            first
                .record_intended_action(action(SHADOW, 0, b"first"))
                .expect("records");
        }
        let objects_after_first = objects(database(&directory));
        {
            let second = store(&directory);
            assert_eq!(second.intended_action_count().expect("counts"), 1);
        }
        assert_eq!(objects(database(&directory)), objects_after_first);
        assert_eq!(
            rusqlite_version(&database(&directory)),
            SHADOW_COMPARISONS_SCHEMA_VERSION
        );
    }

    #[test]
    fn a_future_database_is_refused_rather_than_downgraded() {
        let directory = private_directory();
        {
            let _ = store(&directory);
        }
        let connection = rusqlite::Connection::open(database(&directory)).expect("opens");
        connection
            .pragma_update(None, "user_version", 99_u32)
            .expect("bumps");
        drop(connection);
        let error = ShadowComparisonStore::open(database(&directory)).expect_err("refused");
        assert_eq!(error.category(), "schema_version");
    }

    #[test]
    fn a_foreign_database_is_refused() {
        let directory = private_directory();
        let path = database(&directory);
        let connection = rusqlite::Connection::open(&path).expect("opens");
        connection
            .execute_batch("CREATE TABLE somebody_elses (x INTEGER);")
            .expect("creates");
        drop(connection);
        // The file the raw connection created is world-readable; the store's own
        // path check would refuse it before it ever read the schema, and this
        // test is about the schema.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private file");
        let error = ShadowComparisonStore::open(&path).expect_err("refused");
        assert_eq!(error.category(), "schema_version");
    }

    fn rusqlite_version(path: &std::path::Path) -> u32 {
        let connection = rusqlite::Connection::open(path).expect("opens");
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("reads")
    }

    fn objects(path: PathBuf) -> Vec<String> {
        let connection = rusqlite::Connection::open(path).expect("opens");
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
            .expect("prepares");
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("queries");
        rows.map(|row| row.expect("row")).collect()
    }
}

mod intended_actions {
    use super::*;

    #[test]
    fn records_once_and_replays_exactly() {
        let directory = private_directory();
        let mut store = store(&directory);
        let first = store
            .record_intended_action(action(SHADOW, 0, b"envelope"))
            .expect("records");
        assert_eq!(first.disposition, ShadowDisposition::Recorded);
        let second = store
            .record_intended_action(action(SHADOW, 0, b"envelope"))
            .expect("replays");
        assert_eq!(second.disposition, ShadowDisposition::AlreadyRecorded);
        assert_eq!(second.row_id, first.row_id);
        assert_eq!(store.intended_action_count().expect("counts"), 1);
    }

    #[test]
    fn a_later_clock_on_a_replay_does_not_rewrite_the_first() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_intended_action(action(SHADOW, 0, b"envelope"))
            .expect("records");
        let mut later = action(SHADOW, 0, b"envelope");
        later.observed_at_ms = 1_800_000_000_000;
        assert_eq!(
            store
                .record_intended_action(later)
                .expect("replays")
                .disposition,
            ShadowDisposition::AlreadyRecorded
        );
        let entries = store
            .intended_actions(SCOPE, SOURCE, SHADOW)
            .expect("reads");
        assert_eq!(entries[0].observed_at_ms, 1_700_000_000_000);
    }

    #[test]
    fn a_different_envelope_under_one_coordinate_is_a_conflict() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_intended_action(action(SHADOW, 0, b"envelope"))
            .expect("records");
        let mut different = action(SHADOW, 0, b"other");
        different.envelope_digest = DIGEST_B;
        let error = store
            .record_intended_action(different)
            .expect_err("conflict");
        assert_eq!(error.category(), "conflict");
        assert!(matches!(
            error,
            ShadowError::Conflict {
                field: "envelope_digest",
                ..
            }
        ));
        assert_eq!(store.intended_action_count().expect("counts"), 1);
    }

    #[test]
    fn a_stale_digest_over_fresh_bytes_names_the_digest() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_intended_action(action(SHADOW, 0, b"envelope"))
            .expect("records");
        let error = store
            .record_intended_action(action(SHADOW, 0, b"other"))
            .expect_err("conflict");
        assert!(matches!(
            error,
            ShadowError::Conflict {
                field: "envelope",
                ..
            }
        ));
    }

    #[test]
    fn the_two_engines_are_separate_coordinates() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_intended_action(action(SHADOW, 0, b"one"))
            .expect("records");
        store
            .record_intended_action(action(LEGACY, 0, b"two"))
            .expect("records");
        assert_eq!(store.intended_action_count().expect("counts"), 2);
        assert_eq!(
            store
                .intended_actions(SCOPE, SOURCE, SHADOW)
                .expect("reads")
                .len(),
            1
        );
    }

    #[test]
    fn envelopes_read_back_in_sequence_order() {
        let directory = private_directory();
        let mut store = store(&directory);
        for sequence in [2, 0, 1] {
            store
                .record_intended_action(action(SHADOW, sequence, b"envelope"))
                .expect("records");
        }
        let sequences: Vec<i64> = store
            .intended_actions(SCOPE, SOURCE, SHADOW)
            .expect("reads")
            .into_iter()
            .map(|entry| entry.sequence)
            .collect();
        assert_eq!(sequences, vec![0, 1, 2]);
    }

    #[test]
    fn source_keys_are_listed_in_first_record_order() {
        let directory = private_directory();
        let mut store = store(&directory);
        for key in ["slack:T:event:B", "slack:T:event:A", "slack:T:event:B"] {
            let mut record = action(SHADOW, 0, b"envelope");
            record.source_key = key;
            let _ = store.record_intended_action(record);
        }
        assert_eq!(
            store.source_keys(SCOPE).expect("reads"),
            vec![
                String::from("slack:T:event:B"),
                String::from("slack:T:event:A")
            ]
        );
    }

    #[test]
    fn refuses_an_uppercase_digest_rather_than_folding_it() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = action(SHADOW, 0, b"envelope");
        record.envelope_digest = "000000000000000000000000000000000000000000000000000000000000000A";
        assert!(matches!(
            store.record_intended_action(record),
            Err(ShadowError::InvalidField("envelope_digest"))
        ));
    }

    #[test]
    fn refuses_an_empty_and_an_over_long_body() {
        let directory = private_directory();
        let mut store = store(&directory);
        assert!(matches!(
            store.record_intended_action(action(SHADOW, 0, b"")),
            Err(ShadowError::InvalidField("envelope"))
        ));
        let long = vec![b'x'; MAX_BODY_BYTES + 1];
        assert!(matches!(
            store.record_intended_action(action(SHADOW, 0, &long)),
            Err(ShadowError::InvalidField("envelope"))
        ));
    }

    #[test]
    fn accepts_a_maximal_source_key() {
        let directory = private_directory();
        let mut store = store(&directory);
        let maximal = "k".repeat(MAX_SOURCE_KEY_BYTES);
        let mut record = action(SHADOW, 0, b"envelope");
        record.source_key = &maximal;
        assert!(store.record_intended_action(record).is_ok());
    }

    #[test]
    fn refuses_a_negative_sequence() {
        let directory = private_directory();
        let mut store = store(&directory);
        assert!(matches!(
            store.record_intended_action(action(SHADOW, -1, b"envelope")),
            Err(ShadowError::InvalidField("sequence"))
        ));
    }
}

mod retention {
    use super::*;

    #[test]
    fn refuses_at_capacity_rather_than_evicting() {
        let directory = private_directory();
        let mut store = ShadowComparisonStore::open_with_retention(
            database(&directory),
            Retention {
                intended_actions: 1,
                ..Retention::full()
            },
        )
        .expect("opens");
        store
            .record_intended_action(action(SHADOW, 0, b"first"))
            .expect("records");
        let error = store
            .record_intended_action(action(SHADOW, 1, b"second"))
            .expect_err("full");
        assert_eq!(error.category(), "log_full");
        assert_eq!(store.intended_action_count().expect("counts"), 1);
        assert_eq!(
            store
                .intended_actions(SCOPE, SOURCE, SHADOW)
                .expect("reads")[0]
                .envelope,
            b"first".to_vec()
        );
    }

    #[test]
    fn a_replay_still_answers_in_a_full_database() {
        let directory = private_directory();
        let mut store = ShadowComparisonStore::open_with_retention(
            database(&directory),
            Retention {
                intended_actions: 1,
                ..Retention::full()
            },
        )
        .expect("opens");
        store
            .record_intended_action(action(SHADOW, 0, b"first"))
            .expect("records");
        assert_eq!(
            store
                .record_intended_action(action(SHADOW, 0, b"first"))
                .expect("replays")
                .disposition,
            ShadowDisposition::AlreadyRecorded
        );
    }

    #[test]
    fn refuses_a_ceiling_of_zero() {
        let directory = private_directory();
        assert!(matches!(
            ShadowComparisonStore::open_with_retention(
                database(&directory),
                Retention {
                    comparisons: 0,
                    ..Retention::full()
                }
            ),
            Err(ShadowError::InvalidField("retention.comparisons"))
        ));
    }
}

mod comparisons {
    use super::*;

    #[test]
    fn records_once_and_conflicts_on_a_changed_verdict() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_comparison(comparison(0, "parity"))
            .expect("records");
        assert_eq!(
            store
                .record_comparison(comparison(0, "parity"))
                .expect("replays")
                .disposition,
            ShadowDisposition::AlreadyRecorded
        );
        let error = store
            .record_comparison(comparison(0, "regression"))
            .expect_err("conflict");
        assert!(matches!(
            error,
            ShadowError::Conflict {
                field: "classification",
                ..
            }
        ));
    }

    #[test]
    fn a_known_deviation_must_name_its_registry_entry() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = comparison(0, "known_deviation");
        record.verdict = "mismatch";
        let error = store.record_comparison(record).expect_err("refused");
        assert_eq!(error.category(), "sqlite");
    }

    #[test]
    fn a_parity_row_may_not_name_a_registry_entry() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = comparison(0, "parity");
        record.deviation_id = Some("dev-0001");
        let error = store.record_comparison(record).expect_err("refused");
        assert_eq!(error.category(), "sqlite");
    }

    #[test]
    fn a_known_deviation_naming_an_entry_is_accepted() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = comparison(0, "known_deviation");
        record.verdict = "mismatch";
        record.deviation_id = Some("dev-0001");
        store.record_comparison(record).expect("records");
        let entries = store.comparisons(SCOPE).expect("reads");
        assert_eq!(entries[0].deviation_id.as_deref(), Some("dev-0001"));
    }

    #[test]
    fn a_verdict_outside_the_closed_vocabulary_is_refused_by_the_database() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = comparison(0, "parity");
        record.verdict = "probably_fine";
        assert_eq!(
            store
                .record_comparison(record)
                .expect_err("refused")
                .category(),
            "sqlite"
        );
    }

    #[test]
    fn a_category_outside_the_closed_vocabulary_is_refused_by_the_database() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = comparison(0, "parity");
        record.category = "vibes";
        assert_eq!(
            store
                .record_comparison(record)
                .expect_err("refused")
                .category(),
            "sqlite"
        );
    }
}

mod gate_decisions {
    use super::*;

    #[test]
    fn a_decision_is_immutable_under_its_own_key() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_gate_decision(decision("gate-0001"))
            .expect("records");
        assert_eq!(
            store
                .record_gate_decision(decision("gate-0001"))
                .expect("replays")
                .disposition,
            ShadowDisposition::AlreadyRecorded
        );
        let mut revised = decision("gate-0001");
        revised.score = 95;
        let error = store.record_gate_decision(revised).expect_err("conflict");
        assert!(matches!(
            error,
            ShadowError::Conflict { field: "score", .. }
        ));
        assert_eq!(store.gate_decisions(SCOPE).expect("reads")[0].score, 87);
    }

    #[test]
    fn a_registry_edit_cannot_rewrite_a_past_decision() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_gate_decision(decision("gate-0001"))
            .expect("records");
        let mut relaxed = decision("gate-0001");
        relaxed.registry_digest = DIGEST_B;
        assert!(matches!(
            store.record_gate_decision(relaxed),
            Err(ShadowError::Conflict {
                field: "registry_digest",
                ..
            })
        ));
    }

    #[test]
    fn re_deciding_a_scope_takes_a_new_key() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_gate_decision(decision("gate-0001"))
            .expect("records");
        let mut later = decision("gate-0002");
        later.score = 95;
        store.record_gate_decision(later).expect("records");
        let scores: Vec<i64> = store
            .gate_decisions(SCOPE)
            .expect("reads")
            .into_iter()
            .map(|entry| entry.score)
            .collect();
        assert_eq!(scores, vec![87, 95]);
    }

    #[test]
    fn a_score_outside_the_range_is_refused() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = decision("gate-0001");
        record.score = 101;
        assert!(matches!(
            store.record_gate_decision(record),
            Err(ShadowError::InvalidField("score"))
        ));
    }

    #[test]
    fn an_accounted_count_above_its_total_is_refused() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = decision("gate-0001");
        record.edge = GateCounts {
            total: 1,
            accounted: 2,
        };
        assert!(matches!(
            store.record_gate_decision(record),
            Err(ShadowError::InvalidField("edge"))
        ));
    }

    #[test]
    fn a_band_outside_the_closed_vocabulary_is_refused_by_the_database() {
        let directory = private_directory();
        let mut store = store(&directory);
        let mut record = decision("gate-0001");
        record.band = "probably-ready";
        assert_eq!(
            store
                .record_gate_decision(record)
                .expect_err("refused")
                .category(),
            "sqlite"
        );
    }

    #[test]
    fn counts_read_back_as_recorded() {
        let directory = private_directory();
        let mut store = store(&directory);
        store
            .record_gate_decision(decision("gate-0001"))
            .expect("records");
        let entry = store.gate_decisions(SCOPE).expect("reads").remove(0);
        assert_eq!(entry.happy.total, 4);
        assert_eq!(entry.production.accounted, 1);
        assert_eq!(entry.band, "cutover-ready");
        assert_eq!(entry.registry_digest, DIGEST_A);
    }
}
