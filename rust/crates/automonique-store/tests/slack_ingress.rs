// SPDX-License-Identifier: Elastic-2.0

//! Durable Slack ingress disposition invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. Row counts are read with a raw SQLite
//! connection rather than through the API under test, so a mutation that
//! reports a replay while inserting a second row cannot hide behind its own
//! bookkeeping. The restart tests close the log and reopen the file: an
//! in-memory log cannot pass them.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::slack_ingress::{
    CONTENT_DIGEST_CHARS, MAX_DISPOSITION_PAGE, MAX_SLACK_IDENTIFIER_BYTES, MAX_SOURCE_KEY_BYTES,
    SLACK_INGRESS_SCHEMA_VERSION, SlackDispositionEntry, SlackDispositionKind,
    SlackDispositionRecord, SlackIngressError, SlackIngressLog, SlackRecordOutcome, SlackRetention,
    SlackStoreDisposition,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

struct PrivateLog {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateLog {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("slack-ingress.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Row count read around the API under test.
    fn raw_count(&self) -> i64 {
        let raw = Connection::open(&self.path).expect("raw reopen");
        raw.query_row(
            "SELECT count(*) FROM slack_ingress_dispositions",
            [],
            |row| row.get(0),
        )
        .expect("raw count")
    }
}

fn log() -> (PrivateLog, SlackIngressLog) {
    let private = PrivateLog::new();
    let opened = SlackIngressLog::open(private.path()).expect("open log");
    (private, opened)
}

fn digest(fill: char) -> String {
    String::from(fill).repeat(CONTENT_DIGEST_CHARS)
}

fn admitted<'a>(source_key: &'a str, content_digest: &'a str) -> SlackDispositionRecord<'a> {
    SlackDispositionRecord {
        source_key,
        app_id: "A0FIRST",
        envelope_id: "envelope-1",
        retry_attempt: 0,
        disposition: SlackStoreDisposition::Admitted { content_digest },
        recorded_at_ms: 1_000,
    }
}

fn denied(source_key: &str) -> SlackDispositionRecord<'_> {
    SlackDispositionRecord {
        source_key,
        app_id: "A0FIRST",
        envelope_id: "envelope-1",
        retry_attempt: 0,
        disposition: SlackStoreDisposition::Denied,
        recorded_at_ms: 1_000,
    }
}

const KEY_A: &str = "slack:A0FIRST:T01:C01:1700000000.000100";
const KEY_B: &str = "slack:A0FIRST:T01:C01:1700000000.000200";

#[test]
fn a_fresh_disposition_is_recorded_exactly_once_and_survives_a_reopen() {
    let (private, mut log) = log();
    let content_digest = digest('a');

    let receipt = log
        .record(admitted(KEY_A, &content_digest))
        .expect("first delivery");
    assert_eq!(receipt.outcome, SlackRecordOutcome::Recorded);
    assert!(!receipt.outcome.is_replay());
    assert!(receipt.entry_id > 0);
    assert_eq!(log.entry_count().expect("count"), 1);
    // Read around the API: a receipt without an insert fails here.
    assert_eq!(private.raw_count(), 1);
    drop(log);

    let reopened = SlackIngressLog::open(private.path()).expect("reopen");
    let entry = reopened
        .disposition(KEY_A)
        .expect("read")
        .expect("row survives the reopen");
    assert_eq!(
        entry,
        SlackDispositionEntry {
            entry_id: receipt.entry_id,
            source_key: KEY_A.to_owned(),
            app_id: "A0FIRST".to_owned(),
            disposition: SlackDispositionKind::Admitted,
            content_digest: Some(content_digest),
            envelope_id: "envelope-1".to_owned(),
            retry_attempt: 0,
            recorded_at_ms: 1_000,
        }
    );

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, SLACK_INGRESS_SCHEMA_VERSION);
}

#[test]
fn an_exact_redelivery_answers_already_recorded_and_rewrites_nothing() {
    let (private, mut log) = log();
    let content_digest = digest('a');
    let first = log
        .record(admitted(KEY_A, &content_digest))
        .expect("first delivery");

    // Slack mints a new envelope_id, raises retry_attempt and arrives later.
    // None of those is part of the binding.
    let redelivery = SlackDispositionRecord {
        envelope_id: "envelope-2",
        retry_attempt: 3,
        recorded_at_ms: 90_000,
        ..admitted(KEY_A, &content_digest)
    };
    let replay = log.record(redelivery).expect("redelivery is a replay");
    assert_eq!(replay.outcome, SlackRecordOutcome::AlreadyRecorded);
    assert!(replay.outcome.is_replay());
    assert_eq!(replay.entry_id, first.entry_id);

    // A second insert would show up here even though the receipt looked right.
    assert_eq!(private.raw_count(), 1);
    assert_eq!(log.entry_count().expect("count"), 1);

    let entry = log.disposition(KEY_A).expect("read").expect("row");
    assert_eq!(entry.envelope_id, "envelope-1");
    assert_eq!(entry.retry_attempt, 0);
    assert_eq!(entry.recorded_at_ms, 1_000);
    assert_eq!(
        entry.content_digest.as_deref(),
        Some(content_digest.as_str())
    );
}

#[test]
fn a_redelivery_that_changes_the_content_conflicts_and_leaves_the_row_intact() {
    let (private, mut log) = log();
    let recorded_digest = digest('a');
    let first = log
        .record(admitted(KEY_A, &recorded_digest))
        .expect("first delivery");

    let fabricated = digest('b');
    let error = log
        .record(admitted(KEY_A, &fabricated))
        .expect_err("a redelivery may not rewrite content");
    assert_eq!(error.category(), "conflict");
    match error {
        SlackIngressError::Conflict {
            field,
            recorded_app_id,
            recorded_disposition,
            recorded_content_digest,
        } => {
            assert_eq!(field, "content_digest");
            assert_eq!(recorded_app_id, "A0FIRST");
            assert_eq!(recorded_disposition, SlackDispositionKind::Admitted);
            assert_eq!(
                recorded_content_digest.as_deref(),
                Some(recorded_digest.as_str())
            );
        }
        other => panic!("expected a conflict, got {other:?}"),
    }

    assert_eq!(private.raw_count(), 1);
    let entry = log.disposition(KEY_A).expect("read").expect("row");
    assert_eq!(entry.entry_id, first.entry_id);
    assert_eq!(
        entry.content_digest.as_deref(),
        Some(recorded_digest.as_str())
    );
    assert_eq!(entry.envelope_id, "envelope-1");
}

#[test]
fn a_redelivery_that_changes_the_decision_or_the_app_conflicts_by_name() {
    let (private, mut log) = log();
    log.record(denied(KEY_A)).expect("first delivery");

    let content_digest = digest('a');
    let promoted = log
        .record(admitted(KEY_A, &content_digest))
        .expect_err("a denied event may not become admitted by redelivery");
    assert_eq!(promoted.category(), "conflict");
    match promoted {
        SlackIngressError::Conflict {
            field,
            recorded_disposition,
            recorded_content_digest,
            ..
        } => {
            assert_eq!(field, "disposition");
            assert_eq!(recorded_disposition, SlackDispositionKind::Denied);
            assert_eq!(recorded_content_digest, None);
        }
        other => panic!("expected a conflict, got {other:?}"),
    }

    let rehomed = log
        .record(SlackDispositionRecord {
            app_id: "A0SECOND",
            ..denied(KEY_A)
        })
        .expect_err("one source_key belongs to one app");
    assert_eq!(rehomed.category(), "conflict");
    match rehomed {
        SlackIngressError::Conflict {
            field,
            recorded_app_id,
            ..
        } => {
            assert_eq!(field, "app_id");
            assert_eq!(recorded_app_id, "A0FIRST");
        }
        other => panic!("expected a conflict, got {other:?}"),
    }

    assert_eq!(private.raw_count(), 1);
    let entry = log.disposition(KEY_A).expect("read").expect("row");
    assert_eq!(entry.disposition, SlackDispositionKind::Denied);
    assert_eq!(entry.content_digest, None);
    assert_eq!(entry.app_id, "A0FIRST");
}

#[test]
fn recovery_pages_are_bounded_ordered_and_scoped_to_one_app() {
    let (_private, mut log) = log();
    for (index, key) in ["k1", "k2", "k3"].iter().enumerate() {
        let recorded_at_ms = 1_000 + i64::try_from(index).expect("small index") * 10;
        log.record(SlackDispositionRecord {
            source_key: key,
            recorded_at_ms,
            ..denied(key)
        })
        .expect("record");
    }
    log.record(SlackDispositionRecord {
        source_key: "other-app",
        app_id: "A0SECOND",
        ..denied("other-app")
    })
    .expect("record for a second app");

    let page = log
        .app_dispositions("A0FIRST", 0, 2)
        .expect("bounded first page");
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].source_key, "k1");
    assert_eq!(page[0].recorded_at_ms, 1_000);
    assert_eq!(page[1].source_key, "k2");
    assert_eq!(page[1].recorded_at_ms, 1_010);

    let rest = log
        .app_dispositions("A0FIRST", 1_020, MAX_DISPOSITION_PAGE)
        .expect("second page");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].source_key, "k3");

    // Another app's rows are never in this app's answer, however wide the page.
    let all = log
        .app_dispositions("A0FIRST", 0, MAX_DISPOSITION_PAGE)
        .expect("whole app");
    assert_eq!(all.len(), 3);
    assert!(all.iter().all(|entry| entry.app_id == "A0FIRST"));
    let second = log
        .app_dispositions("A0SECOND", 0, MAX_DISPOSITION_PAGE)
        .expect("second app");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].source_key, "other-app");

    assert_eq!(
        log.app_dispositions("A0FIRST", 0, 0)
            .expect_err("an unbounded page has no spelling")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        log.app_dispositions("A0FIRST", 0, MAX_DISPOSITION_PAGE + 1)
            .expect_err("the page bound is exact")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        log.app_dispositions("A0FIRST", -1, 1)
            .expect_err("negative instants are refused")
            .category(),
        "invalid_field"
    );
}

#[test]
fn a_full_log_refuses_a_new_disposition_but_still_answers_a_replay() {
    let private = PrivateLog::new();
    let mut log = SlackIngressLog::open_with_capacity(private.path(), 1).expect("open at capacity");
    assert_eq!(log.capacity(), 1);
    assert_eq!(log.path(), private.path());
    log.record(denied(KEY_A)).expect("first delivery");

    let error = log
        .record(denied(KEY_B))
        .expect_err("a disposition that cannot be recorded must not be acked");
    assert_eq!(error.category(), "log_full");
    assert!(error.to_string().contains('1'));
    assert_eq!(private.raw_count(), 1);

    // A replay writes nothing, so a full log must never degrade it to a refusal.
    let replay = log.record(denied(KEY_A)).expect("replay in a full log");
    assert_eq!(replay.outcome, SlackRecordOutcome::AlreadyRecorded);
    assert_eq!(private.raw_count(), 1);

    assert_eq!(
        SlackIngressLog::open_with_capacity(private.path(), 0)
            .expect_err("zero capacity is not a spelling")
            .category(),
        "invalid_field"
    );
}

#[test]
fn pruning_forgets_a_source_key_and_the_same_event_is_then_recorded_fresh() {
    let (private, mut log) = log();
    let first = log.record(denied(KEY_A)).expect("first delivery");
    log.record(SlackDispositionRecord {
        source_key: "other-app",
        app_id: "A0SECOND",
        ..denied("other-app")
    })
    .expect("second app");

    let untouched = log
        .prune(SlackRetention {
            app_id: "A0FIRST",
            older_than_ms: 1_000,
        })
        .expect("horizon excludes the row itself");
    assert_eq!(untouched.removed, 0);
    assert_eq!(untouched.remaining, 2);

    let outcome = log
        .prune(SlackRetention {
            app_id: "A0FIRST",
            older_than_ms: 1_001,
        })
        .expect("prune");
    assert_eq!(outcome.removed, 1);
    assert_eq!(outcome.remaining, 1);
    assert_eq!(private.raw_count(), 1);
    assert_eq!(log.disposition(KEY_A).expect("read"), None);
    // The other app is out of scope no matter how old its rows are.
    assert!(log.disposition("other-app").expect("read").is_some());

    // The documented cost: a pruned key is forgotten, not remembered as absent.
    let refreshed = log.record(denied(KEY_A)).expect("recorded a second time");
    assert_eq!(refreshed.outcome, SlackRecordOutcome::Recorded);
    assert_ne!(refreshed.entry_id, first.entry_id);
}

#[test]
fn malformed_caller_fields_are_refused_by_name_and_write_nothing() {
    let (private, mut log) = log();
    let content_digest = digest('a');
    let long_key = "k".repeat(MAX_SOURCE_KEY_BYTES + 1);
    let long_app = "a".repeat(MAX_SLACK_IDENTIFIER_BYTES + 1);
    let short_digest = digest('a')[1..].to_owned();
    let upper_digest = digest('A');

    let refusals: Vec<SlackDispositionRecord<'_>> = vec![
        admitted("", &content_digest),
        admitted(&long_key, &content_digest),
        SlackDispositionRecord {
            app_id: &long_app,
            ..admitted(KEY_A, &content_digest)
        },
        SlackDispositionRecord {
            app_id: "",
            ..admitted(KEY_A, &content_digest)
        },
        SlackDispositionRecord {
            envelope_id: "envelope\n1",
            ..admitted(KEY_A, &content_digest)
        },
        SlackDispositionRecord {
            recorded_at_ms: -1,
            ..admitted(KEY_A, &content_digest)
        },
        admitted(KEY_A, &short_digest),
        admitted(KEY_A, &upper_digest),
    ];
    for record in refusals {
        let error = log.record(record).expect_err("malformed field refused");
        assert_eq!(error.category(), "invalid_field");
    }
    assert_eq!(private.raw_count(), 0);

    assert_eq!(
        log.disposition("")
            .expect_err("an empty key is not a lookup")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        log.prune(SlackRetention {
            app_id: "A0FIRST",
            older_than_ms: -1,
        })
        .expect_err("negative horizon refused")
        .category(),
        "invalid_field"
    );
}

#[test]
fn a_hand_written_row_that_breaks_the_grammar_surfaces_as_corruption() {
    let (private, mut log) = log();
    log.record(denied(KEY_A)).expect("first delivery");
    drop(log);

    // Rows this API would have refused: the grammar is not a column CHECK.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms)
         VALUES ('', 'A0FIRST', 'denied', NULL, 'envelope-x', 0, 1500)",
        [],
    )
    .expect("smuggle an empty source key");
    drop(raw);

    let reopened = SlackIngressLog::open(private.path()).expect("reopen");
    let error = reopened
        .app_dispositions("A0FIRST", 0, MAX_DISPOSITION_PAGE)
        .expect_err("a smuggled row is refused, not believed");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("source_key"));
}

#[test]
fn a_hand_written_digest_of_the_right_width_but_the_wrong_alphabet_is_corruption() {
    let (private, mut log) = log();
    log.record(admitted(KEY_A, &digest('a'))).expect("delivery");
    drop(log);

    // Length 64 satisfies the column CHECK; the alphabet is checked on read.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms)
         VALUES (?1, 'A0FIRST', 'admitted', ?2, 'envelope-x', 0, 1500)",
        params![KEY_B, "Z".repeat(CONTENT_DIGEST_CHARS)],
    )
    .expect("smuggle a non-hex digest");
    drop(raw);

    let reopened = SlackIngressLog::open(private.path()).expect("reopen");
    let error = reopened
        .disposition(KEY_B)
        .expect_err("a non-hex digest is refused, not believed");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("content_digest"));
    // The well-formed row beside it still reads.
    assert!(reopened.disposition(KEY_A).expect("read").is_some());
}

#[test]
fn the_database_itself_refuses_a_digest_on_a_content_free_disposition() {
    let (private, mut log) = log();
    log.record(denied(KEY_A)).expect("delivery");
    drop(log);

    let raw = Connection::open(private.path()).expect("raw write");
    let smuggled = raw.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms)
         VALUES (?1, 'A0FIRST', 'denied', ?2, 'envelope-x', 0, 1500)",
        params![KEY_B, digest('a')],
    );
    assert!(
        smuggled.is_err(),
        "the digest-presence rule is a database constraint, not only an API rule"
    );
    let unknown = raw.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms)
         VALUES (?1, 'A0FIRST', 'refused', NULL, 'envelope-x', 0, 1500)",
        params![KEY_B],
    );
    assert!(
        unknown.is_err(),
        "the disposition vocabulary is closed in the database"
    );
    let duplicate = raw.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms)
         VALUES (?1, 'A0FIRST', 'denied', NULL, 'envelope-x', 0, 1500)",
        params![KEY_A],
    );
    assert!(
        duplicate.is_err(),
        "source_key uniqueness is a database constraint"
    );
    drop(raw);
    assert_eq!(private.raw_count(), 1);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, log) = log();
    drop(log);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = SlackIngressLog::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateLog::new();
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private.path())
        .expect("private file");

    let raw = Connection::open(private.path()).expect("raw create");
    raw.execute_batch("CREATE TABLE foreign_rows (id INTEGER PRIMARY KEY) STRICT;")
        .expect("foreign table");
    drop(raw);

    let error = SlackIngressLog::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_log_file_is_refused() {
    let (private, log) = log();
    drop(log);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = SlackIngressLog::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: a NULL must not slip the digest coupling
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, so a coupling
// written over a nullable column as a bare comparison admits the very row it
// was written to refuse — `length(NULL) = 64` is `NULL`, not false. This
// coupling spells `content_digest IS NOT NULL` before it measures anything, so
// the admitted-without-a-digest row is refused rather than believed. The
// opposite half, a digest on a content-free disposition, is covered by
// `the_database_itself_refuses_a_digest_on_a_content_free_disposition`.
// ---------------------------------------------------------------------------

#[test]
fn a_null_never_slips_the_content_digest_coupling() {
    let (private, log) = log();
    drop(log);

    let raw = Connection::open(private.path()).expect("raw write");
    let disposition = |source_key: &str, coupled: &str| {
        format!(
            "INSERT INTO slack_ingress_dispositions
                 (source_key, app_id, envelope_id, retry_attempt, recorded_at_ms,
                  disposition, content_digest)
             VALUES ('{source_key}', 'A0FIRST', 'envelope-x', 0, 1500, {coupled})"
        )
    };
    let whole = digest('a');

    for (what, statement) in [
        (
            "an admitted delivery with no digest at all",
            disposition("slack:audit:none", "'admitted', NULL"),
        ),
        (
            "an admitted delivery with a short digest",
            disposition("slack:audit:short", "'admitted', 'abc'"),
        ),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: both legal pairings still land.
    raw.execute(
        &disposition("slack:audit:whole", &format!("'admitted', '{whole}'")),
        [],
    )
    .expect("an admitted delivery with a whole digest");
    raw.execute(&disposition("slack:audit:denied", "'denied', NULL"), [])
        .expect("a denied delivery with no digest");
}
