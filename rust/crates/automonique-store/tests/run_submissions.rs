// SPDX-License-Identifier: Elastic-2.0

//! Durable run-submission custody invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the log and reopen
//! the file: an in-memory log cannot pass them, which is the whole reason this
//! module is durable. The document assertions compare bytes rather than
//! lengths, because custody that reproduces something *like* the accepted
//! document is not custody.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::run_submissions::{
    MAX_DOCUMENT_BYTES, MAX_IDENTIFIER_BYTES, MAX_RUN_SUBMISSIONS, RUN_SUBMISSIONS_SCHEMA_VERSION,
    RunSubmission, RunSubmissionDisposition, RunSubmissionLog, RunSubmissionState,
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
        let path = directory.path().join("run-submissions.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn log() -> (PrivateLog, RunSubmissionLog) {
    let private = PrivateLog::new();
    let opened = RunSubmissionLog::open(private.path()).expect("open log");
    (private, opened)
}

const DIGEST_A: &str = "aa11111111111111111111111111111111111111111111111111111111111111";
const DIGEST_B: &str = "bb22222222222222222222222222222222222222222222222222222222222222";

fn submission<'a>(
    idempotency_key: &'a str,
    run_id: &'a str,
    spec_digest: &'a str,
    document: &'a [u8],
) -> RunSubmission<'a> {
    RunSubmission {
        idempotency_key,
        run_id,
        spec_digest,
        document,
        accepted_at_ms: 1_000,
    }
}

#[test]
fn a_fresh_log_stamps_its_schema_version() {
    let (private, opened) = log();
    assert_eq!(opened.path(), private.path());
    assert_eq!(opened.capacity(), MAX_RUN_SUBMISSIONS);
    assert_eq!(opened.submission_count().expect("count"), 0);
    drop(opened);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, RUN_SUBMISSIONS_SCHEMA_VERSION);
}

#[test]
fn a_foreign_or_populated_database_is_refused() {
    let (private, opened) = log();
    drop(opened);
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999_u32)
        .expect("stamp foreign version");
    drop(raw);
    let error = RunSubmissionLog::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");

    let other = PrivateLog::new();
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(other.path())
        .expect("private file");
    let raw = Connection::open(other.path()).expect("raw create");
    raw.execute_batch("CREATE TABLE foreign_rows (id INTEGER PRIMARY KEY) STRICT;")
        .expect("foreign table");
    drop(raw);
    assert_eq!(
        RunSubmissionLog::open(other.path())
            .expect_err("populated database")
            .category(),
        "schema_version"
    );
}

#[test]
fn a_group_readable_log_file_is_refused() {
    let (private, opened) = log();
    drop(opened);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");
    assert_eq!(
        RunSubmissionLog::open(private.path())
            .expect_err("insecure file")
            .category(),
        "insecure_path"
    );
}

#[test]
fn a_new_document_is_accepted_and_an_exact_resubmission_replays_the_same_row() {
    let (_private, mut opened) = log();
    let document = br#"{"schema":"automonique.run-spec/v1"}"#;
    let first = opened
        .record(submission("operator:1", "run-1", DIGEST_A, document))
        .expect("first acceptance");
    assert_eq!(first.disposition, RunSubmissionDisposition::Accepted);
    assert!(!first.disposition.is_replay());
    assert!(first.submission_id > 0);

    // A retry carries a later clock. That is not part of the binding.
    let replay = opened
        .record(RunSubmission {
            accepted_at_ms: 9_999,
            ..submission("operator:1", "run-1", DIGEST_A, document)
        })
        .expect("exact replay");
    assert_eq!(
        replay.disposition,
        RunSubmissionDisposition::AlreadyAccepted
    );
    assert!(replay.disposition.is_replay());
    assert_eq!(replay.submission_id, first.submission_id);
    assert_eq!(opened.submission_count().expect("count"), 1);

    let entry = opened
        .submission("operator:1")
        .expect("read")
        .expect("row exists");
    assert_eq!(entry.submission_id, first.submission_id);
    assert_eq!(entry.run_id, "run-1");
    assert_eq!(entry.spec_digest, DIGEST_A);
    assert_eq!(entry.document, document);
    assert_eq!(entry.state, RunSubmissionState::Accepted);
    // The first acceptance's clock, not the replay's.
    assert_eq!(entry.accepted_at_ms, 1_000);
}

#[test]
fn a_reused_key_conflicts_on_the_first_differing_coordinate_and_writes_nothing() {
    let (_private, mut opened) = log();
    let document = b"canonical-document-a";
    let accepted = opened
        .record(submission("operator:1", "run-1", DIGEST_A, document))
        .expect("first acceptance");

    for (altered, expected_field) in [
        (
            submission("operator:1", "run-2", DIGEST_A, document),
            "run_id",
        ),
        (
            submission("operator:1", "run-1", DIGEST_B, document),
            "spec_digest",
        ),
        (
            // A stale digest presented for fresh bytes: the digest matches the
            // row, so only comparing the document catches this one.
            submission("operator:1", "run-1", DIGEST_A, b"canonical-document-b"),
            "document",
        ),
    ] {
        let error = opened.record(altered).expect_err("conflicting reuse");
        assert_eq!(error.category(), "conflict");
        assert!(
            error.to_string().contains(expected_field),
            "expected {expected_field}: {error}"
        );
        // The refusal names the row and its digest, never the stored bytes.
        assert!(!error.to_string().contains("canonical-document-a"));
    }

    assert_eq!(opened.submission_count().expect("count"), 1);
    let entry = opened
        .submission("operator:1")
        .expect("read")
        .expect("row exists");
    assert_eq!(entry.submission_id, accepted.submission_id);
    assert_eq!(entry.run_id, "run-1");
    assert_eq!(entry.spec_digest, DIGEST_A);
    assert_eq!(entry.document, document);
}

#[test]
fn custody_survives_close_and_reopen() {
    let private = PrivateLog::new();
    let document: Vec<u8> = (0..=255_u8).cycle().take(4_096).collect();
    let first = {
        let mut opened = RunSubmissionLog::open(private.path()).expect("open");
        opened
            .record(submission("operator:restart", "run-7", DIGEST_A, &document))
            .expect("acceptance")
    };

    let mut reopened = RunSubmissionLog::open(private.path()).expect("reopen");
    let entry = reopened
        .submission("operator:restart")
        .expect("read")
        .expect("row survives");
    assert_eq!(entry.submission_id, first.submission_id);
    // Byte-exact custody, including the bytes a text column would have mangled.
    assert_eq!(entry.document, document);

    let replay = reopened
        .record(submission("operator:restart", "run-7", DIGEST_A, &document))
        .expect("replay after restart");
    assert_eq!(replay.submission_id, first.submission_id);
    assert_eq!(
        replay.disposition,
        RunSubmissionDisposition::AlreadyAccepted
    );
    assert_eq!(reopened.submission_count().expect("count"), 1);
}

#[test]
fn submissions_are_listed_per_run_in_acceptance_order() {
    let (_private, mut opened) = log();
    let first = opened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect("first");
    let second = opened
        .record(submission("operator:2", "run-1", DIGEST_B, b"document-b"))
        .expect("second");
    opened
        .record(submission("operator:3", "run-2", DIGEST_A, b"document-c"))
        .expect("other run");

    let listed = opened.run_submissions("run-1").expect("list");
    assert_eq!(
        listed
            .iter()
            .map(|entry| entry.submission_id)
            .collect::<Vec<_>>(),
        vec![first.submission_id, second.submission_id]
    );
    assert!(opened.run_submissions("run-3").expect("list").is_empty());
}

#[test]
fn capacity_refuses_new_submissions_but_never_a_replay() {
    let private = PrivateLog::new();
    let mut opened = RunSubmissionLog::open_with_capacity(private.path(), 1).expect("open");
    let accepted = opened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect("first fills the log");

    let error = opened
        .record(submission("operator:2", "run-1", DIGEST_A, b"document-a"))
        .expect_err("log is full");
    assert_eq!(error.category(), "log_full");

    // A replay writes nothing, so a full log must still answer it.
    let replay = opened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect("replay in a full log");
    assert_eq!(replay.submission_id, accepted.submission_id);
    assert_eq!(
        replay.disposition,
        RunSubmissionDisposition::AlreadyAccepted
    );
    // A conflicting reuse is a conflict, not a capacity refusal.
    assert_eq!(
        opened
            .record(submission("operator:1", "run-1", DIGEST_B, b"document-a"))
            .expect_err("conflicting reuse in a full log")
            .category(),
        "conflict"
    );
    assert_eq!(opened.submission_count().expect("count"), 1);

    assert_eq!(
        RunSubmissionLog::open_with_capacity(private.path(), 0)
            .expect_err("zero capacity")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        RunSubmissionLog::open_with_capacity(private.path(), MAX_RUN_SUBMISSIONS + 1)
            .expect_err("capacity above the ceiling")
            .category(),
        "invalid_field"
    );
}

#[test]
fn malformed_fields_are_refused_before_any_write() {
    let (_private, mut opened) = log();
    let long = "k".repeat(MAX_IDENTIFIER_BYTES + 1);
    let oversized = vec![b'x'; MAX_DOCUMENT_BYTES + 1];
    for (candidate, field) in [
        (submission("", "run-1", DIGEST_A, b"d"), "idempotency_key"),
        (
            submission(&long, "run-1", DIGEST_A, b"d"),
            "idempotency_key",
        ),
        (
            submission("k\u{7}bell", "run-1", DIGEST_A, b"d"),
            "idempotency_key",
        ),
        (submission("operator:1", "", DIGEST_A, b"d"), "run_id"),
        // A digest of the wrong width, uppercase, or not hexadecimal at all.
        (
            submission("operator:1", "run-1", "aa11", b"d"),
            "spec_digest",
        ),
        (
            submission(
                "operator:1",
                "run-1",
                "AA11111111111111111111111111111111111111111111111111111111111111",
                b"d",
            ),
            "spec_digest",
        ),
        (
            submission(
                "operator:1",
                "run-1",
                "zz11111111111111111111111111111111111111111111111111111111111111",
                b"d",
            ),
            "spec_digest",
        ),
        (
            // A digest with its algorithm name does not fit this column: the
            // stored value is the bare hex body.
            submission(
                "operator:1",
                "run-1",
                "sha256:aa111111111111111111111111111111111111111111111111111111111111",
                b"d",
            ),
            "spec_digest",
        ),
        (submission("operator:1", "run-1", DIGEST_A, b""), "document"),
        (
            submission("operator:1", "run-1", DIGEST_A, &oversized),
            "document",
        ),
    ] {
        let error = opened.record(candidate).expect_err("malformed field");
        assert_eq!(error.category(), "invalid_field");
        assert!(
            error.to_string().contains(field),
            "expected {field}: {error}"
        );
    }
    assert_eq!(
        opened
            .record(RunSubmission {
                accepted_at_ms: -1,
                ..submission("operator:1", "run-1", DIGEST_A, b"d")
            })
            .expect_err("negative clock")
            .category(),
        "invalid_field"
    );
    assert_eq!(opened.submission_count().expect("count"), 0);
}

#[test]
fn the_state_vocabulary_has_exactly_one_spelling() {
    assert_eq!(
        RunSubmissionState::from_spelling("accepted"),
        Some(RunSubmissionState::Accepted)
    );
    // No lane can reach these states, so no spelling of them exists.
    for absent in ["executing", "completed", "failed", "Accepted", ""] {
        assert_eq!(RunSubmissionState::from_spelling(absent), None);
    }

    let (private, mut opened) = log();
    opened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect("acceptance");
    drop(opened);

    // The database refuses the word too: the vocabulary is a column CHECK, not
    // only a Rust match.
    let raw = Connection::open(private.path()).expect("raw write");
    let error = raw
        .execute(
            "UPDATE run_submissions SET state = 'executing' WHERE idempotency_key = 'operator:1'",
            [],
        )
        .expect_err("state is a closed vocabulary");
    assert!(error.to_string().contains("CHECK"), "{error}");
    for statement in [
        "INSERT INTO run_submissions
         (idempotency_key, run_id, spec_digest, document, accepted_at_ms, state)
         VALUES ('k', 'run-1', 'aa', x'7b', 1, 'accepted')",
        "INSERT INTO run_submissions
         (idempotency_key, run_id, spec_digest, document, accepted_at_ms, state)
         VALUES ('k', 'run-1', 'aa11111111111111111111111111111111111111111111111111111111111111',
                 x'', 1, 'accepted')",
    ] {
        assert!(
            raw.execute(statement, []).is_err(),
            "the schema admitted a row it must refuse"
        );
    }
}

#[test]
fn hand_written_rows_surface_as_corruption_on_read_and_on_record() {
    let (private, mut opened) = log();
    opened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect("acceptance");
    drop(opened);

    // Column CHECKs bound the width; the lowercase-hex grammar is enforced in
    // code, so an uppercase digest is smuggled past the database.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_submissions SET spec_digest = ?1 WHERE idempotency_key = 'operator:1'",
        params!["AA11111111111111111111111111111111111111111111111111111111111111"],
    )
    .expect("smuggle uppercase digest");
    drop(raw);

    let mut reopened = RunSubmissionLog::open(private.path()).expect("reopen");
    let error = reopened
        .submission("operator:1")
        .expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("spec_digest"), "{error}");

    // Recording reads before it writes, so corruption stops a write too.
    let error = reopened
        .record(submission("operator:1", "run-1", DIGEST_A, b"document-a"))
        .expect_err("corruption refusal on record");
    assert_eq!(error.category(), "corrupt");

    // An unrelated key is unaffected: corruption is per-row, not per-database.
    assert_eq!(
        reopened
            .record(submission("operator:2", "run-2", DIGEST_B, b"document-b"))
            .expect("unrelated acceptance")
            .disposition,
        RunSubmissionDisposition::Accepted
    );

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_submissions SET run_id = ?1 WHERE idempotency_key = 'operator:2'",
        params!["run\u{7}bell"],
    )
    .expect("smuggle control character");
    drop(raw);
    let reopened = RunSubmissionLog::open(private.path()).expect("reopen");
    let error = reopened
        .submission("operator:2")
        .expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("run_id"), "{error}");
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: no CHECK here can be handed a NULL
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, which is only a
// hazard where a CHECK can be handed a NULL. Every column this table constrains
// is `NOT NULL`, so the digest width and the non-empty document are decided
// rather than waved through.
// ---------------------------------------------------------------------------

#[test]
fn no_nullable_column_reaches_a_check_in_this_table() {
    let (private, log) = log();
    drop(log);

    let raw = Connection::open(private.path()).expect("raw write");
    let submission = |coupled: &str| {
        format!(
            "INSERT INTO run_submissions
                 (idempotency_key, run_id, accepted_at_ms,
                  spec_digest, document, state)
             VALUES ('audit:key', 'run:alpha', 0, {coupled})"
        )
    };
    let whole = "a".repeat(64);

    for (what, statement) in [
        // A NULL is refused by the column, so no CHECK here is ever handed one.
        (
            "a digestless submission",
            submission("NULL, x'01', 'accepted'"),
        ),
        (
            "a documentless submission",
            submission(&format!("'{whole}', NULL, 'accepted'")),
        ),
        // And the constraints themselves bite on the values that do reach them.
        (
            "a digest of the wrong width",
            submission("'abc', x'01', 'accepted'"),
        ),
        (
            "an empty document",
            submission(&format!("'{whole}', x'', 'accepted'")),
        ),
        (
            "a state outside the one-word vocabulary",
            submission(&format!("'{whole}', x'01', 'pending'")),
        ),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: a legal submission still lands.
    raw.execute(&submission(&format!("'{whole}', x'01', 'accepted'")), [])
        .expect("a whole digest over a non-empty document");
}
