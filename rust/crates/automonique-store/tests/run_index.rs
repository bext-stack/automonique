// SPDX-License-Identifier: Elastic-2.0

//! Durable run index invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the index and reopen
//! the file: an in-memory index cannot pass them, which is the whole reason this
//! module exists.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::run_index::{
    MAX_IDENTIFIER_BYTES, MAX_INDEX_PAGE, MAX_RUN_INDEX_ENTRIES, RUN_INDEX_SCHEMA_VERSION,
    RunIndex, RunIndexEntry, RunSpoolState, StateAdvance,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

struct PrivateIndex {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateIndex {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("run-index.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn index() -> (PrivateIndex, RunIndex) {
    let private = PrivateIndex::new();
    let opened = RunIndex::open(private.path()).expect("open index");
    (private, opened)
}

fn entry(submission_id: i64, run_id: &str) -> RunIndexEntry<'_> {
    RunIndexEntry {
        submission_id,
        run_id,
        registered_at_ms: 1_000,
    }
}

fn advance(
    submission_id: i64,
    expected_revision: u64,
    new_state: RunSpoolState,
    last_sequence: u64,
) -> StateAdvance {
    StateAdvance {
        submission_id,
        expected_revision,
        new_state,
        last_sequence,
        now_ms: 2_000,
    }
}

/// Register one submission and drive it to `running` at sequence one.
fn running(index: &mut RunIndex, submission_id: i64, run_id: &str) {
    index
        .register(entry(submission_id, run_id))
        .expect("register");
    index
        .advance_state(advance(submission_id, 1, RunSpoolState::Running, 1))
        .expect("advance to running");
}

fn submissions(entries: &[automonique_store::run_index::RunIndexRecord]) -> Vec<i64> {
    entries.iter().map(|entry| entry.submission_id).collect()
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_index_stamps_its_schema_version() {
    let (private, index) = index();
    assert_eq!(index.path(), private.path());
    assert_eq!(index.capacity(), MAX_RUN_INDEX_ENTRIES);
    assert_eq!(index.entry_count().expect("count"), 0);
    assert_eq!(index.retained_range().expect("range"), None);
    drop(index);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, RUN_INDEX_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, index) = index();
    drop(index);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = RunIndex::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateIndex::new();
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

    let error = RunIndex::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_index_file_is_refused() {
    let (private, index) = index();
    drop(index);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = RunIndex::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_group_readable_directory_is_refused() {
    let private = PrivateIndex::new();
    let directory = private.path().parent().expect("parent");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).expect("loosen dir mode");

    let error = RunIndex::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn an_out_of_range_capacity_is_refused() {
    let private = PrivateIndex::new();
    for capacity in [0, MAX_RUN_INDEX_ENTRIES + 1] {
        let error =
            RunIndex::open_with_capacity(private.path(), capacity).expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[test]
fn a_registered_submission_reads_back_at_ready() {
    let (_private, mut index) = index();

    let receipt = index.register(entry(7, "run:alpha")).expect("register");
    assert_eq!(receipt.submission_id, 7);
    assert_eq!(receipt.spool_state, RunSpoolState::Ready);
    assert_eq!(receipt.last_sequence, 0);
    assert_eq!(receipt.revision, 1);
    assert_eq!(receipt.updated_at_ms, 1_000);

    let record = index.entry(7).expect("entry").expect("a row");
    assert_eq!(record.index_id, receipt.index_id);
    assert_eq!(record.run_id, "run:alpha");
    assert_eq!(record.spool_state, RunSpoolState::Ready);
    assert_eq!(record.last_sequence, 0);
    assert_eq!(record.revision, 1);
    assert_eq!(index.entry_count().expect("count"), 1);
    assert!(index.entry(8).expect("absent entry").is_none());
}

#[test]
fn a_duplicate_submission_is_refused_and_writes_nothing() {
    let (_private, mut index) = index();
    index.register(entry(7, "run:alpha")).expect("register");
    index
        .advance_state(advance(7, 1, RunSpoolState::Running, 4))
        .expect("advance");

    // Even re-registering the *same* run is refused: it would reset a row a
    // writer has already advanced.
    let error = index
        .register(entry(7, "run:alpha"))
        .expect_err("duplicate refusal");
    assert_eq!(error.category(), "already_registered");
    assert!(error.to_string().contains("run:alpha"));

    let error = index
        .register(entry(7, "run:beta"))
        .expect_err("duplicate refusal");
    assert_eq!(error.category(), "already_registered");

    let record = index.entry(7).expect("entry").expect("a row");
    assert_eq!(record.spool_state, RunSpoolState::Running);
    assert_eq!(record.last_sequence, 4);
    assert_eq!(record.revision, 2);
    assert_eq!(index.entry_count().expect("count"), 1);
}

#[test]
fn a_non_positive_submission_id_is_refused_everywhere() {
    let (_private, mut index) = index();

    for submission_id in [-1, 0] {
        let error = index
            .register(entry(submission_id, "run:alpha"))
            .expect_err("submission refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("submission_id"));

        assert_eq!(
            index
                .entry(submission_id)
                .expect_err("read refusal")
                .category(),
            "invalid_field"
        );
        assert_eq!(
            index
                .advance_state(advance(submission_id, 1, RunSpoolState::Running, 1))
                .expect_err("advance refusal")
                .category(),
            "invalid_field"
        );
    }
    assert_eq!(index.entry_count().expect("count"), 0);
}

#[test]
fn identifiers_and_times_outside_the_store_grammar_are_refused() {
    let (_private, mut index) = index();
    let over_long = "r".repeat(MAX_IDENTIFIER_BYTES + 1);

    for run_id in ["", over_long.as_str(), "run:\u{7}bell"] {
        let error = index
            .register(entry(1, run_id))
            .expect_err("identifier refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("run_id"));
        assert_eq!(
            index
                .by_run_id(run_id)
                .expect_err("read refusal")
                .category(),
            "invalid_field"
        );
    }

    let error = index
        .register(RunIndexEntry {
            submission_id: 1,
            run_id: "run:alpha",
            registered_at_ms: -1,
        })
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("registered_at_ms"));

    index.register(entry(1, "run:alpha")).expect("register");
    let error = index
        .advance_state(StateAdvance {
            submission_id: 1,
            expected_revision: 1,
            new_state: RunSpoolState::Running,
            last_sequence: 1,
            now_ms: -1,
        })
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("now_ms"));

    let error = index
        .advance_state(advance(1, 0, RunSpoolState::Running, 1))
        .expect_err("revision refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("expected_revision"));

    // A boundary-length identifier is admitted, so the refusal above is the
    // bound and not an off-by-one.
    let exact = "r".repeat(MAX_IDENTIFIER_BYTES);
    index.register(entry(2, &exact)).expect("boundary register");
    assert_eq!(index.by_run_id(&exact).expect("read").len(), 1);
}

#[test]
fn two_submissions_may_name_one_run_and_both_are_listed() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    index.register(entry(2, "run:alpha")).expect("register");
    index.register(entry(3, "run:beta")).expect("register");

    let alpha = index.by_run_id("run:alpha").expect("read");
    assert_eq!(submissions(&alpha), vec![1, 2]);
    let beta = index.by_run_id("run:beta").expect("read");
    assert_eq!(submissions(&beta), vec![3]);
    assert!(index.by_run_id("run:absent").expect("read").is_empty());
}

// ---------------------------------------------------------------------------
// The state lattice
// ---------------------------------------------------------------------------

#[test]
fn a_run_advances_ready_to_running_to_completed() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    let running = index
        .advance_state(advance(1, 1, RunSpoolState::Running, 1))
        .expect("advance to running");
    assert_eq!(running.spool_state, RunSpoolState::Running);
    assert_eq!(running.last_sequence, 1);
    assert_eq!(running.revision, 2);

    let completed = index
        .advance_state(advance(1, 2, RunSpoolState::Completed, 9))
        .expect("advance to completed");
    assert_eq!(completed.spool_state, RunSpoolState::Completed);
    assert_eq!(completed.last_sequence, 9);
    assert_eq!(completed.revision, 3);

    let record = index.entry(1).expect("entry").expect("a row");
    assert_eq!(record.spool_state, RunSpoolState::Completed);
    assert_eq!(record.last_sequence, 9);
    assert_eq!(record.revision, 3);
    assert_eq!(record.updated_at_ms, 2_000);
}

#[test]
fn every_terminal_spelling_is_reachable_from_running() {
    let (_private, mut index) = index();

    for (submission_id, state) in [
        RunSpoolState::Completed,
        RunSpoolState::Failed,
        RunSpoolState::Cancelled,
        RunSpoolState::TimedOut,
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = i64::try_from(submission_id).expect("small") + 1;
        running(&mut index, submission_id, "run:alpha");
        let receipt = index
            .advance_state(advance(submission_id, 2, state, 2))
            .expect("advance to a terminal state");
        assert_eq!(receipt.spool_state, state);
        assert!(state.is_terminal());
        assert_eq!(
            index
                .entry(submission_id)
                .expect("entry")
                .expect("a row")
                .spool_state,
            state
        );
    }
}

#[test]
fn a_ready_run_may_not_skip_straight_to_a_terminal_state() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    for state in [
        RunSpoolState::Completed,
        RunSpoolState::Failed,
        RunSpoolState::Cancelled,
        RunSpoolState::TimedOut,
    ] {
        let error = index
            .advance_state(advance(1, 1, state, 1))
            .expect_err("skip refusal");
        assert_eq!(error.category(), "illegal_transition");
        assert!(error.to_string().contains("ready"));
        assert!(error.to_string().contains(state.as_str()));
    }

    // Nothing was written by any of them.
    let record = index.entry(1).expect("entry").expect("a row");
    assert_eq!(record.spool_state, RunSpoolState::Ready);
    assert_eq!(record.revision, 1);
}

#[test]
fn a_terminal_run_is_never_left() {
    let (_private, mut index) = index();

    for (submission_id, terminal) in [
        RunSpoolState::Completed,
        RunSpoolState::Failed,
        RunSpoolState::Cancelled,
        RunSpoolState::TimedOut,
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = i64::try_from(submission_id).expect("small") + 1;
        running(&mut index, submission_id, "run:alpha");
        index
            .advance_state(advance(submission_id, 2, terminal, 2))
            .expect("advance to a terminal state");

        // Every destination, including the state the row already holds.
        for destination in RunSpoolState::ALL {
            let error = index
                .advance_state(advance(submission_id, 3, destination, 3))
                .expect_err("terminal refusal");
            assert_eq!(error.category(), "illegal_transition");
            assert!(error.to_string().contains(terminal.as_str()));
        }

        let record = index.entry(submission_id).expect("entry").expect("a row");
        assert_eq!(record.spool_state, terminal);
        assert_eq!(record.last_sequence, 2);
        assert_eq!(record.revision, 3);
    }
}

#[test]
fn nothing_ever_returns_to_ready() {
    let (_private, mut index) = index();
    running(&mut index, 1, "run:alpha");

    let error = index
        .advance_state(advance(1, 2, RunSpoolState::Ready, 2))
        .expect_err("ready refusal");
    assert_eq!(error.category(), "illegal_transition");
    assert!(error.to_string().contains("running"));
    assert!(error.to_string().contains("ready"));

    // The registration path is the only writer of `ready`, and it is closed to
    // a submission that already has a row.
    assert_eq!(
        index
            .register(entry(1, "run:alpha"))
            .expect_err("duplicate refusal")
            .category(),
        "already_registered"
    );
    assert_eq!(
        index.entry(1).expect("entry").expect("a row").spool_state,
        RunSpoolState::Running
    );
}

#[test]
fn running_may_be_re_reported_at_the_same_or_a_higher_sequence() {
    let (_private, mut index) = index();
    running(&mut index, 1, "run:alpha");

    let same = index
        .advance_state(advance(1, 2, RunSpoolState::Running, 1))
        .expect("a run that has not moved");
    assert_eq!(same.last_sequence, 1);
    assert_eq!(same.revision, 3);

    let moved = index
        .advance_state(advance(1, 3, RunSpoolState::Running, 12))
        .expect("further events");
    assert_eq!(moved.last_sequence, 12);
    assert_eq!(moved.revision, 4);
}

#[test]
fn the_lattice_predicate_admits_exactly_the_transitions_the_spool_produces() {
    for from in RunSpoolState::ALL {
        for to in RunSpoolState::ALL {
            let expected = match (from, to) {
                (RunSpoolState::Ready, RunSpoolState::Running) => true,
                (RunSpoolState::Running, next) => next != RunSpoolState::Ready,
                _ => false,
            };
            assert_eq!(
                from.may_advance_to(to),
                expected,
                "{from} -> {to} disagrees with the lattice"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Revision and sequence
// ---------------------------------------------------------------------------

#[test]
fn a_stale_expected_revision_is_refused_and_writes_nothing() {
    let (_private, mut index) = index();
    running(&mut index, 1, "run:alpha");

    for expected in [1, 3, 99] {
        let error = index
            .advance_state(advance(1, expected, RunSpoolState::Completed, 5))
            .expect_err("revision refusal");
        assert_eq!(error.category(), "revision_mismatch");
        assert!(error.to_string().contains("durable revision is 2"));
    }

    let record = index.entry(1).expect("entry").expect("a row");
    assert_eq!(record.spool_state, RunSpoolState::Running);
    assert_eq!(record.revision, 2);
    assert_eq!(record.last_sequence, 1);
}

#[test]
fn a_backward_sequence_is_refused() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    index
        .advance_state(advance(1, 1, RunSpoolState::Running, 8))
        .expect("advance to running");

    for sequence in [0, 1, 7] {
        let error = index
            .advance_state(advance(1, 2, RunSpoolState::Running, sequence))
            .expect_err("sequence refusal");
        assert_eq!(error.category(), "sequence_regression");
        assert!(error.to_string().contains("durable 8"));
    }

    let error = index
        .advance_state(advance(1, 2, RunSpoolState::Completed, 3))
        .expect_err("sequence refusal");
    assert_eq!(error.category(), "sequence_regression");

    let record = index.entry(1).expect("entry").expect("a row");
    assert_eq!(record.last_sequence, 8);
    assert_eq!(record.revision, 2);
}

#[test]
fn a_state_change_at_an_unmoved_sequence_is_refused() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    // `ready` carries sequence zero, and the first event is sequence one, so a
    // `running` report at zero describes a spool that cannot exist.
    let error = index
        .advance_state(advance(1, 1, RunSpoolState::Running, 0))
        .expect_err("sequence refusal");
    assert_eq!(error.category(), "sequence_regression");

    index
        .advance_state(advance(1, 1, RunSpoolState::Running, 4))
        .expect("advance to running");

    // The terminal event is itself an event, so it cannot share the sequence
    // the running observation already recorded.
    let error = index
        .advance_state(advance(1, 2, RunSpoolState::Failed, 4))
        .expect_err("sequence refusal");
    assert_eq!(error.category(), "sequence_regression");
    assert!(error.to_string().contains("does not advance"));

    index
        .advance_state(advance(1, 2, RunSpoolState::Failed, 5))
        .expect("the terminal event is a new sequence");
}

#[test]
fn an_unregistered_submission_cannot_advance() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    let error = index
        .advance_state(advance(2, 1, RunSpoolState::Running, 1))
        .expect_err("missing row refusal");
    assert_eq!(error.category(), "not_found");
    assert_eq!(index.entry_count().expect("count"), 1);
}

// ---------------------------------------------------------------------------
// Pagination and the retained window
// ---------------------------------------------------------------------------

#[test]
fn a_page_is_bounded_and_resumes_from_its_cursor() {
    let (_private, mut index) = index();
    for submission_id in 1..=5 {
        index
            .register(entry(submission_id, "run:alpha"))
            .expect("register");
    }

    let first = index.page(0, 2).expect("first page");
    assert_eq!(submissions(&first.entries), vec![1, 2]);
    let cursor = first.next_cursor.expect("more rows follow");

    let second = index.page(cursor, 2).expect("second page");
    assert_eq!(submissions(&second.entries), vec![3, 4]);

    let third = index
        .page(second.next_cursor.expect("more rows follow"), 2)
        .expect("third page");
    assert_eq!(submissions(&third.entries), vec![5]);
    assert_eq!(
        third.next_cursor, None,
        "an exhausted listing offers no continuation"
    );

    // A page that exactly fills its limit with nothing behind it is still the
    // end, and says so.
    let exact = index.page(0, 5).expect("exact page");
    assert_eq!(exact.entries.len(), 5);
    assert_eq!(exact.next_cursor, None);
}

#[test]
fn a_state_filtered_page_carries_exactly_the_matching_rows() {
    let (_private, mut index) = index();
    // 1: ready, 2: running, 3: completed, 4: failed, 5: ready.
    index.register(entry(1, "run:alpha")).expect("register");
    running(&mut index, 2, "run:beta");
    running(&mut index, 3, "run:gamma");
    index
        .advance_state(advance(3, 2, RunSpoolState::Completed, 2))
        .expect("complete");
    running(&mut index, 4, "run:delta");
    index
        .advance_state(advance(4, 2, RunSpoolState::Failed, 2))
        .expect("fail");
    index.register(entry(5, "run:epsilon")).expect("register");

    let ready = index
        .page_in_states(0, MAX_INDEX_PAGE, &[RunSpoolState::Ready])
        .expect("ready page");
    assert_eq!(submissions(&ready.entries), vec![1, 5]);

    let terminal = index
        .page_in_states(
            0,
            MAX_INDEX_PAGE,
            &[
                RunSpoolState::Completed,
                RunSpoolState::Failed,
                RunSpoolState::Cancelled,
                RunSpoolState::TimedOut,
            ],
        )
        .expect("terminal page");
    assert_eq!(submissions(&terminal.entries), vec![3, 4]);

    let none = index
        .page_in_states(0, MAX_INDEX_PAGE, &[RunSpoolState::TimedOut])
        .expect("empty page");
    assert!(none.entries.is_empty());
    assert_eq!(none.next_cursor, None);

    // The filter pages exactly as the unfiltered listing does.
    let first = index
        .page_in_states(0, 1, &[RunSpoolState::Ready])
        .expect("first filtered page");
    assert_eq!(submissions(&first.entries), vec![1]);
    let second = index
        .page_in_states(
            first.next_cursor.expect("more rows follow"),
            1,
            &[RunSpoolState::Ready],
        )
        .expect("second filtered page");
    assert_eq!(submissions(&second.entries), vec![5]);
    assert_eq!(second.next_cursor, None);

    // Naming every state is the same query as naming none.
    let all = index
        .page_in_states(0, MAX_INDEX_PAGE, &RunSpoolState::ALL)
        .expect("unrestricted page");
    assert_eq!(
        submissions(&all.entries),
        submissions(&index.page(0, MAX_INDEX_PAGE).expect("page").entries)
    );
}

#[test]
fn an_empty_or_repeating_state_filter_is_refused() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    let error = index
        .page_in_states(0, 10, &[])
        .expect_err("empty filter refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("states"));

    let error = index
        .page_in_states(
            0,
            10,
            &[
                RunSpoolState::Ready,
                RunSpoolState::Running,
                RunSpoolState::Ready,
            ],
        )
        .expect_err("repeat refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("states"));
}

#[test]
fn a_cursor_above_the_retained_window_is_refused() {
    let (_private, mut index) = index();

    // An empty index retains nothing, so only the beginning is resumable.
    let empty = index.page(0, 10).expect("empty page");
    assert!(empty.entries.is_empty());
    assert_eq!(empty.next_cursor, None);
    let error = index.page(1, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains("retained index_id 0"));

    for submission_id in 1..=3 {
        index
            .register(entry(submission_id, "run:alpha"))
            .expect("register");
    }
    let range = index.retained_range().expect("range").expect("a window");

    // The last retained row is a resumable cursor; one past it is not.
    let caught_up = index.page(range.last, 10).expect("caught-up page");
    assert!(caught_up.entries.is_empty());
    let error = index.page(range.last + 1, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains("retained index_id 3"));
}

#[test]
fn a_filtered_page_judges_its_cursor_against_the_whole_index() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    running(&mut index, 2, "run:beta");
    index.register(entry(3, "run:gamma")).expect("register");

    let range = index.retained_range().expect("range").expect("a window");

    // The highest row is `ready`, so a `running` filter excludes it. Resuming
    // after it is still a legal position in the listing order.
    let page = index
        .page_in_states(range.last, 10, &[RunSpoolState::Running])
        .expect("caught-up filtered page");
    assert!(page.entries.is_empty());

    let error = index
        .page_in_states(range.last + 1, 10, &[RunSpoolState::Running])
        .expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
}

#[test]
fn a_limit_outside_its_bounds_is_refused() {
    let (_private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");

    for limit in [0, MAX_INDEX_PAGE + 1] {
        let error = index.page(0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));

        let error = index
            .page_in_states(0, limit, &[RunSpoolState::Ready])
            .expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
    }
    assert_eq!(
        index.page(0, MAX_INDEX_PAGE).expect("page").entries.len(),
        1
    );
}

#[test]
fn the_retained_window_grows_as_rows_are_added() {
    let (_private, mut index) = index();
    assert_eq!(index.retained_range().expect("range"), None);

    for submission_id in 1..=4 {
        index
            .register(entry(submission_id, "run:alpha"))
            .expect("register");
        let range = index.retained_range().expect("range").expect("a window");
        assert_eq!(range.first, 1, "nothing is deleted, so the floor is one");
        assert_eq!(
            range.last,
            u64::try_from(submission_id).expect("small"),
            "the ceiling follows registration order"
        );
    }

    // Advancing a state moves no boundary: the window is registration order.
    index
        .advance_state(advance(1, 1, RunSpoolState::Running, 1))
        .expect("advance");
    let range = index.retained_range().expect("range").expect("a window");
    assert_eq!((range.first, range.last), (1, 4));
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn an_advanced_row_survives_close_and_reopen() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    index.register(entry(2, "run:beta")).expect("register");
    index
        .advance_state(advance(1, 1, RunSpoolState::Running, 3))
        .expect("advance to running");
    index
        .advance_state(advance(1, 2, RunSpoolState::Cancelled, 4))
        .expect("advance to cancelled");
    drop(index);

    let reopened = RunIndex::open(private.path()).expect("reopen");
    let record = reopened.entry(1).expect("entry").expect("a row");
    assert_eq!(record.spool_state, RunSpoolState::Cancelled);
    assert_eq!(record.last_sequence, 4);
    assert_eq!(record.revision, 3);
    assert_eq!(record.run_id, "run:alpha");
    assert_eq!(
        reopened
            .entry(2)
            .expect("entry")
            .expect("a row")
            .spool_state,
        RunSpoolState::Ready
    );
    assert_eq!(
        reopened
            .retained_range()
            .expect("range")
            .expect("a window")
            .last,
        2
    );

    // The revision the reopened handle reports is the one an advance must
    // expect: a restarted writer needs no memory of its own.
    let mut reopened = RunIndex::open(private.path()).expect("reopen");
    let error = reopened
        .advance_state(advance(1, 3, RunSpoolState::Running, 5))
        .expect_err("terminal refusal");
    assert_eq!(error.category(), "illegal_transition");
    reopened
        .advance_state(advance(2, 1, RunSpoolState::Running, 1))
        .expect("the untouched row still advances");
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_unknown_state_surfaces_as_corruption() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_index SET spool_state = 'aborted' WHERE submission_id = 1",
        [],
    )
    .expect_err("check constraint refuses an unknown state");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE run_index SET spool_state = 'aborted' WHERE submission_id = 1",
        [],
    )
    .expect("smuggle state");
    drop(raw);

    // Every read path refuses it rather than guessing what 'aborted' meant.
    let reopened = RunIndex::open(private.path()).expect("reopen");
    let error = reopened.entry(1).expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("spool_state"));
    assert_eq!(
        reopened
            .by_run_id("run:alpha")
            .expect_err("read refusal")
            .category(),
        "corrupt"
    );
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .page_in_states(0, 10, &RunSpoolState::ALL)
            .expect_err("filtered page refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_sequence_contradicting_its_state_surfaces_as_corruption() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    index.register(entry(2, "run:beta")).expect("register");
    index
        .advance_state(advance(2, 1, RunSpoolState::Running, 6))
        .expect("advance");
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_index SET last_sequence = 5 WHERE submission_id = 1",
        [],
    )
    .expect_err("check constraint binds ready to sequence zero");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    // `ready` at a non-zero sequence, and `running` at zero: both halves of the
    // binding, smuggled in opposite directions.
    raw.execute(
        "UPDATE run_index SET last_sequence = 5 WHERE submission_id = 1",
        [],
    )
    .expect("smuggle ready sequence");
    raw.execute(
        "UPDATE run_index SET last_sequence = 0 WHERE submission_id = 2",
        [],
    )
    .expect("smuggle running sequence");
    // A negative sequence is not even representable as the u64 this API stores.
    raw.execute(
        "INSERT INTO run_index
         (submission_id, run_id, spool_state, last_sequence, updated_at_ms, revision)
         VALUES (3, 'run:gamma', 'running', -4, 10, 2)",
        [],
    )
    .expect("smuggle negative sequence");
    drop(raw);

    let reopened = RunIndex::open(private.path()).expect("reopen");
    for submission_id in [1, 2, 3] {
        let error = reopened.entry(submission_id).expect_err("sequence refusal");
        assert_eq!(error.category(), "corrupt");
        assert!(error.to_string().contains("last_sequence"));
    }
}

#[test]
fn a_hand_written_control_character_run_id_surfaces_as_corruption() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_index SET run_id = ?1 WHERE submission_id = 1",
        params!["run:\u{7}bell"],
    )
    .expect("smuggle control character");
    drop(raw);

    let reopened = RunIndex::open(private.path()).expect("reopen");
    let error = reopened.entry(1).expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("run_id"));

    // Registration reads before it writes, so corruption stops a write to the
    // same row too, while an unrelated submission is unaffected.
    let mut reopened = RunIndex::open(private.path()).expect("reopen");
    assert_eq!(
        reopened
            .register(entry(1, "run:alpha"))
            .expect_err("corruption refusal")
            .category(),
        "corrupt"
    );
    reopened
        .register(entry(2, "run:beta"))
        .expect("an unrelated submission is unaffected");
}

#[test]
fn a_hand_written_ready_row_at_a_second_revision_surfaces_as_corruption() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    drop(index);

    // `ready` is written by registration alone and nothing returns to it, so a
    // `ready` row above revision one is a row this API never wrote. No CHECK
    // stops it — the read path is the whole defence.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE run_index SET revision = 2 WHERE submission_id = 1",
        [],
    )
    .expect("smuggle revision");
    drop(raw);

    let reopened = RunIndex::open(private.path()).expect("reopen");
    let error = reopened.entry(1).expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn a_hand_written_non_positive_identity_surfaces_as_corruption() {
    let (private, index) = index();
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "INSERT INTO run_index
         (index_id, submission_id, run_id, spool_state, last_sequence, updated_at_ms, revision)
         VALUES (1, -3, 'run:alpha', 'ready', 0, 10, 1)",
        [],
    )
    .expect("smuggle negative submission");
    drop(raw);

    let reopened = RunIndex::open(private.path()).expect("reopen");
    let error = reopened
        .by_run_id("run:alpha")
        .expect_err("identity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("submission_id"));
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[test]
fn the_index_refuses_to_grow_past_its_capacity() {
    let private = PrivateIndex::new();
    let mut index = RunIndex::open_with_capacity(private.path(), 2).expect("open index");
    index.register(entry(1, "run:alpha")).expect("register");
    index.register(entry(2, "run:beta")).expect("register");

    let error = index
        .register(entry(3, "run:gamma"))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "index_full");
    assert!(error.to_string().contains("capacity of 2"));
    assert_eq!(index.entry_count().expect("count"), 2);

    // A full index still advances and still reads: neither adds a row, and
    // nothing here evicts to make room.
    index
        .advance_state(advance(1, 1, RunSpoolState::Running, 1))
        .expect("a full index still advances");
    assert_eq!(index.page(0, 10).expect("page").entries.len(), 2);
    assert_eq!(
        index
            .register(entry(4, "run:delta"))
            .expect_err("capacity refusal")
            .category(),
        "index_full"
    );
}

// ---------------------------------------------------------------------------
// Anti-drift
// ---------------------------------------------------------------------------

/// The six spellings are the wire contract, pinned by literal.
///
/// `automonique_runner::spool::RunState` is the authority: its `as_str` renders
/// these exact words into the runner's status file, and its `state_from_events`
/// is what discriminates the four terminal ones out of a terminal event's
/// payload. This crate does not depend on the runner, so the pin is a literal
/// one and deliberately independent of the pin
/// `automonique_protocol::runs_api::RunState` carries for the wire side —
/// a rename has to break both, in two crates, before it can land.
#[test]
fn the_six_state_spellings_match_the_runner_spool() {
    assert_eq!(
        RunSpoolState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect::<Vec<_>>(),
        vec![
            "ready",
            "running",
            "completed",
            "failed",
            "cancelled",
            "timed_out",
        ]
    );

    for state in RunSpoolState::ALL {
        assert_eq!(RunSpoolState::from_spelling(state.as_str()), Some(state));
        assert_eq!(state.to_string(), state.as_str());
    }
    assert_eq!(RunSpoolState::from_spelling("timedout"), None);
    assert_eq!(RunSpoolState::from_spelling("TIMED_OUT"), None);
    assert_eq!(RunSpoolState::from_spelling("aborted"), None);

    // The four the spool's terminal-event payload discriminates into.
    let terminal: Vec<&str> = RunSpoolState::ALL
        .iter()
        .filter(|state| state.is_terminal())
        .map(|state| state.as_str())
        .collect();
    assert_eq!(
        terminal,
        vec!["completed", "failed", "cancelled", "timed_out"]
    );
}

/// The stored column admits exactly the six spellings and nothing else.
#[test]
fn the_stored_vocabulary_is_closed_to_anything_else() {
    let (private, mut index) = index();
    index.register(entry(1, "run:alpha")).expect("register");
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    for spelling in ["", "READY", "timedout", "succeeded", "accepted"] {
        raw.execute(
            "UPDATE run_index SET spool_state = ?1 WHERE submission_id = 1",
            params![spelling],
        )
        .expect_err("the column refuses a spelling outside the vocabulary");
    }
    for state in RunSpoolState::ALL {
        // `ready` is the row's current state; the others need the sequence to
        // move with them, which the binding CHECK enforces.
        let sequence = i64::from(state != RunSpoolState::Ready);
        raw.execute(
            "UPDATE run_index SET spool_state = ?1, last_sequence = ?2 WHERE submission_id = 1",
            params![state.as_str(), sequence],
        )
        .expect("the column admits every spelling this build defines");
    }
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: the ready binding has no nullable side
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, which is only a
// hazard where a CHECK can be handed a NULL. Every column this table's CHECKs
// speak about is `NOT NULL`, so none of them ever can be, and this test is what
// keeps that true: it drives a NULL at each of them through a raw connection and
// watches the column refuse it before the CHECK is ever consulted.
// ---------------------------------------------------------------------------

#[test]
fn no_nullable_column_reaches_a_check_in_this_table() {
    let (private, index) = index();
    drop(index);

    let raw = Connection::open(private.path()).expect("raw write");
    let entry = |submission_id: &str, coupled: &str| {
        format!(
            "INSERT INTO run_index
                 (submission_id, run_id, updated_at_ms, revision,
                  spool_state, last_sequence)
             VALUES ({submission_id}, 'run:alpha', 0, 1, {coupled})"
        )
    };

    for (what, statement) in [
        // A NULL on either side of the binding is refused by the column, so the
        // binding is never asked a question it would answer with NULL.
        ("a stateless entry", entry("1", "NULL, 0")),
        ("a sequenceless entry", entry("1", "'ready', NULL")),
        (
            "an entry belonging to no submission",
            entry("NULL", "'ready', 0"),
        ),
        // And the binding itself bites on the values that do reach it.
        ("a ready entry past sequence zero", entry("1", "'ready', 5")),
        (
            "a running entry still at sequence zero",
            entry("1", "'running', 0"),
        ),
        ("a submission identity below one", entry("0", "'ready', 0")),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: both legal pairings still land.
    raw.execute(&entry("1", "'ready', 0"), [])
        .expect("a fresh entry sits at ready and sequence zero");
    raw.execute(&entry("2", "'running', 5"), [])
        .expect("a started entry carries the sequence it reached");
}
