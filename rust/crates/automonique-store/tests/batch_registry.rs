// SPDX-License-Identifier: Elastic-2.0

//! Durable batch registry invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the registry and
//! reopen the file: an in-memory registry cannot pass them, which is the whole
//! reason this module exists.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.
//!
//! The atomicity test installs a `BEFORE INSERT` trigger that aborts the *last*
//! member row, the technique `tests/provider_journal.rs` and `tests/store.rs`
//! use, then reopens the file to prove nothing durable survived the refusal.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::batch_registry::{
    BATCH_REGISTRY_SCHEMA_VERSION, BatchRegistration, BatchRegistry, ConcurrencyKind,
    ConcurrencyPolicy, MAX_BATCH_ID_BYTES, MAX_BATCH_LABEL_BYTES, MAX_BATCH_MEMBERS,
    MAX_BATCH_PAGE, MAX_BATCHES, MAX_MEMBER_KEY_BYTES, MemberAdvance, MemberProgress,
};
use automonique_store::run_index::RunSpoolState;
use rusqlite::Connection;
use tempfile::TempDir;

struct PrivateRegistry {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateRegistry {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("batches.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn registry() -> (PrivateRegistry, BatchRegistry) {
    let private = PrivateRegistry::new();
    let opened = BatchRegistry::open(private.path()).expect("open registry");
    (private, opened)
}

const READY: MemberProgress = MemberProgress::Run(RunSpoolState::Ready);
const RUNNING: MemberProgress = MemberProgress::Run(RunSpoolState::Running);
const COMPLETED: MemberProgress = MemberProgress::Run(RunSpoolState::Completed);
const FAILED: MemberProgress = MemberProgress::Run(RunSpoolState::Failed);
const CANCELLED: MemberProgress = MemberProgress::Run(RunSpoolState::Cancelled);
const TIMED_OUT: MemberProgress = MemberProgress::Run(RunSpoolState::TimedOut);
const TERMINALS: [MemberProgress; 4] = [COMPLETED, FAILED, CANCELLED, TIMED_OUT];

fn declared<'a>(batch_id: &'a str, members: &'a [&'a str]) -> BatchRegistration<'a> {
    BatchRegistration {
        batch_id,
        label: Some("nightly eval"),
        concurrency: ConcurrencyPolicy::Sequential,
        members,
        now_ms: 1_000,
    }
}

fn advance<'a>(
    batch_id: &'a str,
    member_key: &'a str,
    expected_revision: u64,
    new_progress: MemberProgress,
    last_sequence: u64,
) -> MemberAdvance<'a> {
    MemberAdvance {
        batch_id,
        member_key,
        expected_revision,
        new_progress,
        last_sequence,
        now_ms: 2_000,
    }
}

/// Register a two-member batch and walk its first member to `running`.
fn live_batch(store: &mut BatchRegistry) {
    store
        .register(declared("batch:one", &["sub:a", "sub:b"]))
        .expect("register");
    store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("submitted");
    store
        .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 7))
        .expect("running");
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_registry_stamps_its_schema_version() {
    let (private, store) = registry();
    assert_eq!(store.path(), private.path());
    assert_eq!(store.capacity(), MAX_BATCHES);
    assert_eq!(store.batch_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, BATCH_REGISTRY_SCHEMA_VERSION);

    // Both tables are STRICT, and the members table carries the two uniqueness
    // guarantees a second writer must not be able to break.
    let strict_tables: u32 = raw
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table' AND sql LIKE '%STRICT%'",
            [],
            |row| row.get(0),
        )
        .expect("strict tables");
    assert_eq!(strict_tables, 2);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, store) = registry();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = BatchRegistry::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateRegistry::new();
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

    let error = BatchRegistry::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_registry_file_is_refused() {
    let (private, store) = registry();
    drop(store);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = BatchRegistry::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_group_readable_directory_is_refused() {
    let private = PrivateRegistry::new();
    let directory = private.path().parent().expect("parent");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).expect("loosen dir mode");

    let error = BatchRegistry::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn an_out_of_range_capacity_is_refused() {
    let private = PrivateRegistry::new();
    for capacity in [0, MAX_BATCHES + 1] {
        let error =
            BatchRegistry::open_with_capacity(private.path(), capacity).expect_err("capacity");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[test]
fn register_writes_the_whole_membership_at_unsubmitted_in_ordinal_order() {
    let (_private, mut store) = registry();
    let receipt = store
        .register(BatchRegistration {
            batch_id: "batch:one",
            label: Some("nightly eval"),
            concurrency: ConcurrencyPolicy::bounded_parallel(4).expect("policy"),
            // Deliberately not in sorted order: declaration order is the
            // ordinal order, and nothing here sorts a membership.
            members: &["sub:c", "sub:a", "sub:b"],
            now_ms: 1_000,
        })
        .expect("register");
    assert_eq!(receipt.entry_id, 1);
    assert_eq!(receipt.member_count, 3);
    assert_eq!(receipt.revision, 1);
    assert_eq!(receipt.created_at_ms, 1_000);

    let view = store.batch("batch:one").expect("read").expect("present");
    assert_eq!(view.batch.entry_id, 1);
    assert_eq!(view.batch.batch_id, "batch:one");
    assert_eq!(view.batch.label.as_deref(), Some("nightly eval"));
    assert_eq!(
        view.batch.concurrency,
        ConcurrencyPolicy::BoundedParallel { max_in_flight: 4 }
    );
    assert_eq!(
        view.batch.concurrency.kind(),
        ConcurrencyKind::BoundedParallel
    );
    assert_eq!(view.batch.created_at_ms, 1_000);
    assert_eq!(view.batch.revision, 1);

    let keys: Vec<&str> = view
        .members
        .iter()
        .map(|member| member.member_key.as_str())
        .collect();
    assert_eq!(
        keys,
        ["sub:c", "sub:a", "sub:b"],
        "declaration order is kept"
    );
    for (position, member) in view.members.iter().enumerate() {
        assert_eq!(member.ordinal as usize, position);
        assert_eq!(member.progress, MemberProgress::Unsubmitted);
        assert_eq!(member.last_sequence, 0);
        assert_eq!(member.revision, 1);
        assert_eq!(member.updated_at_ms, 1_000);
        assert_eq!(member.batch_id, "batch:one");
    }
    assert_eq!(
        view.progresses(),
        vec![MemberProgress::Unsubmitted; 3],
        "the slice the protocol's roll_up consumes"
    );

    assert_eq!(store.batch_count().expect("count"), 1);
    assert_eq!(
        store
            .retained_range()
            .expect("range")
            .expect("present")
            .last,
        1
    );
}

#[test]
fn a_label_is_optional_and_a_sequential_batch_declares_no_ceiling() {
    let (private, mut store) = registry();
    store
        .register(BatchRegistration {
            batch_id: "batch:bare",
            label: None,
            concurrency: ConcurrencyPolicy::Sequential,
            members: &["sub:a"],
            now_ms: 5,
        })
        .expect("register");

    let view = store.batch("batch:bare").expect("read").expect("present");
    assert_eq!(view.batch.label, None);
    assert_eq!(view.batch.concurrency, ConcurrencyPolicy::Sequential);
    assert_eq!(view.batch.concurrency.declared_ceiling(), None);
    assert_eq!(view.batch.concurrency.kind(), ConcurrencyKind::Sequential);
    drop(store);

    // Both columns are genuinely NULL, not an empty string and a zero standing
    // in for one: an absent label and an undeclared ceiling are absences.
    let raw = Connection::open(private.path()).expect("raw reopen");
    let (label, ceiling): (Option<String>, Option<i64>) = raw
        .query_row(
            "SELECT label, concurrency_max FROM batches WHERE batch_id = 'batch:bare'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("stored row");
    assert_eq!(label, None);
    assert_eq!(ceiling, None);
}

#[test]
fn a_second_registration_of_one_batch_is_refused_and_writes_nothing() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a", "sub:b"]))
        .expect("register");
    store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("submitted");

    let error = store
        .register(BatchRegistration {
            batch_id: "batch:one",
            label: Some("a second try"),
            concurrency: ConcurrencyPolicy::bounded_parallel(2).expect("policy"),
            members: &["sub:x", "sub:y", "sub:z"],
            now_ms: 9_000,
        })
        .expect_err("duplicate identity");
    assert_eq!(error.category(), "already_registered");
    assert!(error.to_string().contains("2 members"));

    // Not one field of the recorded batch moved, and the advanced member kept
    // the progress a re-registration would have reset.
    let view = store.batch("batch:one").expect("read").expect("present");
    assert_eq!(view.batch.label.as_deref(), Some("nightly eval"));
    assert_eq!(view.batch.concurrency, ConcurrencyPolicy::Sequential);
    assert_eq!(view.members.len(), 2);
    assert_eq!(view.members[0].progress, READY);
    assert_eq!(view.members[0].revision, 2);
    assert!(store.member("batch:one", "sub:x").expect("read").is_none());
    assert_eq!(store.batch_count().expect("count"), 1);
}

#[test]
fn a_repeated_member_key_refuses_the_batch_and_writes_nothing() {
    let (_private, mut store) = registry();
    let error = store
        .register(declared("batch:one", &["sub:a", "sub:b", "sub:a"]))
        .expect_err("repeated key");
    assert_eq!(error.category(), "duplicate_member");
    assert!(error.to_string().contains("sub:a"));

    // The whole batch is discarded, not merely the repeat: no batch row, and no
    // member row for the keys that were fine.
    assert!(store.batch("batch:one").expect("read").is_none());
    assert!(store.member("batch:one", "sub:b").expect("read").is_none());
    assert_eq!(store.batch_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
}

#[test]
fn an_empty_membership_is_refused() {
    let (_private, mut store) = registry();
    let error = store
        .register(declared("batch:empty", &[]))
        .expect_err("empty batch");
    assert_eq!(error.category(), "empty_batch");
    assert_eq!(store.batch_count().expect("count"), 0);
}

#[test]
fn a_membership_at_the_ceiling_is_admitted_and_one_above_it_is_refused() {
    let (_private, mut store) = registry();
    let keys: Vec<String> = (0..=MAX_BATCH_MEMBERS)
        .map(|index| format!("sub:{index}"))
        .collect();
    let borrowed: Vec<&str> = keys.iter().map(String::as_str).collect();

    let error = store
        .register(declared("batch:over", &borrowed))
        .expect_err("over ceiling");
    assert_eq!(error.category(), "too_many_members");
    assert!(error.to_string().contains(&format!("{MAX_BATCH_MEMBERS}")));
    assert_eq!(store.batch_count().expect("count"), 0);

    let receipt = store
        .register(declared("batch:full", &borrowed[..MAX_BATCH_MEMBERS]))
        .expect("maximal batch");
    assert_eq!(receipt.member_count, MAX_BATCH_MEMBERS);
    let view = store.batch("batch:full").expect("read").expect("present");
    assert_eq!(view.members.len(), MAX_BATCH_MEMBERS);
    assert_eq!(
        view.members[MAX_BATCH_MEMBERS - 1].ordinal as usize,
        MAX_BATCH_MEMBERS - 1
    );
}

#[test]
fn an_incoherent_concurrency_ceiling_is_refused_both_ways() {
    let (_private, mut store) = registry();

    // The checked constructor refuses both ends.
    assert_eq!(
        ConcurrencyPolicy::bounded_parallel(0)
            .expect_err("zero ceiling")
            .category(),
        "concurrency_ceiling_zero"
    );
    let unreachable = u32::try_from(MAX_BATCH_MEMBERS + 1).expect("ceiling fits");
    assert_eq!(
        ConcurrencyPolicy::bounded_parallel(unreachable)
            .expect_err("unreachable ceiling")
            .category(),
        "concurrency_ceiling_unreachable"
    );

    // And so does registration, which cannot assume the constructor was used:
    // the variant is publicly constructible, exactly as the protocol's is.
    for (ceiling, category) in [
        (0, "concurrency_ceiling_zero"),
        (unreachable, "concurrency_ceiling_unreachable"),
    ] {
        let error = store
            .register(BatchRegistration {
                concurrency: ConcurrencyPolicy::BoundedParallel {
                    max_in_flight: ceiling,
                },
                ..declared("batch:one", &["sub:a"])
            })
            .expect_err("smuggled ceiling");
        assert_eq!(error.category(), category);
    }
    assert_eq!(store.batch_count().expect("count"), 0);

    // A ceiling exactly at the membership ceiling binds and is admitted.
    let maximal = u32::try_from(MAX_BATCH_MEMBERS).expect("ceiling fits");
    store
        .register(BatchRegistration {
            concurrency: ConcurrencyPolicy::bounded_parallel(maximal).expect("policy"),
            ..declared("batch:one", &["sub:a"])
        })
        .expect("maximal ceiling");
}

#[test]
fn the_stored_concurrency_coupling_refuses_both_halves() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:seq", &["sub:a"]))
        .expect("sequential");
    store
        .register(BatchRegistration {
            concurrency: ConcurrencyPolicy::bounded_parallel(3).expect("policy"),
            ..declared("batch:par", &["sub:a"])
        })
        .expect("bounded parallel");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    // The CHECK stops a second writer outright, both halves of the coupling.
    for statement in [
        "UPDATE batches SET concurrency_max = 2 WHERE batch_id = 'batch:seq'",
        "UPDATE batches SET concurrency_max = NULL WHERE batch_id = 'batch:par'",
    ] {
        raw.execute(statement, [])
            .expect_err("the coupling CHECK refuses it");
    }
    // With the CHECK disabled the rows get in anyway, and the read path is what
    // protects callers from them.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE batches SET concurrency_max = 2 WHERE batch_id = 'batch:seq'",
        [],
    )
    .expect("smuggle a ceiling onto a sequential batch");
    raw.execute(
        "UPDATE batches SET concurrency_max = NULL WHERE batch_id = 'batch:par'",
        [],
    )
    .expect("smuggle a ceiling-less bounded batch");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    for batch_id in ["batch:seq", "batch:par"] {
        let error = reopened.batch(batch_id).expect_err("coupling refusal");
        assert_eq!(error.category(), "corrupt");
        assert!(error.to_string().contains("concurrency_max"));
    }
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt",
        "a listing answers a corrupt table the same way a lookup does"
    );
}

#[test]
fn malformed_fields_are_refused_before_anything_is_written() {
    let (_private, mut store) = registry();
    let long_id = "b".repeat(MAX_BATCH_ID_BYTES + 1);
    let long_label = "l".repeat(MAX_BATCH_LABEL_BYTES + 1);
    let long_key = "k".repeat(MAX_MEMBER_KEY_BYTES + 1);
    let long_key_members = [long_key.as_str()];

    let cases: [(BatchRegistration<'_>, &str); 7] = [
        (declared("", &["sub:a"]), "batch_id"),
        (declared(&long_id, &["sub:a"]), "batch_id"),
        (declared("batch:bad\nid", &["sub:a"]), "batch_id"),
        (
            BatchRegistration {
                label: Some(&long_label),
                ..declared("batch:one", &["sub:a"])
            },
            "label",
        ),
        (declared("batch:one", &[""]), "member_key"),
        (declared("batch:one", &long_key_members), "member_key"),
        (
            BatchRegistration {
                now_ms: -1,
                ..declared("batch:one", &["sub:a"])
            },
            "now_ms",
        ),
    ];
    for (registration, field) in cases {
        let error = store.register(registration).expect_err("field refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(
            error.to_string().contains(field),
            "expected a refusal naming {field}, got {error}"
        );
    }
    assert_eq!(store.batch_count().expect("count"), 0);

    // The exact ceilings are admitted, so the bound is the bound and not one
    // byte short of it.
    store
        .register(BatchRegistration {
            batch_id: &"b".repeat(MAX_BATCH_ID_BYTES),
            label: Some(&"l".repeat(MAX_BATCH_LABEL_BYTES)),
            concurrency: ConcurrencyPolicy::Sequential,
            members: &[&"k".repeat(MAX_MEMBER_KEY_BYTES)],
            now_ms: 0,
        })
        .expect("maximal fields");
}

#[test]
fn registration_is_refused_at_capacity_rather_than_evicting() {
    let private = PrivateRegistry::new();
    let mut store = BatchRegistry::open_with_capacity(private.path(), 2).expect("open");
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("first");
    store
        .register(declared("batch:two", &["sub:a"]))
        .expect("second");

    let error = store
        .register(declared("batch:three", &["sub:a"]))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "registry_full");
    assert!(error.to_string().contains("capacity of 2"));

    // The two recorded batches are untouched: nothing evicted to make room.
    assert_eq!(store.batch_count().expect("count"), 2);
    assert!(store.batch("batch:one").expect("read").is_some());
    assert!(store.batch("batch:two").expect("read").is_some());
    assert!(store.batch("batch:three").expect("read").is_none());

    // Advances and reads keep working at capacity, because neither adds a
    // batch.
    store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("advance at capacity");
}

// ---------------------------------------------------------------------------
// Atomicity
// ---------------------------------------------------------------------------

#[test]
fn a_refused_last_member_row_discards_the_whole_batch() {
    let private = PrivateRegistry::new();
    let store = BatchRegistry::open(private.path()).expect("open");
    drop(store);

    // Abort the *last* member insert of a three-member batch. The two before it
    // and the batch row itself have already been written inside the
    // transaction, which is exactly what must not survive.
    let raw = Connection::open(private.path()).expect("fault connection");
    raw.execute_batch(
        "CREATE TRIGGER fail_last_batch_member
         BEFORE INSERT ON batch_members
         WHEN NEW.member_key = 'sub:c'
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .expect("fault trigger");
    drop(raw);

    let mut store = BatchRegistry::open(private.path()).expect("reopen");
    let error = store
        .register(declared("batch:one", &["sub:a", "sub:b", "sub:c"]))
        .expect_err("fault rolls back");
    assert_eq!(error.category(), "sqlite");

    // Nothing from the refused registration landed, on this handle...
    assert!(store.batch("batch:one").expect("read").is_none());
    assert!(store.member("batch:one", "sub:a").expect("read").is_none());
    assert!(store.member("batch:one", "sub:b").expect("read").is_none());
    assert_eq!(store.batch_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
    drop(store);

    // ...nor in the file, which is the only claim that outlives the process.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute_batch("DROP TRIGGER fail_last_batch_member;")
        .expect("drop trigger");
    let batches: i64 = raw
        .query_row("SELECT count(*) FROM batches", [], |row| row.get(0))
        .expect("batch rows");
    let members: i64 = raw
        .query_row("SELECT count(*) FROM batch_members", [], |row| row.get(0))
        .expect("member rows");
    assert_eq!((batches, members), (0, 0), "nothing durable survived");
    drop(raw);

    // With the fault removed the same registration succeeds whole, so the
    // refusal above left no half-written state behind it either.
    let mut reopened = BatchRegistry::open(private.path()).expect("reopen");
    reopened
        .register(declared("batch:one", &["sub:a", "sub:b", "sub:c"]))
        .expect("clean registration");
    assert_eq!(
        reopened
            .batch("batch:one")
            .expect("read")
            .expect("present")
            .members
            .len(),
        3
    );
}

// ---------------------------------------------------------------------------
// The member lattice
// ---------------------------------------------------------------------------

#[test]
fn a_member_walks_unsubmitted_to_ready_to_running_to_terminal() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");

    let submitted = store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("submitted");
    assert_eq!(submitted.progress, READY);
    assert_eq!(submitted.last_sequence, 0);
    assert_eq!(submitted.revision, 2);
    assert_eq!(submitted.ordinal, 0);

    let started = store
        .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 1))
        .expect("running");
    assert_eq!(started.revision, 3);
    assert_eq!(started.last_sequence, 1);

    // A re-report of `running` is admitted at an equal sequence: a writer may
    // observe a run that has not moved.
    let unmoved = store
        .advance_member(advance("batch:one", "sub:a", 3, RUNNING, 1))
        .expect("still running");
    assert_eq!(unmoved.revision, 4);
    let moved = store
        .advance_member(advance("batch:one", "sub:a", 4, RUNNING, 9))
        .expect("running on");
    assert_eq!(moved.last_sequence, 9);

    let done = store
        .advance_member(advance("batch:one", "sub:a", 5, COMPLETED, 10))
        .expect("completed");
    assert_eq!(done.progress, COMPLETED);
    assert_eq!(done.revision, 6);

    let member = store
        .member("batch:one", "sub:a")
        .expect("read")
        .expect("present");
    assert_eq!(member.progress, COMPLETED);
    assert_eq!(member.last_sequence, 10);
    assert_eq!(member.revision, 6);
    assert_eq!(member.updated_at_ms, 2_000);
}

#[test]
fn every_terminal_progress_is_reachable_from_running() {
    for terminal in TERMINALS {
        let (_private, mut store) = registry();
        store
            .register(declared("batch:one", &["sub:a"]))
            .expect("register");
        store
            .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
            .expect("submitted");
        store
            .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 1))
            .expect("running");
        let receipt = store
            .advance_member(advance("batch:one", "sub:a", 3, terminal, 2))
            .expect("terminal");
        assert_eq!(receipt.progress, terminal);
        assert!(terminal.is_terminal());
    }
}

#[test]
fn illegal_transitions_are_refused_and_change_nothing() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");

    // From `unsubmitted`, only `ready` is admitted: a member cannot start
    // running, or end, without a submission having been recorded.
    for illegal in [RUNNING, COMPLETED, FAILED, CANCELLED, TIMED_OUT] {
        let sequence = u64::from(!illegal.has_not_started());
        let error = store
            .advance_member(advance("batch:one", "sub:a", 1, illegal, sequence))
            .expect_err("illegal from unsubmitted");
        assert_eq!(error.category(), "illegal_transition");
        assert!(error.to_string().contains("unsubmitted"));
    }
    // Nor to itself: `unsubmitted -> unsubmitted` would credit a submission
    // nobody made and bump a revision for nothing.
    assert_eq!(
        store
            .advance_member(advance(
                "batch:one",
                "sub:a",
                1,
                MemberProgress::Unsubmitted,
                0
            ))
            .expect_err("unsubmitted repeat")
            .category(),
        "illegal_transition"
    );
    let member = store
        .member("batch:one", "sub:a")
        .expect("read")
        .expect("present");
    assert_eq!(member.progress, MemberProgress::Unsubmitted);
    assert_eq!(member.revision, 1, "a refusal bumps no revision");

    // From `ready`: only `running`. The `ready -> terminal` jump the run index
    // refuses is refused here for the same reason, and `ready` never repeats.
    store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("submitted");
    for illegal in [MemberProgress::Unsubmitted, READY] {
        assert_eq!(
            store
                .advance_member(advance("batch:one", "sub:a", 2, illegal, 0))
                .expect_err("illegal from ready")
                .category(),
            "illegal_transition"
        );
    }
    for terminal in TERMINALS {
        assert_eq!(
            store
                .advance_member(advance("batch:one", "sub:a", 2, terminal, 1))
                .expect_err("ready may not jump to a terminal")
                .category(),
            "illegal_transition"
        );
    }

    // From `running`: never back to `ready` or `unsubmitted`.
    store
        .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 4))
        .expect("running");
    for illegal in [MemberProgress::Unsubmitted, READY] {
        assert_eq!(
            store
                .advance_member(advance("batch:one", "sub:a", 3, illegal, 0))
                .expect_err("no way back")
                .category(),
            "illegal_transition"
        );
    }
    assert_eq!(
        store
            .member("batch:one", "sub:a")
            .expect("read")
            .expect("present")
            .revision,
        3,
        "three accepted writes, and not one refusal among them"
    );
}

#[test]
fn a_terminal_member_leaves_its_state_for_nothing() {
    for terminal in TERMINALS {
        let (_private, mut store) = registry();
        store
            .register(declared("batch:one", &["sub:a"]))
            .expect("register");
        store
            .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
            .expect("submitted");
        store
            .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 1))
            .expect("running");
        store
            .advance_member(advance("batch:one", "sub:a", 3, terminal, 2))
            .expect("terminal");

        for destination in MemberProgress::ALL {
            let sequence = if destination.has_not_started() { 0 } else { 99 };
            let error = store
                .advance_member(advance("batch:one", "sub:a", 4, destination, sequence))
                .expect_err("terminal is terminal");
            assert_eq!(
                error.category(),
                "illegal_transition",
                "{terminal} must not become {destination}"
            );
        }
        let member = store
            .member("batch:one", "sub:a")
            .expect("read")
            .expect("present");
        assert_eq!(member.progress, terminal);
        assert_eq!(member.last_sequence, 2);
        assert_eq!(member.revision, 4);
    }
}

#[test]
fn a_backward_sequence_is_refused_for_a_repeat_and_for_a_change() {
    let (_private, mut store) = registry();
    live_batch(&mut store);

    // A re-report of the same state at a lower sequence.
    let error = store
        .advance_member(advance("batch:one", "sub:a", 3, RUNNING, 6))
        .expect_err("sequence regression");
    assert_eq!(error.category(), "sequence_regression");
    assert!(error.to_string().contains('7'));

    // A state change at an equal sequence: the event that changed the state is
    // itself a new event, so it must move.
    assert_eq!(
        store
            .advance_member(advance("batch:one", "sub:a", 3, COMPLETED, 7))
            .expect_err("a change needs a strictly greater sequence")
            .category(),
        "sequence_regression"
    );

    let member = store
        .member("batch:one", "sub:a")
        .expect("read")
        .expect("present");
    assert_eq!(member.progress, RUNNING);
    assert_eq!(member.last_sequence, 7);
    assert_eq!(member.revision, 3);

    // A strictly greater sequence is admitted, which proves the two refusals
    // above were about the sequence and not about the transition.
    store
        .advance_member(advance("batch:one", "sub:a", 3, COMPLETED, 8))
        .expect("completed");
}

#[test]
fn a_sequence_that_disagrees_with_its_progress_is_refused() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");

    // `unsubmitted` and `ready` mean zero spool events, so neither admits a
    // sequence; every other progress means at least one, so none admits zero.
    for (progress, sequence) in [
        (MemberProgress::Unsubmitted, 1),
        (READY, 1),
        (RUNNING, 0),
        (COMPLETED, 0),
        (FAILED, 0),
        (CANCELLED, 0),
        (TIMED_OUT, 0),
    ] {
        let error = store
            .advance_member(advance("batch:one", "sub:a", 1, progress, sequence))
            .expect_err("coupling refusal");
        assert_eq!(
            error.category(),
            "sequence_coupling",
            "{progress} must not carry last_sequence {sequence}"
        );
        assert!(error.to_string().contains(progress.as_str()));
    }

    // The coupling is a property of the request alone, so it is refused ahead
    // of a revision that does not match either.
    assert_eq!(
        store
            .advance_member(advance("batch:one", "sub:a", 99, READY, 5))
            .expect_err("coupling first")
            .category(),
        "sequence_coupling"
    );
    assert_eq!(
        store
            .member("batch:one", "sub:a")
            .expect("read")
            .expect("present")
            .revision,
        1
    );
}

#[test]
fn an_advance_is_revision_checked() {
    let (_private, mut store) = registry();
    live_batch(&mut store);

    for stale in [1, 2, 4] {
        let error = store
            .advance_member(advance("batch:one", "sub:a", stale, COMPLETED, 8))
            .expect_err("revision refusal");
        assert_eq!(error.category(), "revision_mismatch");
        assert!(error.to_string().contains("durable revision is 3"));
    }
    assert_eq!(
        store
            .advance_member(advance("batch:one", "sub:a", 0, COMPLETED, 8))
            .expect_err("zero revision")
            .category(),
        "invalid_field"
    );

    let member = store
        .member("batch:one", "sub:a")
        .expect("read")
        .expect("present");
    assert_eq!(member.progress, RUNNING);
    assert_eq!(member.revision, 3);

    store
        .advance_member(advance("batch:one", "sub:a", 3, COMPLETED, 8))
        .expect("the exact revision is accepted");
}

#[test]
fn an_advance_touches_one_member_of_one_batch_and_nothing_else() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a", "sub:b", "sub:c"]))
        .expect("first batch");
    // The same member key in another batch is another row entirely.
    store
        .register(declared("batch:two", &["sub:a"]))
        .expect("second batch");

    store
        .advance_member(advance("batch:one", "sub:b", 1, READY, 0))
        .expect("submitted");
    store
        .advance_member(advance("batch:one", "sub:b", 2, RUNNING, 3))
        .expect("running");

    let view = store.batch("batch:one").expect("read").expect("present");
    assert_eq!(view.members[1].progress, RUNNING);
    for sibling in [0, 2] {
        let member = &view.members[sibling];
        assert_eq!(member.progress, MemberProgress::Unsubmitted);
        assert_eq!(member.last_sequence, 0);
        assert_eq!(member.revision, 1);
        assert_eq!(
            member.updated_at_ms, 1_000,
            "a sibling's instant is untouched"
        );
    }
    let elsewhere = store
        .member("batch:two", "sub:a")
        .expect("read")
        .expect("present");
    assert_eq!(elsewhere.progress, MemberProgress::Unsubmitted);
    assert_eq!(elsewhere.revision, 1);
    assert_ne!(elsewhere.member_entry_id, view.members[0].member_entry_id);

    // The batch row itself never moves: nothing here rewrites a batch.
    assert_eq!(view.batch.revision, 1);
    assert_eq!(view.batch.created_at_ms, 1_000);
}

#[test]
fn an_advance_names_which_of_the_two_identities_is_unknown() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");

    let missing_batch = store
        .advance_member(advance("batch:absent", "sub:a", 1, READY, 0))
        .expect_err("unknown batch");
    assert_eq!(missing_batch.category(), "not_found");
    assert!(missing_batch.to_string().contains("batch"));

    let missing_member = store
        .advance_member(advance("batch:one", "sub:absent", 1, READY, 0))
        .expect_err("unknown member");
    assert_eq!(missing_member.category(), "not_found");
    assert!(missing_member.to_string().contains("batch member"));

    assert!(store.batch("batch:absent").expect("read").is_none());
    assert!(
        store
            .member("batch:one", "sub:absent")
            .expect("read")
            .is_none()
    );
    assert!(
        store
            .member("batch:absent", "sub:a")
            .expect("read")
            .is_none()
    );
}

#[test]
fn malformed_advance_fields_are_refused() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    let long_key = "k".repeat(MAX_MEMBER_KEY_BYTES + 1);

    let cases: [(MemberAdvance<'_>, &str); 4] = [
        (advance("", "sub:a", 1, READY, 0), "batch_id"),
        (advance("batch:one", "", 1, READY, 0), "member_key"),
        (advance("batch:one", &long_key, 1, READY, 0), "member_key"),
        (
            MemberAdvance {
                now_ms: -5,
                ..advance("batch:one", "sub:a", 1, READY, 0)
            },
            "now_ms",
        ),
    ];
    for (request, field) in cases {
        let error = store.advance_member(request).expect_err("field refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains(field));
    }
}

// ---------------------------------------------------------------------------
// Reads, pagination and persistence
// ---------------------------------------------------------------------------

#[test]
fn a_page_is_bounded_ordered_and_cursor_checked() {
    let (_private, mut store) = registry();
    for index in 1..=5 {
        store
            .register(declared(&format!("batch:{index}"), &["sub:a"]))
            .expect("register");
    }

    for limit in [0, MAX_BATCH_PAGE + 1] {
        let error = store.page(0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));
    }

    let first = store.page(0, 2).expect("first page");
    let ids: Vec<&str> = first
        .entries
        .iter()
        .map(|batch| batch.batch_id.as_str())
        .collect();
    assert_eq!(ids, ["batch:1", "batch:2"]);
    assert_eq!(first.next_cursor, Some(2));

    let second = store.page(2, 2).expect("second page");
    assert_eq!(second.next_cursor, Some(4));
    let last = store.page(4, 2).expect("last page");
    assert_eq!(last.entries.len(), 1);
    assert_eq!(
        last.next_cursor, None,
        "an exhausted listing is not one that merely filled its page"
    );

    // A cursor at the highest recorded row is an empty page; one above it is a
    // refusal, because those are different answers.
    let empty = store.page(5, 2).expect("cursor at the end");
    assert!(empty.entries.is_empty());
    assert_eq!(empty.next_cursor, None);
    let error = store.page(6, 2).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains("retained entry_id 5"));

    assert_eq!(
        store
            .retained_range()
            .expect("range")
            .expect("present")
            .first,
        1
    );
    assert_eq!(
        store
            .retained_range()
            .expect("range")
            .expect("present")
            .last,
        5
    );
}

#[test]
fn a_page_of_batches_carries_no_members() {
    let (_private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a", "sub:b"]))
        .expect("register");

    // The page type has no member field at all; the membership comes from the
    // per-batch read, which is the shape the module documents.
    let page = store.page(0, 10).expect("page");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].batch_id, "batch:one");
    assert_eq!(
        store
            .batch(&page.entries[0].batch_id)
            .expect("read")
            .expect("present")
            .members
            .len(),
        2
    );
}

#[test]
fn every_row_survives_a_reopen() {
    let private = PrivateRegistry::new();
    let mut store = BatchRegistry::open(private.path()).expect("open");
    store
        .register(BatchRegistration {
            batch_id: "batch:one",
            label: None,
            concurrency: ConcurrencyPolicy::bounded_parallel(2).expect("policy"),
            members: &["sub:a", "sub:b"],
            now_ms: 11,
        })
        .expect("register");
    store
        .advance_member(advance("batch:one", "sub:b", 1, READY, 0))
        .expect("submitted");
    store
        .advance_member(advance("batch:one", "sub:b", 2, RUNNING, 4))
        .expect("running");
    drop(store);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let view = reopened.batch("batch:one").expect("read").expect("present");
    assert_eq!(
        view.batch.concurrency,
        ConcurrencyPolicy::BoundedParallel { max_in_flight: 2 }
    );
    assert_eq!(view.batch.label, None);
    assert_eq!(view.batch.created_at_ms, 11);
    assert_eq!(view.members[0].progress, MemberProgress::Unsubmitted);
    assert_eq!(view.members[1].progress, RUNNING);
    assert_eq!(view.members[1].last_sequence, 4);
    assert_eq!(view.members[1].revision, 3);
    assert_eq!(
        view.progresses(),
        vec![MemberProgress::Unsubmitted, RUNNING]
    );

    // WAL and foreign keys survive the reopen too.
    let journal: String = reopened
        .page(0, 1)
        .map(|_| String::new())
        .map(|_| "checked".to_owned())
        .expect("read after reopen");
    assert_eq!(journal, "checked");
    drop(reopened);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let mode: String = raw
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert!(mode.eq_ignore_ascii_case("wal"));
}

#[test]
fn a_member_row_cannot_outlive_the_batch_it_names() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    // The foreign key is what stops a member naming a batch that is not there.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "foreign_keys", true)
        .expect("enable foreign keys");
    raw.execute("DELETE FROM batches WHERE batch_id = 'batch:one'", [])
        .expect_err("a batch with members cannot be deleted");
    raw.execute(
        "INSERT INTO batch_members
         (batch_id, member_key, ordinal, progress, last_sequence, updated_at_ms, revision)
         VALUES ('batch:absent', 'sub:a', 0, 'unsubmitted', 0, 1, 1)",
        [],
    )
    .expect_err("a member of no batch is refused");
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_progress_outside_the_vocabulary_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE batch_members SET progress = 'submitted' WHERE member_key = 'sub:a'",
        [],
    )
    .expect("smuggle a progress");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("progress"));
    assert_eq!(
        reopened
            .member("batch:one", "sub:a")
            .expect_err("lookup refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_sequence_that_contradicts_its_progress_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a", "sub:b"]))
        .expect("register");
    store
        .advance_member(advance("batch:one", "sub:a", 1, READY, 0))
        .expect("submitted");
    store
        .advance_member(advance("batch:one", "sub:a", 2, RUNNING, 3))
        .expect("running");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    // Both halves of the coupling are refused by the CHECK first.
    for statement in [
        "UPDATE batch_members SET last_sequence = 5 WHERE member_key = 'sub:b'",
        "UPDATE batch_members SET last_sequence = 0 WHERE member_key = 'sub:a'",
    ] {
        raw.execute(statement, [])
            .expect_err("the coupling CHECK refuses it");
    }
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE batch_members SET last_sequence = 5 WHERE member_key = 'sub:b'",
        [],
    )
    .expect("smuggle events onto an unsubmitted member");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("coupling refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("last_sequence"));
}

#[test]
fn an_unsubmitted_member_above_revision_one_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    // Registration is the only writer of `unsubmitted` and no transition
    // returns to it, so a higher revision is a row this API never produced.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute(
        "UPDATE batch_members SET revision = 2 WHERE member_key = 'sub:a'",
        [],
    )
    .expect("smuggle a revision");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn an_ordinal_gap_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a", "sub:b", "sub:c"]))
        .expect("register");
    drop(store);

    // A batch missing its middle position is a membership nobody declared, and
    // a caller that rolled it up would report a batch state over the wrong set.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute("DELETE FROM batch_members WHERE member_key = 'sub:b'", [])
        .expect("open a gap");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("ordinal refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("ordinal"));

    // A membership that starts above zero is refused the same way.
    drop(reopened);
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute("DELETE FROM batch_members WHERE member_key = 'sub:a'", [])
        .expect("drop the first position");
    drop(raw);
    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    assert_eq!(
        reopened
            .batch("batch:one")
            .expect_err("ordinal refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_batch_with_no_members_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute("DELETE FROM batch_members", [])
        .expect("empty the membership");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("membership refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("batch_members"));

    // The batch row on its own still reads through the listing, which is what
    // makes the refusal above about the membership and not about the batch.
    assert_eq!(reopened.page(0, 10).expect("page").entries.len(), 1);
}

#[test]
fn a_batch_above_revision_one_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    // Nothing in this release moves a batch row, so a second revision is a row
    // this API could not have written.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute("UPDATE batches SET revision = 2", [])
        .expect("smuggle a revision");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn a_malformed_stored_identifier_is_refused_on_read() {
    let (private, mut store) = registry();
    store
        .register(declared("batch:one", &["sub:a"]))
        .expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute("UPDATE batches SET label = ''", [])
        .expect("smuggle an empty label");
    drop(raw);

    let reopened = BatchRegistry::open(private.path()).expect("reopen");
    let error = reopened.batch("batch:one").expect_err("label refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("label"));
}

// ---------------------------------------------------------------------------
// Spellings pinned by literal
// ---------------------------------------------------------------------------

/// The stored vocabularies, pinned by literal against
/// `automonique_protocol::batch_runner`, which this crate cannot import.
///
/// `ConcurrencyKind` is that module's `ConcurrencyKind`, `MemberProgress` is its
/// `MemberProgress` — `Unsubmitted` beside the six `RunState` spellings, which
/// arrive here through `run_index::RunSpoolState` — and the four ceilings are
/// its `MAX_BATCH_MEMBERS`, `MAX_BATCH_ID_BYTES`, `MAX_BATCH_LABEL_BYTES` and
/// `MAX_BATCH_MEMBER_KEY_BYTES`. A rename or a renumber there has to break this
/// test as well as the module, which is the whole point of pinning it twice.
#[test]
fn the_protocol_vocabulary_is_pinned_by_literal() {
    assert_eq!(
        ConcurrencyKind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        ["sequential", "bounded_parallel"]
    );
    assert_eq!(
        MemberProgress::ALL
            .iter()
            .map(|progress| progress.as_str())
            .collect::<Vec<_>>(),
        [
            "unsubmitted",
            "ready",
            "running",
            "completed",
            "failed",
            "cancelled",
            "timed_out"
        ]
    );
    for progress in MemberProgress::ALL {
        assert_eq!(
            MemberProgress::from_spelling(progress.as_str()),
            Some(progress)
        );
        assert_eq!(progress.to_string(), progress.as_str());
    }
    assert_eq!(MemberProgress::from_spelling("submitted"), None);
    assert_eq!(ConcurrencyKind::from_spelling("unbounded"), None);

    // `unsubmitted` is the one word the run vocabulary has no spelling for, and
    // the six that follow are exactly that vocabulary.
    assert_eq!(MemberProgress::Unsubmitted.run_state(), None);
    assert_eq!(
        MemberProgress::ALL[1..]
            .iter()
            .map(|progress| progress.run_state().expect("a run state"))
            .collect::<Vec<_>>(),
        RunSpoolState::ALL.to_vec()
    );
    assert_eq!(RunSpoolState::from_spelling("unsubmitted"), None);

    assert_eq!(MAX_BATCH_MEMBERS, 256);
    assert_eq!(MAX_BATCH_ID_BYTES, 128);
    assert_eq!(MAX_BATCH_LABEL_BYTES, 128);
    assert_eq!(MAX_MEMBER_KEY_BYTES, 128);
}

/// The whole lattice as a truth table, so an edge cannot be quietly added.
#[test]
fn the_member_lattice_is_exactly_five_edges() {
    let expected = [
        (MemberProgress::Unsubmitted, READY),
        (READY, RUNNING),
        (RUNNING, RUNNING),
        (RUNNING, COMPLETED),
        (RUNNING, FAILED),
        (RUNNING, CANCELLED),
        (RUNNING, TIMED_OUT),
    ];
    for from in MemberProgress::ALL {
        for to in MemberProgress::ALL {
            assert_eq!(
                from.may_advance_to(to),
                expected.contains(&(from, to)),
                "{from} -> {to}"
            );
        }
    }

    // The two derived predicates the coupling and the rollup rest on.
    for progress in MemberProgress::ALL {
        assert_eq!(
            progress.has_not_started(),
            matches!(progress, MemberProgress::Unsubmitted) || progress == READY
        );
        assert_eq!(progress.is_terminal(), TERMINALS.contains(&progress));
    }
    assert!(
        !MemberProgress::Unsubmitted.is_terminal(),
        "a member that was never submitted has not finished, it has not begun"
    );
}
