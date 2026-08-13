// SPDX-License-Identifier: Elastic-2.0

//! Durable generation audit invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the audit and reopen
//! the file: an in-memory audit cannot pass them, which is the whole reason this
//! module exists.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::generation_audit::{
    EndKind, GENERATION_AUDIT_SCHEMA_VERSION, GenerationAudit, MAX_HISTORY_PAGE,
    MAX_IDENTIFIER_BYTES, MAX_TENURE_RECORDS, SelfEndKind, Succession, TenureEnding, TenureOpening,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

struct PrivateAudit {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateAudit {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("generation-audit.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn audit() -> (PrivateAudit, GenerationAudit) {
    let private = PrivateAudit::new();
    let opened = GenerationAudit::open(private.path()).expect("open audit");
    (private, opened)
}

fn opening<'a>(holder_id: &'a str, lease_epoch: u64, started_at_ms: i64) -> TenureOpening<'a> {
    TenureOpening {
        generation_id: "generation:alpha",
        holder_id,
        lease_epoch,
        started_at_ms,
    }
}

fn succession<'a>(
    holder_id: &'a str,
    lease_epoch: u64,
    started_at_ms: i64,
    observed_at_ms: i64,
) -> Succession<'a> {
    Succession {
        opening: opening(holder_id, lease_epoch, started_at_ms),
        observed_at_ms,
    }
}

fn ending<'a>(
    holder_id: &'a str,
    lease_epoch: u64,
    expected_revision: u64,
    ended_at_ms: i64,
    end_kind: SelfEndKind,
) -> TenureEnding<'a> {
    TenureEnding {
        generation_id: "generation:alpha",
        holder_id,
        lease_epoch,
        expected_revision,
        ended_at_ms,
        end_kind,
    }
}

fn full_history(audit: &GenerationAudit) -> (usize, usize) {
    let history = audit
        .history("generation:alpha", 0, MAX_HISTORY_PAGE)
        .expect("history");
    (history.tenures.len(), history.handoffs.len())
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_audit_stamps_its_schema_version() {
    let (private, audit) = audit();
    assert_eq!(audit.path(), private.path());
    assert_eq!(audit.capacity(), MAX_TENURE_RECORDS);
    assert_eq!(audit.tenure_count().expect("count"), 0);
    assert_eq!(audit.handoff_count().expect("count"), 0);
    drop(audit);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, GENERATION_AUDIT_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, audit) = audit();
    drop(audit);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = GenerationAudit::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateAudit::new();
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

    let error = GenerationAudit::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_audit_file_is_refused() {
    let (private, audit) = audit();
    drop(audit);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = GenerationAudit::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_group_readable_directory_is_refused() {
    let private = PrivateAudit::new();
    let directory = private.path().parent().expect("parent");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).expect("loosen dir mode");

    let error = GenerationAudit::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn an_out_of_range_capacity_is_refused() {
    let private = PrivateAudit::new();
    for capacity in [0, MAX_TENURE_RECORDS + 1] {
        let error = GenerationAudit::open_with_capacity(private.path(), capacity)
            .expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn a_clean_handoff_records_open_release_and_the_successors_observation() {
    let (_private, mut audit) = audit();

    let first = audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open first tenure");
    assert_eq!(first.lease_epoch, 1);
    assert_eq!(first.revision, 1);
    assert!(first.is_open());
    assert_eq!(first.ended_at_ms, None);
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        Some(first.clone())
    );

    // The holder closes its own tenure. Only this half is a self-claim.
    let released = audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Released))
        .expect("release own tenure");
    assert_eq!(released.end_kind, Some(EndKind::Released));
    assert_eq!(released.ended_at_ms, Some(2_000));
    assert_eq!(released.revision, 2);
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        None,
        "a closed tenure leaves no open record"
    );

    // The successor records what it found; it does not get to name the kind.
    let succeeded = audit
        .succeed_tenure(succession("holder:two", 2, 2_100, 2_200))
        .expect("succeed");
    assert_eq!(succeeded.handoff.predecessor_end_kind, EndKind::Released);
    assert_eq!(succeeded.handoff.predecessor_epoch, 1);
    assert_eq!(succeeded.handoff.successor_epoch, 2);
    assert_eq!(succeeded.handoff.observed_at_ms, 2_200);
    assert_eq!(succeeded.handoff.predecessor_tenure_id, first.tenure_id);
    assert_eq!(
        succeeded.handoff.successor_tenure_id,
        succeeded.tenure.tenure_id
    );
    assert!(succeeded.tenure.is_open());
    assert_eq!(succeeded.tenure.revision, 1);

    // The predecessor's row is byte-for-byte what its own holder wrote: a
    // succession over a terminal tenure rewrites nothing.
    assert_eq!(succeeded.predecessor, released);
    assert_eq!(
        audit.tenure("generation:alpha", 1).expect("read first"),
        Some(released)
    );

    let history = audit
        .history("generation:alpha", 0, MAX_HISTORY_PAGE)
        .expect("history");
    assert_eq!(history.tenures.len(), 2);
    assert_eq!(history.tenures[0].lease_epoch, 1);
    assert_eq!(history.tenures[1].lease_epoch, 2);
    assert_eq!(history.handoffs.len(), 1);
    assert_eq!(history.handoffs[0], succeeded.handoff);
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        Some(succeeded.tenure)
    );
}

#[test]
fn a_second_open_tenure_for_one_generation_refuses() {
    let (_private, mut audit) = audit();
    let first = audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open first tenure");

    let error = audit
        .open_tenure(opening("holder:two", 2, 1_500))
        .expect_err("double open refusal");
    assert_eq!(error.category(), "tenure_open");
    assert!(error.to_string().contains("holder:one"));

    // Nothing was written by the refused call.
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert_eq!(audit.tenure("generation:alpha", 2).expect("read"), None);
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        Some(first)
    );
}

#[test]
fn open_tenure_refuses_a_generation_that_already_has_terminal_history() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open first tenure");
    audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Released))
        .expect("release");

    // A successor owes the log an observation; there is no path that opens a
    // later tenure without one.
    let error = audit
        .open_tenure(opening("holder:two", 2, 2_100))
        .expect_err("successor must record a handoff");
    assert_eq!(error.category(), "predecessor_recorded");
    assert_eq!(audit.tenure_count().expect("count"), 1);

    audit
        .succeed_tenure(succession("holder:two", 2, 2_100, 2_200))
        .expect("succeed");
    assert_eq!(full_history(&audit), (2, 1));
}

#[test]
fn succession_without_any_recorded_predecessor_refuses() {
    let (_private, mut audit) = audit();
    let error = audit
        .succeed_tenure(succession("holder:one", 1, 1_000, 1_000))
        .expect_err("no predecessor");
    assert_eq!(error.category(), "not_found");
    assert!(error.to_string().contains("predecessor_tenure"));
    assert_eq!(audit.tenure_count().expect("count"), 0);
}

#[test]
fn ending_a_tenure_twice_refuses_and_the_first_close_stands() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");

    // A stale expectation is refused before anything is written.
    let error = audit
        .end_tenure(ending("holder:one", 1, 2, 2_000, SelfEndKind::Released))
        .expect_err("revision refusal");
    assert_eq!(error.category(), "revision_mismatch");
    assert!(
        audit
            .tenure("generation:alpha", 1)
            .expect("read")
            .expect("row")
            .is_open()
    );

    let released = audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Released))
        .expect("release");

    // The revision moved, so the same call cannot be replayed...
    let error = audit
        .end_tenure(ending("holder:one", 1, 1, 3_000, SelfEndKind::Expired))
        .expect_err("second close refusal");
    assert_eq!(error.category(), "already_ended");
    assert!(error.to_string().contains("released"));

    // ...and neither can a caller that guessed the new revision. A terminal
    // tenure is never rewritten, not even to the same kind.
    for (revision, kind) in [(2, SelfEndKind::Expired), (2, SelfEndKind::Released)] {
        let error = audit
            .end_tenure(ending("holder:one", 1, revision, 3_000, kind))
            .expect_err("terminal tenure refusal");
        assert_eq!(error.category(), "already_ended");
    }

    assert_eq!(
        audit.tenure("generation:alpha", 1).expect("read"),
        Some(released),
        "the durable row is exactly what the first close wrote"
    );
}

#[test]
fn a_holder_cannot_close_another_holders_tenure() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");

    let error = audit
        .end_tenure(ending("holder:two", 1, 1, 2_000, SelfEndKind::Released))
        .expect_err("holder refusal");
    assert_eq!(error.category(), "holder_mismatch");
    assert!(error.to_string().contains("holder:one"));
    assert!(
        audit
            .tenure("generation:alpha", 1)
            .expect("read")
            .expect("row")
            .is_open()
    );

    let error = audit
        .end_tenure(ending("holder:one", 7, 1, 2_000, SelfEndKind::Released))
        .expect_err("unknown tenure refusal");
    assert_eq!(error.category(), "not_found");
}

#[test]
fn a_tenure_cannot_end_before_it_started() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 5_000))
        .expect("open");

    let error = audit
        .end_tenure(ending("holder:one", 1, 1, 4_999, SelfEndKind::Expired))
        .expect_err("time refusal");
    assert_eq!(error.category(), "end_before_start");

    // A successor superseding at an instant before the predecessor started is
    // refused on the same grounds, and writes nothing.
    let error = audit
        .succeed_tenure(succession("holder:two", 2, 4_000, 4_500))
        .expect_err("supersede time refusal");
    assert_eq!(error.category(), "end_before_start");
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert_eq!(audit.handoff_count().expect("count"), 0);
}

// ---------------------------------------------------------------------------
// Supersession
// ---------------------------------------------------------------------------

#[test]
fn a_successor_supersedes_an_open_predecessor_in_one_transaction() {
    let (_private, mut audit) = audit();
    let first = audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");

    // holder:one never closed its row; the successor's opening transaction
    // writes the predecessor's end and its own start together.
    let succeeded = audit
        .succeed_tenure(succession("holder:two", 2, 9_000, 9_100))
        .expect("supersede");

    assert_eq!(succeeded.predecessor.tenure_id, first.tenure_id);
    assert_eq!(succeeded.predecessor.end_kind, Some(EndKind::Superseded));
    assert_eq!(succeeded.predecessor.ended_at_ms, Some(9_100));
    assert_eq!(succeeded.predecessor.revision, 2);
    assert_eq!(succeeded.predecessor.holder_id, "holder:one");
    assert_eq!(
        audit.tenure("generation:alpha", 1).expect("read"),
        Some(succeeded.predecessor.clone())
    );

    assert_eq!(succeeded.handoff.predecessor_end_kind, EndKind::Superseded);
    assert_eq!(succeeded.handoff.observed_at_ms, 9_100);
    assert_eq!(succeeded.tenure.started_at_ms, 9_000);
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        Some(succeeded.tenure.clone())
    );
    assert_eq!(full_history(&audit), (2, 1));

    // The superseded holder cannot come back and claim a clean release.
    let error = audit
        .end_tenure(ending("holder:one", 1, 1, 9_500, SelfEndKind::Released))
        .expect_err("superseded tenure refusal");
    assert_eq!(error.category(), "already_ended");
    assert!(error.to_string().contains("superseded"));
}

#[test]
fn a_refused_successor_row_discards_the_predecessors_supersede() {
    let private = PrivateAudit::new();
    // One tenure of capacity: the predecessor fills it, so the successor's row
    // — the second write of the succession transaction — cannot land.
    let mut audit = GenerationAudit::open_with_capacity(private.path(), 1).expect("open audit");
    let first = audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");

    let error = audit
        .succeed_tenure(succession("holder:two", 2, 9_000, 9_100))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "audit_full");

    // The predecessor's supersede was rolled back with the rest of the
    // transaction. Two calls instead of one would have left it superseded with
    // no successor and no handoff.
    assert_eq!(
        audit.tenure("generation:alpha", 1).expect("read"),
        Some(first.clone()),
        "the predecessor must still be open at revision 1"
    );
    assert_eq!(
        audit.latest_open("generation:alpha").expect("latest open"),
        Some(first)
    );
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert_eq!(audit.handoff_count().expect("count"), 0);
    assert_eq!(full_history(&audit), (1, 0));

    // The same refusal survives a reopen: nothing half-written was durable.
    drop(audit);
    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    assert!(
        reopened
            .latest_open("generation:alpha")
            .expect("latest open")
            .expect("row")
            .is_open()
    );
    assert_eq!(reopened.handoff_count().expect("count"), 0);
}

#[test]
fn a_successor_epoch_must_rise_but_need_not_be_contiguous() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 4, 1_000))
        .expect("open");

    for epoch in [1, 4] {
        let error = audit
            .succeed_tenure(succession("holder:two", epoch, 2_000, 2_000))
            .expect_err("epoch refusal");
        assert_eq!(error.category(), "epoch_regression");
        assert!(error.to_string().contains('4'));
    }
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert!(
        audit
            .tenure("generation:alpha", 4)
            .expect("read")
            .expect("row")
            .is_open(),
        "a refused succession must not close the predecessor"
    );

    // Crash window 1: a tenure whose audit row was never written leaves a gap,
    // and the log must still be able to record the tenure that follows it.
    let succeeded = audit
        .succeed_tenure(succession("holder:three", 9, 3_000, 3_000))
        .expect("non-contiguous succession");
    assert_eq!(succeeded.handoff.predecessor_epoch, 4);
    assert_eq!(succeeded.handoff.successor_epoch, 9);
}

#[test]
fn generations_are_independent_of_one_another() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open alpha");
    audit
        .open_tenure(TenureOpening {
            generation_id: "generation:beta",
            holder_id: "holder:one",
            lease_epoch: 1,
            started_at_ms: 1_000,
        })
        .expect("open beta");

    assert_eq!(audit.tenure_count().expect("count"), 2);
    assert_eq!(full_history(&audit), (1, 0));
    let beta = audit
        .history("generation:beta", 0, MAX_HISTORY_PAGE)
        .expect("beta history");
    assert_eq!(beta.tenures.len(), 1);
    assert_eq!(beta.tenures[0].generation_id, "generation:beta");
    assert_eq!(
        audit.history("generation:gamma", 0, 1).expect("unknown"),
        automonique_store::generation_audit::GenerationHistory {
            tenures: Vec::new(),
            handoffs: Vec::new(),
        },
        "an unrecorded generation is empty, not an error"
    );
}

// ---------------------------------------------------------------------------
// Capacity and page bounds
// ---------------------------------------------------------------------------

#[test]
fn a_full_audit_refuses_a_new_tenure_but_still_closes_an_open_one() {
    let private = PrivateAudit::new();
    let mut audit = GenerationAudit::open_with_capacity(private.path(), 1).expect("open audit");
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open alpha");

    let error = audit
        .open_tenure(TenureOpening {
            generation_id: "generation:beta",
            holder_id: "holder:one",
            lease_epoch: 1,
            started_at_ms: 1_000,
        })
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "audit_full");
    assert!(error.to_string().contains('1'));

    // Closing adds no row, so a full audit can still record how a tenure ended.
    audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Expired))
        .expect("close inside a full audit");
    assert_eq!(audit.tenure_count().expect("count"), 1);
}

#[test]
fn history_pages_are_bounded_and_ordered() {
    let (_private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:1", 1, 1_000))
        .expect("open");
    for epoch in 2..=5u64 {
        let now = 1_000 + i64::try_from(epoch).expect("epoch fits") * 100;
        audit
            .succeed_tenure(Succession {
                opening: TenureOpening {
                    generation_id: "generation:alpha",
                    holder_id: "holder:n",
                    lease_epoch: epoch,
                    started_at_ms: now,
                },
                observed_at_ms: now,
            })
            .expect("succeed");
    }

    for limit in [0, MAX_HISTORY_PAGE + 1] {
        let error = audit
            .history("generation:alpha", 0, limit)
            .expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));
    }

    let page = audit.history("generation:alpha", 0, 2).expect("first page");
    assert_eq!(
        page.tenures
            .iter()
            .map(|tenure| tenure.lease_epoch)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        page.handoffs
            .iter()
            .map(|handoff| handoff.successor_epoch)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "handoffs page by successor epoch, of which epoch 1 has none"
    );

    let next = audit
        .history("generation:alpha", 2, 2)
        .expect("second page");
    assert_eq!(
        next.tenures
            .iter()
            .map(|tenure| tenure.lease_epoch)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );

    let tail = audit
        .history("generation:alpha", 4, MAX_HISTORY_PAGE)
        .expect("tail");
    assert_eq!(tail.tenures.len(), 1);
    assert_eq!(tail.tenures[0].lease_epoch, 5);
    assert!(tail.tenures[0].is_open());
    assert_eq!(tail.handoffs.len(), 1);
    assert_eq!(tail.handoffs[0].predecessor_end_kind, EndKind::Superseded);
}

// ---------------------------------------------------------------------------
// Caller field validation
// ---------------------------------------------------------------------------

#[test]
fn malformed_caller_fields_refuse_before_touching_the_database() {
    let (_private, mut audit) = audit();
    let over_long = "h".repeat(MAX_IDENTIFIER_BYTES + 1);

    let cases: Vec<(TenureOpening<'_>, &str)> = vec![
        (opening("", 1, 0), "holder_id"),
        (opening("holder\u{7}one", 1, 0), "holder_id"),
        (opening(over_long.as_str(), 1, 0), "holder_id"),
        (opening("holder:one", 0, 0), "lease_epoch"),
        (opening("holder:one", 1, -1), "started_at_ms"),
        (
            TenureOpening {
                generation_id: "",
                holder_id: "holder:one",
                lease_epoch: 1,
                started_at_ms: 0,
            },
            "generation_id",
        ),
    ];
    for (candidate, field) in cases {
        let error = audit.open_tenure(candidate).expect_err("field refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains(field), "expected {field}");
    }
    assert_eq!(audit.tenure_count().expect("count"), 0);

    audit
        .open_tenure(opening("holder:one", 1, 5_000))
        .expect("open");

    // A successor records after it acquires, never before.
    let error = audit
        .succeed_tenure(succession("holder:two", 2, 6_000, 5_999))
        .expect_err("observation order refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("observed_at_ms"));

    let error = audit
        .end_tenure(ending("holder:one", 1, 0, 6_000, SelfEndKind::Released))
        .expect_err("revision refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("expected_revision"));

    let error = audit
        .end_tenure(ending("holder:one", 1, 1, -1, SelfEndKind::Released))
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");

    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert_eq!(audit.handoff_count().expect("count"), 0);
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn the_end_kind_vocabulary_is_closed_on_read_not_only_by_the_check() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Expired))
        .expect("expire");
    drop(audit);

    // The column CHECK is the first line: a plain writer cannot smuggle a kind.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE generation_tenures SET end_kind = 'seized' WHERE lease_epoch = 1",
        [],
    )
    .expect_err("check constraint refuses an unknown kind");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE generation_tenures SET end_kind = 'seized' WHERE lease_epoch = 1",
        [],
    )
    .expect("smuggle end kind");
    drop(raw);

    // Every read path refuses it rather than guessing what 'seized' meant.
    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .tenure("generation:alpha", 1)
        .expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("end_kind"));
    assert_eq!(
        reopened
            .latest_open("generation:alpha")
            .expect_err("latest open refusal")
            .category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .history("generation:alpha", 0, MAX_HISTORY_PAGE)
            .expect_err("history refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_half_terminal_tenure_surfaces_as_corruption() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    drop(audit);

    // 'released' with no ended_at_ms: the pair is written together or not at
    // all, and the read path says so even when the CHECK was bypassed.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE generation_tenures SET end_kind = 'released', revision = 2
         WHERE lease_epoch = 1",
        [],
    )
    .expect("smuggle half terminal row");
    drop(raw);

    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .tenure("generation:alpha", 1)
        .expect_err("terminality refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("tenure_terminality"));
}

#[test]
fn a_hand_written_revision_surfaces_as_corruption() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    drop(audit);

    // This module updates a row exactly once, so an open tenure is at revision
    // 1 and a terminal one at revision 2. Anything else is somebody else's row.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE generation_tenures SET revision = 7 WHERE lease_epoch = 1",
        [],
    )
    .expect("smuggle revision");
    drop(raw);

    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .tenure("generation:alpha", 1)
        .expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn a_hand_written_over_long_holder_surfaces_as_corruption() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    drop(audit);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE generation_tenures SET holder_id = ?1 WHERE lease_epoch = 1",
        params!["h".repeat(4_096)],
    )
    .expect("smuggle holder");
    drop(raw);

    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .tenure("generation:alpha", 1)
        .expect_err("length refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("holder_id"));
}

#[test]
fn a_hand_written_open_tenure_below_a_terminal_one_surfaces_as_corruption() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    audit
        .succeed_tenure(succession("holder:two", 2, 2_000, 2_000))
        .expect("supersede");
    audit
        .end_tenure(ending("holder:two", 2, 1, 3_000, SelfEndKind::Released))
        .expect("release");
    drop(audit);

    // Reopen the earlier tenure. The partial unique index still holds — there
    // is exactly one open row — but an open tenure below a terminal one is not
    // something this API can write.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE generation_tenures SET ended_at_ms = NULL, end_kind = NULL, revision = 1
         WHERE lease_epoch = 1",
        [],
    )
    .expect("smuggle stranded open tenure");
    drop(raw);

    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .latest_open("generation:alpha")
        .expect_err("stranded open refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("open_tenure_not_latest"));
}

#[test]
fn a_handoff_disagreeing_with_its_predecessor_surfaces_as_corruption() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    audit
        .succeed_tenure(succession("holder:two", 2, 2_000, 2_000))
        .expect("supersede");
    drop(audit);

    // A kind inside the vocabulary, so the CHECK passes, but not the kind the
    // tenure it names actually carries.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE generation_handoffs SET predecessor_end_kind = 'released'",
        [],
    )
    .expect("smuggle handoff kind");
    drop(raw);

    let reopened = GenerationAudit::open(private.path()).expect("reopen");
    let error = reopened
        .history("generation:alpha", 0, MAX_HISTORY_PAGE)
        .expect_err("handoff refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("predecessor_end_kind"));

    // The tenure rows themselves are untouched and still read cleanly.
    assert_eq!(
        reopened
            .tenure("generation:alpha", 1)
            .expect("read")
            .expect("row")
            .end_kind,
        Some(EndKind::Superseded)
    );
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

#[test]
fn reopen_keeps_wal_pragmas_and_every_durable_row() {
    let (private, mut audit) = audit();
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Released))
        .expect("release");
    let succeeded = audit
        .succeed_tenure(succession("holder:two", 2, 2_100, 2_200))
        .expect("succeed");
    drop(audit);

    let raw = Connection::open(private.path()).expect("inspect pragmas");
    let mode: String = raw
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(mode, "wal");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user version");
    assert_eq!(version, GENERATION_AUDIT_SCHEMA_VERSION);
    drop(raw);

    let mut reopened = GenerationAudit::open(private.path()).expect("reopen");
    let history = reopened
        .history("generation:alpha", 0, MAX_HISTORY_PAGE)
        .expect("history");
    assert_eq!(history.tenures.len(), 2);
    assert_eq!(history.tenures[0].end_kind, Some(EndKind::Released));
    assert_eq!(history.tenures[0].revision, 2);
    assert!(history.tenures[1].is_open());
    assert_eq!(history.handoffs, vec![succeeded.handoff]);
    assert_eq!(
        reopened.latest_open("generation:alpha").expect("open"),
        Some(succeeded.tenure)
    );

    // The recovered open tenure is still closable by its own holder, at the
    // revision the reopened row reports.
    let closed = reopened
        .end_tenure(ending("holder:two", 2, 1, 4_000, SelfEndKind::Expired))
        .expect("close after restart");
    assert_eq!(closed.end_kind, Some(EndKind::Expired));
    assert_eq!(closed.revision, 2);
}

#[test]
fn a_lowered_capacity_refuses_new_tenures_without_disturbing_recorded_ones() {
    let private = PrivateAudit::new();
    let mut audit = GenerationAudit::open(private.path()).expect("open audit");
    audit
        .open_tenure(opening("holder:one", 1, 1_000))
        .expect("open");
    audit
        .end_tenure(ending("holder:one", 1, 1, 2_000, SelfEndKind::Released))
        .expect("release");
    drop(audit);

    let mut narrowed = GenerationAudit::open_with_capacity(private.path(), 1).expect("reopen");
    assert_eq!(narrowed.capacity(), 1);
    let error = narrowed
        .succeed_tenure(succession("holder:two", 2, 2_100, 2_200))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "audit_full");

    // Reads and the recorded history are unaffected by the handle's bound.
    assert_eq!(full_history(&narrowed), (1, 0));
    assert_eq!(
        narrowed
            .tenure("generation:alpha", 1)
            .expect("read")
            .expect("row")
            .end_kind,
        Some(EndKind::Released)
    );
}
