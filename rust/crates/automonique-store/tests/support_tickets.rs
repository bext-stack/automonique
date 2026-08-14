// SPDX-License-Identifier: Elastic-2.0

//! Durable support ticket store invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the store and reopen
//! the file: an in-memory store cannot pass them, which is the whole reason this
//! module exists.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::support_tickets::{
    FleetTicket, MAX_COMMENT_COUNT, MAX_FLEET_ISSUE_ID_BYTES, MAX_REQUESTED_BY_BYTES,
    MAX_SITE_LABEL_BYTES, MAX_SUPPORT_TICKETS, MAX_TENANT_NAME_BYTES, MAX_TICKET_PAGE,
    MAX_TICKET_TITLE_BYTES, MAX_TICKET_TOKEN_BYTES, MAX_TIMESTAMP_BYTES,
    SUPPORT_TICKETS_SCHEMA_VERSION, SupportTicketStore, TicketLifecycle, TicketRecord,
    TicketTransition,
};
use rusqlite::Connection;
use tempfile::TempDir;

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("support-tickets.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn store() -> (PrivateStore, SupportTicketStore) {
    let private = PrivateStore::new();
    let opened = SupportTicketStore::open(private.path()).expect("open store");
    (private, opened)
}

/// One complete sighting, as the connector's decoder would have produced it.
fn ticket(fleet_issue_id: &str) -> FleetTicket<'_> {
    FleetTicket {
        fleet_issue_id,
        title: "Panne de paiement",
        tenant_name: "Boulangerie Milo",
        site_label: Some("milo.invalid"),
        fleet_status: "triaging",
        priority: "high",
        source: "email",
        requested_by: "Claire",
        comment_count: 3,
        created_at: "2026-08-10T09:12:00.000Z",
        updated_at: "2026-08-13T17:04:11.000Z",
        observed_at_ms: 1_000,
    }
}

fn ids(page: &[TicketRecord]) -> Vec<String> {
    page.iter()
        .map(|record| record.fleet_issue_id.clone())
        .collect()
}

/// Record a ticket and drive it to `lifecycle`, one legal step at a time.
fn drive(store: &mut SupportTicketStore, fleet_issue_id: &str, lifecycle: TicketLifecycle) {
    let mut receipt = store.record(&ticket(fleet_issue_id)).expect("record");
    for step in TicketLifecycle::ALL {
        if step.rank() == 0 || step.rank() > lifecycle.rank() {
            continue;
        }
        receipt = store
            .transition(TicketTransition {
                fleet_issue_id,
                expected_revision: receipt.revision,
                lifecycle: step,
                now_ms: 2_000,
            })
            .expect("transition");
    }
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_store_stamps_its_schema_version() {
    let (private, store) = store();
    assert_eq!(store.path(), private.path());
    assert_eq!(store.capacity(), MAX_SUPPORT_TICKETS);
    assert_eq!(store.ticket_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, SUPPORT_TICKETS_SCHEMA_VERSION);
    let journal: String = raw
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal_mode");
    assert!(journal.eq_ignore_ascii_case("wal"));
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = SupportTicketStore::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateStore::new();
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

    let error = SupportTicketStore::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_world_readable_directory_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("group-readable permissions");
    let error = SupportTicketStore::open(directory.path().join("support-tickets.sqlite3"))
        .expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn an_out_of_range_capacity_is_refused() {
    let private = PrivateStore::new();
    for capacity in [0, MAX_SUPPORT_TICKETS + 1] {
        let error = SupportTicketStore::open_with_capacity(private.path(), capacity)
            .expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
    }
}

// ---------------------------------------------------------------------------
// Recording, and the dedup key
// ---------------------------------------------------------------------------

#[test]
fn a_first_sighting_lands_at_new_with_both_instants_equal() {
    let (_private, mut store) = store();
    let receipt = store.record(&ticket("iss-1")).expect("record");
    assert!(receipt.inserted, "a first sighting creates the row");
    assert!(receipt.changed);
    assert_eq!(receipt.lifecycle, TicketLifecycle::New);
    assert_eq!(receipt.revision, 1);

    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.ticket_id, receipt.ticket_id);
    assert_eq!(record.fleet_issue_id, "iss-1");
    assert_eq!(record.title, "Panne de paiement");
    assert_eq!(record.tenant_name, "Boulangerie Milo");
    assert_eq!(record.site_label.as_deref(), Some("milo.invalid"));
    assert_eq!(record.fleet_status, "triaging");
    assert_eq!(record.priority, "high");
    assert_eq!(record.source, "email");
    assert_eq!(record.requested_by, "Claire");
    assert_eq!(record.comment_count, 3);
    // The fleet's own timestamps are retained verbatim, never reformatted.
    assert_eq!(record.created_at, "2026-08-10T09:12:00.000Z");
    assert_eq!(record.updated_at, "2026-08-13T17:04:11.000Z");
    assert_eq!(record.first_seen_ms, 1_000);
    assert_eq!(record.last_synced_ms, 1_000);
    assert_eq!(record.lifecycle, TicketLifecycle::New);
    assert_eq!(record.revision, 1);
}

/// THE DEDUP KEY. A re-poll of the same board updates the row it already has.
#[test]
fn a_re_poll_updates_the_row_and_never_inserts_a_second_one() {
    let (_private, mut store) = store();
    store.record(&ticket("iss-1")).expect("first sighting");

    let mut again = ticket("iss-1");
    again.observed_at_ms = 5_000;
    again.comment_count = 4;
    again.fleet_status = "in_progress";
    let receipt = store.record(&again).expect("second sighting");

    assert!(!receipt.inserted, "the fleet id is the dedup key");
    assert!(receipt.changed, "the fleet said something different");
    assert_eq!(receipt.revision, 2);
    assert_eq!(store.ticket_count().expect("count"), 1);

    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.comment_count, 4);
    assert_eq!(record.fleet_status, "in_progress");
    // The host's own columns are untouched by the fleet's writer.
    assert_eq!(record.first_seen_ms, 1_000, "first_seen_ms is written once");
    assert_eq!(record.last_synced_ms, 5_000);
    assert_eq!(record.lifecycle, TicketLifecycle::New);
}

/// `revision` counts what the row *says*, not how often it was looked at.
#[test]
fn an_unchanged_re_poll_advances_the_sync_instant_and_leaves_the_revision() {
    let (_private, mut store) = store();
    store.record(&ticket("iss-1")).expect("first sighting");

    let mut again = ticket("iss-1");
    again.observed_at_ms = 9_000;
    let receipt = store.record(&again).expect("second sighting");
    assert!(!receipt.inserted);
    assert!(!receipt.changed, "nothing the fleet owns moved");
    assert_eq!(receipt.revision, 1, "a poll is not a change");

    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.last_synced_ms, 9_000);
    assert_eq!(record.revision, 1);

    // Which is what keeps a revision a caller read earlier usable: the
    // transition below would have failed if polling had bumped it.
    store
        .transition(TicketTransition {
            fleet_issue_id: "iss-1",
            expected_revision: 1,
            lifecycle: TicketLifecycle::Acknowledged,
            now_ms: 9_000,
        })
        .expect("a poll must not invalidate a revision");
}

#[test]
fn an_absent_and_an_empty_site_label_are_different_and_only_one_is_admitted() {
    let (_private, mut store) = store();
    let mut absent = ticket("iss-1");
    absent.site_label = None;
    store.record(&absent).expect("record");
    assert_eq!(
        store
            .ticket("iss-1")
            .expect("read")
            .expect("present")
            .site_label,
        None
    );

    let mut empty = ticket("iss-2");
    empty.site_label = Some("");
    let error = store.record(&empty).expect_err("empty label refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("site_label"));
    assert_eq!(store.ticket_count().expect("count"), 1);
}

#[test]
fn an_absent_ticket_reads_as_nothing_rather_than_a_refusal() {
    let (_private, store) = store();
    assert_eq!(store.ticket("iss-absent").expect("read"), None);
}

#[test]
fn a_sighting_older_than_the_last_one_is_refused_rather_than_silently_dropped() {
    let (_private, mut store) = store();
    let mut first = ticket("iss-1");
    first.observed_at_ms = 5_000;
    store.record(&first).expect("record");

    let mut stale = ticket("iss-1");
    stale.observed_at_ms = 4_999;
    let error = store.record(&stale).expect_err("backward clock refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("observed_at_ms"));
    // Nothing was written.
    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.last_synced_ms, 5_000);
    assert_eq!(record.revision, 1);
}

#[test]
fn every_field_ceiling_is_exact() {
    let (_private, mut store) = store();
    let cases: [(&str, usize); 7] = [
        ("fleet_issue_id", MAX_FLEET_ISSUE_ID_BYTES),
        ("title", MAX_TICKET_TITLE_BYTES),
        ("tenant_name", MAX_TENANT_NAME_BYTES),
        ("site_label", MAX_SITE_LABEL_BYTES),
        ("fleet_status", MAX_TICKET_TOKEN_BYTES),
        ("requested_by", MAX_REQUESTED_BY_BYTES),
        ("created_at", MAX_TIMESTAMP_BYTES),
    ];
    for (field, max) in cases {
        for (width, admitted) in [(max, true), (max + 1, false)] {
            let filler = "v".repeat(width);
            let mut candidate = ticket(&filler);
            // A distinct key per case, so an admitted row does not collide.
            let key = format!("{field}-{width}");
            if field != "fleet_issue_id" {
                candidate.fleet_issue_id = &key;
            }
            match field {
                "title" => candidate.title = &filler,
                "tenant_name" => candidate.tenant_name = &filler,
                "site_label" => candidate.site_label = Some(&filler),
                "fleet_status" => candidate.fleet_status = &filler,
                "requested_by" => candidate.requested_by = &filler,
                "created_at" => candidate.created_at = &filler,
                _ => {}
            }
            assert_eq!(
                store.record(&candidate).is_ok(),
                admitted,
                "{field} at {width} bytes"
            );
        }
    }

    for (count, admitted) in [(MAX_COMMENT_COUNT, true), (MAX_COMMENT_COUNT + 1, false)] {
        let key = format!("comments-{count}");
        let mut candidate = ticket(&key);
        candidate.comment_count = count;
        assert_eq!(
            store.record(&candidate).is_ok(),
            admitted,
            "comment_count {count}"
        );
    }
}

#[test]
fn empty_and_control_bearing_fields_are_refused_by_the_field_that_owns_the_rule() {
    let (_private, mut store) = store();
    // The four fields the connector requires non-empty are required here too.
    for field in ["fleet_issue_id", "title", "fleet_status", "priority"] {
        let mut candidate = ticket("iss-1");
        match field {
            "fleet_issue_id" => candidate.fleet_issue_id = "",
            "title" => candidate.title = "",
            "fleet_status" => candidate.fleet_status = "",
            _ => candidate.priority = "",
        }
        let error = store.record(&candidate).expect_err("emptiness refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains(field), "{field} must be named");
    }

    // The three the connector admits empty are admitted here too.
    let mut permissive = ticket("iss-empty");
    permissive.tenant_name = "";
    permissive.source = "";
    permissive.requested_by = "";
    store
        .record(&permissive)
        .expect("the fleet legitimately sends these empty");

    // A control character cannot reach a terminal through this store.
    let mut hostile = ticket("iss-hostile");
    hostile.title = "Panne\u{1b}[2J";
    let error = store.record(&hostile).expect_err("control refusal");
    assert_eq!(error.category(), "invalid_field");

    // Nor through a timestamp, which is printable ASCII or nothing.
    let mut stamped = ticket("iss-stamped");
    stamped.updated_at = "2026-08-13\u{7}";
    assert_eq!(
        store
            .record(&stamped)
            .expect_err("timestamp refusal")
            .category(),
        "invalid_field"
    );

    let mut negative = ticket("iss-negative");
    negative.observed_at_ms = -1;
    assert_eq!(
        store
            .record(&negative)
            .expect_err("time refusal")
            .category(),
        "invalid_field"
    );
}

// ---------------------------------------------------------------------------
// The lifecycle lattice
// ---------------------------------------------------------------------------

#[test]
fn a_ticket_walks_the_whole_lattice_one_step_at_a_time() {
    let (_private, mut store) = store();
    let mut receipt = store.record(&ticket("iss-1")).expect("record");
    assert_eq!(receipt.lifecycle, TicketLifecycle::New);

    for (step, expected_revision) in [
        (TicketLifecycle::Acknowledged, 2),
        (TicketLifecycle::Working, 3),
        (TicketLifecycle::Answered, 4),
        (TicketLifecycle::Closed, 5),
    ] {
        receipt = store
            .transition(TicketTransition {
                fleet_issue_id: "iss-1",
                expected_revision: receipt.revision,
                lifecycle: step,
                now_ms: 2_000,
            })
            .expect("legal step");
        assert_eq!(receipt.lifecycle, step);
        assert_eq!(receipt.revision, expected_revision);
        assert!(!receipt.inserted, "a transition never creates a row");
    }
    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Closed);
    assert_eq!(record.revision, 5);
}

/// The one shortcut the lattice admits, and the reason it exists: the fleet can
/// close a ticket at any point, including one nobody here ever looked at.
#[test]
fn closed_is_reachable_from_every_state_that_is_not_already_closed() {
    let (_private, mut store) = store();
    for origin in [
        TicketLifecycle::New,
        TicketLifecycle::Acknowledged,
        TicketLifecycle::Working,
        TicketLifecycle::Answered,
    ] {
        let key = format!("iss-{}", origin.as_str());
        drive(&mut store, &key, origin);
        let record = store.ticket(&key).expect("read").expect("present");
        assert_eq!(record.lifecycle, origin);
        let receipt = store
            .transition(TicketTransition {
                fleet_issue_id: &key,
                expected_revision: record.revision,
                lifecycle: TicketLifecycle::Closed,
                now_ms: 3_000,
            })
            .expect("closing is always legal from a live ticket");
        assert_eq!(receipt.lifecycle, TicketLifecycle::Closed);
    }
}

#[test]
fn a_backward_a_skipping_and_a_repeated_transition_are_all_refused() {
    let (_private, mut store) = store();
    drive(&mut store, "iss-1", TicketLifecycle::Working);
    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Working);

    for illegal in [
        // Backwards.
        TicketLifecycle::New,
        TicketLifecycle::Acknowledged,
        // The state it already holds.
        TicketLifecycle::Working,
    ] {
        let error = store
            .transition(TicketTransition {
                fleet_issue_id: "iss-1",
                expected_revision: record.revision,
                lifecycle: illegal,
                now_ms: 4_000,
            })
            .expect_err("lattice refusal");
        assert_eq!(error.category(), "illegal_transition");
        assert!(error.to_string().contains(illegal.as_str()));
    }

    // Skipping forward past a step, on a row that has not reached it.
    let mut fresh = store.record(&ticket("iss-2")).expect("record");
    for skipped in [TicketLifecycle::Working, TicketLifecycle::Answered] {
        assert_eq!(
            store
                .transition(TicketTransition {
                    fleet_issue_id: "iss-2",
                    expected_revision: fresh.revision,
                    lifecycle: skipped,
                    now_ms: 4_000,
                })
                .expect_err("skip refusal")
                .category(),
            "illegal_transition"
        );
    }
    fresh = store
        .transition(TicketTransition {
            fleet_issue_id: "iss-2",
            expected_revision: fresh.revision,
            lifecycle: TicketLifecycle::Acknowledged,
            now_ms: 4_000,
        })
        .expect("the one legal step");
    assert_eq!(fresh.lifecycle, TicketLifecycle::Acknowledged);

    // Nothing written by any refusal above.
    assert_eq!(
        store
            .ticket("iss-1")
            .expect("read")
            .expect("present")
            .revision,
        record.revision
    );
}

#[test]
fn a_closed_ticket_is_never_left() {
    let (_private, mut store) = store();
    drive(&mut store, "iss-1", TicketLifecycle::Closed);
    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Closed);

    for target in TicketLifecycle::ALL {
        let error = store
            .transition(TicketTransition {
                fleet_issue_id: "iss-1",
                expected_revision: record.revision,
                lifecycle: target,
                now_ms: 5_000,
            })
            .expect_err("terminality refusal");
        assert_eq!(error.category(), "illegal_transition");
    }
    // But the fleet may keep talking about it: content still records.
    let mut later = ticket("iss-1");
    later.observed_at_ms = 6_000;
    later.comment_count = 9;
    let receipt = store.record(&later).expect("a closed ticket still syncs");
    assert!(!receipt.inserted);
    assert_eq!(receipt.lifecycle, TicketLifecycle::Closed);
}

#[test]
fn the_lattice_predicate_admits_exactly_the_transitions_the_store_writes() {
    for from in TicketLifecycle::ALL {
        for to in TicketLifecycle::ALL {
            let expected =
                !from.is_terminal() && (to.is_terminal() || to.rank() == from.rank() + 1);
            assert_eq!(
                from.may_advance_to(to),
                expected,
                "{from} -> {to}",
                from = from.as_str(),
                to = to.as_str()
            );
        }
    }
    assert!(TicketLifecycle::Closed.is_terminal());
    for live in [
        TicketLifecycle::New,
        TicketLifecycle::Acknowledged,
        TicketLifecycle::Working,
        TicketLifecycle::Answered,
    ] {
        assert!(!live.is_terminal());
    }
}

#[test]
fn a_stale_expected_revision_is_refused_and_writes_nothing() {
    let (_private, mut store) = store();
    store.record(&ticket("iss-1")).expect("record");
    store
        .transition(TicketTransition {
            fleet_issue_id: "iss-1",
            expected_revision: 1,
            lifecycle: TicketLifecycle::Acknowledged,
            now_ms: 2_000,
        })
        .expect("first transition");

    let error = store
        .transition(TicketTransition {
            fleet_issue_id: "iss-1",
            expected_revision: 1,
            lifecycle: TicketLifecycle::Working,
            now_ms: 3_000,
        })
        .expect_err("revision refusal");
    assert_eq!(error.category(), "revision_mismatch");
    assert!(error.to_string().contains('2'));
    let record = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Acknowledged);
    assert_eq!(record.revision, 2);
}

#[test]
fn an_unrecorded_ticket_cannot_transition() {
    let (_private, mut store) = store();
    let error = store
        .transition(TicketTransition {
            fleet_issue_id: "iss-absent",
            expected_revision: 1,
            lifecycle: TicketLifecycle::Acknowledged,
            now_ms: 2_000,
        })
        .expect_err("existence refusal");
    assert_eq!(error.category(), "not_found");

    for bad in ["", &"v".repeat(MAX_FLEET_ISSUE_ID_BYTES + 1)] {
        assert_eq!(
            store
                .transition(TicketTransition {
                    fleet_issue_id: bad,
                    expected_revision: 1,
                    lifecycle: TicketLifecycle::Acknowledged,
                    now_ms: 2_000,
                })
                .expect_err("identifier refusal")
                .category(),
            "invalid_field"
        );
    }
    assert_eq!(
        store
            .transition(TicketTransition {
                fleet_issue_id: "iss-1",
                expected_revision: 0,
                lifecycle: TicketLifecycle::Acknowledged,
                now_ms: 2_000,
            })
            .expect_err("revision refusal")
            .category(),
        "invalid_field"
    );
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[test]
fn a_page_is_bounded_and_resumes_from_its_cursor() {
    let (_private, mut store) = store();
    for index in 1..=5 {
        store
            .record(&ticket(&format!("iss-{index}")))
            .expect("record");
    }

    let first = store.page(0, 2).expect("first page");
    assert_eq!(ids(&first.tickets), ["iss-1", "iss-2"]);
    let cursor = first.next_cursor.expect("a further row was seen");
    let second = store.page(cursor, 2).expect("second page");
    assert_eq!(ids(&second.tickets), ["iss-3", "iss-4"]);
    let last = store
        .page(second.next_cursor.expect("cursor"), 2)
        .expect("last page");
    assert_eq!(ids(&last.tickets), ["iss-5"]);
    assert_eq!(
        last.next_cursor, None,
        "an exhausted listing is not a filled one"
    );

    // An exactly-filled page still reports no cursor when nothing follows.
    let exact = store.page(0, 5).expect("exact page");
    assert_eq!(exact.tickets.len(), 5);
    assert_eq!(exact.next_cursor, None);
}

#[test]
fn a_lifecycle_filtered_page_carries_exactly_the_matching_rows() {
    let (_private, mut store) = store();
    drive(&mut store, "iss-new", TicketLifecycle::New);
    drive(&mut store, "iss-working", TicketLifecycle::Working);
    drive(&mut store, "iss-closed", TicketLifecycle::Closed);

    let open = store
        .page_in_lifecycles(
            0,
            MAX_TICKET_PAGE,
            &[
                TicketLifecycle::New,
                TicketLifecycle::Acknowledged,
                TicketLifecycle::Working,
                TicketLifecycle::Answered,
            ],
        )
        .expect("open page");
    assert_eq!(ids(&open.tickets), ["iss-new", "iss-working"]);

    let closed = store
        .page_in_lifecycles(0, MAX_TICKET_PAGE, &[TicketLifecycle::Closed])
        .expect("closed page");
    assert_eq!(ids(&closed.tickets), ["iss-closed"]);

    let all = store
        .page_in_lifecycles(0, MAX_TICKET_PAGE, &TicketLifecycle::ALL)
        .expect("unrestricted page");
    assert_eq!(all.tickets.len(), 3);
}

#[test]
fn an_empty_or_repeating_lifecycle_filter_is_refused() {
    let (_private, store) = store();
    assert_eq!(
        store
            .page_in_lifecycles(0, 10, &[])
            .expect_err("empty filter refusal")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        store
            .page_in_lifecycles(0, 10, &[TicketLifecycle::New, TicketLifecycle::New])
            .expect_err("repeating filter refusal")
            .category(),
        "invalid_field"
    );
}

#[test]
fn a_cursor_above_the_retained_window_is_refused_rather_than_answered_empty() {
    let (_private, mut store) = store();
    store.record(&ticket("iss-1")).expect("record");

    // At the highest recorded row: an empty page, which is a real answer.
    let empty = store.page(1, 10).expect("empty page");
    assert!(empty.tickets.is_empty());
    assert_eq!(empty.next_cursor, None);

    let error = store.page(2, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains('2'));

    // A filter must not turn a resumable cursor into a refusal, nor rescue one.
    assert_eq!(
        store
            .page_in_lifecycles(2, 10, &[TicketLifecycle::Closed])
            .expect_err("filtered cursor refusal")
            .category(),
        "cursor_out_of_range"
    );
    store
        .page_in_lifecycles(1, 10, &[TicketLifecycle::Closed])
        .expect("a cursor the filter excluded is still a position");
}

#[test]
fn a_limit_outside_its_bounds_is_refused() {
    let (_private, store) = store();
    for limit in [0, MAX_TICKET_PAGE + 1] {
        assert_eq!(
            store.page(0, limit).expect_err("limit refusal").category(),
            "invalid_field"
        );
    }
    store.page(0, MAX_TICKET_PAGE).expect("the exact ceiling");
}

#[test]
fn the_retained_window_grows_as_rows_are_added() {
    let (_private, mut store) = store();
    assert_eq!(store.retained_range().expect("range"), None);
    for index in 1..=3 {
        store
            .record(&ticket(&format!("iss-{index}")))
            .expect("record");
        let range = store.retained_range().expect("range").expect("non-empty");
        assert_eq!(range.first, 1, "nothing deletes, so the floor stays");
        assert_eq!(range.last, index);
    }
    assert_eq!(store.ticket_count().expect("count"), 3);
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

#[test]
fn a_recorded_and_transitioned_ticket_survives_close_and_reopen() {
    let (private, mut store) = store();
    drive(&mut store, "iss-1", TicketLifecycle::Working);
    let mut later = ticket("iss-1");
    later.observed_at_ms = 7_000;
    later.priority = "urgent";
    store.record(&later).expect("later sighting");
    drop(store);

    let reopened = SupportTicketStore::open(private.path()).expect("reopen");
    let record = reopened.ticket("iss-1").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Working);
    assert_eq!(record.priority, "urgent");
    assert_eq!(record.first_seen_ms, 1_000);
    assert_eq!(record.last_synced_ms, 7_000);
    assert_eq!(record.revision, 4);
    assert_eq!(reopened.ticket_count().expect("count"), 1);
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[test]
fn the_store_refuses_to_grow_past_its_capacity_and_never_evicts() {
    let private = PrivateStore::new();
    let mut store = SupportTicketStore::open_with_capacity(private.path(), 2).expect("open store");
    store.record(&ticket("iss-1")).expect("first");
    store.record(&ticket("iss-2")).expect("second");

    let error = store
        .record(&ticket("iss-3"))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "store_full");
    assert!(error.to_string().contains('2'));
    assert_eq!(store.ticket_count().expect("count"), 2);
    // The oldest row is still there: capacity refuses, it does not evict.
    assert!(store.ticket("iss-1").expect("read").is_some());

    // A full store still records what the fleet says about tickets it holds,
    // because an update is not growth.
    let mut moved = ticket("iss-1");
    moved.observed_at_ms = 8_000;
    moved.comment_count = 11;
    let receipt = store.record(&moved).expect("an update is not growth");
    assert!(!receipt.inserted);
    store
        .transition(TicketTransition {
            fleet_issue_id: "iss-1",
            expected_revision: receipt.revision,
            lifecycle: TicketLifecycle::Acknowledged,
            now_ms: 8_000,
        })
        .expect("a transition is not growth either");
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_unknown_lifecycle_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(&ticket("iss-1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE support_tickets SET lifecycle = 'escalated' WHERE fleet_issue_id = 'iss-1'",
        [],
    )
    .expect_err("check constraint refuses an unknown lifecycle");

    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE support_tickets SET lifecycle = 'escalated' WHERE fleet_issue_id = 'iss-1'",
        [],
    )
    .expect("smuggle lifecycle");
    drop(raw);

    // Every read path refuses it rather than guessing what 'escalated' meant.
    let reopened = SupportTicketStore::open(private.path()).expect("reopen");
    let error = reopened.ticket("iss-1").expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("lifecycle"));
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .page_in_lifecycles(0, 10, &TicketLifecycle::ALL)
            .expect_err("filtered page refusal")
            .category(),
        "corrupt",
        "a filter selects rows; it must never hide a corrupt one"
    );
}

#[test]
fn a_hand_written_row_outside_this_apis_grammar_surfaces_as_corruption() {
    let cases: [(&str, &str); 5] = [
        ("title", "UPDATE support_tickets SET title = ''"),
        (
            "created_at",
            "UPDATE support_tickets SET created_at = 'hier\u{7}'",
        ),
        (
            "comment_count",
            "UPDATE support_tickets SET comment_count = 10001",
        ),
        (
            "last_synced_ms",
            "UPDATE support_tickets SET last_synced_ms = first_seen_ms - 1",
        ),
        ("site_label", "UPDATE support_tickets SET site_label = ''"),
    ];
    for (field, statement) in cases {
        let (private, mut store) = store();
        store.record(&ticket("iss-1")).expect("record");
        drop(store);

        let raw = Connection::open(private.path()).expect("raw write");
        raw.pragma_update(None, "ignore_check_constraints", true)
            .expect("disable checks");
        raw.execute(statement, []).expect("smuggle row");
        drop(raw);

        let reopened = SupportTicketStore::open(private.path()).expect("reopen");
        let error = reopened.ticket("iss-1").expect_err("corruption refusal");
        assert_eq!(error.category(), "corrupt", "{field}");
        assert!(error.to_string().contains(field), "{field} must be named");
    }
}

#[test]
fn a_hand_written_non_positive_identity_surfaces_as_corruption() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "INSERT INTO support_tickets
         (ticket_id, fleet_issue_id, title, tenant_name, site_label, fleet_status, priority,
          source, requested_by, comment_count, created_at, updated_at,
          first_seen_ms, last_synced_ms, lifecycle, revision)
         VALUES (-3, 'iss-1', 'Titre', 'Tenant', NULL, 'open', 'normal',
                 'email', 'Claire', 0, '2026-01-01', '2026-01-01', 0, 0, 'new', 1)",
        [],
    )
    .expect("smuggle negative identity");
    drop(raw);

    let reopened = SupportTicketStore::open(private.path()).expect("reopen");
    let error = reopened.ticket("iss-1").expect_err("identity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("ticket_id"));
}

#[test]
fn a_hand_written_zero_revision_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(&ticket("iss-1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute("UPDATE support_tickets SET revision = 0", [])
        .expect("smuggle revision");
    drop(raw);

    let reopened = SupportTicketStore::open(private.path()).expect("reopen");
    let error = reopened.ticket("iss-1").expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

// ---------------------------------------------------------------------------
// The stored vocabulary, and the nullable-column trap
// ---------------------------------------------------------------------------

#[test]
fn the_stored_lifecycle_vocabulary_is_closed_to_anything_else() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    let row = |lifecycle: &str, key: &str| {
        format!(
            "INSERT INTO support_tickets
             (fleet_issue_id, title, tenant_name, site_label, fleet_status, priority,
              source, requested_by, comment_count, created_at, updated_at,
              first_seen_ms, last_synced_ms, lifecycle, revision)
             VALUES ('{key}', 'Titre', 'Tenant', NULL, 'open', 'normal',
                     'email', 'Claire', 0, '2026-01-01', '2026-01-01', 0, 0,
                     '{lifecycle}', 1)"
        )
    };
    for rejected in ["", "NEW", "escalated", "open", "done"] {
        assert!(
            raw.execute(&row(rejected, "iss-x"), []).is_err(),
            "the database must refuse the lifecycle {rejected:?}"
        );
    }
    for admitted in TicketLifecycle::ALL {
        raw.execute(&row(admitted.as_str(), admitted.as_str()), [])
            .expect("every spelling this API writes must land");
    }
}

/// The nullable-CHECK trap, watched rather than assumed.
///
/// `site_label` is the one nullable column in this table, so it is the one place
/// a CHECK could evaluate to `NULL` and be admitted. The constraint spells
/// `IS NOT NULL` on the branch that reads it, and this test is what proves the
/// binding still bites on the values that do reach it.
#[test]
fn the_one_nullable_column_never_reaches_a_check_that_would_answer_null() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    let row = |key: &str, site_label: &str, instants: &str| {
        format!(
            "INSERT INTO support_tickets
             (fleet_issue_id, title, tenant_name, site_label, fleet_status, priority,
              source, requested_by, comment_count, created_at, updated_at,
              first_seen_ms, last_synced_ms, lifecycle, revision)
             VALUES ('{key}', 'Titre', 'Tenant', {site_label}, 'open', 'normal',
                     'email', 'Claire', 0, '2026-01-01', '2026-01-01', {instants},
                     'new', 1)"
        )
    };

    for (what, statement) in [
        // The nullable column's own binding, on the values that do reach it.
        ("an empty site label", row("a", "''", "0, 0")),
        (
            "an over-long site label",
            row(
                "b",
                &format!("'{}'", "v".repeat(MAX_SITE_LABEL_BYTES + 1)),
                "0, 0",
            ),
        ),
        // A NULL in any non-nullable column is refused by the column itself, so
        // no CHECK is ever asked a question it would answer NULL.
        (
            "a titleless ticket",
            row("c", "NULL", "0, 0").replace("'c', 'Titre'", "'c', NULL"),
        ),
        (
            "a ticket belonging to no fleet issue",
            row("d", "NULL", "0, 0").replace("'d', 'Titre'", "NULL, 'Titre'"),
        ),
        (
            "a lifecycleless ticket",
            row("e2", "NULL", "0, 0").replace("'new', 1", "NULL, 1"),
        ),
        (
            "a sync instant before the first sighting",
            row("e", "NULL", "10, 9"),
        ),
        ("a negative first sighting", row("f", "NULL", "-1, 0")),
        (
            "a comment count past its ceiling",
            row("g", "NULL", "0, 0").replace(", 0, '2026-01-01'", ", 10001, '2026-01-01'"),
        ),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: both legal shapes of the nullable column
    // still land, and so does an equal instant pair.
    raw.execute(&row("present", "'milo.invalid'", "5, 5"), [])
        .expect("a named site lands");
    raw.execute(&row("absent", "NULL", "5, 6"), [])
        .expect("an unnamed site lands");
}

/// The five spellings this store writes are the five the daemon's intake worker
/// and any later surface will read. Pinned by literal here so a rename has to
/// break this test as well as the enum.
#[test]
fn the_lifecycle_spellings_are_pinned() {
    assert_eq!(
        TicketLifecycle::ALL.map(TicketLifecycle::as_str),
        ["new", "acknowledged", "working", "answered", "closed"]
    );
    for lifecycle in TicketLifecycle::ALL {
        assert_eq!(
            TicketLifecycle::from_spelling(lifecycle.as_str()),
            Some(lifecycle)
        );
        assert_eq!(lifecycle.to_string(), lifecycle.as_str());
    }
    for outside in ["", "NEW", "open", "done", "escalated"] {
        assert_eq!(TicketLifecycle::from_spelling(outside), None);
    }
}
