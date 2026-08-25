// SPDX-License-Identifier: Elastic-2.0

//! Durable automation registry invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart test closes the registry and
//! reopens the file: an in-memory registry cannot pass it, which is the whole
//! reason this module exists.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::automation_store::{
    AUTOMATION_STORE_SCHEMA_VERSION, AutomationJob, AutomationJobSpec, AutomationRecord,
    AutomationRegistration, AutomationSchedule, AutomationStore, EnablementState,
    EnablementTransition, MAX_AUTOMATION_PAGE, MAX_AUTOMATIONS, MAX_IDENTIFIER_BYTES,
    MAX_PROMPT_BYTES,
};
use rusqlite::{Connection, params};
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
        let path = directory.path().join("automations.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn registry() -> (PrivateRegistry, AutomationStore) {
    let private = PrivateRegistry::new();
    let opened = AutomationStore::open(private.path()).expect("open registry");
    (private, opened)
}

/// The one representative job every registration here carries: a fixed
/// interval of one minute, first due one minute after the registration instant.
fn job() -> AutomationJobSpec<'static> {
    AutomationJobSpec {
        schedule: AutomationSchedule::Every {
            interval_ms: 60_000,
        },
        scope: "workspace:reports",
        prompt: "summarize the night",
        first_fire_at_ms: 61_000,
    }
}

fn declared(automation_id: &str) -> AutomationRegistration<'_> {
    AutomationRegistration {
        automation_id,
        actor: "ops:ada",
        now_ms: 1_000,
        job: job(),
    }
}

/// The job half of one row, or a panic naming the row that lost it.
fn job_of(store: &AutomationStore, automation_id: &str) -> AutomationJob {
    store
        .entry(automation_id)
        .expect("entry")
        .expect("a row")
        .job
        .expect("a row registered with a job")
}

fn change<'a>(
    automation_id: &'a str,
    expected_revision: u64,
    new_enablement: EnablementState,
    actor: &'a str,
    cause: Option<&'a str>,
) -> EnablementTransition<'a> {
    EnablementTransition {
        automation_id,
        expected_revision,
        new_enablement,
        actor,
        cause,
        now_ms: 2_000,
    }
}

/// Register one automation and withdraw it, so the row sits `paused` at
/// revision two.
fn paused(store: &mut AutomationStore, automation_id: &str) {
    store.register(declared(automation_id)).expect("register");
    store
        .transition(change(
            automation_id,
            1,
            EnablementState::Paused,
            "ops:ada",
            Some("flapping"),
        ))
        .expect("pause");
}

/// Register one automation and archive it, so the row sits terminal.
fn archived(store: &mut AutomationStore, automation_id: &str) {
    store.register(declared(automation_id)).expect("register");
    store
        .transition(change(
            automation_id,
            1,
            EnablementState::Archived,
            "ops:ada",
            Some("retired"),
        ))
        .expect("archive");
}

fn identities(entries: &[AutomationRecord]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| entry.automation_id.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_registry_stamps_its_schema_version() {
    let (private, store) = registry();
    assert_eq!(store.path(), private.path());
    assert_eq!(store.capacity(), MAX_AUTOMATIONS);
    assert_eq!(store.automation_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, AUTOMATION_STORE_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, store) = registry();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = AutomationStore::open(private.path()).expect_err("schema refusal");
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

    let error = AutomationStore::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_registry_file_is_refused() {
    let (private, store) = registry();
    drop(store);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = AutomationStore::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_group_readable_directory_is_refused() {
    let private = PrivateRegistry::new();
    let directory = private.path().parent().expect("parent");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).expect("loosen dir mode");

    let error = AutomationStore::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn an_out_of_range_capacity_is_refused() {
    let private = PrivateRegistry::new();
    for capacity in [0, MAX_AUTOMATIONS + 1] {
        let error = AutomationStore::open_with_capacity(private.path(), capacity)
            .expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[test]
fn a_registered_automation_reads_back_enabled_at_revision_one() {
    let (_private, mut store) = registry();

    let receipt = store.register(declared("auto:nightly")).expect("register");
    assert_eq!(receipt.enablement, EnablementState::Enabled);
    assert_eq!(receipt.revision, 1);
    assert_eq!(receipt.updated_at_ms, 1_000);

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.entry_id, receipt.entry_id);
    assert_eq!(record.automation_id, "auto:nightly");
    assert_eq!(record.enablement, EnablementState::Enabled);
    assert_eq!(record.revision, 1);
    assert_eq!(record.actor, "ops:ada");
    assert_eq!(record.cause, None);
    assert_eq!(record.created_at_ms, 1_000);
    assert_eq!(record.updated_at_ms, 1_000);
    assert!(record.admits_occurrence());
    assert_eq!(
        record.resumed_by(),
        None,
        "a freshly declared automation was never paused, so nobody resumed it"
    );
    // The job reads back whole, first due where the caller said, with no
    // occurrence active and none fired.
    assert_eq!(
        record.job,
        Some(AutomationJob {
            schedule: AutomationSchedule::Every {
                interval_ms: 60_000
            },
            scope: "workspace:reports".to_owned(),
            prompt: "summarize the night".to_owned(),
            next_fire_at_ms: Some(61_000),
            last_fired_at_ms: None,
            active_occurrence_ms: None,
        })
    );

    assert_eq!(store.automation_count().expect("count"), 1);
    assert!(store.entry("auto:absent").expect("absent").is_none());
}

#[test]
fn a_duplicate_automation_is_refused_and_writes_nothing() {
    let (_private, mut store) = registry();
    paused(&mut store, "auto:nightly");

    let error = store
        .register(declared("auto:nightly"))
        .expect_err("duplicate refusal");
    assert_eq!(error.category(), "already_registered");
    assert!(
        error.to_string().contains("paused"),
        "the refusal reports what it collided with: {error}"
    );

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Paused);
    assert_eq!(record.revision, 2);
    assert_eq!(record.cause.as_deref(), Some("flapping"));
    assert_eq!(store.automation_count().expect("count"), 1);
}

#[test]
fn re_registering_an_archived_automation_is_refused() {
    let (_private, mut store) = registry();
    archived(&mut store, "auto:nightly");

    // The lattice refuses every way out of `archived`; registration must not be
    // a back door that resets the row to `enabled`.
    let error = store
        .register(declared("auto:nightly"))
        .expect_err("duplicate refusal");
    assert_eq!(error.category(), "already_registered");
    assert!(error.to_string().contains("archived"));

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Archived);
    assert_eq!(record.revision, 2);
    assert!(!record.admits_occurrence());
}

#[test]
fn identifiers_and_times_outside_the_grammar_are_refused() {
    let (_private, mut store) = registry();
    let over_long = "a".repeat(MAX_IDENTIFIER_BYTES + 1);

    for automation_id in ["", over_long.as_str(), "auto:\u{7}bell"] {
        let error = store
            .register(declared(automation_id))
            .expect_err("identifier refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("automation_id"));
        assert_eq!(
            store
                .entry(automation_id)
                .expect_err("read refusal")
                .category(),
            "invalid_field"
        );
    }

    for actor in ["", over_long.as_str(), "ops:\u{7}bell"] {
        let error = store
            .register(AutomationRegistration {
                automation_id: "auto:nightly",
                actor,
                now_ms: 1_000,
                job: job(),
            })
            .expect_err("actor refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("actor"));
    }

    let error = store
        .register(AutomationRegistration {
            automation_id: "auto:nightly",
            actor: "ops:ada",
            now_ms: -1,
            job: job(),
        })
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("now_ms"));
    assert_eq!(store.automation_count().expect("count"), 0);

    store.register(declared("auto:nightly")).expect("register");
    for cause in ["", over_long.as_str(), "why:\u{7}bell"] {
        let error = store
            .transition(change(
                "auto:nightly",
                1,
                EnablementState::Paused,
                "ops:ada",
                Some(cause),
            ))
            .expect_err("cause refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("cause"));
    }

    let error = store
        .transition(change(
            "auto:nightly",
            0,
            EnablementState::Paused,
            "ops:ada",
            Some("flapping"),
        ))
        .expect_err("revision refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("expected_revision"));

    let error = store
        .transition(EnablementTransition {
            automation_id: "auto:nightly",
            expected_revision: 1,
            new_enablement: EnablementState::Paused,
            actor: "ops:ada",
            cause: Some("flapping"),
            now_ms: -1,
        })
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("now_ms"));

    // Boundary-length values are admitted, so the refusals above are the bound
    // and not an off-by-one.
    let exact = "a".repeat(MAX_IDENTIFIER_BYTES);
    store
        .register(AutomationRegistration {
            automation_id: &exact,
            actor: &exact,
            now_ms: 1_000,
            job: job(),
        })
        .expect("boundary register");
    store
        .transition(change(
            &exact,
            1,
            EnablementState::Paused,
            &exact,
            Some(&exact),
        ))
        .expect("boundary pause");

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Enabled);
    assert_eq!(record.revision, 1, "nothing above was written");
}

// ---------------------------------------------------------------------------
// The enablement lattice
// ---------------------------------------------------------------------------

#[test]
fn a_pause_and_the_resume_that_follows_name_different_actors() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    let paused = store
        .transition(change(
            "auto:nightly",
            1,
            EnablementState::Paused,
            "ops:ada",
            Some("noisy on weekends"),
        ))
        .expect("pause");
    assert_eq!(paused.enablement, EnablementState::Paused);
    assert_eq!(paused.revision, 2);
    assert_eq!(paused.updated_at_ms, 2_000);

    let withdrawn = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(withdrawn.enablement, EnablementState::Paused);
    assert_eq!(withdrawn.actor, "ops:ada");
    assert_eq!(withdrawn.cause.as_deref(), Some("noisy on weekends"));
    assert_eq!(withdrawn.revision, 2);
    assert!(!withdrawn.admits_occurrence());
    assert_eq!(
        withdrawn.resumed_by(),
        None,
        "a withdrawn automation has not been resumed"
    );
    assert_eq!(
        withdrawn.created_at_ms, 1_000,
        "the declaration instant is not rewritten by a transition"
    );

    let resumed = store
        .transition(change(
            "auto:nightly",
            2,
            EnablementState::Enabled,
            "ops:blake",
            None,
        ))
        .expect("resume");
    assert_eq!(resumed.enablement, EnablementState::Enabled);
    assert_eq!(resumed.revision, 3);

    let back = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(back.enablement, EnablementState::Enabled);
    assert_eq!(
        back.actor, "ops:blake",
        "the resume names who reopened it, not who paused it"
    );
    assert_eq!(back.cause, None, "an enabled row carries no cause");
    assert_eq!(back.revision, 3);
    assert!(back.admits_occurrence());
    assert_eq!(back.resumed_by(), Some("ops:blake"));
}

#[test]
fn both_live_states_may_be_archived() {
    let (_private, mut store) = registry();

    store
        .register(declared("auto:from-enabled"))
        .expect("register");
    let receipt = store
        .transition(change(
            "auto:from-enabled",
            1,
            EnablementState::Archived,
            "ops:blake",
            Some("superseded by auto:hourly"),
        ))
        .expect("archive an enabled automation");
    assert_eq!(receipt.enablement, EnablementState::Archived);
    assert_eq!(receipt.revision, 2);

    paused(&mut store, "auto:from-paused");
    let receipt = store
        .transition(change(
            "auto:from-paused",
            2,
            EnablementState::Archived,
            "ops:blake",
            Some("never coming back"),
        ))
        .expect("archive a paused automation");
    assert_eq!(receipt.enablement, EnablementState::Archived);
    assert_eq!(receipt.revision, 3);

    let record = store
        .entry("auto:from-paused")
        .expect("entry")
        .expect("a row");
    assert_eq!(record.actor, "ops:blake");
    assert_eq!(record.cause.as_deref(), Some("never coming back"));
    assert!(!record.admits_occurrence());
}

#[test]
fn an_archived_automation_is_never_left() {
    let (_private, mut store) = registry();
    archived(&mut store, "auto:nightly");

    // Every destination, including the state the row already holds.
    for destination in EnablementState::ALL {
        let cause = destination.requires_cause().then_some("second thoughts");
        let error = store
            .transition(change("auto:nightly", 2, destination, "ops:blake", cause))
            .expect_err("terminal refusal");
        assert_eq!(error.category(), "illegal_transition");
        assert!(error.to_string().contains("archived"));
    }

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Archived);
    assert_eq!(record.revision, 2);
    assert_eq!(record.actor, "ops:ada");
    assert_eq!(record.cause.as_deref(), Some("retired"));
}

#[test]
fn no_state_transitions_to_itself() {
    let (_private, mut store) = registry();

    store.register(declared("auto:live")).expect("register");
    let error = store
        .transition(change(
            "auto:live",
            1,
            EnablementState::Enabled,
            "ops:blake",
            None,
        ))
        .expect_err("self-transition refusal");
    assert_eq!(error.category(), "illegal_transition");
    let record = store.entry("auto:live").expect("entry").expect("a row");
    assert_eq!(record.revision, 1);
    assert_eq!(
        record.actor, "ops:ada",
        "a refused resume credits nobody with reopening it"
    );

    // Re-pausing would overwrite the cause the operator still has to resume
    // from, which is the reason the protocol refuses it too.
    paused(&mut store, "auto:withdrawn");
    let error = store
        .transition(change(
            "auto:withdrawn",
            2,
            EnablementState::Paused,
            "ops:blake",
            Some("a different reason"),
        ))
        .expect_err("self-transition refusal");
    assert_eq!(error.category(), "illegal_transition");
    let record = store
        .entry("auto:withdrawn")
        .expect("entry")
        .expect("a row");
    assert_eq!(record.revision, 2);
    assert_eq!(record.cause.as_deref(), Some("flapping"));
    assert_eq!(record.actor, "ops:ada");
}

#[test]
fn the_lattice_predicate_admits_exactly_the_protocol_lifecycle() {
    for from in EnablementState::ALL {
        for to in EnablementState::ALL {
            let expected = matches!(
                (from, to),
                (EnablementState::Enabled, EnablementState::Paused)
                    | (EnablementState::Paused, EnablementState::Enabled)
                    | (
                        EnablementState::Enabled | EnablementState::Paused,
                        EnablementState::Archived
                    )
            );
            assert_eq!(
                from.may_transition_to(to),
                expected,
                "{from} -> {to} disagrees with the lattice"
            );
        }
    }

    // Only `enabled` fires, and only the two withdrawn states owe a cause.
    assert!(EnablementState::Enabled.admits_occurrence());
    assert!(!EnablementState::Paused.admits_occurrence());
    assert!(!EnablementState::Archived.admits_occurrence());
    assert!(!EnablementState::Enabled.requires_cause());
    assert!(EnablementState::Paused.requires_cause());
    assert!(EnablementState::Archived.requires_cause());
}

// ---------------------------------------------------------------------------
// The cause coupling
// ---------------------------------------------------------------------------

#[test]
fn a_withdrawal_with_no_stated_cause_is_refused() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    for state in [EnablementState::Paused, EnablementState::Archived] {
        let error = store
            .transition(change("auto:nightly", 1, state, "ops:ada", None))
            .expect_err("cause refusal");
        assert_eq!(error.category(), "cause_required");
        assert!(error.to_string().contains(state.as_str()));
    }

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Enabled);
    assert_eq!(record.revision, 1);
}

#[test]
fn an_enabled_transition_carrying_a_cause_is_refused() {
    let (_private, mut store) = registry();
    paused(&mut store, "auto:nightly");

    let error = store
        .transition(change(
            "auto:nightly",
            2,
            EnablementState::Enabled,
            "ops:blake",
            Some("because I said so"),
        ))
        .expect_err("cause refusal");
    assert_eq!(error.category(), "cause_forbidden");
    assert!(error.to_string().contains("enabled"));

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Paused);
    assert_eq!(record.revision, 2);
    assert_eq!(record.cause.as_deref(), Some("flapping"));
}

#[test]
fn the_cause_coupling_is_judged_before_the_durable_state() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    // A stale revision and a missing cause together: the request is malformed
    // whatever the row says, so the caller hears that first.
    let error = store
        .transition(change(
            "auto:nightly",
            99,
            EnablementState::Paused,
            "ops:ada",
            None,
        ))
        .expect_err("cause refusal");
    assert_eq!(error.category(), "cause_required");

    // Even for an automation that does not exist at all.
    let error = store
        .transition(change(
            "auto:absent",
            1,
            EnablementState::Paused,
            "ops:ada",
            None,
        ))
        .expect_err("cause refusal");
    assert_eq!(error.category(), "cause_required");

    // With a cause supplied, the same two requests reach the guards they were
    // always going to reach.
    assert_eq!(
        store
            .transition(change(
                "auto:nightly",
                99,
                EnablementState::Paused,
                "ops:ada",
                Some("flapping"),
            ))
            .expect_err("revision refusal")
            .category(),
        "revision_mismatch"
    );
    assert_eq!(
        store
            .transition(change(
                "auto:absent",
                1,
                EnablementState::Paused,
                "ops:ada",
                Some("flapping"),
            ))
            .expect_err("missing row refusal")
            .category(),
        "not_found"
    );
}

// ---------------------------------------------------------------------------
// Revision
// ---------------------------------------------------------------------------

#[test]
fn a_stale_expected_revision_is_refused_and_writes_nothing() {
    let (_private, mut store) = registry();
    paused(&mut store, "auto:nightly");

    for expected in [1, 3, 99] {
        let error = store
            .transition(change(
                "auto:nightly",
                expected,
                EnablementState::Enabled,
                "ops:blake",
                None,
            ))
            .expect_err("revision refusal");
        assert_eq!(error.category(), "revision_mismatch");
        assert!(error.to_string().contains("durable revision is 2"));
    }

    let record = store.entry("auto:nightly").expect("entry").expect("a row");
    assert_eq!(record.enablement, EnablementState::Paused);
    assert_eq!(record.revision, 2);
    assert_eq!(record.actor, "ops:ada");

    // The durable revision is the one that works, and it moves on afterwards.
    store
        .transition(change(
            "auto:nightly",
            2,
            EnablementState::Enabled,
            "ops:blake",
            None,
        ))
        .expect("resume at the durable revision");
    assert_eq!(
        store
            .transition(change(
                "auto:nightly",
                2,
                EnablementState::Paused,
                "ops:blake",
                Some("again"),
            ))
            .expect_err("the old revision is spent")
            .category(),
        "revision_mismatch"
    );
}

#[test]
fn an_unregistered_automation_cannot_transition() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    let error = store
        .transition(change(
            "auto:absent",
            1,
            EnablementState::Paused,
            "ops:ada",
            Some("flapping"),
        ))
        .expect_err("missing row refusal");
    assert_eq!(error.category(), "not_found");
    assert_eq!(store.automation_count().expect("count"), 1);
}

// ---------------------------------------------------------------------------
// Pagination and the retained window
// ---------------------------------------------------------------------------

#[test]
fn a_page_is_bounded_and_resumes_from_its_cursor() {
    let (_private, mut store) = registry();
    let ids = ["auto:1", "auto:2", "auto:3", "auto:4", "auto:5"];
    for id in ids {
        store.register(declared(id)).expect("register");
    }

    let first = store.page(0, 2).expect("first page");
    assert_eq!(identities(&first.entries), vec!["auto:1", "auto:2"]);
    let cursor = first.next_cursor.expect("more rows follow");

    let second = store.page(cursor, 2).expect("second page");
    assert_eq!(identities(&second.entries), vec!["auto:3", "auto:4"]);

    let third = store
        .page(second.next_cursor.expect("more rows follow"), 2)
        .expect("third page");
    assert_eq!(identities(&third.entries), vec!["auto:5"]);
    assert_eq!(
        third.next_cursor, None,
        "an exhausted listing offers no continuation"
    );

    // A page that exactly fills its limit with nothing behind it is still the
    // end, and says so.
    let exact = store.page(0, 5).expect("exact page");
    assert_eq!(exact.entries.len(), 5);
    assert_eq!(exact.next_cursor, None);
}

#[test]
fn a_state_filtered_page_carries_exactly_the_matching_rows() {
    let (_private, mut store) = registry();
    // 1: enabled, 2: paused, 3: archived, 4: enabled, 5: paused.
    store.register(declared("auto:1")).expect("register");
    paused(&mut store, "auto:2");
    archived(&mut store, "auto:3");
    store.register(declared("auto:4")).expect("register");
    paused(&mut store, "auto:5");

    let live = store
        .page_in_states(0, MAX_AUTOMATION_PAGE, &[EnablementState::Enabled])
        .expect("enabled page");
    assert_eq!(identities(&live.entries), vec!["auto:1", "auto:4"]);

    let withdrawn = store
        .page_in_states(
            0,
            MAX_AUTOMATION_PAGE,
            &[EnablementState::Paused, EnablementState::Archived],
        )
        .expect("withdrawn page");
    assert_eq!(
        identities(&withdrawn.entries),
        vec!["auto:2", "auto:3", "auto:5"]
    );

    let none = store
        .page_in_states(0, MAX_AUTOMATION_PAGE, &[EnablementState::Archived])
        .expect("archived page");
    assert_eq!(identities(&none.entries), vec!["auto:3"]);

    // The filter pages exactly as the unfiltered listing does.
    let first = store
        .page_in_states(0, 1, &[EnablementState::Paused])
        .expect("first filtered page");
    assert_eq!(identities(&first.entries), vec!["auto:2"]);
    let second = store
        .page_in_states(
            first.next_cursor.expect("more rows follow"),
            1,
            &[EnablementState::Paused],
        )
        .expect("second filtered page");
    assert_eq!(identities(&second.entries), vec!["auto:5"]);
    assert_eq!(second.next_cursor, None);

    // Naming every state is the same query as naming none.
    let all = store
        .page_in_states(0, MAX_AUTOMATION_PAGE, &EnablementState::ALL)
        .expect("unrestricted page");
    assert_eq!(
        identities(&all.entries),
        identities(&store.page(0, MAX_AUTOMATION_PAGE).expect("page").entries)
    );
}

#[test]
fn an_empty_or_repeating_state_filter_is_refused() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    let error = store
        .page_in_states(0, 10, &[])
        .expect_err("empty filter refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("states"));

    let error = store
        .page_in_states(
            0,
            10,
            &[
                EnablementState::Enabled,
                EnablementState::Paused,
                EnablementState::Enabled,
            ],
        )
        .expect_err("repeat refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("states"));
}

#[test]
fn a_cursor_above_the_retained_window_is_refused() {
    let (_private, mut store) = registry();

    // An empty registry retains nothing, so only the beginning is resumable.
    let empty = store.page(0, 10).expect("empty page");
    assert!(empty.entries.is_empty());
    assert_eq!(empty.next_cursor, None);
    let error = store.page(1, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains("retained entry_id 0"));

    for id in ["auto:1", "auto:2", "auto:3"] {
        store.register(declared(id)).expect("register");
    }
    let range = store.retained_range().expect("range").expect("a window");

    // The last retained row is a resumable cursor; one past it is not.
    let caught_up = store.page(range.last, 10).expect("caught-up page");
    assert!(caught_up.entries.is_empty());
    let error = store.page(range.last + 1, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains("retained entry_id 3"));
}

#[test]
fn a_filtered_page_judges_its_cursor_against_the_whole_registry() {
    let (_private, mut store) = registry();
    store.register(declared("auto:1")).expect("register");
    paused(&mut store, "auto:2");
    store.register(declared("auto:3")).expect("register");

    let range = store.retained_range().expect("range").expect("a window");

    // The highest row is `enabled`, so a `paused` filter excludes it. Resuming
    // after it is still a legal position in the listing order.
    let page = store
        .page_in_states(range.last, 10, &[EnablementState::Paused])
        .expect("caught-up filtered page");
    assert!(page.entries.is_empty());

    let error = store
        .page_in_states(range.last + 1, 10, &[EnablementState::Paused])
        .expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
}

#[test]
fn a_limit_outside_its_bounds_is_refused() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    for limit in [0, MAX_AUTOMATION_PAGE + 1] {
        let error = store.page(0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));

        let error = store
            .page_in_states(0, limit, &[EnablementState::Enabled])
            .expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
    }
    assert_eq!(
        store
            .page(0, MAX_AUTOMATION_PAGE)
            .expect("page")
            .entries
            .len(),
        1
    );
}

#[test]
fn the_retained_window_grows_as_rows_are_added() {
    let (_private, mut store) = registry();
    assert_eq!(store.retained_range().expect("range"), None);

    for (position, id) in ["auto:1", "auto:2", "auto:3", "auto:4"]
        .into_iter()
        .enumerate()
    {
        store.register(declared(id)).expect("register");
        let range = store.retained_range().expect("range").expect("a window");
        assert_eq!(range.first, 1, "nothing is deleted, so the floor is one");
        assert_eq!(
            range.last,
            u64::try_from(position).expect("small") + 1,
            "the ceiling follows registration order"
        );
    }

    // Archiving moves no boundary: the window is registration order, and an
    // archived row keeps its place.
    store
        .transition(change(
            "auto:1",
            1,
            EnablementState::Archived,
            "ops:ada",
            Some("retired"),
        ))
        .expect("archive");
    let range = store.retained_range().expect("range").expect("a window");
    assert_eq!((range.first, range.last), (1, 4));
    assert_eq!(store.automation_count().expect("count"), 4);
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn a_transitioned_row_survives_close_and_reopen() {
    let (private, mut store) = registry();
    store.register(declared("auto:live")).expect("register");
    paused(&mut store, "auto:withdrawn");
    store
        .transition(change(
            "auto:withdrawn",
            2,
            EnablementState::Enabled,
            "ops:blake",
            None,
        ))
        .expect("resume");
    archived(&mut store, "auto:gone");
    drop(store);

    let reopened = AutomationStore::open(private.path()).expect("reopen");
    let resumed = reopened
        .entry("auto:withdrawn")
        .expect("entry")
        .expect("a row");
    assert_eq!(resumed.enablement, EnablementState::Enabled);
    assert_eq!(resumed.revision, 3);
    assert_eq!(
        resumed.resumed_by(),
        Some("ops:blake"),
        "who reopened it outlives the process that recorded it"
    );
    assert_eq!(
        reopened
            .entry("auto:gone")
            .expect("entry")
            .expect("a row")
            .cause
            .as_deref(),
        Some("retired")
    );
    assert_eq!(
        reopened
            .entry("auto:live")
            .expect("entry")
            .expect("a row")
            .resumed_by(),
        None
    );

    // The revision a reopened handle reports is the one a transition must
    // expect: a restarted operator console needs no memory of its own.
    let mut reopened = AutomationStore::open(private.path()).expect("reopen");
    let error = reopened
        .transition(change(
            "auto:gone",
            2,
            EnablementState::Enabled,
            "ops:blake",
            None,
        ))
        .expect_err("terminal refusal");
    assert_eq!(error.category(), "illegal_transition");
    reopened
        .transition(change(
            "auto:withdrawn",
            3,
            EnablementState::Paused,
            "ops:ada",
            Some("again"),
        ))
        .expect("the resumed row still moves");
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_unknown_enablement_surfaces_as_corruption() {
    let (private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE automations SET enablement = 'retired' WHERE automation_id = 'auto:nightly'",
        [],
    )
    .expect_err("check constraint refuses an unknown enablement");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE automations SET enablement = 'retired' WHERE automation_id = 'auto:nightly'",
        [],
    )
    .expect("smuggle enablement");
    drop(raw);

    // Every read path refuses it rather than guessing what 'retired' meant.
    let reopened = AutomationStore::open(private.path()).expect("reopen");
    let error = reopened
        .entry("auto:nightly")
        .expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("enablement"));
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .page_in_states(0, 10, &EnablementState::ALL)
            .expect_err("filtered page refusal")
            .category(),
        "corrupt"
    );
    // A filter that matches none of the row's spelling must not hide it either:
    // a filtered listing and an unfiltered one answer a corrupt table the same
    // way.
    for state in EnablementState::ALL {
        assert_eq!(
            reopened
                .page_in_states(0, 10, &[state])
                .expect_err("filtered page refusal")
                .category(),
            "corrupt",
            "a {state} filter hid the corrupt row"
        );
    }
}

#[test]
fn a_hand_written_broken_cause_coupling_surfaces_as_corruption() {
    let (private, mut store) = registry();
    store.register(declared("auto:live")).expect("register");
    paused(&mut store, "auto:withdrawn");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE automations SET cause = 'sneaky' WHERE automation_id = 'auto:live'",
        [],
    )
    .expect_err("check constraint couples enabled to an absent cause");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    // An enabled row carrying a cause, and a paused row carrying none: both
    // halves of the coupling, smuggled in opposite directions.
    raw.execute(
        "UPDATE automations SET cause = 'sneaky' WHERE automation_id = 'auto:live'",
        [],
    )
    .expect("smuggle a cause onto an enabled row");
    raw.execute(
        "UPDATE automations SET cause = NULL WHERE automation_id = 'auto:withdrawn'",
        [],
    )
    .expect("smuggle a causeless pause");
    drop(raw);

    let reopened = AutomationStore::open(private.path()).expect("reopen");
    for automation_id in ["auto:live", "auto:withdrawn"] {
        let error = reopened.entry(automation_id).expect_err("coupling refusal");
        assert_eq!(error.category(), "corrupt");
        assert!(error.to_string().contains("cause"));
    }
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_withdrawn_row_at_revision_one_surfaces_as_corruption() {
    let (private, mut store) = registry();
    paused(&mut store, "auto:nightly");
    drop(store);

    // Registration is the only writer of revision one and it always writes
    // `enabled`, so a withdrawn row at revision one is a row this API never
    // wrote. No CHECK stops it — the read path is the whole defence.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE automations SET revision = 1 WHERE automation_id = 'auto:nightly'",
        [],
    )
    .expect("smuggle revision");
    drop(raw);

    let reopened = AutomationStore::open(private.path()).expect("reopen");
    let error = reopened
        .entry("auto:nightly")
        .expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn a_hand_written_control_character_actor_surfaces_as_corruption() {
    let (private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE automations SET actor = ?1 WHERE automation_id = 'auto:nightly'",
        params!["ops:\u{7}bell"],
    )
    .expect("smuggle control character");
    drop(raw);

    let reopened = AutomationStore::open(private.path()).expect("reopen");
    let error = reopened
        .entry("auto:nightly")
        .expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("actor"));

    // Registration reads before it writes, so corruption stops a write to the
    // same identity too, while an unrelated automation is unaffected.
    let mut reopened = AutomationStore::open(private.path()).expect("reopen");
    assert_eq!(
        reopened
            .register(declared("auto:nightly"))
            .expect_err("corruption refusal")
            .category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .transition(change(
                "auto:nightly",
                1,
                EnablementState::Paused,
                "ops:ada",
                Some("flapping"),
            ))
            .expect_err("corruption refusal")
            .category(),
        "corrupt"
    );
    reopened
        .register(declared("auto:other"))
        .expect("an unrelated automation is unaffected");
}

#[test]
fn a_hand_written_non_positive_identity_surfaces_as_corruption() {
    let (private, store) = registry();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO automations
         (entry_id, automation_id, revision, enablement, actor, cause,
          created_at_ms, updated_at_ms)
         VALUES (-3, 'auto:nightly', 1, 'enabled', 'ops:ada', NULL, 10, 10)",
        [],
    )
    .expect("smuggle negative identity");
    drop(raw);

    let reopened = AutomationStore::open(private.path()).expect("reopen");
    let error = reopened
        .entry("auto:nightly")
        .expect_err("identity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("entry_id"));
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[test]
fn the_registry_refuses_to_grow_past_its_capacity() {
    let private = PrivateRegistry::new();
    let mut store = AutomationStore::open_with_capacity(private.path(), 2).expect("open registry");
    store.register(declared("auto:1")).expect("register");
    store.register(declared("auto:2")).expect("register");

    let error = store
        .register(declared("auto:3"))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "registry_full");
    assert!(error.to_string().contains("capacity of 2"));
    assert_eq!(store.automation_count().expect("count"), 2);

    // A full registry still transitions and still reads: neither adds a row.
    store
        .transition(change(
            "auto:1",
            1,
            EnablementState::Archived,
            "ops:ada",
            Some("retired"),
        ))
        .expect("a full registry still transitions");
    assert_eq!(store.page(0, 10).expect("page").entries.len(), 2);

    // Archiving frees no room: nothing here evicts, and the archival is the
    // record that must survive.
    assert_eq!(
        store
            .register(declared("auto:3"))
            .expect_err("capacity refusal")
            .category(),
        "registry_full"
    );
}

// ---------------------------------------------------------------------------
// Anti-drift
// ---------------------------------------------------------------------------

/// The three spellings are the protocol contract, pinned by literal.
///
/// `automonique_protocol::automation::EnablementState` is the authority: its
/// `as_str` renders these exact words, its `AutomationEnablement` gives the two
/// withdrawn ones a `PauseCause` and the third none, and its
/// `AutomationRevision::permits` is the lattice
/// `EnablementState::may_transition_to` reproduces. This crate does not depend
/// on the protocol crate — its dependencies are `nix` and `rusqlite` — so the
/// pin is a literal one, and a rename has to break both crates before it can
/// land.
#[test]
fn the_three_enablement_spellings_match_the_protocol() {
    assert_eq!(
        EnablementState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect::<Vec<_>>(),
        vec!["enabled", "paused", "archived"]
    );

    for state in EnablementState::ALL {
        assert_eq!(EnablementState::from_spelling(state.as_str()), Some(state));
        assert_eq!(state.to_string(), state.as_str());
    }
    assert_eq!(EnablementState::from_spelling("ENABLED"), None);
    assert_eq!(EnablementState::from_spelling("disabled"), None);
    assert_eq!(EnablementState::from_spelling("retired"), None);
    assert_eq!(EnablementState::from_spelling(""), None);

    // The two the protocol's `AutomationEnablement` gives a `PauseCause`.
    let withdrawn: Vec<&str> = EnablementState::ALL
        .iter()
        .filter(|state| state.requires_cause())
        .map(|state| state.as_str())
        .collect();
    assert_eq!(withdrawn, vec!["paused", "archived"]);
}

/// The stored column admits exactly the three spellings and nothing else.
#[test]
fn the_stored_vocabulary_is_closed_to_anything_else() {
    let (private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    for spelling in ["", "ENABLED", "disabled", "retired", "active"] {
        raw.execute(
            "UPDATE automations SET enablement = ?1, cause = 'why'
             WHERE automation_id = 'auto:nightly'",
            params![spelling],
        )
        .expect_err("the column refuses a spelling outside the vocabulary");
    }
    for state in EnablementState::ALL {
        // The coupling CHECK requires the cause to move with the state, so both
        // columns are written together.
        let cause = state.requires_cause().then_some("why");
        raw.execute(
            "UPDATE automations SET enablement = ?1, cause = ?2
             WHERE automation_id = 'auto:nightly'",
            params![state.as_str(), cause],
        )
        .expect("the column admits every spelling this build defines");
    }
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: a NULL must not slip the cause coupling
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, so a coupling
// written over a nullable column as a bare comparison admits the very row it
// was written to refuse. `cause` is the nullable column here, and the coupling
// is NULL-safe by construction: `(enablement = 'enabled') = (cause IS NULL)`
// compares two results that are each `0` or `1`, because `enablement` is
// `NOT NULL` and `IS NULL` never yields `NULL`. The causeless-withdrawal half is
// the one a bare comparison would have lost, so it is spelled out below.
// ---------------------------------------------------------------------------

#[test]
fn a_null_never_slips_the_cause_coupling() {
    let (private, store) = registry();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    let automation = |automation_id: &str, coupled: &str| {
        format!(
            "INSERT INTO automations
                 (automation_id, revision, actor, created_at_ms, updated_at_ms,
                  enablement, cause)
             VALUES ('{automation_id}', 1, 'operator', 0, 0, {coupled})"
        )
    };

    for (what, statement) in [
        (
            "a pause with no stated cause",
            automation("auto:paused", "'paused', NULL"),
        ),
        (
            "an archival with no stated cause",
            automation("auto:archived", "'archived', NULL"),
        ),
        (
            "an enabled automation carrying a cause",
            automation("auto:enabled", "'enabled', 'why'"),
        ),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: both legal pairings still land.
    for (what, statement) in [
        (
            "an enabled automation with no cause",
            automation("auto:live", "'enabled', NULL"),
        ),
        (
            "a pause with a stated cause",
            automation("auto:withdrawn", "'paused', 'why'"),
        ),
    ] {
        raw.execute(&statement, [])
            .unwrap_or_else(|error| panic!("the database must admit {what}: {error}"));
    }
}

// ---------------------------------------------------------------------------
// The job, and where its occurrences have got to
// ---------------------------------------------------------------------------

/// The v1 table, exactly as the previous build created it, so a migration
/// starts from what is really on disk rather than from a stand-in.
const SCHEMA_V1_AS_SHIPPED: &str = r#"
CREATE TABLE automations (
    entry_id INTEGER PRIMARY KEY,
    automation_id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    enablement TEXT NOT NULL CHECK (
        enablement IN ('enabled', 'paused', 'archived')
    ),
    actor TEXT NOT NULL,
    cause TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK ((enablement = 'enabled') = (cause IS NULL))
) STRICT;

CREATE INDEX automations_by_enablement ON automations(enablement, entry_id);
"#;

/// A registry the previous build wrote: two rows, one of them paused, and no
/// job column anywhere.
fn v1_registry() -> PrivateRegistry {
    let private = PrivateRegistry::new();
    let raw = Connection::open(private.path()).expect("create v1 registry");
    raw.execute_batch(SCHEMA_V1_AS_SHIPPED).expect("v1 schema");
    raw.pragma_update(None, "user_version", 1u32)
        .expect("stamp v1");
    raw.execute(
        "INSERT INTO automations
         (automation_id, revision, enablement, actor, cause, created_at_ms, updated_at_ms)
         VALUES ('legacy:enabled', 1, 'enabled', 'ops:ada', NULL, 10, 10),
                ('legacy:paused', 2, 'paused', 'ops:bob', 'held', 10, 20)",
        [],
    )
    .expect("v1 rows");
    drop(raw);
    // A raw connection creates the file world-readable; the previous build
    // created it private, and the registry refuses anything else.
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o600))
        .expect("private registry file");
    private
}

#[test]
fn a_version_one_registry_migrates_forward_and_its_rows_read_back_without_a_job() {
    let private = v1_registry();
    let mut store = AutomationStore::open(private.path()).expect("open migrates");
    let version: u32 = Connection::open(private.path())
        .expect("raw read")
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, AUTOMATION_STORE_SCHEMA_VERSION);

    // Every column the previous build wrote is exactly where it was, and the
    // job half is absent rather than defaulted.
    let enabled = store
        .entry("legacy:enabled")
        .expect("entry")
        .expect("the legacy row survived");
    assert_eq!(enabled.revision, 1);
    assert_eq!(enabled.enablement, EnablementState::Enabled);
    assert_eq!(enabled.actor, "ops:ada");
    assert_eq!(enabled.job, None);
    assert!(enabled.admits_occurrence());
    let paused = store
        .entry("legacy:paused")
        .expect("entry")
        .expect("the paused legacy row survived");
    assert_eq!(paused.enablement, EnablementState::Paused);
    assert_eq!(paused.cause.as_deref(), Some("held"));
    assert_eq!(paused.job, None);

    // A row with no job is never due and admits nothing, whatever `now` is.
    assert!(store.due(i64::MAX, 8).expect("due").is_empty());
    assert!(store.active_occurrences(8).expect("active").is_empty());
    assert_eq!(
        store
            .admit_occurrence("legacy:enabled", 0)
            .expect_err("no job to admit under")
            .category(),
        "unscheduled"
    );

    // It still moves along the lattice exactly as before.
    store
        .transition(change(
            "legacy:paused",
            2,
            EnablementState::Enabled,
            "ops:ada",
            None,
        ))
        .expect("a legacy row resumes");

    // And the widened table takes a new registration, which is due and lists
    // after the legacy rows in registration order.
    store.register(declared("auto:nightly")).expect("register");
    let due = store.due(61_000, 8).expect("due");
    assert_eq!(identities(&due), vec!["auto:nightly"]);
    assert_eq!(
        identities(&store.page(0, 8).expect("page").entries),
        vec!["legacy:enabled", "legacy:paused", "auto:nightly"]
    );

    // Reopening does not migrate twice.
    drop(store);
    let reopened = AutomationStore::open(private.path()).expect("reopen a v2 registry");
    assert_eq!(reopened.automation_count().expect("count"), 3);
}

/// The couplings a fresh registry holds as table constraints cannot be added
/// to a migrated one, so the read path holds them there instead.
#[test]
fn a_migrated_registry_refuses_half_a_job_on_read() {
    let private = v1_registry();
    drop(AutomationStore::open(private.path()).expect("migrate"));

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE automations SET scope = 'workspace:reports' WHERE automation_id = 'legacy:enabled'",
        [],
    )
    .expect("a migrated table has no coupling constraint to refuse this");
    drop(raw);

    let store = AutomationStore::open(private.path()).expect("reopen");
    let error = store
        .entry("legacy:enabled")
        .expect_err("half a job is corruption");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("job"));
    // The untouched row beside it still reads.
    assert!(store.entry("legacy:paused").expect("entry").is_some());
}

#[test]
fn a_fresh_registry_refuses_half_a_job_in_the_database_itself() {
    let (private, store) = registry();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    let row = |automation_id: &str, job_columns: &str| {
        format!(
            "INSERT INTO automations
                 (automation_id, revision, enablement, actor, cause, created_at_ms, updated_at_ms,
                  schedule_kind, schedule_at_ms, schedule_interval_ms, scope, prompt,
                  next_fire_at_ms, last_fired_at_ms, active_occurrence_ms)
             VALUES ('{automation_id}', 1, 'enabled', 'operator', NULL, 0, 0, {job_columns})"
        )
    };
    for (what, columns) in [
        (
            "a scope with no schedule",
            "NULL, NULL, NULL, 'ws', NULL, NULL, NULL, NULL",
        ),
        (
            "a prompt with no schedule",
            "NULL, NULL, NULL, NULL, 'p', NULL, NULL, NULL",
        ),
        (
            "a next instant with no schedule",
            "NULL, NULL, NULL, NULL, NULL, 5, NULL, NULL",
        ),
        (
            "a one-shot with no instant",
            "'once', NULL, NULL, 'ws', 'p', 5, NULL, NULL",
        ),
        (
            "an interval carrying a one-shot instant",
            "'every', 5, 60000, 'ws', 'p', 5, NULL, NULL",
        ),
        (
            "an interval of zero",
            "'every', NULL, 0, 'ws', 'p', 5, NULL, NULL",
        ),
        (
            "a schedule kind outside the vocabulary",
            "'cron', NULL, NULL, 'ws', 'p', 5, NULL, NULL",
        ),
        (
            "a scheduled row with no scope",
            "'every', NULL, 60000, NULL, 'p', 5, NULL, NULL",
        ),
    ] {
        assert!(
            raw.execute(&row("auto:bad", columns), []).is_err(),
            "the database must refuse {what}"
        );
    }
    // Tightness: both legal shapes still land.
    raw.execute(
        &row("auto:once", "'once', 5, NULL, 'ws', 'p', 5, NULL, NULL"),
        [],
    )
    .expect("a one-shot lands");
    raw.execute(
        &row("auto:every", "'every', NULL, 60000, 'ws', 'p', 5, 0, 5"),
        [],
    )
    .expect("an interval with an active occurrence lands");
    raw.execute(
        &row(
            "auto:bare",
            "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL",
        ),
        [],
    )
    .expect("a row with no job lands");
    drop(raw);

    let store = AutomationStore::open(private.path()).expect("reopen");
    assert_eq!(
        job_of(&store, "auto:once").schedule,
        AutomationSchedule::Once { at_ms: 5 }
    );
    assert_eq!(job_of(&store, "auto:every").active_occurrence_ms, Some(5));
    assert_eq!(
        store.entry("auto:bare").expect("entry").expect("a row").job,
        None
    );
}

#[test]
fn a_job_outside_its_grammar_is_refused_before_a_row_is_written() {
    let (_private, mut store) = registry();
    let over_long_prompt = "p".repeat(MAX_PROMPT_BYTES + 1);
    let over_long_scope = "s".repeat(MAX_IDENTIFIER_BYTES + 1);
    fn with(job: AutomationJobSpec<'_>) -> AutomationRegistration<'_> {
        AutomationRegistration {
            automation_id: "auto:nightly",
            actor: "ops:ada",
            now_ms: 1_000,
            job,
        }
    }
    for (field, spec) in [
        ("scope", AutomationJobSpec { scope: "", ..job() }),
        (
            "scope",
            AutomationJobSpec {
                scope: "ws\n1",
                ..job()
            },
        ),
        (
            "scope",
            AutomationJobSpec {
                scope: &over_long_scope,
                ..job()
            },
        ),
        (
            "prompt",
            AutomationJobSpec {
                prompt: "",
                ..job()
            },
        ),
        (
            "prompt",
            AutomationJobSpec {
                prompt: "a\0b",
                ..job()
            },
        ),
        (
            "prompt",
            AutomationJobSpec {
                prompt: &over_long_prompt,
                ..job()
            },
        ),
        (
            "schedule",
            AutomationJobSpec {
                schedule: AutomationSchedule::Every { interval_ms: 0 },
                ..job()
            },
        ),
        (
            "schedule",
            AutomationJobSpec {
                schedule: AutomationSchedule::Once { at_ms: -1 },
                ..job()
            },
        ),
        (
            "first_fire_at_ms",
            AutomationJobSpec {
                first_fire_at_ms: -1,
                ..job()
            },
        ),
    ] {
        let error = store
            .register(with(spec))
            .expect_err("a job outside its grammar is refused");
        assert_eq!(error.category(), "invalid_field", "{field}");
        assert!(error.to_string().contains(field), "{field}: {error}");
    }
    assert_eq!(store.automation_count().expect("count"), 0);

    // A prompt is prose: a newline is text, and the bound itself is admitted.
    store
        .register(with(AutomationJobSpec {
            prompt: "line one\nline two",
            ..job()
        }))
        .expect("a multi-line prompt");
    let exact = "p".repeat(MAX_PROMPT_BYTES);
    store
        .register(AutomationRegistration {
            automation_id: "auto:maximal",
            actor: "ops:ada",
            now_ms: 1_000,
            job: AutomationJobSpec {
                prompt: &exact,
                ..job()
            },
        })
        .expect("a prompt at the bound");
    assert_eq!(
        job_of(&store, "auto:maximal").prompt.len(),
        MAX_PROMPT_BYTES
    );
}

#[test]
fn due_answers_from_the_caller_s_clock_oldest_instant_first() {
    let (_private, mut store) = registry();
    fn at(automation_id: &str, first_fire_at_ms: i64) -> AutomationRegistration<'_> {
        AutomationRegistration {
            automation_id,
            actor: "ops:ada",
            now_ms: 1_000,
            job: AutomationJobSpec {
                first_fire_at_ms,
                ..job()
            },
        }
    }
    store.register(at("auto:late", 3_000)).expect("register");
    store.register(at("auto:early", 2_000)).expect("register");
    store.register(at("auto:later", 4_000)).expect("register");
    store.register(at("auto:same", 2_000)).expect("register");

    // Nothing is due before its instant; at the instant it is.
    assert!(store.due(1_999, 8).expect("due").is_empty());
    assert_eq!(
        identities(&store.due(2_000, 8).expect("due")),
        vec!["auto:early", "auto:same"],
        "equal instants order by registration"
    );
    assert_eq!(
        identities(&store.due(5_000, 8).expect("due")),
        vec!["auto:early", "auto:same", "auto:late", "auto:later"]
    );
    // The batch is bounded, and the bound is the page bound.
    assert_eq!(
        identities(&store.due(5_000, 2).expect("due")),
        vec!["auto:early", "auto:same"]
    );
    for limit in [0, MAX_AUTOMATION_PAGE + 1] {
        assert_eq!(
            store
                .due(5_000, limit)
                .expect_err("limit refusal")
                .category(),
            "invalid_field"
        );
    }
    assert_eq!(
        store.due(-1, 8).expect_err("time refusal").category(),
        "invalid_field"
    );

    // A withdrawn automation is not due, and neither is one with an
    // occurrence already active.
    store
        .transition(change(
            "auto:early",
            1,
            EnablementState::Paused,
            "ops:ada",
            Some("held"),
        ))
        .expect("pause");
    store.admit_occurrence("auto:same", 2_000).expect("admit");
    assert_eq!(
        identities(&store.due(5_000, 8).expect("due")),
        vec!["auto:late", "auto:later"]
    );
    assert_eq!(
        identities(&store.active_occurrences(8).expect("active")),
        vec!["auto:same"]
    );
}

#[test]
fn an_occurrence_is_admitted_advanced_and_settled_by_compare_and_set() {
    let (_private, mut store) = registry();
    store.register(declared("auto:nightly")).expect("register");

    // Admission names the instant that is due, and nothing else.
    assert_eq!(
        store
            .admit_occurrence("auto:nightly", 60_999)
            .expect_err("not the due instant")
            .category(),
        "occurrence_mismatch"
    );
    store
        .admit_occurrence("auto:nightly", 61_000)
        .expect("admit the due instant");
    let admitted = job_of(&store, "auto:nightly");
    assert_eq!(admitted.active_occurrence_ms, Some(61_000));
    assert_eq!(
        admitted.next_fire_at_ms,
        Some(61_000),
        "admission advances nothing"
    );
    assert_eq!(admitted.last_fired_at_ms, None);
    // A second admission — a replayed tick — is a mismatch, not a second
    // occurrence.
    assert_eq!(
        store
            .admit_occurrence("auto:nightly", 61_000)
            .expect_err("already active")
            .category(),
        "occurrence_mismatch"
    );
    assert!(store.due(i64::MAX, 8).expect("due").is_empty());

    // Settling as fired before the advance is refused: the instant would stay
    // due and fire again.
    assert_eq!(
        store
            .settle_occurrence("auto:nightly", 61_000, true)
            .expect_err("advance first")
            .category(),
        "occurrence_mismatch"
    );

    // The advance applies once; its replay answers false and changes nothing.
    assert!(
        store
            .advance_after_start("auto:nightly", 61_000, Some(121_000))
            .expect("advance")
    );
    assert!(
        !store
            .advance_after_start("auto:nightly", 61_000, Some(181_000))
            .expect("a replayed advance")
    );
    assert_eq!(
        job_of(&store, "auto:nightly").next_fire_at_ms,
        Some(121_000),
        "the replay kept the first successor"
    );
    // A successor that does not follow the instant is refused outright.
    assert_eq!(
        store
            .advance_after_start("auto:nightly", 61_000, Some(61_000))
            .expect_err("a successor is later than its instant")
            .category(),
        "invalid_field"
    );
    // And the advance is about the active instant, not any instant.
    assert_eq!(
        store
            .advance_after_start("auto:nightly", 121_000, Some(181_000))
            .expect_err("not the active instant")
            .category(),
        "occurrence_mismatch"
    );

    // Settling as fired clears the active occurrence and records the instant.
    store
        .settle_occurrence("auto:nightly", 61_000, true)
        .expect("settle");
    let settled = job_of(&store, "auto:nightly");
    assert_eq!(settled.active_occurrence_ms, None);
    assert_eq!(settled.last_fired_at_ms, Some(61_000));
    assert_eq!(settled.next_fire_at_ms, Some(121_000));
    // A replayed settle is a mismatch: nothing is active to settle.
    assert_eq!(
        store
            .settle_occurrence("auto:nightly", 61_000, true)
            .expect_err("nothing active")
            .category(),
        "occurrence_mismatch"
    );
    // The row is due again at its successor and nowhere before it.
    assert!(store.due(120_999, 8).expect("due").is_empty());
    assert_eq!(
        identities(&store.due(121_000, 8).expect("due")),
        vec!["auto:nightly"]
    );

    // A one-shot advances to nothing further, and settles.
    store
        .register(AutomationRegistration {
            automation_id: "auto:once",
            actor: "ops:ada",
            now_ms: 1_000,
            job: AutomationJobSpec {
                schedule: AutomationSchedule::Once { at_ms: 5_000 },
                first_fire_at_ms: 5_000,
                ..job()
            },
        })
        .expect("register a one-shot");
    store.admit_occurrence("auto:once", 5_000).expect("admit");
    assert!(
        store
            .advance_after_start("auto:once", 5_000, None)
            .expect("advance to nothing")
    );
    store
        .settle_occurrence("auto:once", 5_000, true)
        .expect("settle");
    let exhausted = job_of(&store, "auto:once");
    assert_eq!(exhausted.next_fire_at_ms, None);
    assert_eq!(exhausted.last_fired_at_ms, Some(5_000));
    assert!(
        store
            .due(i64::MAX, 8)
            .expect("due")
            .iter()
            .all(|record| record.automation_id != "auto:once"),
        "an exhausted one-shot is never due again"
    );
    assert_eq!(
        store
            .admit_occurrence("auto:once", 5_000)
            .expect_err("nothing is due")
            .category(),
        "occurrence_mismatch"
    );
}

/// An occurrence that never started keeps the instant it was due at, unless
/// the caller advanced past it on purpose; either way the row is no longer
/// active and nothing is recorded as fired.
#[test]
fn settling_an_occurrence_that_never_fired_records_no_firing() {
    let (_private, mut store) = registry();
    store.register(declared("auto:kept")).expect("register");
    store.register(declared("auto:skipped")).expect("register");
    store.admit_occurrence("auto:kept", 61_000).expect("admit");
    store
        .admit_occurrence("auto:skipped", 61_000)
        .expect("admit");

    // Kept: the instant stays due, so a resume fires it.
    store
        .settle_occurrence("auto:kept", 61_000, false)
        .expect("settle unfired");
    let kept = job_of(&store, "auto:kept");
    assert_eq!(kept.active_occurrence_ms, None);
    assert_eq!(kept.last_fired_at_ms, None);
    assert_eq!(kept.next_fire_at_ms, Some(61_000));

    // Skipped: the caller advanced first, so the instant is gone for good.
    assert!(
        store
            .advance_after_start("auto:skipped", 61_000, Some(121_000))
            .expect("advance")
    );
    store
        .settle_occurrence("auto:skipped", 61_000, false)
        .expect("settle unfired");
    let skipped = job_of(&store, "auto:skipped");
    assert_eq!(skipped.active_occurrence_ms, None);
    assert_eq!(skipped.last_fired_at_ms, None);
    assert_eq!(skipped.next_fire_at_ms, Some(121_000));
}

#[test]
fn occurrence_verbs_name_what_they_refuse() {
    let (_private, mut store) = registry();
    for (what, error) in [
        (
            "admit an unregistered automation",
            store
                .admit_occurrence("auto:absent", 0)
                .expect_err("absent"),
        ),
        (
            "advance an unregistered automation",
            store
                .advance_after_start("auto:absent", 0, None)
                .expect_err("absent"),
        ),
        (
            "settle an unregistered automation",
            store
                .settle_occurrence("auto:absent", 0, false)
                .expect_err("absent"),
        ),
    ] {
        assert_eq!(error.category(), "not_found", "{what}");
    }
    store.register(declared("auto:nightly")).expect("register");
    for (what, error) in [
        (
            "admit at a negative instant",
            store
                .admit_occurrence("auto:nightly", -1)
                .expect_err("negative"),
        ),
        (
            "advance to a negative successor",
            store
                .advance_after_start("auto:nightly", 61_000, Some(-1))
                .expect_err("negative"),
        ),
        (
            "admit an ungrammatical identity",
            store
                .admit_occurrence("", 61_000)
                .expect_err("empty identity"),
        ),
    ] {
        assert_eq!(error.category(), "invalid_field", "{what}");
    }
    // A paused automation admits nothing, and says the row is not where the
    // caller believed rather than that it is unregistered.
    store
        .transition(change(
            "auto:nightly",
            1,
            EnablementState::Paused,
            "ops:ada",
            Some("held"),
        ))
        .expect("pause");
    assert_eq!(
        store
            .admit_occurrence("auto:nightly", 61_000)
            .expect_err("withdrawn")
            .category(),
        "occurrence_mismatch"
    );
    // The occurrence bookkeeping survived the pause untouched, and the row is
    // still not due because it is withdrawn.
    assert_eq!(job_of(&store, "auto:nightly").next_fire_at_ms, Some(61_000));
    assert!(store.due(i64::MAX, 8).expect("due").is_empty());
}

/// The bookkeeping is durable: what one handle admitted, a fresh handle on the
/// same file finds active, which is what a restarted worker reconciles from.
#[test]
fn an_active_occurrence_survives_close_and_reopen() {
    let private = PrivateRegistry::new();
    let mut store = AutomationStore::open(private.path()).expect("open");
    store.register(declared("auto:nightly")).expect("register");
    store
        .admit_occurrence("auto:nightly", 61_000)
        .expect("admit");
    assert!(
        store
            .advance_after_start("auto:nightly", 61_000, Some(121_000))
            .expect("advance")
    );
    drop(store);

    let mut reopened = AutomationStore::open(private.path()).expect("reopen");
    let active = reopened.active_occurrences(8).expect("active");
    assert_eq!(identities(&active), vec!["auto:nightly"]);
    let job = active[0].job.clone().expect("a job");
    assert_eq!(job.active_occurrence_ms, Some(61_000));
    assert_eq!(job.next_fire_at_ms, Some(121_000));
    assert!(reopened.due(i64::MAX, 8).expect("due").is_empty());
    reopened
        .settle_occurrence("auto:nightly", 61_000, true)
        .expect("the reopened handle settles what the first admitted");
    assert_eq!(
        job_of(&reopened, "auto:nightly").last_fired_at_ms,
        Some(61_000)
    );
}

#[test]
fn the_two_schedule_spellings_are_the_stored_vocabulary() {
    assert_eq!(AutomationSchedule::Once { at_ms: 0 }.kind(), "once");
    assert_eq!(AutomationSchedule::Every { interval_ms: 1 }.kind(), "every");
    let (private, mut store) = registry();
    store.register(declared("auto:every")).expect("register");
    store
        .register(AutomationRegistration {
            automation_id: "auto:once",
            actor: "ops:ada",
            now_ms: 1_000,
            job: AutomationJobSpec {
                schedule: AutomationSchedule::Once { at_ms: 5_000 },
                first_fire_at_ms: 5_000,
                ..job()
            },
        })
        .expect("register");
    drop(store);
    let raw = Connection::open(private.path()).expect("raw read");
    let kinds: Vec<(String, String)> = raw
        .prepare("SELECT automation_id, schedule_kind FROM automations ORDER BY entry_id")
        .expect("statement")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("kinds");
    assert_eq!(
        kinds,
        vec![
            ("auto:every".to_owned(), "every".to_owned()),
            ("auto:once".to_owned(), "once".to_owned()),
        ]
    );
}
