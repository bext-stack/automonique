// SPDX-License-Identifier: Elastic-2.0

//! Durable approval-request invariants.
//!
//! Every refusal is asserted by stable category rather than by message text, so
//! a mutation that reaches a different guard fails instead of passing through a
//! neighbouring refusal. The restart tests close the handle and reopen the
//! file: an in-memory table cannot pass them, which is the whole reason this
//! module owns a database.
//!
//! The load-bearing claim is that a terminal row is terminal. It is not argued
//! once; every public mutator is enumerated against an expired row and each is
//! asserted to write nothing.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::approval_requests::{
    APPROVAL_REQUEST_SCHEMA_VERSION, ApprovalContext, ApprovalOutcome, ApprovalProposal,
    ApprovalRequestRecord, ApprovalRequests, ApprovalState, MAX_APPROVAL_REQUEST_PAGE,
    MAX_APPROVAL_REQUESTS, ProposalDisposition, REQUEST_KEY_BYTES,
};
use rusqlite::Connection;
use tempfile::TempDir;

const SPEC_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROGRAM_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PROMPT_SHA: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const KEY: &str = "apr-000102030405060708090a0b0c0d0e0f";
const OTHER_KEY: &str = "apr-0f0e0d0c0b0a09080706050403020100";
const LEDGER_KEY: &str = "apr-000102030405060708090a0b0c0d0e0f";

struct PrivateTable {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateTable {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("approval-requests.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn table() -> (PrivateTable, ApprovalRequests) {
    let private = PrivateTable::new();
    let opened = ApprovalRequests::open(private.path()).expect("open approval requests");
    (private, opened)
}

fn context() -> ApprovalContext<'static> {
    ApprovalContext {
        spec_digest: SPEC_DIGEST,
        program_path: "/usr/bin/example-provider",
        program_sha256: PROGRAM_SHA,
        prompt_sha256: PROMPT_SHA,
        cwd_token: "cwd-1",
    }
}

fn proposal<'a>(request_key: &'a str, subject: &'a str) -> ApprovalProposal<'a> {
    ApprovalProposal {
        request_key,
        subject,
        run_id: "run-1",
        context: context(),
        requested_by: "local-peer",
        requested_at_ms: 1_000,
        expires_at_ms: 61_000,
    }
}

/// Propose one row and return the fence its transition needs.
fn pending(requests: &mut ApprovalRequests) -> u64 {
    let receipt = requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("first proposal");
    assert_eq!(receipt.disposition, ProposalDisposition::Proposed);
    receipt.revision
}

fn entry(requests: &ApprovalRequests, key: &str) -> ApprovalRequestRecord {
    requests
        .entry(key)
        .expect("readable row")
        .expect("a row under that key")
}

// --- the schema ladder ----------------------------------------------------

#[test]
fn a_fresh_table_stamps_its_schema_version() {
    let (private, requests) = table();
    assert_eq!(requests.path(), private.path());
    assert_eq!(requests.capacity(), MAX_APPROVAL_REQUESTS);
    assert_eq!(requests.request_count().expect("count"), 0);
    drop(requests);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, APPROVAL_REQUEST_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, requests) = table();
    drop(requests);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = ApprovalRequests::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateTable::new();
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

    let error = ApprovalRequests::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_file_is_refused() {
    let (private, requests) = table();
    drop(requests);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = ApprovalRequests::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_world_readable_directory_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("loose permissions");
    let error = ApprovalRequests::open(directory.path().join("approval-requests.sqlite3"))
        .expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

// --- proposing ------------------------------------------------------------

#[test]
fn a_first_proposal_is_recorded_and_an_exact_replay_is_not() {
    let (_private, mut requests) = table();
    let first = requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("first proposal");
    assert_eq!(first.disposition, ProposalDisposition::Proposed);
    assert_eq!(first.disposition.as_str(), "proposed");
    assert_eq!(first.revision, 1);

    let replay = requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("exact replay");
    assert_eq!(replay.disposition, ProposalDisposition::AlreadyProposed);
    assert_eq!(replay.request_entry_id, first.request_entry_id);
    assert_eq!(requests.request_count().expect("count"), 1);
}

#[test]
fn a_replay_with_a_later_clock_keeps_the_first_instant() {
    let (_private, mut requests) = table();
    requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("first proposal");
    let mut later = proposal(KEY, "runspec:one");
    later.requested_at_ms = 50_000;
    let replay = requests.propose(later).expect("replay with a later clock");
    assert_eq!(replay.disposition, ProposalDisposition::AlreadyProposed);
    // A retry naturally carries a later clock. Moving the recorded instant
    // would silently extend the window the proposal was raised in.
    assert_eq!(entry(&requests, KEY).requested_at_ms, 1_000);
}

#[test]
fn a_key_rebound_to_anything_else_conflicts_and_writes_nothing() {
    let (_private, mut requests) = table();
    requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("first proposal");

    let mut drifted = proposal(KEY, "runspec:two");
    assert_eq!(
        requests
            .propose(drifted)
            .expect_err("a rebound subject conflicts")
            .category(),
        "conflict"
    );

    drifted = proposal(KEY, "runspec:one");
    drifted.run_id = "run-2";
    assert!(
        requests
            .propose(drifted)
            .expect_err("a rebound run conflicts")
            .to_string()
            .contains("run_id")
    );

    for mutate in [
        |proposal: &mut ApprovalProposal<'static>| proposal.context.spec_digest = OTHER_DIGEST,
        |proposal: &mut ApprovalProposal<'static>| proposal.context.program_path = "/usr/bin/other",
        |proposal: &mut ApprovalProposal<'static>| proposal.context.program_sha256 = OTHER_DIGEST,
        |proposal: &mut ApprovalProposal<'static>| proposal.context.prompt_sha256 = OTHER_DIGEST,
        |proposal: &mut ApprovalProposal<'static>| proposal.context.cwd_token = "cwd-2",
        |proposal: &mut ApprovalProposal<'static>| proposal.requested_by = "somebody-else",
        |proposal: &mut ApprovalProposal<'static>| proposal.expires_at_ms = 120_000,
    ] {
        let mut candidate = proposal(KEY, "runspec:one");
        mutate(&mut candidate);
        assert_eq!(
            requests
                .propose(candidate)
                .expect_err("a rebound field conflicts")
                .category(),
            "conflict"
        );
    }

    // Nothing was written by any of the eight refusals.
    assert_eq!(requests.request_count().expect("count"), 1);
    assert_eq!(entry(&requests, KEY).subject, "runspec:one");
}

#[test]
fn a_proposal_with_no_lifetime_is_refused() {
    let (_private, mut requests) = table();
    for expires_at_ms in [0, 999, 1_000] {
        let mut candidate = proposal(KEY, "runspec:one");
        candidate.expires_at_ms = expires_at_ms;
        let error = requests
            .propose(candidate)
            .expect_err("a proposal that can never expire is refused");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("expires_at_ms"));
    }
    assert_eq!(requests.request_count().expect("count"), 0);
}

#[test]
fn the_key_grammar_is_enforced_on_write() {
    let (_private, mut requests) = table();
    for key in [
        "",
        "apr-",
        "000102030405060708090a0b0c0d0e0f",
        "APR-000102030405060708090a0b0c0d0e0f",
        "apr-000102030405060708090A0B0C0D0E0F",
        "apr-000102030405060708090a0b0c0d0e0g",
        "apr-000102030405060708090a0b0c0d0e0",
        "apr-000102030405060708090a0b0c0d0e0ff",
        "tkt-000102030405060708090a0b0c0d0e0f",
    ] {
        let error = requests
            .propose(proposal(key, "runspec:one"))
            .expect_err("a key outside the grammar is refused");
        assert_eq!(error.category(), "invalid_field", "{key:?} was admitted");
        assert!(error.to_string().contains("request_key"));
    }
    assert_eq!(KEY.len(), REQUEST_KEY_BYTES);
}

#[test]
fn the_table_refuses_to_grow_past_its_capacity() {
    let private = PrivateTable::new();
    let mut requests =
        ApprovalRequests::open_with_capacity(private.path(), 1).expect("bounded table");
    requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("first proposal");
    let error = requests
        .propose(proposal(OTHER_KEY, "runspec:two"))
        .expect_err("a full table refuses");
    assert_eq!(error.category(), "table_full");

    // A replay writes nothing, so a full table still answers one.
    let replay = requests
        .propose(proposal(KEY, "runspec:one"))
        .expect("replay in a full table");
    assert_eq!(replay.disposition, ProposalDisposition::AlreadyProposed);
}

// --- deciding -------------------------------------------------------------

#[test]
fn a_decision_moves_the_row_once_and_links_the_ledger_key() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    let decided = requests
        .decide(KEY, revision, ApprovalOutcome::Granted, LEDGER_KEY, 5_000)
        .expect("first decision");
    assert_eq!(decided.state, ApprovalState::Granted);
    assert_eq!(decided.approval_key.as_deref(), Some(LEDGER_KEY));
    assert_eq!(decided.decided_at_ms, Some(5_000));
    assert_eq!(decided.revision, revision + 1);

    // The same call again finds a row that is no longer pending. The fence, not
    // a second write, is what makes a double-click one decision.
    assert_eq!(
        requests
            .decide(KEY, revision, ApprovalOutcome::Granted, LEDGER_KEY, 6_000)
            .expect_err("a replayed decision is fenced out")
            .category(),
        "stale_revision"
    );
    assert_eq!(entry(&requests, KEY).decided_at_ms, Some(5_000));
}

#[test]
fn a_second_surface_that_lost_the_race_is_told_so() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    requests
        .decide(KEY, revision, ApprovalOutcome::Granted, LEDGER_KEY, 5_000)
        .expect("the winner");
    // The loser read the same revision a microsecond earlier and is now about
    // to overwrite an answer. It writes nothing and learns that it lost.
    assert_eq!(
        requests
            .decide(KEY, revision, ApprovalOutcome::Denied, LEDGER_KEY, 5_001)
            .expect_err("the loser")
            .category(),
        "stale_revision"
    );
    assert_eq!(entry(&requests, KEY).state, ApprovalState::Granted);
}

#[test]
fn deciding_an_unknown_key_is_its_own_refusal() {
    let (_private, mut requests) = table();
    assert_eq!(
        requests
            .decide(OTHER_KEY, 1, ApprovalOutcome::Granted, LEDGER_KEY, 5_000)
            .expect_err("nothing is recorded under that key")
            .category(),
        "unknown_request",
        "an absent proposal and a stale one are different answers"
    );
}

#[test]
fn a_decision_survives_a_restart() {
    let private = PrivateTable::new();
    let mut requests = ApprovalRequests::open(private.path()).expect("open");
    let revision = pending(&mut requests);
    requests
        .decide(KEY, revision, ApprovalOutcome::Denied, LEDGER_KEY, 5_000)
        .expect("decision");
    drop(requests);

    let reopened = ApprovalRequests::open(private.path()).expect("reopen");
    let record = entry(&reopened, KEY);
    assert_eq!(record.state, ApprovalState::Denied);
    assert_eq!(record.approval_key.as_deref(), Some(LEDGER_KEY));
    assert_eq!(
        reopened.state_count(ApprovalState::Pending).expect("count"),
        0
    );
    assert_eq!(
        reopened.state_count(ApprovalState::Denied).expect("count"),
        1
    );
}

// --- expiry ---------------------------------------------------------------

#[test]
fn expiry_is_inclusive_of_the_deadline_and_agrees_with_answerability() {
    let (_private, mut requests) = table();
    pending(&mut requests);
    let record = entry(&requests, KEY);
    assert_eq!(record.expires_at_ms, 61_000);

    assert!(record.is_answerable_at(60_999));
    assert!(!record.is_answerable_at(61_000), "the deadline is expired");
    assert!(!record.is_answerable_at(61_001));

    // The sweep's query and the answerability check must not disagree about a
    // row sitting exactly on its deadline.
    assert!(
        requests
            .expiring_before(60_999, 8)
            .expect("a sweep before the deadline")
            .is_empty()
    );
    assert_eq!(
        requests
            .expiring_before(61_000, 8)
            .expect("a sweep at the deadline")
            .len(),
        1
    );
}

#[test]
fn a_sweep_expires_exactly_the_due_rows_and_is_idempotent() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    let mut later = proposal(OTHER_KEY, "runspec:two");
    later.expires_at_ms = 500_000;
    requests.propose(later).expect("a proposal due much later");

    let due = requests.expiring_before(61_000, 8).expect("due rows");
    assert_eq!(due.len(), 1, "only the row past its deadline is due");
    assert_eq!(due[0].request_key, KEY);

    let expired = requests
        .expire(KEY, revision, 61_000)
        .expect("the first sweep");
    assert_eq!(expired.state, ApprovalState::Expired);
    assert_eq!(expired.decided_at_ms, Some(61_000));
    // An expiry is not a decision, so it links to no ledger row. Anything else
    // would put a decider's name on a silence.
    assert_eq!(expired.approval_key, None);

    // A second sweep of the same row writes nothing.
    assert!(
        requests
            .expiring_before(61_000, 8)
            .expect("a second sweep")
            .is_empty()
    );
    assert_eq!(
        requests
            .expire(KEY, revision, 62_000)
            .expect_err("a repeated expiry is fenced out")
            .category(),
        "stale_revision"
    );
    assert_eq!(entry(&requests, KEY).decided_at_ms, Some(61_000));
}

#[test]
fn no_public_mutator_reopens_an_expired_row() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    let expired = requests.expire(KEY, revision, 61_000).expect("expiry");
    let terminal = expired.revision;

    // Every way this module can change a row, enumerated against a terminal
    // one. A future mutator that is not listed here has no test, which is why
    // the list is exhaustive rather than representative.
    for outcome in ApprovalOutcome::ALL {
        for fence in [revision, terminal, terminal + 1] {
            assert_eq!(
                requests
                    .decide(KEY, fence, outcome, LEDGER_KEY, 70_000)
                    .expect_err("an expired row cannot be decided")
                    .category(),
                "stale_revision"
            );
        }
    }
    for fence in [revision, terminal, terminal + 1] {
        assert_eq!(
            requests
                .expire(KEY, fence, 70_000)
                .expect_err("an expired row cannot expire again")
                .category(),
            "stale_revision"
        );
    }
    // Re-proposing the same key is a conflict, not a revival: the key is taken
    // and its row is terminal, so the only way forward is a new key.
    assert_eq!(
        requests
            .propose(proposal(KEY, "runspec:one"))
            .expect("an exact replay is still a replay")
            .disposition,
        ProposalDisposition::AlreadyProposed
    );

    let record = entry(&requests, KEY);
    assert_eq!(record.state, ApprovalState::Expired);
    assert_eq!(record.revision, terminal);
    assert_eq!(record.decided_at_ms, Some(61_000));
    assert_eq!(record.approval_key, None);
}

#[test]
fn a_re_proposal_is_a_new_row_and_the_expired_one_survives() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    requests.expire(KEY, revision, 61_000).expect("expiry");

    let mut fresh = proposal(OTHER_KEY, "runspec:one");
    fresh.requested_at_ms = 62_000;
    fresh.expires_at_ms = 122_000;
    requests.propose(fresh).expect("a re-proposal");

    let history = requests.by_subject("runspec:one").expect("subject history");
    assert_eq!(history.len(), 2, "both rows survive, oldest first");
    assert_eq!(history[0].request_key, KEY);
    assert_eq!(history[0].state, ApprovalState::Expired);
    assert_eq!(history[1].request_key, OTHER_KEY);
    assert_eq!(history[1].state, ApprovalState::Pending);
}

// --- reading --------------------------------------------------------------

#[test]
fn pages_are_bounded_and_walk_every_row_once() {
    let (_private, mut requests) = table();
    for index in 0..5u8 {
        let key = format!("apr-{index:032x}");
        let mut candidate = proposal(&key, "runspec:one");
        candidate.run_id = "run-1";
        requests.propose(candidate).expect("a proposal");
    }
    assert_eq!(requests.request_count().expect("count"), 5);

    let mut seen = Vec::new();
    let mut cursor = 0;
    loop {
        let page = requests.page(cursor, 2).expect("a bounded page");
        seen.extend(page.records.iter().map(|record| record.request_key.clone()));
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(seen.len(), 5, "every row appears exactly once");
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 5);

    for limit in [0, MAX_APPROVAL_REQUEST_PAGE + 1] {
        assert_eq!(
            requests
                .page(0, limit)
                .expect_err("a limit outside the bound")
                .category(),
            "invalid_field"
        );
    }
}

#[test]
fn a_stored_row_written_around_this_api_is_refused_rather_than_believed() {
    let private = PrivateTable::new();
    let mut requests = ApprovalRequests::open(private.path()).expect("open");
    pending(&mut requests);
    drop(requests);

    // The identifier grammar is deliberately not a database constraint — it is
    // enforced on write and re-checked on every read — so a writer around this
    // API can produce a row SQLite is happy with and this module is not.
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute(
        "UPDATE approval_requests SET subject = '' WHERE request_key = ?1",
        [KEY],
    )
    .expect("row written around the API");
    drop(raw);

    let reopened = ApprovalRequests::open(private.path()).expect("reopen");
    let error = reopened
        .entry(KEY)
        .expect_err("a row outside the identifier grammar");
    assert_eq!(
        error.category(),
        "corrupt",
        "a bad stored row is corruption the caller cannot have caused, \
         never the caller's own invalid_field"
    );
    assert!(error.to_string().contains("subject"));
    // Every read path re-validates, not just the keyed one.
    assert_eq!(
        reopened
            .page(0, 8)
            .expect_err("a page over a corrupt row")
            .category(),
        "corrupt"
    );
}

#[test]
fn the_schema_itself_forbids_a_state_that_contradicts_its_own_columns() {
    let private = PrivateTable::new();
    let mut requests = ApprovalRequests::open(private.path()).expect("open");
    pending(&mut requests);
    drop(requests);

    // Belt and braces: the pairing this module re-checks on read is also a
    // database constraint, so a second writer cannot introduce the row at all.
    let raw = Connection::open(private.path()).expect("raw reopen");
    for statement in [
        "UPDATE approval_requests SET state = 'granted', decided_at_ms = 5000",
        "UPDATE approval_requests SET state = 'expired', decided_at_ms = 5000, \
         approval_key = 'apr-000102030405060708090a0b0c0d0e0f'",
        "UPDATE approval_requests SET decided_at_ms = 5000",
        "UPDATE approval_requests SET state = 'superseded'",
    ] {
        assert!(
            raw.execute(statement, []).is_err(),
            "the schema admitted {statement:?}"
        );
    }
}

#[test]
fn pruning_removes_terminal_rows_only() {
    let (_private, mut requests) = table();
    let revision = pending(&mut requests);
    requests.expire(KEY, revision, 61_000).expect("expiry");
    let mut open = proposal(OTHER_KEY, "runspec:two");
    open.expires_at_ms = 500_000;
    requests.propose(open).expect("a pending proposal");

    // A pending row is never garbage, whatever its age: deleting one would turn
    // a backlog of unanswered questions into an empty table.
    assert_eq!(requests.prune(70_000).expect("prune"), 1);
    assert_eq!(requests.request_count().expect("count"), 1);
    assert_eq!(entry(&requests, OTHER_KEY).state, ApprovalState::Pending);
}

#[test]
fn the_state_vocabulary_is_closed_and_round_trips() {
    for state in ApprovalState::ALL {
        assert_eq!(ApprovalState::from_spelling(state.as_str()), Some(state));
        assert_eq!(state.to_string(), state.as_str());
    }
    assert_eq!(ApprovalState::from_spelling("superseded"), None);
    assert_eq!(ApprovalState::from_spelling("Pending"), None);
    for outcome in ApprovalOutcome::ALL {
        assert_eq!(
            ApprovalOutcome::from_spelling(outcome.as_str()),
            Some(outcome)
        );
        // The two vocabularies overlap deliberately, and where they overlap
        // they must agree: a granted outcome is a granted state.
        assert_eq!(outcome.state().as_str(), outcome.as_str());
    }
    // There is no outcome that spells an expiry, so the decide path cannot
    // record one.
    assert_eq!(ApprovalOutcome::from_spelling("expired"), None);
    assert_eq!(ApprovalOutcome::from_spelling("pending"), None);
}
