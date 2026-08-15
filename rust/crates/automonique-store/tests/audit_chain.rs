// SPDX-License-Identifier: Elastic-2.0

//! Durable audit chain invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the chain and reopen
//! the file: an in-memory chain cannot pass them, which is the whole reason
//! this module exists.
//!
//! Append-only is asserted from both sides everywhere it matters: the answer
//! the call returns *and* the durable rows and row count afterwards. An
//! implementation that answered `AlreadyRecorded` while inserting a second row,
//! or that answered `ChainBroken` after writing anyway, would satisfy only the
//! first half.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise
//! stop them. That is the point: a CHECK protects the database from a second
//! writer, and the read path must protect *callers* from a row that got in
//! anyway.
//!
//! Records are built here through `automonique_protocol::audit`, which is where
//! the hashing lives. That is not a dependency this crate's library modules
//! take, and deliberately so — but a test that hand-wrote hashes would be
//! proving the chain against a second implementation of the thing under test.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_protocol::audit::{AuditCategory, AuditEvent, AuditOutcome, AuditRecord};
use automonique_store::audit_chain::{
    AUDIT_CHAIN_SCHEMA_VERSION, AuditAppend, AuditChain, AuditDisposition, GENESIS_PREV_HASH,
    MAX_AUDIT_PAGE, MAX_AUDIT_RECORDS, MAX_IDENTIFIER_BYTES,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

struct PrivateChain {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateChain {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("audit-chain.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Create the database file the way this module would, before a raw
    /// connection writes to it.
    ///
    /// `Connection::open` creates under the process umask, which is not
    /// private, and this module refuses a database it cannot vouch for. A test
    /// that hand-writes a file has to establish the mode itself, or it proves
    /// only that the privacy check works.
    fn create_private(&self) {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
            .expect("private file");
    }
}

fn opened() -> (PrivateChain, AuditChain) {
    let private = PrivateChain::new();
    let chain = AuditChain::open(private.path()).expect("open chain");
    (private, chain)
}

/// One record built for `subject`, at the position the chain is currently at.
fn built(chain: &AuditChain, subject: &str) -> AuditRecord {
    let (seq, prev) = chain.head().expect("head").map_or_else(
        || (1, GENESIS_PREV_HASH.to_owned()),
        |head| (head.seq + 1, head.record_hash),
    );
    AuditRecord::link(
        seq,
        &prev,
        AuditEvent {
            recorded_at: "2026-08-15T12:00:00Z",
            actor: "operator:ada",
            surface: "admin.socket",
            category: AuditCategory::Approval,
            subject,
            outcome: AuditOutcome::Success,
        },
    )
    .expect("record")
}

/// The append one record names. Borrowed from values the caller must keep
/// alive, which is why the two hashes and the body are bound outside.
fn appendable<'a>(
    record: &'a AuditRecord,
    record_id: &'a str,
    body: &'a [u8],
    record_hash: &'a str,
) -> AuditAppend<'a> {
    AuditAppend {
        record_id,
        recorded_at: record.recorded_at(),
        actor: record.actor(),
        surface: record.surface(),
        category: record.category().as_str(),
        subject: record.subject(),
        outcome: record.outcome().as_str(),
        body,
        prev_hash: record.prev_hash(),
        record_hash,
    }
}

/// Append one record for `subject` and return its durable identity.
fn append(chain: &mut AuditChain, subject: &str) -> (u64, AuditDisposition, String) {
    let record = built(chain, subject);
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash();
    let receipt = chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect("append");
    (receipt.seq, receipt.disposition, record_id)
}

/// Append `count` records with distinguishable subjects.
fn fill(chain: &mut AuditChain, count: u64) {
    for index in 1..=count {
        append(chain, &format!("run:{index}"));
    }
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_chain_stamps_its_schema_version() {
    let (private, chain) = opened();
    assert_eq!(chain.path(), private.path());
    assert_eq!(chain.capacity(), MAX_AUDIT_RECORDS);
    assert_eq!(chain.record_count().expect("count"), 0);
    assert_eq!(chain.head().expect("head"), None);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, AUDIT_CHAIN_SCHEMA_VERSION);
}

#[test]
fn the_schema_version_this_module_owns_is_stable() {
    // A bump here is a migration decision, not an implementation detail.
    assert_eq!(AUDIT_CHAIN_SCHEMA_VERSION, 1);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, chain) = opened();
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999_u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = AuditChain::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_non_empty_database_without_this_schema_is_refused() {
    let private = PrivateChain::new();
    private.create_private();
    let raw = Connection::open(private.path()).expect("raw create");
    raw.execute_batch("CREATE TABLE something_else (id INTEGER PRIMARY KEY) STRICT;")
        .expect("foreign table");
    drop(raw);

    let error = AuditChain::open(private.path()).expect_err("foreign database refusal");
    assert_eq!(error.category(), "schema_version");
}

/// A v1 database this build did not create still opens, and keeps its rows.
///
/// The schema is written out here by hand rather than imported, because that is
/// the only way this test can be about a database this build did not write.
/// This is the migration-replay proof for a ladder whose only rung is v1: the
/// property it pins is that a stamped v1 file is admitted unchanged, so a
/// future v2 has something to migrate *from*.
#[test]
fn a_hand_written_v1_database_opens_and_keeps_every_row() {
    let private = PrivateChain::new();
    let record = AuditRecord::link(
        1,
        GENESIS_PREV_HASH,
        AuditEvent {
            recorded_at: "2026-08-15T12:00:00Z",
            actor: "operator:ada",
            surface: "admin.socket",
            category: AuditCategory::Cancellation,
            subject: "run:old",
            outcome: AuditOutcome::Success,
        },
    )
    .expect("record");

    private.create_private();
    let raw = Connection::open(private.path()).expect("raw create");
    raw.execute_batch(
        "CREATE TABLE audit_records (
            seq INTEGER PRIMARY KEY CHECK (seq >= 1),
            record_id TEXT NOT NULL UNIQUE,
            recorded_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            surface TEXT NOT NULL,
            category TEXT NOT NULL CHECK (
                category IN ('approval', 'action', 'override', 'cancellation',
                             'policy', 'escalation')),
            subject TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (
                outcome IN ('success', 'failure', 'timeout', 'denied', 'escalated')),
            body BLOB NOT NULL CHECK (length(body) > 0),
            prev_hash TEXT NOT NULL
                CHECK (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
            record_hash TEXT NOT NULL UNIQUE
                CHECK (length(record_hash) = 64 AND record_hash NOT GLOB '*[^0-9a-f]*'),
            revision INTEGER NOT NULL CHECK (revision = 1)
        ) STRICT;
        CREATE INDEX audit_records_by_subject ON audit_records(subject, seq);",
    )
    .expect("v1 schema");
    raw.execute(
        "INSERT INTO audit_records
         (seq, record_id, recorded_at, actor, surface, category, subject, outcome,
          body, prev_hash, record_hash, revision)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
        params![
            record.record_id(),
            record.recorded_at(),
            record.actor(),
            record.surface(),
            record.category().as_str(),
            record.subject(),
            record.outcome().as_str(),
            record.to_canonical_bytes(),
            record.prev_hash(),
            record.record_hash(),
        ],
    )
    .expect("v1 row");
    raw.pragma_update(None, "user_version", AUDIT_CHAIN_SCHEMA_VERSION)
        .expect("stamp v1");
    drop(raw);

    let mut opened = AuditChain::open(private.path()).expect("a v1 database opens");
    let entry = opened.entry(1).expect("read").expect("the v1 row survived");
    assert_eq!(entry.subject, "run:old");
    assert_eq!(entry.category, "cancellation");
    assert_eq!(entry.record_hash, record.record_hash());
    assert_eq!(opened.verify_structure().expect("structure"), 1);

    // The opened database is the schema this build writes, not merely one that
    // opens: the next append continues the chain it found.
    let (seq, disposition, _) = append(&mut opened, "run:new");
    assert_eq!(seq, 2);
    assert_eq!(disposition, AuditDisposition::Recorded);
    assert_eq!(opened.verify_structure().expect("structure"), 2);
}

#[test]
fn a_world_readable_chain_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("permissive permissions");
    let error = AuditChain::open(directory.path().join("audit-chain.sqlite3"))
        .expect_err("insecure path refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_capacity_outside_its_range_is_refused() {
    let private = PrivateChain::new();
    for capacity in [0, MAX_AUDIT_RECORDS + 1] {
        let error =
            AuditChain::open_with_capacity(private.path(), capacity).expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Appending, replaying and conflicting
// ---------------------------------------------------------------------------

#[test]
fn the_first_record_links_to_sixty_four_zeros_and_takes_seq_one() {
    let (_private, mut chain) = opened();
    let (seq, disposition, record_id) = append(&mut chain, "run:alpha");
    assert_eq!(seq, 1);
    assert_eq!(disposition, AuditDisposition::Recorded);

    let entry = chain.entry(1).expect("read").expect("present");
    assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
    assert_eq!(entry.record_id, record_id);
    let head = chain
        .head()
        .expect("head")
        .expect("a head after one append");
    assert_eq!(head.seq, 1);
    assert_eq!(head.record_hash, entry.record_hash);
}

#[test]
fn each_record_links_to_the_one_before_it() {
    let (_private, mut chain) = opened();
    fill(&mut chain, 8);

    let page = chain.page(0, MAX_AUDIT_PAGE).expect("page");
    assert_eq!(page.entries.len(), 8);
    let mut expected_prev = GENESIS_PREV_HASH.to_owned();
    for (index, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
        assert_eq!(entry.prev_hash, expected_prev);
        expected_prev.clone_from(&entry.record_hash);
    }
    assert_eq!(chain.verify_structure().expect("structure"), 8);
}

#[test]
fn an_exact_replay_answers_already_recorded_and_writes_no_second_row() {
    let (_private, mut chain) = opened();
    let record = built(&chain, "run:alpha");
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash();

    let first = chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect("first append");
    assert_eq!(first.disposition, AuditDisposition::Recorded);

    let replay = chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect("replay");
    assert_eq!(replay.disposition, AuditDisposition::AlreadyRecorded);
    assert_eq!(replay.seq, first.seq);

    // The second half: a replay that inserted a second row would still have
    // answered AlreadyRecorded above.
    assert_eq!(chain.record_count().expect("count"), 1);
    assert_eq!(chain.head().expect("head").expect("head").seq, 1);
}

#[test]
fn an_exact_replay_after_close_and_reopen_is_already_recorded() {
    let private = PrivateChain::new();
    let (record, record_id, body, record_hash) = {
        let mut chain = AuditChain::open(private.path()).expect("open chain");
        let record = built(&chain, "run:alpha");
        let record_id = record.record_id();
        let body = record.to_canonical_bytes();
        let record_hash = record.record_hash();
        let receipt = chain
            .append(appendable(&record, &record_id, &body, &record_hash))
            .expect("first append");
        assert_eq!(receipt.disposition, AuditDisposition::Recorded);
        (record, record_id, body, record_hash)
    };

    // The whole point of the module: the answer survives the process that gave
    // it. An in-memory chain records a second, contradictory record here.
    let mut reopened = AuditChain::open(private.path()).expect("reopen chain");
    let replay = reopened
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect("replay");
    assert_eq!(replay.disposition, AuditDisposition::AlreadyRecorded);
    assert_eq!(replay.seq, 1);
    assert_eq!(reopened.record_count().expect("count"), 1);
}

#[test]
fn an_identifier_presented_with_a_different_record_conflicts_and_writes_nothing() {
    let (_private, mut chain) = opened();
    let record = built(&chain, "run:alpha");
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash();
    chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect("first append");

    let mut forged = appendable(&record, &record_id, &body, &record_hash);
    forged.subject = "run:beta";
    let error = chain.append(forged).expect_err("conflict refusal");
    assert_eq!(error.category(), "conflict");
    assert!(error.to_string().contains("subject"));
    assert!(error.to_string().contains(&record_hash));

    assert_eq!(chain.record_count().expect("count"), 1);
    assert_eq!(
        chain.entry(1).expect("read").expect("present").subject,
        "run:alpha",
        "a refused append must not have rewritten the durable row"
    );
}

#[test]
fn a_prev_hash_that_is_not_the_head_is_chain_broken_and_writes_nothing() {
    let (_private, mut chain) = opened();
    fill(&mut chain, 3);
    let head = chain.head().expect("head").expect("head");

    // A record built against the head as it was two appends ago.
    let stale = AuditRecord::link(
        4,
        &"a".repeat(64),
        AuditEvent {
            recorded_at: "2026-08-15T12:00:00Z",
            actor: "operator:ada",
            surface: "admin.socket",
            category: AuditCategory::Approval,
            subject: "run:stale",
            outcome: AuditOutcome::Success,
        },
    )
    .expect("record");
    let record_id = stale.record_id();
    let body = stale.to_canonical_bytes();
    let record_hash = stale.record_hash();

    let error = chain
        .append(appendable(&stale, &record_id, &body, &record_hash))
        .expect_err("chain broken refusal");
    assert_eq!(error.category(), "chain_broken");
    let rendered = error.to_string();
    assert!(rendered.contains(&head.record_hash), "{rendered}");
    assert!(rendered.contains("seq 4"), "{rendered}");

    assert_eq!(chain.record_count().expect("count"), 3);
    assert_eq!(chain.verify_structure().expect("structure"), 3);
}

#[test]
fn a_genesis_record_presented_to_a_non_empty_chain_is_chain_broken() {
    let (_private, mut chain) = opened();
    fill(&mut chain, 2);
    let record = AuditRecord::link(
        1,
        GENESIS_PREV_HASH,
        AuditEvent {
            recorded_at: "2026-08-15T12:00:00Z",
            actor: "operator:ada",
            surface: "admin.socket",
            category: AuditCategory::Approval,
            subject: "run:restart",
            outcome: AuditOutcome::Success,
        },
    )
    .expect("record");
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash();

    let error = chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect_err("a second genesis must be refused");
    assert_eq!(error.category(), "chain_broken");
    assert_eq!(chain.record_count().expect("count"), 2);
}

#[test]
fn a_full_chain_refuses_appends_but_still_replays_and_reads() {
    let private = PrivateChain::new();
    let mut chain = AuditChain::open_with_capacity(private.path(), 2).expect("open chain");
    fill(&mut chain, 2);

    let overflow = built(&chain, "run:third");
    let overflow_id = overflow.record_id();
    let overflow_body = overflow.to_canonical_bytes();
    let overflow_hash = overflow.record_hash();
    let error = chain
        .append(appendable(
            &overflow,
            &overflow_id,
            &overflow_body,
            &overflow_hash,
        ))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "chain_full");
    assert!(error.to_string().contains('2'));

    // A replay writes nothing, so a full chain must still answer one rather
    // than degrading into a refusal a retrying caller cannot tell from a real
    // one.
    let first = chain.entry(1).expect("read").expect("present");
    let replay = chain
        .append(AuditAppend {
            record_id: &first.record_id,
            recorded_at: &first.recorded_at,
            actor: &first.actor,
            surface: &first.surface,
            category: &first.category,
            subject: &first.subject,
            outcome: &first.outcome,
            body: &first.body,
            prev_hash: &first.prev_hash,
            record_hash: &first.record_hash,
        })
        .expect("a replay in a full chain");
    assert_eq!(replay.disposition, AuditDisposition::AlreadyRecorded);
    assert_eq!(chain.record_count().expect("count"), 2);
    assert_eq!(chain.verify_structure().expect("structure"), 2);
}

// ---------------------------------------------------------------------------
// Field admission
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_field_is_refused_by_name_and_nothing_is_written() {
    let (_private, mut chain) = opened();
    let record = built(&chain, "run:alpha");
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash();
    let long = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
    let good = appendable(&record, &record_id, &body, &record_hash);

    let mut candidates = Vec::new();
    for (field, spoiled) in [
        (
            "record_id",
            AuditAppend {
                record_id: "",
                ..good
            },
        ),
        (
            "actor",
            AuditAppend {
                actor: "ops\u{7}bell",
                ..good
            },
        ),
        (
            "category",
            AuditAppend {
                category: "maybe",
                ..good
            },
        ),
        (
            "outcome",
            AuditAppend {
                outcome: "probably",
                ..good
            },
        ),
        (
            "prev_hash",
            AuditAppend {
                prev_hash: "not-a-hash",
                ..good
            },
        ),
        ("body", AuditAppend { body: b"", ..good }),
        (
            "subject",
            AuditAppend {
                subject: &long,
                ..good
            },
        ),
    ] {
        candidates.push((field, spoiled));
    }
    for (field, candidate) in candidates {
        let error = chain.append(candidate).expect_err("field refusal");
        assert_eq!(error.category(), "invalid_field", "field {field}");
        assert!(error.to_string().contains(field), "field {field}");
    }

    assert_eq!(chain.record_count().expect("count"), 0);
}

#[test]
fn an_uppercase_hash_is_refused_rather_than_folded() {
    let (_private, mut chain) = opened();
    let record = built(&chain, "run:alpha");
    let record_id = record.record_id();
    let body = record.to_canonical_bytes();
    let record_hash = record.record_hash().to_uppercase();

    let error = chain
        .append(appendable(&record, &record_id, &body, &record_hash))
        .expect_err("case refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("record_hash"));
}

// ---------------------------------------------------------------------------
// Structural verification, and what it catches
// ---------------------------------------------------------------------------

#[test]
fn a_deleted_middle_record_leaves_a_gap_verify_structure_names() {
    let (private, mut chain) = opened();
    fill(&mut chain, 5);
    assert_eq!(chain.verify_structure().expect("structure"), 5);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute("DELETE FROM audit_records WHERE seq = 3", [])
        .expect("delete a middle record");
    drop(raw);

    let reopened = AuditChain::open(private.path()).expect("reopen");
    let error = reopened
        .verify_structure()
        .expect_err("a chain with a hole must not verify");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("seq_not_contiguous"));
}

#[test]
fn a_cut_link_is_named_as_such() {
    let (private, mut chain) = opened();
    fill(&mut chain, 4);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE audit_records SET prev_hash = ?1 WHERE seq = 3",
        params!["a".repeat(64)],
    )
    .expect("cut the link");
    drop(raw);

    let reopened = AuditChain::open(private.path()).expect("reopen");
    let error = reopened
        .verify_structure()
        .expect_err("a cut link must not verify");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("prev_hash_link"));
}

#[test]
fn a_genesis_that_does_not_link_to_zeros_is_named_separately() {
    let (private, mut chain) = opened();
    fill(&mut chain, 2);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE audit_records SET prev_hash = ?1 WHERE seq = 1",
        params!["b".repeat(64)],
    )
    .expect("rewrite the genesis link");
    drop(raw);

    let reopened = AuditChain::open(private.path()).expect("reopen");
    let error = reopened
        .verify_structure()
        .expect_err("a false genesis must not verify");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("genesis_prev_hash"));
}

// ---------------------------------------------------------------------------
// Rows written around this API
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_unknown_category_surfaces_as_corruption() {
    let (private, mut chain) = opened();
    fill(&mut chain, 1);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE audit_records SET category = 'maybe' WHERE seq = 1",
        [],
    )
    .expect_err("the column CHECK refuses a category outside the vocabulary");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE audit_records SET category = 'maybe' WHERE seq = 1",
        [],
    )
    .expect("smuggle category");
    drop(raw);

    // Every read path refuses it rather than guessing what 'maybe' meant.
    let reopened = AuditChain::open(private.path()).expect("reopen");
    let error = reopened.entry(1).expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("category"));
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
    assert_eq!(
        reopened
            .verify_structure()
            .expect_err("structure refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_control_character_actor_surfaces_as_corruption() {
    let (private, mut chain) = opened();
    fill(&mut chain, 1);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE audit_records SET actor = ?1 WHERE seq = 1",
        params!["ops:\u{7}bell"],
    )
    .expect("smuggle control character");
    drop(raw);

    let reopened = AuditChain::open(private.path()).expect("reopen");
    let error = reopened.entry(1).expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("actor"));
}

/// Append-only is a property of the table, not only of the write path.
#[test]
fn the_stored_revision_is_pinned_to_one_and_hashes_are_unique() {
    let (private, mut chain) = opened();
    fill(&mut chain, 2);
    drop(chain);

    let raw = Connection::open(private.path()).expect("raw write");
    for revision in [0, 2, -1] {
        raw.execute(
            "UPDATE audit_records SET revision = ?1 WHERE seq = 1",
            params![revision],
        )
        .expect_err("the column CHECK admits exactly one revision");
    }

    // A second row cannot claim a position, an identifier, or a hash that is
    // already taken, so a writer cannot fork the chain without deleting first.
    let first: (String, String) = raw
        .query_row(
            "SELECT record_id, record_hash FROM audit_records WHERE seq = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read first");
    raw.execute(
        "UPDATE audit_records SET record_hash = ?1 WHERE seq = 2",
        params![first.1],
    )
    .expect_err("record_hash is unique");
    raw.execute(
        "UPDATE audit_records SET record_id = ?1 WHERE seq = 2",
        params![first.0],
    )
    .expect_err("record_id is unique");
    raw.execute("UPDATE audit_records SET seq = 1 WHERE seq = 2", [])
        .expect_err("seq is the primary key");
    raw.execute("UPDATE audit_records SET seq = 0 WHERE seq = 2", [])
        .expect_err("the column CHECK admits no seq below one");
    raw.execute(
        "UPDATE audit_records SET prev_hash = 'short' WHERE seq = 2",
        [],
    )
    .expect_err("the column CHECK admits only a 64-digit hash");
    raw.execute(
        "UPDATE audit_records SET record_hash = ?1 WHERE seq = 2",
        params!["A".repeat(64)],
    )
    .expect_err("the column CHECK admits no uppercase hex");
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[test]
fn a_page_walks_the_whole_chain_in_order() {
    let (_private, mut chain) = opened();
    fill(&mut chain, 12);

    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = chain.page(cursor, 5).expect("page");
        seen.extend(page.entries.iter().map(|entry| entry.seq));
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(seen, (1..=12).collect::<Vec<u64>>());
}

#[test]
fn a_cursor_past_the_end_is_refused_by_name() {
    let (_private, mut chain) = opened();
    fill(&mut chain, 3);
    let error = chain.page(9, 5).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains('3'));
}

#[test]
fn a_limit_outside_its_range_is_refused() {
    let (_private, chain) = opened();
    for limit in [0, MAX_AUDIT_PAGE + 1] {
        let error = chain.page(0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));
    }
}

#[test]
fn a_record_is_reachable_by_its_identifier_and_by_its_position() {
    let (_private, mut chain) = opened();
    let (seq, _, record_id) = append(&mut chain, "run:alpha");

    let by_seq = chain.entry(seq).expect("read").expect("present");
    let by_id = chain.record(&record_id).expect("read").expect("present");
    assert_eq!(by_seq, by_id);
    assert_eq!(by_seq.subject, "run:alpha");

    assert_eq!(chain.entry(99).expect("read"), None);
    assert_eq!(chain.record("aud-nothing").expect("read"), None);
    assert_eq!(
        chain.entry(0).expect_err("zero seq refusal").category(),
        "invalid_field"
    );
}
