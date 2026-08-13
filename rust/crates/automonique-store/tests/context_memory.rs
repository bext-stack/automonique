// SPDX-License-Identifier: Elastic-2.0

//! Durable context memory item invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the store and reopen
//! the file: an in-memory store cannot pass them, which is the whole reason this
//! module exists.
//!
//! Write-once is asserted from both sides everywhere it matters: the answer the
//! call returns *and* the durable row and row count afterwards. An
//! implementation that answered `AlreadyRecorded` while inserting a second row,
//! or that answered `Conflict` after overwriting the binding, would satisfy only
//! the first half. The supersession tests do the same for the one amendment this
//! module offers: a stamp must leave the recorded binding byte-for-byte intact.
//!
//! Workspace scope is asserted the same way. It is not enough that a lookup in
//! the wrong workspace misses; the row it missed has to still be there, holding
//! its own binding, so a key that collided across workspaces fails here rather
//! than silently answering one project's question with another project's memory.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::context_memory::{
    CONTENT_DIGEST_CHARS, CONTEXT_MEMORY_SCHEMA_VERSION, ContextMemoryStore, Kept,
    MAX_MEMORY_FIELD_BYTES, MAX_MEMORY_ITEMS, MAX_MEMORY_PAGE, MemoryDisposition, MemoryItem,
    MemoryItemRecord, MemoryTrust, RetainedMemoryRange, SupersessionRequest,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

/// A 64-character lowercase hex digest, and a second one that differs.
const DIGEST_A: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DIGEST_B: &str = "1111111111111111111111111111111111111111111111111111111111111111";

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("context-memory.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn store() -> (PrivateStore, ContextMemoryStore) {
    let private = PrivateStore::new();
    let opened = ContextMemoryStore::open(private.path()).expect("open store");
    (private, opened)
}

fn captured<'a>(
    workspace: &'a str,
    memory_key: &'a str,
    label: &'a str,
    content_digest: &'a str,
    trust: MemoryTrust,
) -> MemoryItemRecord<'a> {
    MemoryItemRecord {
        workspace,
        memory_key,
        label,
        content_digest,
        trust,
        created_at_ms: 1_000,
    }
}

/// The canonical capture used wherever the fields themselves are not the subject
/// of the test.
fn lesson<'a>(workspace: &'a str, memory_key: &'a str) -> MemoryItemRecord<'a> {
    captured(
        workspace,
        memory_key,
        "workspace-convention:test-command",
        DIGEST_A,
        MemoryTrust::ActorSupplied,
    )
}

fn correction<'a>(
    workspace: &'a str,
    memory_key: &'a str,
    replacement_key: &'a str,
) -> SupersessionRequest<'a> {
    SupersessionRequest {
        workspace,
        memory_key,
        replacement_key,
        superseded_at_ms: 2_000,
    }
}

fn keys(entries: &[MemoryItem]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| entry.memory_key.as_str())
        .collect()
}

fn read(store: &ContextMemoryStore, workspace: &str, memory_key: &str) -> MemoryItem {
    store
        .item(workspace, memory_key)
        .expect("read item")
        .expect("item present")
}

/// The whole durable binding, as a comparable tuple, for "nothing was written"
/// assertions.
fn binding(
    store: &ContextMemoryStore,
    workspace: &str,
    memory_key: &str,
) -> (
    String,
    String,
    String,
    i64,
    u64,
    Option<String>,
    Option<i64>,
) {
    let item = read(store, workspace, memory_key);
    (
        item.label,
        item.content_digest,
        item.trust.as_str().to_owned(),
        item.created_at_ms,
        item.revision,
        item.superseded_by,
        item.superseded_at_ms,
    )
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_store_stamps_its_schema_version() {
    let (private, store) = store();
    assert_eq!(store.path(), private.path());
    assert_eq!(store.capacity(), MAX_MEMORY_ITEMS);
    assert_eq!(store.item_count().expect("count"), 0);
    assert_eq!(store.retained_range().expect("range"), None);
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, CONTEXT_MEMORY_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = ContextMemoryStore::open(private.path()).expect_err("schema refusal");
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

    let error = ContextMemoryStore::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_store_file_is_refused() {
    let (private, store) = store();
    drop(store);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = ContextMemoryStore::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_capacity_outside_its_range_is_refused() {
    let private = PrivateStore::new();
    for capacity in [0, MAX_MEMORY_ITEMS + 1] {
        let error = ContextMemoryStore::open_with_capacity(private.path(), capacity)
            .expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Recording, replay and conflict
// ---------------------------------------------------------------------------

#[test]
fn a_recorded_item_reads_back_with_every_field() {
    let (_private, mut store) = store();
    let receipt = store
        .record(captured(
            "acme/api",
            "mem:build-command",
            "workspace-convention:build",
            DIGEST_A,
            MemoryTrust::Compatibility,
        ))
        .expect("record");
    assert_eq!(receipt.disposition, MemoryDisposition::Recorded);
    assert_eq!(receipt.created_at_ms, 1_000);

    let item = read(&store, "acme/api", "mem:build-command");
    assert_eq!(item.entry_id, receipt.entry_id);
    assert_eq!(item.workspace, "acme/api");
    assert_eq!(item.memory_key, "mem:build-command");
    assert_eq!(item.label, "workspace-convention:build");
    assert_eq!(item.content_digest, DIGEST_A);
    assert_eq!(item.trust, MemoryTrust::Compatibility);
    assert_eq!(item.created_at_ms, 1_000);
    assert_eq!(item.revision, 1);
    assert_eq!(item.superseded_by, None);
    assert_eq!(item.superseded_at_ms, None);
    assert!(!item.is_superseded());
    assert_eq!(store.item_count().expect("count"), 1);
}

#[test]
fn an_exact_replay_writes_nothing() {
    let (_private, mut store) = store();
    let first = store.record(lesson("acme/api", "mem:1")).expect("record");
    let before = binding(&store, "acme/api", "mem:1");

    let replay = store.record(lesson("acme/api", "mem:1")).expect("replay");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);
    assert_eq!(store.item_count().expect("count"), 1);
    assert_eq!(binding(&store, "acme/api", "mem:1"), before);
}

#[test]
fn a_replay_carrying_a_later_clock_keeps_the_first_instant() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");

    let mut retried = lesson("acme/api", "mem:1");
    retried.created_at_ms = 9_999;
    let replay = store.record(retried).expect("replay");

    // A retry naturally carries a later clock. The receipt reports the first
    // recording's instant, and the durable row keeps it.
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.created_at_ms, 1_000);
    assert_eq!(read(&store, "acme/api", "mem:1").created_at_ms, 1_000);
}

#[test]
fn a_differing_binding_conflicts_and_writes_nothing() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    let before = binding(&store, "acme/api", "mem:1");

    let cases: [(MemoryItemRecord<'_>, &str); 3] = [
        (
            captured(
                "acme/api",
                "mem:1",
                "a-different-label",
                DIGEST_A,
                MemoryTrust::ActorSupplied,
            ),
            "label",
        ),
        (
            captured(
                "acme/api",
                "mem:1",
                "workspace-convention:test-command",
                DIGEST_B,
                MemoryTrust::ActorSupplied,
            ),
            "content_digest",
        ),
        (
            captured(
                "acme/api",
                "mem:1",
                "workspace-convention:test-command",
                DIGEST_A,
                MemoryTrust::Untrusted,
            ),
            "trust_class",
        ),
    ];
    for (presented, field) in cases {
        let error = store.record(presented).expect_err("conflict");
        assert_eq!(error.category(), "conflict");
        assert!(
            error.to_string().contains(field),
            "conflict should name {field}: {error}"
        );
        // The recorded binding travels with the refusal.
        assert!(error.to_string().contains(DIGEST_A));
        assert!(error.to_string().contains("actor_supplied"));
    }
    // Write-once from the other side: nothing moved, and no second row appeared.
    assert_eq!(binding(&store, "acme/api", "mem:1"), before);
    assert_eq!(store.item_count().expect("count"), 1);
}

#[test]
fn the_binding_survives_close_and_reopen() {
    let (private, mut store) = store();
    let first = store.record(lesson("acme/api", "mem:1")).expect("record");
    let before = binding(&store, "acme/api", "mem:1");
    drop(store);

    let mut reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    assert_eq!(binding(&reopened, "acme/api", "mem:1"), before);

    // Idempotency and write-once are properties of the file, not of the handle.
    let replay = reopened
        .record(lesson("acme/api", "mem:1"))
        .expect("replay after restart");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);

    let error = reopened
        .record(captured(
            "acme/api",
            "mem:1",
            "workspace-convention:test-command",
            DIGEST_B,
            MemoryTrust::ActorSupplied,
        ))
        .expect_err("conflict after restart");
    assert_eq!(error.category(), "conflict");
    assert_eq!(binding(&reopened, "acme/api", "mem:1"), before);
    assert_eq!(reopened.item_count().expect("count"), 1);
}

// ---------------------------------------------------------------------------
// The trust vocabulary
// ---------------------------------------------------------------------------

/// The spellings, the order and the absent fourth class are pinned by literal.
///
/// The authority is `automonique_protocol::context::TrustClass`, whose variants
/// are declared `Untrusted, Compatibility, ActorSupplied, Policy` in that order
/// with exactly these `as_str` spellings. This crate depends on `nix` and
/// `rusqlite` and cannot import that one, so the agreement is asserted here
/// rather than derived, and a rename on either side fails this test rather than
/// landing.
#[test]
fn the_trust_spellings_and_their_order_are_pinned() {
    assert_eq!(MemoryTrust::Untrusted.as_str(), "untrusted");
    assert_eq!(MemoryTrust::Compatibility.as_str(), "compatibility");
    assert_eq!(MemoryTrust::ActorSupplied.as_str(), "actor_supplied");
    assert_eq!(
        MemoryTrust::ALL,
        [
            MemoryTrust::Untrusted,
            MemoryTrust::Compatibility,
            MemoryTrust::ActorSupplied
        ]
    );
    // Least to most trusted, the protocol's declaration order.
    assert!(MemoryTrust::Untrusted < MemoryTrust::Compatibility);
    assert!(MemoryTrust::Compatibility < MemoryTrust::ActorSupplied);

    for trust in MemoryTrust::ALL {
        assert_eq!(MemoryTrust::from_spelling(trust.as_str()), Some(trust));
        assert_eq!(trust.to_string(), trust.as_str());
    }

    // The fourth class of the protocol's enum is not a value here. Memory enters
    // a manifest as a supplied component, and supplied content is never policy.
    assert_eq!(MemoryTrust::from_spelling("policy"), None);
    assert_eq!(MemoryTrust::from_spelling("Untrusted"), None);
    assert_eq!(MemoryTrust::from_spelling(""), None);
}

#[test]
fn the_stored_trust_text_is_the_pinned_spelling() {
    let (private, mut store) = store();
    for (index, trust) in MemoryTrust::ALL.into_iter().enumerate() {
        store
            .record(captured(
                "acme/api",
                &format!("mem:{index}"),
                "workspace-convention:test-command",
                DIGEST_A,
                trust,
            ))
            .expect("record");
    }
    drop(store);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let mut statement = raw
        .prepare("SELECT trust_class FROM memory_items ORDER BY entry_id")
        .expect("prepare");
    let stored: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|value| value.expect("column"))
        .collect();
    assert_eq!(stored, ["untrusted", "compatibility", "actor_supplied"]);
}

#[test]
fn a_hand_written_policy_trust_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE memory_items SET trust_class = 'policy' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect_err("the column CHECK has no policy spelling in it");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET trust_class = 'policy' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle a promoted trust class");
    drop(raw);

    // Every read path refuses it rather than guessing. In particular nothing
    // treats an unrecognised class as the lowest one and carries on.
    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("trust_class"));
    assert_eq!(
        reopened
            .page("acme/api", 0, 10)
            .expect_err("page refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_unknown_trust_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET trust_class = 'trusted' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle trust class");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("trust_class"));
}

// ---------------------------------------------------------------------------
// Workspace scope
// ---------------------------------------------------------------------------

#[test]
fn the_same_key_in_two_workspaces_is_two_items() {
    let (private, mut store) = store();
    let first = store
        .record(captured(
            "acme/api",
            "mem:build-command",
            "api-build",
            DIGEST_A,
            MemoryTrust::ActorSupplied,
        ))
        .expect("record in the first workspace");
    let second = store
        .record(captured(
            "acme/web",
            "mem:build-command",
            "web-build",
            DIGEST_B,
            MemoryTrust::Untrusted,
        ))
        .expect("record in the second workspace");

    // Two rows, not a replay and not a conflict: the key is unique within a
    // workspace, never host-wide.
    assert_ne!(first.entry_id, second.entry_id);
    assert_eq!(second.disposition, MemoryDisposition::Recorded);
    assert_eq!(store.item_count().expect("count"), 2);

    let api = read(&store, "acme/api", "mem:build-command");
    let web = read(&store, "acme/web", "mem:build-command");
    assert_eq!(api.label, "api-build");
    assert_eq!(api.content_digest, DIGEST_A);
    assert_eq!(api.trust, MemoryTrust::ActorSupplied);
    assert_eq!(web.label, "web-build");
    assert_eq!(web.content_digest, DIGEST_B);
    assert_eq!(web.trust, MemoryTrust::Untrusted);

    // A workspace that recorded nothing sees nothing, rather than seeing another
    // project's memory under the same key.
    assert_eq!(
        store
            .item("acme/mobile", "mem:build-command")
            .expect("read a workspace with no rows"),
        None
    );
    drop(store);

    // And the scope is a property of the file.
    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    assert_eq!(
        read(&reopened, "acme/api", "mem:build-command").content_digest,
        DIGEST_A
    );
    assert_eq!(
        read(&reopened, "acme/web", "mem:build-command").content_digest,
        DIGEST_B
    );
}

#[test]
fn a_page_is_scoped_to_one_workspace() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/web", "mem:2")).expect("record");
    store.record(lesson("acme/api", "mem:3")).expect("record");

    let api = store.page("acme/api", 0, 10).expect("page");
    assert_eq!(keys(&api.entries), vec!["mem:1", "mem:3"]);
    assert_eq!(api.next_cursor, None);
    assert!(
        api.entries
            .iter()
            .all(|entry| entry.workspace == "acme/api")
    );

    let web = store.page("acme/web", 0, 10).expect("page");
    assert_eq!(keys(&web.entries), vec!["mem:2"]);

    let empty = store.page("acme/mobile", 0, 10).expect("page");
    assert!(empty.entries.is_empty());
    assert_eq!(empty.next_cursor, None);
}

#[test]
fn a_corrupt_row_is_not_hidden_by_the_workspace_filter() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/web", "mem:2")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET trust_class = 'policy' WHERE workspace = 'acme/api'",
        [],
    )
    .expect("smuggle trust class");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    // The workspace that owns the row sees the corruption; the filter selects it
    // and therefore cannot hide it.
    assert_eq!(
        reopened
            .page("acme/api", 0, 10)
            .expect_err("page refusal")
            .category(),
        "corrupt"
    );
    // The other workspace's listing was never that row's answer, and it stays
    // readable rather than being poisoned by a neighbour.
    let web = reopened.page("acme/web", 0, 10).expect("page");
    assert_eq!(keys(&web.entries), vec!["mem:2"]);
}

#[test]
fn a_replacement_in_another_workspace_is_absent() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store
        .record(lesson("acme/web", "mem:2"))
        .expect("record elsewhere");

    let error = store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect_err("cross-workspace refusal");
    assert_eq!(error.category(), "not_found");
    assert!(error.to_string().contains("replacement"));
    // Nothing was stamped.
    assert!(!read(&store, "acme/api", "mem:1").is_superseded());
}

// ---------------------------------------------------------------------------
// Supersession
// ---------------------------------------------------------------------------

#[test]
fn superseding_stamps_the_row_without_touching_the_binding() {
    let (_private, mut store) = store();
    let original = store.record(lesson("acme/api", "mem:1")).expect("record");
    store
        .record(captured(
            "acme/api",
            "mem:2",
            "workspace-convention:test-command-v2",
            DIGEST_B,
            MemoryTrust::ActorSupplied,
        ))
        .expect("record the replacement");

    let receipt = store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");
    assert_eq!(receipt.entry_id, original.entry_id);
    assert_eq!(receipt.disposition, MemoryDisposition::Recorded);
    assert_eq!(receipt.superseded_at_ms, 2_000);
    assert_eq!(receipt.revision, 2);

    let item = read(&store, "acme/api", "mem:1");
    // The stamp, and only the stamp.
    assert_eq!(item.superseded_by.as_deref(), Some("mem:2"));
    assert_eq!(item.superseded_at_ms, Some(2_000));
    assert_eq!(item.revision, 2);
    assert!(item.is_superseded());
    // The corrected item stays exactly as it was captured: this is a correction,
    // not an edit, and the original evidence survives it.
    assert_eq!(item.label, "workspace-convention:test-command");
    assert_eq!(item.content_digest, DIGEST_A);
    assert_eq!(item.trust, MemoryTrust::ActorSupplied);
    assert_eq!(item.created_at_ms, 1_000);
    // The replacement is untouched and is not itself superseded.
    assert!(!read(&store, "acme/api", "mem:2").is_superseded());
    assert_eq!(store.item_count().expect("count"), 2);
}

#[test]
fn an_exact_supersession_replay_writes_nothing() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    let first = store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");
    let before = binding(&store, "acme/api", "mem:1");

    let mut retried = correction("acme/api", "mem:1", "mem:2");
    retried.superseded_at_ms = 9_999;
    let replay = store.supersede(retried).expect("replay");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);
    // The first stamp's instant, not the retry's.
    assert_eq!(replay.superseded_at_ms, 2_000);
    assert_eq!(replay.revision, 2);
    assert_eq!(binding(&store, "acme/api", "mem:1"), before);
}

#[test]
fn a_second_different_replacement_is_refused() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    store.record(lesson("acme/api", "mem:3")).expect("record");
    store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");
    let before = binding(&store, "acme/api", "mem:1");

    let error = store
        .supersede(correction("acme/api", "mem:1", "mem:3"))
        .expect_err("re-pointing refusal");
    assert_eq!(error.category(), "already_superseded");
    assert!(error.to_string().contains("mem:2"));
    // A supersession extends the history and never rewrites it.
    assert_eq!(binding(&store, "acme/api", "mem:1"), before);
}

#[test]
fn an_item_cannot_supersede_itself() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");

    let error = store
        .supersede(correction("acme/api", "mem:1", "mem:1"))
        .expect_err("self-supersession refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("replacement_key"));
    assert!(!read(&store, "acme/api", "mem:1").is_superseded());
}

#[test]
fn superseding_an_absent_item_or_replacement_is_not_found() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");

    let missing_item = store
        .supersede(correction("acme/api", "mem:absent", "mem:1"))
        .expect_err("absent item");
    assert_eq!(missing_item.category(), "not_found");
    assert!(missing_item.to_string().contains("item"));

    let missing_replacement = store
        .supersede(correction("acme/api", "mem:1", "mem:absent"))
        .expect_err("absent replacement");
    assert_eq!(missing_replacement.category(), "not_found");
    assert!(missing_replacement.to_string().contains("replacement"));
    assert!(!read(&store, "acme/api", "mem:1").is_superseded());
}

#[test]
fn a_superseded_item_still_replays_its_recording_and_still_conflicts() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");

    // A correction is a separate durable fact; it does not make the original
    // recording disagree with itself.
    let replay = store
        .record(lesson("acme/api", "mem:1"))
        .expect("replay a superseded item");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.created_at_ms, 1_000);

    // And the binding is still write-once: a superseded row is not an editable
    // one.
    let error = store
        .record(captured(
            "acme/api",
            "mem:1",
            "workspace-convention:test-command",
            DIGEST_B,
            MemoryTrust::ActorSupplied,
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert_eq!(read(&store, "acme/api", "mem:1").content_digest, DIGEST_A);
}

#[test]
fn a_supersession_survives_close_and_reopen() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    store.record(lesson("acme/api", "mem:3")).expect("record");
    store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");
    let before = binding(&store, "acme/api", "mem:1");
    drop(store);

    let mut reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    assert_eq!(binding(&reopened, "acme/api", "mem:1"), before);

    // One-time and one-way are properties of the file too.
    let replay = reopened
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("replay after restart");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    let error = reopened
        .supersede(correction("acme/api", "mem:1", "mem:3"))
        .expect_err("re-pointing refusal after restart");
    assert_eq!(error.category(), "already_superseded");
    assert_eq!(binding(&reopened, "acme/api", "mem:1"), before);
}

#[test]
fn a_supersession_chain_leaves_every_link_readable() {
    let (_private, mut store) = store();
    for key in ["mem:1", "mem:2", "mem:3"] {
        store.record(lesson("acme/api", key)).expect("record");
    }
    store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("first correction");
    store
        .supersede(correction("acme/api", "mem:2", "mem:3"))
        .expect("second correction");

    // Walking the chain is the caller's; every link is still a durable row, and
    // nothing was deleted to make room for the correction.
    assert_eq!(
        read(&store, "acme/api", "mem:1").superseded_by.as_deref(),
        Some("mem:2")
    );
    assert_eq!(
        read(&store, "acme/api", "mem:2").superseded_by.as_deref(),
        Some("mem:3")
    );
    assert!(!read(&store, "acme/api", "mem:3").is_superseded());
    assert_eq!(store.item_count().expect("count"), 3);
}

// ---------------------------------------------------------------------------
// Grammar and bounds
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_field_is_refused_on_every_write_path() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:ok")).expect("record");

    let too_long = "w".repeat(MAX_MEMORY_FIELD_BYTES + 1);
    let control = "acme/\u{7}api";
    for (workspace, memory_key, label, field) in [
        ("", "mem:1", "a-label", "workspace"),
        (too_long.as_str(), "mem:1", "a-label", "workspace"),
        (control, "mem:1", "a-label", "workspace"),
        ("acme/api", "", "a-label", "memory_key"),
        ("acme/api", too_long.as_str(), "a-label", "memory_key"),
        ("acme/api", "mem:\u{0}1", "a-label", "memory_key"),
        ("acme/api", "mem:1", "", "label"),
        ("acme/api", "mem:1", too_long.as_str(), "label"),
        ("acme/api", "mem:1", "a\u{1b}label", "label"),
    ] {
        let error = store
            .record(captured(
                workspace,
                memory_key,
                label,
                DIGEST_A,
                MemoryTrust::Untrusted,
            ))
            .expect_err("grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(
            error.to_string().contains(field),
            "refusal should name {field}: {error}"
        );
    }

    // The supersession path applies the same grammar to its own field.
    for replacement in ["", too_long.as_str(), "mem:\u{7}2"] {
        let error = store
            .supersede(correction("acme/api", "mem:ok", replacement))
            .expect_err("grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("replacement_key"));
    }
    assert_eq!(store.item_count().expect("count"), 1);
}

#[test]
fn a_field_at_exactly_the_bound_is_accepted() {
    let (_private, mut store) = store();
    let at_bound = "w".repeat(MAX_MEMORY_FIELD_BYTES);
    assert_eq!(MAX_MEMORY_FIELD_BYTES, 512);
    store
        .record(captured(
            &at_bound,
            &at_bound,
            &at_bound,
            DIGEST_A,
            MemoryTrust::Untrusted,
        ))
        .expect("a field at the ceiling is well-formed");
    assert_eq!(read(&store, &at_bound, &at_bound).label, at_bound);
}

#[test]
fn a_digest_that_is_not_sixty_four_lowercase_hex_digits_is_refused() {
    let (_private, mut store) = store();
    assert_eq!(CONTENT_DIGEST_CHARS, 64);
    assert_eq!(DIGEST_A.len(), CONTENT_DIGEST_CHARS);
    assert_eq!(DIGEST_B.len(), CONTENT_DIGEST_CHARS);

    let short = &DIGEST_A[..63];
    let long = format!("{DIGEST_A}0");
    let uppercase = DIGEST_A.to_uppercase();
    let prefixed = format!("sha256:{}", &DIGEST_A[7..]);
    let non_hex = format!("{}zz", &DIGEST_A[..62]);
    for digest in [
        "",
        short,
        long.as_str(),
        uppercase.as_str(),
        prefixed.as_str(),
        non_hex.as_str(),
    ] {
        let error = store
            .record(captured(
                "acme/api",
                "mem:1",
                "a-label",
                digest,
                MemoryTrust::Untrusted,
            ))
            .expect_err("digest refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("content_digest"));
    }
    assert_eq!(store.item_count().expect("count"), 0);
}

#[test]
fn a_negative_instant_is_refused_on_both_write_paths() {
    let (_private, mut store) = store();
    let mut backwards = lesson("acme/api", "mem:1");
    backwards.created_at_ms = -1;
    let error = store.record(backwards).expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("created_at_ms"));

    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    let mut stamped_backwards = correction("acme/api", "mem:1", "mem:2");
    stamped_backwards.superseded_at_ms = -1;
    let error = store
        .supersede(stamped_backwards)
        .expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("superseded_at_ms"));
    assert!(!read(&store, "acme/api", "mem:1").is_superseded());
}

#[test]
fn a_zero_instant_is_accepted() {
    let (_private, mut store) = store();
    let mut epoch = lesson("acme/api", "mem:1");
    epoch.created_at_ms = 0;
    store.record(epoch).expect("the epoch is a valid instant");
    assert_eq!(read(&store, "acme/api", "mem:1").created_at_ms, 0);
}

#[test]
fn a_malformed_field_is_refused_on_every_read_path() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");

    assert_eq!(
        store
            .item("", "mem:1")
            .expect_err("read refusal")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        store
            .item("acme/api", "")
            .expect_err("read refusal")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        store.page("", 0, 10).expect_err("page refusal").category(),
        "invalid_field"
    );
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_short_digest_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE memory_items SET content_digest = 'abc' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect_err("the column CHECK pins the digest width");
    raw.execute(
        "UPDATE memory_items SET content_digest = ?1 WHERE memory_key = 'mem:1'",
        params![DIGEST_A.to_uppercase()],
    )
    .expect_err("the column CHECK refuses an uppercase digest");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET content_digest = 'abc' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle digest");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("digest refusal on read");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("content_digest"));
    assert_eq!(
        reopened
            .page("acme/api", 0, 10)
            .expect_err("page refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_control_character_label_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE memory_items SET label = ?1 WHERE memory_key = 'mem:1'",
        params!["work\u{7}space"],
    )
    .expect("smuggle label");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("grammar refusal on read");
    // A bad stored row is corruption, never the caller's InvalidField.
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("label"));
}

#[test]
fn a_hand_written_half_stamped_supersession_surfaces_as_corruption() {
    for (columns, invariant) in [
        (
            "superseded_by = 'mem:2', superseded_at_ms = NULL, revision = 2",
            "supersession",
        ),
        (
            "superseded_by = NULL, superseded_at_ms = 2000, revision = 2",
            "supersession",
        ),
        (
            "superseded_by = 'mem:2', superseded_at_ms = 2000, revision = 1",
            "supersession",
        ),
        (
            "superseded_by = 'mem:1', superseded_at_ms = 2000, revision = 2",
            "superseded_by",
        ),
        (
            "superseded_by = 'mem:2', superseded_at_ms = -1, revision = 2",
            "superseded_at_ms",
        ),
    ] {
        let (private, mut store) = store();
        store.record(lesson("acme/api", "mem:1")).expect("record");
        drop(store);

        let raw = Connection::open(private.path()).expect("raw write");
        raw.pragma_update(None, "ignore_check_constraints", true)
            .expect("disable checks");
        raw.execute(
            &format!("UPDATE memory_items SET {columns} WHERE memory_key = 'mem:1'"),
            [],
        )
        .expect("smuggle a half-stamped row");
        drop(raw);

        // A half-stamped row is not a correction: this API writes an unstamped
        // row at revision one or a fully stamped row at revision two, and a
        // reader must not accept anything between them.
        let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
        let error = reopened
            .item("acme/api", "mem:1")
            .expect_err("coupling refusal");
        assert_eq!(error.category(), "corrupt", "for {columns}");
        assert!(
            error.to_string().contains(invariant),
            "{columns} should name {invariant}: {error}"
        );
    }
}

#[test]
fn a_hand_written_third_revision_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE memory_items SET revision = 3 WHERE memory_key = 'mem:1'",
        [],
    )
    .expect_err("the column CHECK admits exactly two revisions");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET revision = 3 WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle a third revision");
    drop(raw);

    // A row has exactly one possible second write and no third.
    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
}

#[test]
fn a_hand_written_non_positive_identity_surfaces_as_corruption() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO memory_items
         (entry_id, workspace, memory_key, label, content_digest, trust_class,
          created_at_ms, superseded_by, superseded_at_ms, revision)
         VALUES (0, 'acme/api', 'mem:0', 'a-label', ?1, 'untrusted', 1000, NULL, NULL, 1)",
        params![DIGEST_A],
    )
    .expect("smuggle a zero identity");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:0")
        .expect_err("identity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("entry_id"));
    // The retained window is derived from the same column and refuses too,
    // rather than reporting a floor no writer produced.
    assert_eq!(
        reopened
            .retained_range()
            .expect_err("range refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_negative_instant_surfaces_as_corruption() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET created_at_ms = -1 WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle instant");
    drop(raw);

    let reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let error = reopened
        .item("acme/api", "mem:1")
        .expect_err("time refusal on read");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("created_at_ms"));
}

#[test]
fn a_corrupt_row_is_refused_on_both_write_paths() {
    let (private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE memory_items SET trust_class = 'policy' WHERE memory_key = 'mem:1'",
        [],
    )
    .expect("smuggle trust class");
    drop(raw);

    // The replay comparison reads the durable row first, and refuses a row it
    // cannot have written rather than treating it as a conflict or a replay.
    let mut reopened = ContextMemoryStore::open(private.path()).expect("reopen");
    let recorded = reopened
        .record(lesson("acme/api", "mem:1"))
        .expect_err("corruption on record");
    assert_eq!(recorded.category(), "corrupt");
    assert!(recorded.to_string().contains("trust_class"));

    let stamped = reopened
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect_err("corruption on supersede");
    assert_eq!(stamped.category(), "corrupt");
    assert!(stamped.to_string().contains("trust_class"));

    // And a corrupt row cannot be laundered by being named as a replacement.
    let named = reopened
        .supersede(correction("acme/api", "mem:2", "mem:1"))
        .expect_err("corruption through the replacement lookup");
    assert_eq!(named.category(), "corrupt");
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

#[test]
fn a_page_walks_a_workspace_in_recording_order() {
    let (_private, mut store) = store();
    for index in 0..5 {
        store
            .record(lesson("acme/api", &format!("mem:{index}")))
            .expect("record");
        // A neighbouring workspace's rows interleave in entry_id order and must
        // not appear in, or shorten, this workspace's pages.
        store
            .record(lesson("acme/web", &format!("web:{index}")))
            .expect("record");
    }

    let first = store.page("acme/api", 0, 2).expect("first page");
    assert_eq!(keys(&first.entries), vec!["mem:0", "mem:1"]);
    let cursor = first.next_cursor.expect("a further row was seen");

    let second = store.page("acme/api", cursor, 2).expect("second page");
    assert_eq!(keys(&second.entries), vec!["mem:2", "mem:3"]);

    let third = store
        .page("acme/api", second.next_cursor.expect("cursor"), 2)
        .expect("third page");
    assert_eq!(keys(&third.entries), vec!["mem:4"]);
    // An exhausted listing is distinguishable from one that merely filled.
    assert_eq!(third.next_cursor, None);
}

#[test]
fn a_page_lists_superseded_items_too() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");
    store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede");

    // A correction is not a deletion, and a listing that hid the corrected item
    // would make it look like one.
    let page = store.page("acme/api", 0, 10).expect("page");
    assert_eq!(keys(&page.entries), vec!["mem:1", "mem:2"]);
    assert!(page.entries[0].is_superseded());
    assert!(!page.entries[1].is_superseded());
}

#[test]
fn a_cursor_is_judged_against_the_whole_store() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/web", "web:1")).expect("record");
    store.record(lesson("acme/api", "mem:2")).expect("record");

    // Row two belongs to another workspace. It is still a position in the
    // listing order, so resuming after it is a page, not a refusal.
    let page = store
        .page("acme/api", 2, 10)
        .expect("resume after a neighbour");
    assert_eq!(keys(&page.entries), vec!["mem:2"]);

    // A cursor at the end is an empty page, which is a different answer from a
    // cursor that is gone.
    let exhausted = store.page("acme/api", 3, 10).expect("exhausted page");
    assert!(exhausted.entries.is_empty());
    assert_eq!(exhausted.next_cursor, None);

    let error = store.page("acme/api", 4, 10).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    assert!(error.to_string().contains('4'));
    assert!(error.to_string().contains('3'));
}

#[test]
fn a_limit_outside_its_range_is_refused() {
    let (_private, mut store) = store();
    store.record(lesson("acme/api", "mem:1")).expect("record");

    for limit in [0, MAX_MEMORY_PAGE + 1] {
        let error = store.page("acme/api", 0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));
    }
    assert_eq!(
        store
            .page("acme/api", 0, MAX_MEMORY_PAGE)
            .expect("the ceiling is a valid limit")
            .entries
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Capacity and the retained window
// ---------------------------------------------------------------------------

#[test]
fn the_store_refuses_to_grow_past_its_capacity() {
    let private = PrivateStore::new();
    let mut store = ContextMemoryStore::open_with_capacity(private.path(), 2).expect("open store");
    assert_eq!(store.capacity(), 2);
    store.record(lesson("acme/api", "mem:1")).expect("first");
    store.record(lesson("acme/api", "mem:2")).expect("second");

    let error = store
        .record(lesson("acme/api", "mem:3"))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "store_full");
    assert!(error.to_string().contains('2'));

    // The ceiling belongs to the database file, so a second workspace does not
    // get a fresh allowance.
    assert_eq!(
        store
            .record(lesson("acme/web", "web:1"))
            .expect_err("capacity refusal")
            .category(),
        "store_full"
    );

    // Refusal, never eviction: the store has no prune, so a full store stays
    // full and the items it holds are exactly the ones it started with.
    assert_eq!(store.item_count().expect("count"), 2);
    assert_eq!(
        keys(&store.page("acme/api", 0, 10).expect("page").entries),
        vec!["mem:1", "mem:2"]
    );
}

#[test]
fn a_full_store_still_replays_supersedes_and_reads() {
    let private = PrivateStore::new();
    let mut store = ContextMemoryStore::open_with_capacity(private.path(), 2).expect("open store");
    let first = store.record(lesson("acme/api", "mem:1")).expect("first");
    store.record(lesson("acme/api", "mem:2")).expect("second");

    // A replay writes nothing, so it must never degrade into a refusal.
    let replay = store
        .record(lesson("acme/api", "mem:1"))
        .expect("replay in a full store");
    assert_eq!(replay.disposition, MemoryDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);

    // A conflicting reuse is a caller bug regardless of how full the store is,
    // so it is reported as one.
    let error = store
        .record(captured(
            "acme/api",
            "mem:1",
            "a-different-label",
            DIGEST_A,
            MemoryTrust::ActorSupplied,
        ))
        .expect_err("conflict in a full store");
    assert_eq!(error.category(), "conflict");

    // A supersession adds no row, so it works at capacity too.
    let stamped = store
        .supersede(correction("acme/api", "mem:1", "mem:2"))
        .expect("supersede in a full store");
    assert_eq!(stamped.disposition, MemoryDisposition::Recorded);
    assert_eq!(store.item_count().expect("count"), 2);
}

#[test]
fn the_retained_window_spans_every_workspace() {
    let (_private, mut store) = store();
    assert_eq!(store.retained_range().expect("range"), None);

    store.record(lesson("acme/api", "mem:1")).expect("record");
    store.record(lesson("acme/web", "web:1")).expect("record");
    assert_eq!(
        store.retained_range().expect("range").expect("non-empty"),
        RetainedMemoryRange { first: 1, last: 2 }
    );
    assert_eq!(store.item_count().expect("count"), 2);
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: a NULL must not slip the supersession coupling
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, so a coupling
// written over a nullable column as a bare comparison admits the very row it
// was written to refuse. `superseded_by` and `superseded_at_ms` are the nullable
// columns here, and the coupling is NULL-safe by construction: `revision` is
// `NOT NULL` and selects exactly one disjunct, and every conjunct touching a
// nullable column is guarded by `IS NULL` / `IS NOT NULL` — which yield `0` or
// `1` and never `NULL` — before any comparison on that column is reached. A
// careless `length(superseded_by) > 0` standing alone would evaluate to NULL for
// a stamped row naming nobody, and that row would land.
// ---------------------------------------------------------------------------

#[test]
fn a_null_never_slips_the_supersession_coupling() {
    let (private, store) = store();
    drop(store);

    let raw = Connection::open(private.path()).expect("raw write");
    let item = |memory_key: &str, coupled: &str| {
        format!(
            "INSERT INTO memory_items
                 (workspace, memory_key, label, content_digest, trust_class,
                  created_at_ms, revision, superseded_by, superseded_at_ms)
             VALUES ('acme/api', '{memory_key}', 'a-label', '{DIGEST_A}',
                     'untrusted', 0, {coupled})"
        )
    };

    for (what, statement) in [
        (
            "a stamped row naming no replacement",
            item("mem:1", "2, NULL, 2000"),
        ),
        (
            "a stamped row with no supersession instant",
            item("mem:2", "2, 'mem:x', NULL"),
        ),
        (
            "a stamped row naming an empty replacement",
            item("mem:3", "2, '', 2000"),
        ),
        (
            "a stamped row dated before the epoch",
            item("mem:4", "2, 'mem:x', -1"),
        ),
        (
            "an unstamped row carrying a replacement",
            item("mem:5", "1, 'mem:x', 2000"),
        ),
        (
            "an unstamped row carrying a supersession instant",
            item("mem:6", "1, NULL, 2000"),
        ),
        (
            "a row at a revision this API never writes",
            item("mem:7", "3, NULL, NULL"),
        ),
    ] {
        assert!(
            raw.execute(&statement, []).is_err(),
            "the database must refuse {what}"
        );
    }

    // Tightness, not mere strictness: both legal states still land, and the
    // epoch is a legal supersession instant.
    for (what, statement) in [
        ("a recorded item", item("mem:live", "1, NULL, NULL")),
        (
            "a superseded item",
            item("mem:corrected", "2, 'mem:live', 2000"),
        ),
        (
            "a supersession stamped at the epoch",
            item("mem:epoch", "2, 'mem:live', 0"),
        ),
    ] {
        raw.execute(&statement, [])
            .unwrap_or_else(|error| panic!("the database must admit {what}: {error}"));
    }
}

/// The public result alias is usable from outside the crate.
#[test]
fn the_result_alias_names_this_module_s_error() {
    let (_private, mut store) = store();
    let outcome: Kept<_> = store.record(lesson("acme/api", "mem:1"));
    assert_eq!(
        outcome.expect("record").disposition,
        MemoryDisposition::Recorded
    );
}
