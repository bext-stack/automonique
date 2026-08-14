// SPDX-License-Identifier: Elastic-2.0

//! Durable operator member roster invariants.
//!
//! Every refusal is asserted by stable category rather than by message text, so
//! a mutation that reaches a different guard fails here instead of slipping
//! through a neighbouring refusal. The restart test closes the store and
//! reopens the file: an in-memory roster cannot pass it, and a roster that did
//! not survive a restart would silently revoke every member the moment a daemon
//! was upgraded.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::operator_members::{
    MAX_OPERATOR_MEMBERS, MemberDisposition, OPERATOR_MEMBERS_SCHEMA_VERSION, OperatorMemberStore,
};
use rusqlite::Connection;
use tempfile::TempDir;

/// A member added at this instant unless a test cares about the value.
const ADDED_MS: i64 = 1_700_000_000_000;

struct PrivateRoster {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateRoster {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("operator-members.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn roster() -> (PrivateRoster, OperatorMemberStore) {
    let private = PrivateRoster::new();
    let opened = OperatorMemberStore::open(private.path()).expect("open roster");
    (private, opened)
}

#[test]
fn a_new_roster_is_private_empty_and_at_the_expected_schema() {
    let (private, store) = roster();
    assert_eq!(store.member_count().expect("count"), 0);
    assert!(store.list_members().expect("list").is_empty());
    assert_eq!(store.capacity(), MAX_OPERATOR_MEMBERS);
    assert_eq!(store.path(), private.path());

    let mode = fs::metadata(private.path())
        .expect("roster metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "the roster must not be group/other readable"
    );

    let connection = Connection::open(private.path()).expect("inspect roster");
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, OPERATOR_MEMBERS_SCHEMA_VERSION);
}

/// The whole mutation vocabulary, and the fact that each answer is about the
/// durable state rather than about the call.
#[test]
fn adding_and_removing_answers_by_what_the_roster_now_holds() {
    let (_private, mut store) = roster();

    assert_eq!(
        store.add_member(7_654_321, ADDED_MS).expect("add"),
        MemberDisposition::Added
    );
    assert!(store.is_member(7_654_321).expect("membership"));
    assert!(!store.is_member(9_999_999).expect("membership"));

    // A repeat is idempotent and is *not* an error: an administrator who adds
    // somebody twice has asked for a state that already holds.
    assert_eq!(
        store
            .add_member(7_654_321, ADDED_MS + 5_000)
            .expect("re-add"),
        MemberDisposition::AlreadyMember
    );
    assert_eq!(store.member_count().expect("count"), 1);
    let members = store.list_members().expect("list");
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].added_at_ms, ADDED_MS,
        "a re-add must not rewrite when the member was first let in"
    );

    assert_eq!(
        store.remove_member(7_654_321).expect("remove"),
        MemberDisposition::Removed
    );
    assert!(!store.is_member(7_654_321).expect("membership"));
    // Removing again is the answer to "this id must not be a member", which is
    // already true.
    assert_eq!(
        store.remove_member(7_654_321).expect("remove again"),
        MemberDisposition::NotAMember
    );
    assert_eq!(store.member_count().expect("count"), 0);

    assert!(MemberDisposition::Added.changed());
    assert!(MemberDisposition::Removed.changed());
    assert!(!MemberDisposition::AlreadyMember.changed());
    assert!(!MemberDisposition::NotAMember.changed());
}

/// The listing is a set ordered by id, which is what a caller composing an
/// authorization gate needs, and it never repeats an id.
#[test]
fn the_listing_is_ordered_by_user_id_and_deduplicated() {
    let (_private, mut store) = roster();
    for user_id in [900, 100, 500, 100, 900] {
        store.add_member(user_id, ADDED_MS).expect("add");
    }
    assert_eq!(store.member_ids().expect("ids"), vec![100, 500, 900]);
    assert_eq!(store.member_count().expect("count"), 3);
}

/// Members outlive the process that added them. This is the reason the roster
/// is a file at all.
#[test]
fn members_survive_closing_and_reopening_the_file() {
    let private = PrivateRoster::new();
    {
        let mut store = OperatorMemberStore::open(private.path()).expect("open roster");
        store.add_member(4_242, ADDED_MS).expect("add");
        store.add_member(9_001, ADDED_MS).expect("add");
        store.remove_member(4_242).expect("remove");
    }
    let store = OperatorMemberStore::open(private.path()).expect("reopen roster");
    assert_eq!(store.member_ids().expect("ids"), vec![9_001]);
}

/// A full roster refuses the addition. It must never make room by forgetting
/// somebody, because that would revoke one operator as a side effect of adding
/// another.
#[test]
fn a_full_roster_refuses_the_addition_and_evicts_nobody() {
    let private = PrivateRoster::new();
    let mut store = OperatorMemberStore::open_with_capacity(private.path(), 2).expect("open");
    store.add_member(11, ADDED_MS).expect("add");
    store.add_member(22, ADDED_MS).expect("add");

    let refusal = store.add_member(33, ADDED_MS).expect_err("roster is full");
    assert_eq!(refusal.category(), "roster_full");
    assert_eq!(
        store.member_ids().expect("ids"),
        vec![11, 22],
        "a refused addition must leave the roster exactly as it was"
    );

    // A full roster still answers a re-add, because a re-add writes nothing…
    assert_eq!(
        store
            .add_member(22, ADDED_MS)
            .expect("re-add in a full roster"),
        MemberDisposition::AlreadyMember
    );
    // …and still revokes, because a ceiling must never trap somebody inside.
    assert_eq!(
        store.remove_member(11).expect("remove from a full roster"),
        MemberDisposition::Removed
    );
    assert_eq!(
        store.add_member(33, ADDED_MS).expect("add after a removal"),
        MemberDisposition::Added
    );
}

#[test]
fn an_id_that_is_not_a_positive_user_id_is_refused_everywhere() {
    let (_private, mut store) = roster();
    for user_id in [0, -1, i64::MIN] {
        assert_eq!(
            store
                .add_member(user_id, ADDED_MS)
                .expect_err("not a user id")
                .category(),
            "invalid_field"
        );
        assert_eq!(
            store
                .remove_member(user_id)
                .expect_err("not a user id")
                .category(),
            "invalid_field"
        );
        assert_eq!(
            store
                .is_member(user_id)
                .expect_err("not a user id")
                .category(),
            "invalid_field"
        );
    }
    assert_eq!(
        store
            .add_member(7, -1)
            .expect_err("negative instant")
            .category(),
        "invalid_field"
    );
    assert_eq!(store.member_count().expect("count"), 0);
}

#[test]
fn a_capacity_outside_the_supported_range_is_refused_at_open() {
    let private = PrivateRoster::new();
    for capacity in [0, MAX_OPERATOR_MEMBERS + 1] {
        assert_eq!(
            OperatorMemberStore::open_with_capacity(private.path(), capacity)
                .expect_err("capacity is out of range")
                .category(),
            "invalid_field"
        );
    }
}

/// A database written by a future build is refused rather than read as if this
/// build understood it.
#[test]
fn an_unsupported_schema_version_is_refused() {
    let private = PrivateRoster::new();
    OperatorMemberStore::open(private.path()).expect("create roster");
    let connection = Connection::open(private.path()).expect("inspect roster");
    connection
        .pragma_update(None, "user_version", OPERATOR_MEMBERS_SCHEMA_VERSION + 1)
        .expect("bump version");
    drop(connection);

    assert_eq!(
        OperatorMemberStore::open(private.path())
            .expect_err("a future schema is unreadable")
            .category(),
        "schema_version"
    );
}

/// The roster refuses to live in a directory anybody else can read.
#[test]
fn a_world_readable_directory_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("permissive permissions");
    let path = directory.path().join("operator-members.sqlite3");
    assert_eq!(
        OperatorMemberStore::open(&path)
            .expect_err("an exposed directory is refused")
            .category(),
        "insecure_path"
    );
}
