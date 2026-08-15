// SPDX-License-Identifier: Elastic-2.0

//! `automonique audit verify`, end to end over a real chain database.
//!
//! The three tamper cases are the reason the verb exists, and each is performed
//! the way an attacker would: raw SQL against the file, behind the API's back.
//! Every one asserts the exact `seq` the break is reported at, because a
//! verifier that only said "broken" would leave an operator to find the record
//! themselves — which is the expensive half.
//!
//! One of the three, the edited body, is invisible to the store's own
//! structural walk: the row is still contiguous and still links. Only
//! recomputing the hash catches it, and that is what this verb adds over the
//! `doctor` line.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_cli::run;
use automonique_protocol::audit::{AuditCategory, AuditEvent, AuditOutcome, AuditRecord};
use automonique_store::audit_chain::{AuditAppend, AuditChain, GENESIS_PREV_HASH};
use rusqlite::{Connection, params};
use tempfile::TempDir;

fn private_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    directory
}

/// A chain of `count` linked records, written through the real API.
fn chain(directory: &TempDir, count: u64) -> PathBuf {
    let path = directory.path().join("audit-chain.sqlite3");
    let mut chain = AuditChain::open(&path).expect("opens");
    for index in 1..=count {
        let (seq, prev) = chain.head().expect("head").map_or_else(
            || (1, GENESIS_PREV_HASH.to_owned()),
            |head| (head.seq + 1, head.record_hash),
        );
        let record = AuditRecord::link(
            seq,
            &prev,
            AuditEvent {
                recorded_at: "2026-08-15T12:00:00Z",
                actor: "operator:ada",
                surface: "admin.socket",
                category: AuditCategory::Cancellation,
                subject: &format!("run:{index}"),
                outcome: AuditOutcome::Success,
            },
        )
        .expect("record");
        let record_id = record.record_id();
        let body = record.to_canonical_bytes();
        let record_hash = record.record_hash();
        chain
            .append(AuditAppend {
                record_id: &record_id,
                recorded_at: record.recorded_at(),
                actor: record.actor(),
                surface: record.surface(),
                category: record.category().as_str(),
                subject: record.subject(),
                outcome: record.outcome().as_str(),
                body: &body,
                prev_hash: record.prev_hash(),
                record_hash: &record_hash,
            })
            .expect("appends");
    }
    path
}

fn invoke(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(arguments, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

fn verify(path: &Path) -> (u8, String, String) {
    invoke(&["audit", "verify", path.to_str().expect("utf-8 path")])
}

/// Open the database behind the API's back, for a tamper the API would refuse.
fn raw(path: &Path) -> Connection {
    Connection::open(path).expect("raw connection")
}

#[test]
fn an_intact_chain_verifies_and_prints_its_head() {
    let directory = private_directory();
    let path = chain(&directory, 6);

    let (code, out, err) = verify(&path);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("records 6"), "{out}");
    assert!(out.contains("structure 6"), "{out}");
    assert!(out.contains("verdict intact"), "{out}");

    // The head hash is printed so an operator can keep the external witness the
    // chain itself cannot provide.
    let head: String = raw(&path)
        .query_row(
            "SELECT record_hash FROM audit_records ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("head");
    assert!(out.contains(&head), "{out}");
}

#[test]
fn an_empty_chain_verifies() {
    let directory = private_directory();
    let path = chain(&directory, 0);
    let (code, out, err) = verify(&path);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("records 0"), "{out}");
    assert!(out.contains("(empty chain)"), "{out}");
}

#[test]
fn a_flipped_body_byte_is_named_at_its_exact_record() {
    let directory = private_directory();
    let path = chain(&directory, 5);

    // A same-length substitution inside a string value: the body is still
    // canonical JSON and still decodes to a well-formed record afterwards, and
    // the row is still contiguous and still linked. Only the hash catches it.
    let connection = raw(&path);
    let body: Vec<u8> = connection
        .query_row("SELECT body FROM audit_records WHERE seq = 3", [], |row| {
            row.get(0)
        })
        .expect("body");
    let tampered = String::from_utf8(body)
        .expect("utf-8 body")
        .replace("operator:ada", "operator:eve");
    connection
        .execute(
            "UPDATE audit_records SET body = ?1 WHERE seq = 3",
            params![tampered.as_bytes()],
        )
        .expect("smuggle an edited body");
    drop(connection);

    let (code, out, err) = verify(&path);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("chain_broken"), "{err}");
    assert!(err.contains("seq 3"), "{err}");
    assert!(err.contains("record_hash_mismatch"), "{err}");
    assert!(out.is_empty(), "a broken chain renders no verdict: {out}");
}

#[test]
fn two_swapped_rows_are_named_at_the_first_one_out_of_place() {
    let directory = private_directory();
    let path = chain(&directory, 5);

    // `seq` is the primary key, so a swap is three statements through a
    // parking position rather than one.
    let connection = raw(&path);
    connection
        .execute_batch(
            "UPDATE audit_records SET seq = 99 WHERE seq = 2;
             UPDATE audit_records SET seq = 2 WHERE seq = 3;
             UPDATE audit_records SET seq = 3 WHERE seq = 99;",
        )
        .expect("swap two rows");
    drop(connection);

    let (code, out, err) = verify(&path);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("chain_broken"), "{err}");
    // The store's structural walk reaches this one first, and reports the
    // broken link rather than the hash mismatch it also produces.
    assert!(err.contains("prev_hash_link"), "{err}");
}

#[test]
fn a_deleted_middle_row_is_named_at_the_gap() {
    let directory = private_directory();
    let path = chain(&directory, 5);

    let connection = raw(&path);
    connection
        .execute("DELETE FROM audit_records WHERE seq = 3", [])
        .expect("delete a middle record");
    drop(connection);

    let (code, out, err) = verify(&path);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("chain_broken"), "{err}");
    assert!(err.contains("seq_not_contiguous"), "{err}");
}

#[test]
fn a_forged_record_consistent_with_itself_is_still_caught_by_the_link() {
    let directory = private_directory();
    let path = chain(&directory, 4);

    // The interesting attack: rewrite a record *and* its hash and identifier,
    // so the row is internally consistent. The record that follows still names
    // the old hash, so the chain catches what the record alone cannot.
    let connection = raw(&path);
    let prev: String = connection
        .query_row(
            "SELECT record_hash FROM audit_records WHERE seq = 1",
            [],
            |row| row.get(0),
        )
        .expect("first hash");
    let forged = AuditRecord::link(
        2,
        &prev,
        AuditEvent {
            recorded_at: "2026-08-15T12:00:00Z",
            actor: "operator:eve",
            surface: "admin.socket",
            category: AuditCategory::Cancellation,
            subject: "run:forged",
            outcome: AuditOutcome::Success,
        },
    )
    .expect("record");
    connection
        .execute(
            "UPDATE audit_records
             SET record_id = ?1, actor = ?2, subject = ?3, body = ?4, record_hash = ?5
             WHERE seq = 2",
            params![
                forged.record_id(),
                forged.actor(),
                forged.subject(),
                forged.to_canonical_bytes(),
                forged.record_hash(),
            ],
        )
        .expect("smuggle a self-consistent forgery");
    drop(connection);

    let (code, out, err) = verify(&path);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("chain_broken"), "{err}");
    assert!(err.contains("prev_hash_link"), "{err}");
}

#[test]
fn a_missing_or_relative_database_is_a_usage_refusal() {
    let (code, _, err) = invoke(&["audit", "verify", "relative/path.sqlite3"]);
    assert_eq!(code, 2);
    assert!(err.contains("invalid_argument"), "{err}");

    let (code, _, err) = invoke(&["audit", "verify", "/nonexistent/audit-chain.sqlite3"]);
    assert_eq!(code, 1);
    assert!(err.contains("store"), "{err}");
}

#[test]
fn an_unknown_audit_action_prints_usage() {
    let (code, _, err) = invoke(&["audit", "shred", "/tmp/whatever.sqlite3"]);
    assert_eq!(code, 2);
    assert!(err.contains("usage: automonique"), "{err}");
    assert!(err.contains("automonique audit verify <database>"), "{err}");
}
