// SPDX-License-Identifier: Elastic-2.0

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};

use automonique_store::sqlite_policy;
use rusqlite::{Connection, TransactionBehavior, params};

const CHILD_PATH_ENV: &str = "AUTOMONIQUE_SQLITE_CRASH_FIXTURE_PATH";
const COMMITTED_ROWS: usize = 64;

#[test]
fn committed_rows_survive_process_crash_under_selected_policy() {
    if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
        run_crash_child(std::path::Path::new(&path));
        return;
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("authority.sqlite3");
    let executable = std::env::current_exe().expect("current test executable");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("committed_rows_survive_process_crash_under_selected_policy")
        .arg("--nocapture")
        .env(CHILD_PATH_ENV, &path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("crash fixture starts");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).expect("fixture output"), 0);
        if line.trim() == "authority-committed" {
            break;
        }
    }
    child.kill().expect("fixture is killed after commit");
    let status = child.wait().expect("fixture is reaped");
    assert!(!status.success(), "the fixture must not shut down cleanly");

    let connection = Connection::open(&path).expect("database reopens");
    sqlite_policy::configure_authoritative(&connection).expect("policy reads back after crash");
    let rows: usize = connection
        .query_row("SELECT COUNT(*) FROM durable_rows", [], |row| row.get(0))
        .expect("committed rows are readable");
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check runs");
    assert_eq!(rows, COMMITTED_ROWS);
    assert_eq!(integrity, "ok");
}

fn run_crash_child(path: &std::path::Path) {
    let mut connection = Connection::open(path).expect("child database opens");
    sqlite_policy::configure_authoritative(&connection).expect("child policy applies");
    connection
        .execute_batch(
            "CREATE TABLE durable_rows (
                 sequence INTEGER PRIMARY KEY,
                 payload BLOB NOT NULL
             ) STRICT;",
        )
        .expect("child schema");
    for sequence in 0..COMMITTED_ROWS {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("child transaction");
        transaction
            .execute(
                "INSERT INTO durable_rows (sequence, payload) VALUES (?1, ?2)",
                params![sequence, vec![0x5a_u8; 1_024]],
            )
            .expect("child insert");
        transaction.commit().expect("child commit");
    }
    println!("authority-committed");
    std::io::stdout().flush().expect("child output flushes");
    loop {
        std::thread::park();
    }
}
