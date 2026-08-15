// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use automonique_store::agent_memory::{
    AgentMemoryStore, MemoryInput, MemoryKind, MemorySensitivity, MemoryStatus, MemoryVisibility,
};
use rusqlite::{Connection, params};

#[test]
fn obsidian_export_excludes_raw_history_and_edits_return_as_proposals() {
    let root = tempfile::tempdir().expect("private root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private mode");
    let database = root.path().join("agent-memory.sqlite3");
    let vault = root.path().join("vault");
    let mut store = AgentMemoryStore::open(&database).expect("memory store");
    let memory = store
        .record_memory(&MemoryInput {
            tenant: "inklura",
            actor: "telegram:42",
            scope: "user:telegram:42",
            kind: MemoryKind::UserProfile,
            content: "Replies should be concise.",
            status: MemoryStatus::Active,
            confidence: 1000,
            sensitivity: MemorySensitivity::Personal,
            visibility: MemoryVisibility::Private,
            source_transport: "telegram",
            source_key: "telegram:update:1",
            valid_from_ms: 1,
            expires_at_ms: None,
            review_at_ms: None,
            created_at_ms: 1,
        })
        .expect("active memory");
    drop(store);

    let binary = env!("CARGO_BIN_EXE_automonique-memory");
    let export = Command::new(binary)
        .args([
            "export-obsidian",
            database.to_str().expect("database path"),
            "inklura",
            "telegram:42",
            vault.to_str().expect("vault path"),
        ])
        .output()
        .expect("export command");
    assert!(export.status.success(), "{:?}", export.stderr);
    let note = vault
        .join("Memories")
        .join(format!("{}.md", memory.reference()));
    let exported = std::fs::read_to_string(&note).expect("exported note");
    assert!(exported.contains("Replies should be concise."));
    assert!(!vault.join("Conversations").exists());
    assert!(!vault.join("agent-memory.sqlite3").exists());

    let edited = exported.replace(
        "Replies should be concise.",
        "Replies should be concise and in French.",
    );
    std::fs::write(&note, edited).expect("edited note");
    let proposal = Command::new(binary)
        .args([
            "propose-obsidian",
            database.to_str().expect("database path"),
            "inklura",
            "telegram:42",
            note.to_str().expect("note path"),
        ])
        .output()
        .expect("proposal command");
    assert!(proposal.status.success(), "{:?}", proposal.stderr);

    let store = AgentMemoryStore::open(&database).expect("memory reopens");
    let proposals = store
        .proposals("inklura", "telegram:42", 5)
        .expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].source_transport, "obsidian");
    assert_eq!(
        proposals[0].content,
        "Replies should be concise and in French."
    );
    assert_eq!(
        store
            .item("inklura", "telegram:42", memory.id)
            .expect("source read")
            .expect("source exists")
            .status,
        MemoryStatus::Active,
        "editing the projection never mutates its canonical source"
    );
}

#[test]
fn telegram_backfill_is_ninety_day_bounded_replayable_and_redacted() {
    let root = tempfile::tempdir().expect("private root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private mode");
    let source = root.path().join("source.sqlite3");
    let database = root.path().join("agent-memory.sqlite3");
    let connection = Connection::open(&source).expect("source");
    connection
        .execute_batch(
            "CREATE TABLE telegram_ingress(
                bot_id INTEGER NOT NULL,
                update_id BLOB NOT NULL,
                source_key TEXT NOT NULL,
                scope TEXT NOT NULL,
                disposition TEXT NOT NULL,
                content BLOB,
                received_ms INTEGER NOT NULL
             ) STRICT;",
        )
        .expect("schema");
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock range");
    connection
        .execute(
            "INSERT INTO telegram_ingress VALUES (?1,?2,?3,?4,'admitted',?5,?6)",
            params![
                123_i64,
                1_u64.to_be_bytes().as_slice(),
                "telegram:123:update:1",
                "telegram:123:42",
                "my token sk-123456789012345678901234".as_bytes(),
                now
            ],
        )
        .expect("source row");
    drop(connection);

    let binary = env!("CARGO_BIN_EXE_automonique-memory");
    for expected in ["recorded=1 duplicate=0", "recorded=0 duplicate=1"] {
        let output = Command::new(binary)
            .args([
                "backfill-telegram",
                database.to_str().expect("database path"),
                "inklura",
                "telegram:42",
                source.to_str().expect("source path"),
                "123",
            ])
            .output()
            .expect("backfill command");
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(
            std::str::from_utf8(&output.stdout).expect("stdout").trim(),
            expected
        );
    }
    let store = AgentMemoryStore::open(&database).expect("memory store");
    let messages = store
        .recent_messages("inklura", "telegram:42", "telegram:42:backfill", now, 5)
        .expect("history");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "my token [REDACTED]");
}
