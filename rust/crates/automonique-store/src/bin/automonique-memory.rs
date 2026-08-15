// SPDX-License-Identifier: Elastic-2.0

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use automonique_protocol::compat::legacy_spelling;
use automonique_store::agent_memory::{
    AgentMemoryStore, DEFAULT_RAW_RETENTION_MS, ExternalIdentity, MemoryInput, MemoryKind,
    MemorySensitivity, MemoryStatus, MemoryVisibility, MessageInput, WriteDisposition,
    redact_content,
};
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest as _, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("automonique-memory: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    let database = PathBuf::from(arguments.next().ok_or_else(usage)?);
    let tenant = arguments.next().ok_or_else(usage)?;
    let actor = arguments.next().ok_or_else(usage)?;
    let mut store = AgentMemoryStore::open(database).map_err(|error| error.to_string())?;
    match command.as_str() {
        "summary" if arguments.next().is_none() => {
            let counts = store
                .counts(&tenant, &actor)
                .map_err(|error| error.to_string())?;
            println!(
                "active={} proposals={} superseded={} deleted={} messages={}",
                counts.active,
                counts.candidates,
                counts.superseded,
                counts.deleted,
                counts.messages
            );
        }
        "export-obsidian" => {
            let vault = PathBuf::from(arguments.next().ok_or_else(usage)?);
            if arguments.next().is_some() {
                return Err(usage());
            }
            export_obsidian(&store, &tenant, &actor, &vault)?;
        }
        "propose-obsidian" => {
            let note = PathBuf::from(arguments.next().ok_or_else(usage)?);
            if arguments.next().is_some() {
                return Err(usage());
            }
            propose_obsidian(&mut store, &tenant, &actor, &note)?;
        }
        "backfill-telegram" => {
            let source = PathBuf::from(arguments.next().ok_or_else(usage)?);
            let bot_id = arguments
                .next()
                .ok_or_else(usage)?
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(usage)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            backfill_telegram(&mut store, &tenant, &actor, &source, bot_id)?;
        }
        "backfill-legacy" => {
            let source = PathBuf::from(arguments.next().ok_or_else(usage)?);
            let telegram_user = arguments.next().ok_or_else(usage)?;
            let slack_user = arguments.next().ok_or_else(usage)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            backfill_legacy(
                &mut store,
                &tenant,
                &actor,
                &source,
                &telegram_user,
                &slack_user,
            )?;
        }
        "hygiene" if arguments.next().is_none() => {
            let expired = store
                .prune_messages(now_ms()?)
                .map_err(|error| error.to_string())?;
            let commands = store
                .prune_control_messages(&tenant, &actor)
                .map_err(|error| error.to_string())?;
            println!("expired={expired} commands={commands}");
        }
        "link-identity" => {
            let platform = arguments.next().ok_or_else(usage)?;
            let application = arguments.next().ok_or_else(usage)?;
            let external_tenant = arguments.next().ok_or_else(usage)?;
            let external_user = arguments.next().ok_or_else(usage)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let result = store
                .bind_identity(
                    &tenant,
                    &actor,
                    ExternalIdentity {
                        platform: &platform,
                        application: &application,
                        external_tenant: &external_tenant,
                        external_user: &external_user,
                    },
                    now_ms()?,
                )
                .map_err(|error| error.to_string())?;
            println!("binding={result:?}");
        }
        "remember-active" => {
            let content = arguments.next().ok_or_else(usage)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let at_ms = now_ms()?;
            let digest = Sha256::digest(content.as_bytes());
            let source_key = format!("owner-reviewed:{digest:x}");
            let memory = store
                .record_memory(&MemoryInput {
                    tenant: &tenant,
                    actor: &actor,
                    scope: &format!("user:{actor}"),
                    kind: MemoryKind::UserProfile,
                    content: &redact_content(&content),
                    status: MemoryStatus::Active,
                    confidence: 1000,
                    sensitivity: MemorySensitivity::Personal,
                    visibility: MemoryVisibility::Private,
                    source_transport: "owner-cli",
                    source_key: &source_key,
                    valid_from_ms: at_ms,
                    expires_at_ms: None,
                    review_at_ms: None,
                    created_at_ms: at_ms,
                })
                .map_err(|error| error.to_string())?;
            println!("memory={}", memory.reference());
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn usage() -> String {
    String::from(
        "usage: automonique-memory <summary|export-obsidian|propose-obsidian|backfill-telegram|backfill-legacy|hygiene|link-identity|remember-active> <database> <tenant> <actor> [command arguments]",
    )
}

/// Import the predecessor's chat history into the durable memory store.
///
/// The source schema and the durable keys written here are the predecessor's
/// spellings, declared once in
/// [`automonique_protocol::compat::legacy_spelling`] and named from there so
/// that re-running this verb still recognises what a previous run recorded.
fn backfill_legacy(
    store: &mut AgentMemoryStore,
    tenant: &str,
    actor: &str,
    source: &Path,
    telegram_user: &str,
    slack_user: &str,
) -> Result<(), String> {
    if !telegram_user.bytes().all(|byte| byte.is_ascii_digit())
        || telegram_user.is_empty()
        || slack_user.is_empty()
        || !slack_user.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(String::from("immutable legacy identities are invalid"));
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let source = Connection::open_with_flags(source, flags)
        .map_err(|_| String::from("source legacy database is unavailable"))?;
    let now = now_ms()?;
    let threshold = now
        .checked_sub(DEFAULT_RAW_RETENTION_MS)
        .ok_or_else(|| String::from("retention threshold is outside supported range"))?;
    let mut event_statement = source
        .prepare(&format!(
            "SELECT messageTs FROM {}
             WHERE author=?1 AND messageTs IS NOT NULL AND at>=?2",
            legacy_spelling::SLACK_EVENTS_TABLE,
        ))
        .map_err(|_| String::from("source legacy event schema is unavailable"))?;
    let eligible_threads = event_statement
        .query_map(params![slack_user, threshold], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| String::from("source legacy events are unreadable"))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| String::from("source legacy event row is corrupt"))?;
    let mut statement = source
        .prepare(&format!(
            "SELECT id,scope,role,content,at FROM {}
             WHERE at>=?1 ORDER BY at,id",
            legacy_spelling::CHAT_MESSAGES_TABLE,
        ))
        .map_err(|_| String::from("source legacy chat schema is unavailable"))?;
    let rows = statement
        .query_map([threshold], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|_| String::from("source legacy history is unreadable"))?;
    let telegram_suffix = format!(":telegram-user:{telegram_user}");
    let legacy_suffix = format!(":{slack_user}");
    let mut recorded = 0_usize;
    let mut duplicate = 0_usize;
    let mut skipped = 0_usize;
    for row in rows {
        let (id, scope, role, content, at_ms) =
            row.map_err(|_| String::from("source legacy chat row is corrupt"))?;
        let transport = if scope.starts_with("telegram:") && scope.ends_with(&telegram_suffix) {
            "telegram"
        } else if let Some(rest) = scope.strip_prefix("slack:") {
            let Some((_, thread)) = rest.split_once(':') else {
                skipped += 1;
                continue;
            };
            if !eligible_threads.contains(thread) {
                skipped += 1;
                continue;
            }
            "slack"
        } else if scope.ends_with(&legacy_suffix) {
            "slack"
        } else {
            skipped += 1;
            continue;
        };
        if role == "user" && content.trim_start().starts_with('/') {
            skipped += 1;
            continue;
        }
        let content = redact_content(&content);
        let conversation_id = format!("{}{scope}", legacy_spelling::CHAT_CONVERSATION_PREFIX);
        let transport_key = format!("{}{id}", legacy_spelling::CHAT_TRANSPORT_KEY_PREFIX);
        match store
            .record_message(&MessageInput {
                tenant,
                actor,
                conversation_id: &conversation_id,
                transport,
                external_scope: &scope,
                transport_key: &transport_key,
                role: &role,
                content: &content,
                created_at_ms: at_ms,
            })
            .map_err(|error| error.to_string())?
        {
            WriteDisposition::Recorded => recorded += 1,
            WriteDisposition::Duplicate => duplicate += 1,
        }
    }
    println!("recorded={recorded} duplicate={duplicate} skipped={skipped}");
    Ok(())
}

fn backfill_telegram(
    store: &mut AgentMemoryStore,
    tenant: &str,
    actor: &str,
    source: &Path,
    bot_id: i64,
) -> Result<(), String> {
    let external_user = actor
        .strip_prefix("telegram:")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| String::from("Telegram actor must be telegram:<immutable-user-id>"))?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let source = Connection::open_with_flags(source, flags)
        .map_err(|_| String::from("source database is unavailable"))?;
    let now = now_ms()?;
    let threshold = now
        .checked_sub(DEFAULT_RAW_RETENTION_MS)
        .ok_or_else(|| String::from("retention threshold is outside supported range"))?;
    let scope = format!("telegram:{bot_id}:{external_user}");
    let mut statement = source
        .prepare(
            "SELECT source_key,content,received_ms FROM telegram_ingress
             WHERE bot_id=?1 AND scope=?2 AND disposition='admitted' AND received_ms>=?3
             ORDER BY received_ms,update_id",
        )
        .map_err(|_| String::from("source Telegram schema is unavailable"))?;
    let rows = statement
        .query_map(params![bot_id, scope, threshold], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| String::from("source Telegram history is unreadable"))?;
    let conversation = format!("telegram:{external_user}:backfill");
    let external_scope = format!("chat:{external_user}");
    let mut recorded = 0usize;
    let mut duplicate = 0usize;
    for row in rows {
        let (source_key, content, received_ms) =
            row.map_err(|_| String::from("source Telegram row is corrupt"))?;
        let content = std::str::from_utf8(&content)
            .map_err(|_| String::from("source Telegram content is not UTF-8"))?;
        if content.trim_start().starts_with('/') {
            continue;
        }
        let content = redact_content(content);
        store
            .bind_identity(
                tenant,
                actor,
                ExternalIdentity {
                    platform: "telegram",
                    application: &bot_id.to_string(),
                    external_tenant: "telegram",
                    external_user,
                },
                received_ms,
            )
            .map_err(|error| error.to_string())?;
        match store
            .record_message(&MessageInput {
                tenant,
                actor,
                conversation_id: &conversation,
                transport: "telegram",
                external_scope: &external_scope,
                transport_key: &source_key,
                role: "user",
                content: &content,
                created_at_ms: received_ms,
            })
            .map_err(|error| error.to_string())?
        {
            WriteDisposition::Recorded => recorded += 1,
            WriteDisposition::Duplicate => duplicate += 1,
        }
    }
    println!("recorded={recorded} duplicate={duplicate}");
    Ok(())
}

fn now_ms() -> Result<i64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| String::from("system clock is outside supported range"))
}

fn export_obsidian(
    store: &AgentMemoryStore,
    tenant: &str,
    actor: &str,
    vault: &Path,
) -> Result<(), String> {
    private_directory(vault)?;
    let memories = vault.join("Memories");
    private_directory(&memories)?;
    let active = store
        .active_for_actor(tenant, actor, now_ms()?)
        .map_err(|error| error.to_string())?;
    for memory in &active {
        let note = format!(
            "---\nsource_memory: {}\nrevision: {}\nkind: {}\nstatus: active\nconfidence: {}\nvisibility: {}\nsource_transport: {}\n---\n\n{}\n",
            memory.reference(),
            memory.revision,
            memory.kind.as_str(),
            memory.confidence,
            memory.visibility.as_str(),
            memory.source_transport,
            memory.content
        );
        atomic_write(
            &memories.join(format!("{}.md", memory.reference())),
            note.as_bytes(),
        )?;
    }
    let index = format!(
        "# Monique memory\n\nGenerated from Automonique's canonical SQLite store. Only reviewed active memories are exported; raw conversations and credentials are excluded. Edit a note, then import it with `propose-obsidian` to create a review proposal.\n\nExported memories: {}\n",
        active.len()
    );
    atomic_write(&vault.join("README.md"), index.as_bytes())?;
    println!("exported={}", active.len());
    Ok(())
}

fn propose_obsidian(
    store: &mut AgentMemoryStore,
    tenant: &str,
    actor: &str,
    note: &Path,
) -> Result<(), String> {
    let bytes = fs::read(note).map_err(|_| String::from("note is unreadable"))?;
    if bytes.len() > automonique_store::agent_memory::MAX_MEMORY_CONTENT_BYTES + 2_048 {
        return Err(String::from("note is too large"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| String::from("note is not UTF-8"))?;
    let rest = text
        .strip_prefix("---\n")
        .ok_or_else(|| String::from("note frontmatter is missing"))?;
    let (frontmatter, body) = rest
        .split_once("\n---\n")
        .ok_or_else(|| String::from("note frontmatter is incomplete"))?;
    let reference = frontmatter
        .lines()
        .find_map(|line| line.strip_prefix("source_memory: "))
        .ok_or_else(|| String::from("source_memory is missing"))?;
    let id = reference
        .strip_prefix("M-")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| String::from("source_memory is invalid"))?;
    let current = store
        .item(tenant, actor, id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| String::from("source memory was not found"))?;
    if current.status != MemoryStatus::Active {
        return Err(String::from("only an active source memory can be edited"));
    }
    let content = body.trim();
    if content.is_empty() || content == current.content {
        return Err(String::from("note has no proposed content change"));
    }
    let digest = Sha256::digest(content.as_bytes());
    let source_key = format!("obsidian:{}:{digest:x}", current.reference());
    let at_ms = now_ms()?;
    let proposal = store
        .record_memory(&MemoryInput {
            tenant,
            actor,
            scope: &current.scope,
            kind: current.kind,
            content,
            status: MemoryStatus::Candidate,
            confidence: 1000,
            sensitivity: current.sensitivity,
            visibility: MemoryVisibility::Private,
            source_transport: "obsidian",
            source_key: &source_key,
            valid_from_ms: at_ms,
            expires_at_ms: current.expires_at_ms,
            review_at_ms: None,
            created_at_ms: at_ms,
        })
        .map_err(|error| error.to_string())?;
    println!("proposal={}", proposal.reference());
    Ok(())
}

fn private_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|_| String::from("vault directory could not be created"))?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| String::from("vault directory is unreadable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(String::from("vault path is not a regular directory"));
    }
    Ok(())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| String::from("vault note could not be opened"))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|_| String::from("vault note could not be written"))?;
    fs::rename(&temporary, path).map_err(|_| String::from("vault note could not be published"))
}
