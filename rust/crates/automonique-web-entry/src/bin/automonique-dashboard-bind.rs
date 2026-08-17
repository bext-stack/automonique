// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, params};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("dashboard memory binding refused: {category}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(state_dir), Some(output), None) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err("usage");
    };
    let state_dir = PathBuf::from(state_dir);
    let output = PathBuf::from(output);
    if !state_dir.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("path");
    }
    let tenant = read_tenant(&state_dir.join("memory/memory.conf"))?;
    let actor = unique_actor(&state_dir.join("agent-memory.sqlite3"), &tenant)?;
    let config = format!(
        "schema=automonique.dashboard-integration/v1\nmemory_tenant={tenant}\nmemory_actor={actor}\nend=automonique.dashboard-integration/v1\n"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|_| "output")?;
    file.write_all(config.as_bytes()).map_err(|_| "output")?;
    file.sync_all().map_err(|_| "output")
}

fn read_tenant(path: &Path) -> Result<String, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "memory_config")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 4096
    {
        return Err("memory_config");
    }
    let text = fs::read_to_string(path).map_err(|_| "memory_config")?;
    let mut lines = text.lines();
    if lines.next() != Some("schema=automonique.memory/v1") {
        return Err("memory_config");
    }
    let tenant = lines
        .next()
        .and_then(|line| line.strip_prefix("tenant="))
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .ok_or("memory_config")?;
    if lines.next() != Some("end=automonique.memory/v1") || lines.next().is_some() {
        return Err("memory_config");
    }
    Ok(tenant.to_owned())
}

fn unique_actor(path: &Path, tenant: &str) -> Result<String, &'static str> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "memory_store")?;
    let cross_transport = actors_for_query(
        &connection,
        "SELECT actor FROM identity_bindings WHERE tenant=?1
         GROUP BY actor HAVING count(DISTINCT platform) >= 2 ORDER BY actor LIMIT 2",
        tenant,
    )?;
    if let [actor] = cross_transport.as_slice() {
        return validated_actor(actor);
    }
    let actors = actors_for_query(
        &connection,
        "SELECT actor FROM (
           SELECT actor FROM memories WHERE tenant=?1
           UNION SELECT actor FROM messages WHERE tenant=?1
           UNION SELECT actor FROM identity_bindings WHERE tenant=?1
         ) ORDER BY actor LIMIT 2",
        tenant,
    )?;
    let [actor] = actors.as_slice() else {
        return Err("memory_actor_not_unique");
    };
    validated_actor(actor)
}

fn actors_for_query(
    connection: &Connection,
    query: &str,
    tenant: &str,
) -> Result<Vec<String>, &'static str> {
    let mut statement = connection.prepare(query).map_err(|_| "memory_store")?;
    statement
        .query_map(params![tenant], |row| row.get::<_, String>(0))
        .map_err(|_| "memory_store")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "memory_store")
}

fn validated_actor(actor: &str) -> Result<String, &'static str> {
    if actor.is_empty()
        || actor.len() > 256
        || !actor.is_ascii()
        || actor.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("memory_actor_invalid");
    }
    Ok(actor.to_owned())
}
