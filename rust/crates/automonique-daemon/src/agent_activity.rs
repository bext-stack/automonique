// SPDX-License-Identifier: Elastic-2.0

//! Bounded metadata-only activity projection for local coding agents.
//!
//! Session contents may contain customer data, prompts and credentials. This
//! adapter never opens them: it counts regular session files whose filesystem
//! modification time falls within the current UTC day.

use std::fs;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

const CODEX_SESSIONS: &str = ".codex/sessions";
const CLAUDE_SESSIONS: &str = ".claude/projects";
const MAX_ENTRIES: usize = 50_000;
const MAX_DEPTH: usize = 12;
const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentActivitySnapshot {
    pub utc_day_start_ms: i64,
    pub codex_session_files: usize,
    pub claude_session_files: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentActivityFailure {
    Clock,
    Unavailable,
    TooManyEntries,
}

pub fn current_day() -> Result<AgentActivitySnapshot, AgentActivityFailure> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .filter(|path| {
            path.is_absolute()
                && path
                    .components()
                    .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
        })
        .ok_or(AgentActivityFailure::Unavailable)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentActivityFailure::Clock)?
        .as_millis();
    let now_ms = i64::try_from(now_ms).map_err(|_| AgentActivityFailure::Clock)?;
    let day_start_ms = now_ms - now_ms.rem_euclid(DAY_MS);
    Ok(AgentActivitySnapshot {
        utc_day_start_ms: day_start_ms,
        codex_session_files: count_modified_since(&home.join(CODEX_SESSIONS), day_start_ms)?,
        claude_session_files: count_modified_since(&home.join(CLAUDE_SESSIONS), day_start_ms)?,
    })
}

fn count_modified_since(root: &Path, threshold_ms: i64) -> Result<usize, AgentActivityFailure> {
    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    let mut seen = 0_usize;
    let mut count = 0_usize;
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(AgentActivityFailure::TooManyEntries);
        }
        let entries = fs::read_dir(directory).map_err(|_| AgentActivityFailure::Unavailable)?;
        for entry in entries {
            seen = seen.saturating_add(1);
            if seen > MAX_ENTRIES {
                return Err(AgentActivityFailure::TooManyEntries);
            }
            let entry = entry.map_err(|_| AgentActivityFailure::Unavailable)?;
            let file_type = entry
                .file_type()
                .map_err(|_| AgentActivityFailure::Unavailable)?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push((entry.path(), depth.saturating_add(1)));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let modified_ms = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .and_then(|duration| i64::try_from(duration.as_millis()).ok());
            if modified_ms.is_some_and(|modified| modified >= threshold_ms) {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_regular_files_but_never_follows_symlinks() {
        let root = tempfile::tempdir().expect("root");
        fs::create_dir(root.path().join("nested")).expect("nested");
        fs::write(root.path().join("nested/session.jsonl"), b"private").expect("session");
        std::os::unix::fs::symlink("nested", root.path().join("alias")).expect("symlink");
        assert_eq!(count_modified_since(root.path(), 0).expect("count"), 1);
    }
}
