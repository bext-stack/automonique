// SPDX-License-Identifier: Elastic-2.0
//! Operator routing table for approved work.
//!
//! A fleet job starts in the working directory the console chose, which is
//! often a repository root rather than the code the ticket is about. The
//! operator knows which host or title prefix maps to which directory and
//! runbook; this module hands that knowledge to the job as one bounded block.
//!
//! The table is a plain text file in the state directory, written by the
//! operator. It is policy, like the work method, so it travels outside the
//! untrusted local-context block. An absent file means no block at all.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// The operator's routing table, relative to the state directory.
pub const ROUTING_FILE: &str = "ticket-routing.md";
/// Ceiling on the rendered table so it cannot crowd the job prompt.
pub const MAX_ROUTING_BYTES: usize = 4 * 1024;

/// Render the routing block, or `None` when the operator wrote no table.
///
/// The file must be a regular file owned by this user and not writable by
/// group or others: it steers where an unattended job edits code.
#[must_use]
pub fn render(state_dir: &Path) -> Option<String> {
    let path = state_dir.join(ROUTING_FILE);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return None;
    }
    if metadata.uid() != fs::metadata(state_dir).ok()?.uid() {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut cut = text.len().min(MAX_ROUTING_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::from("[ticket_routing trust=operator_policy]\n");
    out.push_str(text[..cut].trim_end());
    if cut < text.len() {
        out.push_str("\n[truncated=yes]");
    }
    out.push_str("\n[/ticket_routing]");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn an_absent_or_empty_table_renders_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(render(root.path()), None);
        fs::write(root.path().join(ROUTING_FILE), "  \n").expect("write");
        assert_eq!(render(root.path()), None);
    }

    #[test]
    fn the_table_is_tagged_as_operator_policy_and_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(ROUTING_FILE);
        fs::write(&path, "shop.example.invalid -> /srv/shop\n").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let block = render(root.path()).expect("block");
        assert!(block.starts_with("[ticket_routing trust=operator_policy]\n"));
        assert!(block.contains("shop.example.invalid -> /srv/shop"));
        assert!(block.ends_with("[/ticket_routing]"));

        fs::write(&path, "é".repeat(MAX_ROUTING_BYTES)).expect("write");
        let block = render(root.path()).expect("block");
        assert!(block.contains("[truncated=yes]"));
        assert!(block.len() <= MAX_ROUTING_BYTES + 96);
    }

    #[test]
    fn a_table_others_can_write_or_a_symlink_is_ignored() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(ROUTING_FILE);
        fs::write(&path, "a -> b\n").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("mode");
        assert_eq!(render(root.path()), None);

        fs::remove_file(&path).expect("remove");
        let target = root.path().join("elsewhere.md");
        fs::write(&target, "a -> b\n").expect("write");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert_eq!(render(root.path()), None);
    }
}
