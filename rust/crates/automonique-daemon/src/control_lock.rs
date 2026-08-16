// SPDX-License-Identifier: Elastic-2.0

//! Process-level exclusion for the product state root.
//!
//! SQLite serializes transactions, but it does not decide which daemon is the
//! active generation. This lock does. It is deliberately a separate regular
//! file: locking a database or WAL inode couples process ownership to SQLite's
//! own file lifecycle and creates stale-inode split-brain hazards.

use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::geteuid;

/// A held exclusive lock. Dropping it releases the kernel lock immediately.
#[derive(Debug)]
pub struct ControlLock {
    _file: Flock<File>,
}

/// Why the state-root lock could not be acquired.
#[derive(Debug)]
pub enum ControlLockError {
    /// Another live process holds the lock.
    Held,
    /// The path is not one private, owned regular file.
    InsecurePath,
    /// The filesystem operation failed.
    Io(std::io::Error),
}

impl ControlLock {
    /// Open, lock, and re-check one explicit lock-file inode.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, ControlLockError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(ControlLockError::Io)?;
        let before = validate(&file, path)?;
        let locked =
            Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, error)| {
                if error == Errno::EWOULDBLOCK || error == Errno::EAGAIN {
                    ControlLockError::Held
                } else {
                    ControlLockError::Io(std::io::Error::from_raw_os_error(error as i32))
                }
            })?;
        let after = validate(&locked, path)?;
        if before != after {
            return Err(ControlLockError::InsecurePath);
        }
        Ok(Self { _file: locked })
    }
}

fn validate(file: &File, path: &Path) -> Result<(u64, u64), ControlLockError> {
    let fd = file.metadata().map_err(ControlLockError::Io)?;
    let named = fs::symlink_metadata(path).map_err(ControlLockError::Io)?;
    let uid = geteuid().as_raw();
    if !fd.file_type().is_file()
        || !named.file_type().is_file()
        || fd.uid() != uid
        || named.uid() != uid
        || fd.mode() & 0o7777 != 0o600
        || named.mode() & 0o7777 != 0o600
        || (fd.dev(), fd.ino()) != (named.dev(), named.ino())
    {
        return Err(ControlLockError::InsecurePath);
    }
    Ok((fd.dev(), fd.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_holder_excludes_a_second_and_drop_releases_immediately() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
        let path = directory.path().join("daemon.lock");
        let first = ControlLock::acquire(&path).expect("first holder");
        assert!(matches!(
            ControlLock::acquire(&path),
            Err(ControlLockError::Held)
        ));
        drop(first);
        ControlLock::acquire(&path).expect("successor acquires after drop");
    }

    #[test]
    fn a_loose_or_symlinked_lock_is_refused() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
        let loose = directory.path().join("loose.lock");
        fs::write(&loose, b"").expect("file");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).expect("loose mode");
        assert!(matches!(
            ControlLock::acquire(&loose),
            Err(ControlLockError::InsecurePath)
        ));

        let target = directory.path().join("target.lock");
        fs::write(&target, b"").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        let link = directory.path().join("link.lock");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(matches!(
            ControlLock::acquire(&link),
            Err(ControlLockError::Io(_))
        ));
    }
}
