// SPDX-License-Identifier: Elastic-2.0

//! Process-level exclusion for the product state root.
//!
//! SQLite serializes transactions, but it does not decide which daemon is the
//! active generation. This lock does. It is deliberately a separate regular
//! file: locking a database or WAL inode couples process ownership to SQLite's
//! own file lifecycle and creates stale-inode split-brain hazards.

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd as _;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::FlockArg;
use nix::unistd::geteuid;

/// A held exclusive lock. Dropping it releases the kernel lock immediately.
#[derive(Debug)]
pub struct ControlLock {
    file: File,
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
        lock(&file)?;
        let after = validate(&file, path)?;
        if before != after {
            return Err(ControlLockError::InsecurePath);
        }
        Ok(Self { file })
    }

    /// Duplicate the locked open-file description for a handoff peer.
    pub(crate) fn duplicate(&self) -> Result<File, ControlLockError> {
        self.file.try_clone().map_err(ControlLockError::Io)
    }

    /// Adopt a duplicated lock descriptor received over the private handoff.
    ///
    /// Re-locking a duplicate is idempotent because both descriptors reference
    /// the same kernel open-file description. The named inode is checked before
    /// and after so a swapped lock path cannot become the generation fence.
    pub(crate) fn adopt(file: File, path: impl AsRef<Path>) -> Result<Self, ControlLockError> {
        let path = path.as_ref();
        let before = validate(&file, path)?;
        lock(&file)?;
        let after = validate(&file, path)?;
        if before != after {
            return Err(ControlLockError::InsecurePath);
        }
        Ok(Self { file })
    }
}

fn lock(file: &File) -> Result<(), ControlLockError> {
    // `nix::fcntl::Flock` explicitly unlocks on every wrapper drop, which is
    // wrong for a duplicated open-file description: dropping the source
    // wrapper would unlock the candidate's duplicate too. The syscall-shaped
    // API leaves the kernel lock attached until the final duplicate closes.
    #[allow(deprecated)]
    nix::fcntl::flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock).map_err(|error| {
        if error == Errno::EWOULDBLOCK || error == Errno::EAGAIN {
            ControlLockError::Held
        } else {
            ControlLockError::Io(std::io::Error::from_raw_os_error(error as i32))
        }
    })
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

    #[test]
    fn a_duplicated_lock_transfers_without_an_unlocked_window() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
        let path = directory.path().join("daemon.lock");
        let first = ControlLock::acquire(&path).expect("first holder");
        let inherited = first.duplicate().expect("duplicate descriptor");
        let successor = ControlLock::adopt(inherited, &path).expect("adopt duplicate");
        drop(first);
        assert!(matches!(
            ControlLock::acquire(&path),
            Err(ControlLockError::Held)
        ));
        drop(successor);
        ControlLock::acquire(&path).expect("lock releases with the last duplicate");
    }
}
