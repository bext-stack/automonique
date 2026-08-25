// SPDX-License-Identifier: Elastic-2.0

//! The FUSE filesystem: an in-memory tree whose every byte and object is
//! reserved from the [`Ledger`] before it exists.
//!
//! Storage is process memory on purpose. The spike's question is whether a
//! ceiling can be *enforced* from user space without privilege; where the
//! bytes live is a separate decision the README discusses. Because the ledger
//! bounds the tree, the server's memory is bounded by the byte ceiling plus
//! per-object metadata.
//!
//! No write is cached: the crate negotiates no writeback cache with the
//! kernel, so every `write(2)` in the workload becomes a FUSE `WRITE` that is
//! answered only after the ledger admitted it. The errno the workload sees is
//! therefore the ledger's own answer, at the syscall that asked.

use crate::ledger::{Ceilings, Exceedance, Ledger, LedgerSnapshot, MAX_NAME_BYTES};
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

const ROOT_INO: u64 = 1;
/// How long the kernel may cache an entry or attribute before asking again.
const TTL: Duration = Duration::from_secs(1);
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const PERM_MASK: u32 = 0o7777;
/// Mode bits of the root directory: private to the mount owner.
const ROOT_PERM: u16 = 0o700;

enum Content {
    File(Vec<u8>),
    Directory(BTreeMap<OsString, u64>),
    Symlink(Vec<u8>),
}

struct Node {
    content: Content,
    parent: u64,
    perm: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    open_handles: u32,
    /// Removed from its directory while still open; freed on last release.
    unlinked: bool,
}

impl Node {
    fn new(content: Content, parent: u64, perm: u16, uid: u32, gid: u32) -> Self {
        let now = SystemTime::now();
        Self {
            content,
            parent,
            perm,
            uid,
            gid,
            atime: now,
            mtime: now,
            ctime: now,
            open_handles: 0,
            unlinked: false,
        }
    }

    const fn kind(&self) -> FileType {
        match self.content {
            Content::File(_) => FileType::RegularFile,
            Content::Directory(_) => FileType::Directory,
            Content::Symlink(_) => FileType::Symlink,
        }
    }

    /// Bytes this node holds against the ledger.
    fn size(&self) -> u64 {
        match &self.content {
            Content::File(data) | Content::Symlink(data) => data.len() as u64,
            Content::Directory(_) => 0,
        }
    }

    fn attr(&self, ino: u64) -> FileAttr {
        let size = self.size();
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            crtime: self.ctime,
            kind: self.kind(),
            perm: self.perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: u32::try_from(crate::ledger::STATFS_BLOCK_BYTES).expect("block size fits"),
            flags: 0,
        }
    }
}

/// The tree and the ledger, behind one lock.
pub struct State {
    nodes: HashMap<u64, Node>,
    next_ino: u64,
    ledger: Ledger,
}

/// The state a [`QuotaFs`] serves, shared with whoever mounted it so the
/// ledger can be read back after the session ends.
pub type SharedState = Arc<Mutex<State>>;

impl State {
    fn new(ceilings: Ceilings, uid: u32, gid: u32) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT_INO,
            Node::new(
                Content::Directory(BTreeMap::new()),
                ROOT_INO,
                ROOT_PERM,
                uid,
                gid,
            ),
        );
        Self {
            nodes,
            next_ino: ROOT_INO + 1,
            ledger: Ledger::new(ceilings),
        }
    }

    /// The ledger as it stands.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    fn node(&self, ino: u64) -> Result<&Node, Errno> {
        self.nodes.get(&ino).ok_or(Errno::ENOENT)
    }

    fn node_mut(&mut self, ino: u64) -> Result<&mut Node, Errno> {
        self.nodes.get_mut(&ino).ok_or(Errno::ENOENT)
    }

    fn children(&self, ino: u64) -> Result<&BTreeMap<OsString, u64>, Errno> {
        match &self.node(ino)?.content {
            Content::Directory(children) => Ok(children),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn children_mut(&mut self, ino: u64) -> Result<&mut BTreeMap<OsString, u64>, Errno> {
        match &mut self.node_mut(ino)?.content {
            Content::Directory(children) => Ok(children),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn child(&self, parent: u64, name: &OsStr) -> Result<u64, Errno> {
        self.children(parent)?
            .get(name)
            .copied()
            .ok_or(Errno::ENOENT)
    }

    fn check_name(name: &OsStr) -> Result<(), Errno> {
        let bytes = name.as_bytes();
        if bytes.is_empty() {
            return Err(Errno::EINVAL);
        }
        if bytes.len() > MAX_NAME_BYTES as usize {
            return Err(Errno::ENAMETOOLONG);
        }
        Ok(())
    }

    /// Create one object beneath `parent`, reserving it — and, for a
    /// symlink, its target bytes — from the ledger first.
    fn create_object(
        &mut self,
        parent: u64,
        name: &OsStr,
        content: Content,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<u64, Errno> {
        Self::check_name(name)?;
        if self.children(parent)?.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        self.ledger.reserve_object().map_err(refused)?;
        let bytes = match &content {
            Content::Symlink(target) => target.len() as u64,
            Content::File(_) | Content::Directory(_) => 0,
        };
        if bytes > 0
            && let Err(exceedance) = self.ledger.reserve_bytes(bytes)
        {
            self.ledger.release_object();
            return Err(refused(exceedance));
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes
            .insert(ino, Node::new(content, parent, perm, uid, gid));
        self.children_mut(parent)?.insert(name.to_owned(), ino);
        self.touch(parent);
        Ok(ino)
    }

    /// Forget a node that no directory names and no handle holds, returning
    /// its bytes and its object to the ledger.
    fn drop_node(&mut self, ino: u64) {
        if let Some(node) = self.nodes.remove(&ino) {
            self.ledger.release_bytes(node.size());
            self.ledger.release_object();
        }
    }

    fn touch(&mut self, ino: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            let now = SystemTime::now();
            node.mtime = now;
            node.ctime = now;
        }
    }

    /// Grow or shrink a file to `new_size`, reserving the growth first.
    fn resize(&mut self, ino: u64, new_size: u64) -> Result<(), Errno> {
        let current = match &self.node(ino)?.content {
            Content::File(data) => data.len() as u64,
            Content::Directory(_) => return Err(Errno::EISDIR),
            Content::Symlink(_) => return Err(Errno::EINVAL),
        };
        if new_size > current {
            self.ledger
                .reserve_bytes(new_size - current)
                .map_err(refused)?;
        } else {
            self.ledger.release_bytes(current - new_size);
        }
        let node = self.node_mut(ino)?;
        if let Content::File(data) = &mut node.content {
            let length = usize::try_from(new_size).map_err(|_| Errno::EFBIG)?;
            data.resize(length, 0);
        }
        self.touch(ino);
        Ok(())
    }

    /// Write `data` at `offset`, reserving any growth first. All or nothing.
    fn write_at(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::EFBIG)?;
        let current = match &self.node(ino)?.content {
            Content::File(existing) => existing.len() as u64,
            Content::Directory(_) => return Err(Errno::EISDIR),
            Content::Symlink(_) => return Err(Errno::EINVAL),
        };
        if end > current {
            self.ledger.reserve_bytes(end - current).map_err(refused)?;
        }
        let node = self.node_mut(ino)?;
        if let Content::File(existing) = &mut node.content {
            let start = usize::try_from(offset).map_err(|_| Errno::EFBIG)?;
            let end = usize::try_from(end).map_err(|_| Errno::EFBIG)?;
            if existing.len() < end {
                existing.resize(end, 0);
            }
            existing[start..end].copy_from_slice(data);
        }
        self.touch(ino);
        u32::try_from(data.len()).map_err(|_| Errno::EFBIG)
    }
}

fn refused(exceedance: Exceedance) -> Errno {
    Errno::from_i32(exceedance.errno())
}

fn perm_from_mode(mode: u32) -> u16 {
    u16::try_from(mode & PERM_MASK).expect("twelve bits fit")
}

fn resolve_time(value: TimeOrNow) -> SystemTime {
    match value {
        TimeOrNow::SpecificTime(time) => time,
        TimeOrNow::Now => SystemTime::now(),
    }
}

/// The filesystem handed to `fuser`.
pub struct QuotaFs {
    state: SharedState,
}

impl QuotaFs {
    /// An empty tree under `ceilings`, owned by `uid`/`gid`.
    #[must_use]
    pub fn new(ceilings: Ceilings, uid: u32, gid: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new(ceilings, uid, gid))),
        }
    }

    /// A handle to the state that outlives the session.
    #[must_use]
    pub fn state(&self) -> SharedState {
        Arc::clone(&self.state)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Read the ledger out of a shared state.
#[must_use]
pub fn snapshot(state: &SharedState) -> LedgerSnapshot {
    state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .snapshot()
}

impl Filesystem for QuotaFs {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        // Defaults only: no writeback cache, so every write is answered by
        // the ledger at the syscall that issued it.
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let state = self.lock();
        match state
            .child(parent.0, name)
            .and_then(|ino| state.node(ino).map(|node| node.attr(ino)))
        {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let state = self.lock();
        match state.node(ino.0) {
            Ok(node) => reply.attr(&TTL, &node.attr(ino.0)),
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mut state = self.lock();
        if let Some(size) = size
            && let Err(errno) = state.resize(ino.0, size)
        {
            reply.error(errno);
            return;
        }
        let node = match state.node_mut(ino.0) {
            Ok(node) => node,
            Err(errno) => {
                reply.error(errno);
                return;
            }
        };
        if let Some(mode) = mode {
            node.perm = perm_from_mode(mode);
        }
        if let Some(uid) = uid {
            node.uid = uid;
        }
        if let Some(gid) = gid {
            node.gid = gid;
        }
        if let Some(atime) = atime {
            node.atime = resolve_time(atime);
        }
        if let Some(mtime) = mtime {
            node.mtime = resolve_time(mtime);
        }
        node.ctime = ctime.unwrap_or_else(SystemTime::now);
        reply.attr(&TTL, &node.attr(ino.0));
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let state = self.lock();
        match state.node(ino.0) {
            Ok(Node {
                content: Content::Symlink(target),
                ..
            }) => reply.data(target),
            Ok(_) => reply.error(Errno::EINVAL),
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // Regular files only. Device nodes, fifos and sockets are outside
        // what temporary storage is for, and the runner's read-write grant
        // does not include device creation either.
        if mode & S_IFMT != S_IFREG {
            reply.error(Errno::EPERM);
            return;
        }
        let mut state = self.lock();
        match state.create_object(
            parent.0,
            name,
            Content::File(Vec::new()),
            perm_from_mode(mode),
            req.uid(),
            req.gid(),
        ) {
            Ok(ino) => {
                let attr = state.node(ino).map(|node| node.attr(ino));
                match attr {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(errno) => reply.error(errno),
                }
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let mut state = self.lock();
        match state.create_object(
            parent.0,
            name,
            Content::Directory(BTreeMap::new()),
            perm_from_mode(mode),
            req.uid(),
            req.gid(),
        ) {
            Ok(ino) => {
                let attr = state.node(ino).map(|node| node.attr(ino));
                match attr {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(errno) => reply.error(errno),
                }
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut state = self.lock();
        let result = state.child(parent.0, name).and_then(|ino| {
            let node = state.node(ino)?;
            if matches!(node.content, Content::Directory(_)) {
                return Err(Errno::EISDIR);
            }
            let open = node.open_handles > 0;
            state.children_mut(parent.0)?.remove(name);
            state.touch(parent.0);
            if open {
                // Bytes stay charged until the last descriptor closes: the
                // storage is still consumed, so the ledger still counts it.
                if let Ok(node) = state.node_mut(ino) {
                    node.unlinked = true;
                }
            } else {
                state.drop_node(ino);
            }
            Ok(())
        });
        match result {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut state = self.lock();
        let result = state.child(parent.0, name).and_then(|ino| {
            if !state.children(ino)?.is_empty() {
                return Err(Errno::ENOTEMPTY);
            }
            state.children_mut(parent.0)?.remove(name);
            state.touch(parent.0);
            state.drop_node(ino);
            Ok(())
        });
        match result {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let mut state = self.lock();
        match state.create_object(
            parent.0,
            link_name,
            Content::Symlink(target.as_os_str().as_bytes().to_vec()),
            0o777,
            req.uid(),
            req.gid(),
        ) {
            Ok(ino) => {
                let attr = state.node(ino).map(|node| node.attr(ino));
                match attr {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(errno) => reply.error(errno),
                }
            }
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut state = self.lock();
        let result = (|| {
            State::check_name(newname)?;
            let source = state.child(parent.0, name)?;
            let source_is_dir = matches!(state.node(source)?.content, Content::Directory(_));
            if let Some(&existing) = state.children(newparent.0)?.get(newname) {
                if flags.contains(RenameFlags::RENAME_NOREPLACE) {
                    return Err(Errno::EEXIST);
                }
                if existing == source {
                    return Ok(());
                }
                let target_is_dir = matches!(state.node(existing)?.content, Content::Directory(_));
                match (source_is_dir, target_is_dir) {
                    (true, false) => return Err(Errno::ENOTDIR),
                    (false, true) => return Err(Errno::EISDIR),
                    (true, true) if !state.children(existing)?.is_empty() => {
                        return Err(Errno::ENOTEMPTY);
                    }
                    _ => {}
                }
                state.children_mut(newparent.0)?.remove(newname);
                let open = state.node(existing)?.open_handles > 0;
                if open {
                    state.node_mut(existing)?.unlinked = true;
                } else {
                    state.drop_node(existing);
                }
            }
            state.children_mut(parent.0)?.remove(name);
            state
                .children_mut(newparent.0)?
                .insert(newname.to_owned(), source);
            state.node_mut(source)?.parent = newparent.0;
            state.touch(parent.0);
            state.touch(newparent.0);
            state.touch(source);
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // A hard link would let one set of bytes be named twice while the
        // ledger charges them once; the spike keeps accounting one-to-one.
        reply.error(Errno::EPERM);
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut state = self.lock();
        match state.node_mut(ino.0) {
            Ok(node) if matches!(node.content, Content::Directory(_)) => {
                reply.error(Errno::EISDIR);
            }
            Ok(node) => {
                node.open_handles += 1;
                reply.opened(FileHandle(ino.0), FopenFlags::empty());
            }
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let state = self.lock();
        match state.node(ino.0) {
            Ok(Node {
                content: Content::File(data),
                ..
            }) => {
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                let end = start.saturating_add(size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
            Ok(_) => reply.error(Errno::EINVAL),
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut state = self.lock();
        match state.write_at(ino.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(errno) => reply.error(errno),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut state = self.lock();
        let free = match state.node_mut(ino.0) {
            Ok(node) => {
                node.open_handles = node.open_handles.saturating_sub(1);
                node.unlinked && node.open_handles == 0
            }
            Err(_) => false,
        };
        if free {
            state.drop_node(ino.0);
        }
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let state = self.lock();
        let (parent, children) = match state.node(ino.0) {
            Ok(Node {
                content: Content::Directory(children),
                parent,
                ..
            }) => (*parent, children),
            Ok(_) => {
                reply.error(Errno::ENOTDIR);
                return;
            }
            Err(errno) => {
                reply.error(errno);
                return;
            }
        };
        let mut entries: Vec<(u64, FileType, &OsStr)> = Vec::with_capacity(children.len() + 2);
        entries.push((ino.0, FileType::Directory, OsStr::new(".")));
        entries.push((parent, FileType::Directory, OsStr::new("..")));
        for (name, &child) in children {
            let kind = state
                .node(child)
                .map(Node::kind)
                .unwrap_or(FileType::RegularFile);
            entries.push((child, kind, name.as_os_str()));
        }
        let skip = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, (entry_ino, kind, name)) in entries.into_iter().enumerate().skip(skip) {
            // The offset handed back is the index of the *next* entry.
            if reply.add(INodeNo(entry_ino), (index + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let view = self.lock().ledger.statfs();
        reply.statfs(
            view.blocks,
            view.blocks_free,
            view.blocks_free,
            view.files,
            view.files_free,
            view.block_bytes,
            view.name_max,
            view.block_bytes,
        );
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // The mount carries `default_permissions`, so the kernel checks mode
        // bits against the attributes above before this is ever reached.
        let state = self.lock();
        match state.node(ino.0) {
            Ok(_) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut state = self.lock();
        let created = state
            .create_object(
                parent.0,
                name,
                Content::File(Vec::new()),
                perm_from_mode(mode),
                req.uid(),
                req.gid(),
            )
            .and_then(|ino| {
                let node = state.node_mut(ino)?;
                node.open_handles += 1;
                Ok((ino, node.attr(ino)))
            });
        match created {
            Ok((ino, attr)) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(ino),
                FopenFlags::empty(),
            ),
            Err(errno) => reply.error(errno),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        // Plain preallocation only; hole punching and the other modes are
        // outside what a scratch filesystem needs.
        if mode != 0 {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }
        let mut state = self.lock();
        let result = offset
            .checked_add(length)
            .ok_or(Errno::EFBIG)
            .and_then(|end| {
                let current = state.node(ino.0)?.size();
                if end > current {
                    state.resize(ino.0, end)
                } else {
                    Ok(())
                }
            });
        match result {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }
}
