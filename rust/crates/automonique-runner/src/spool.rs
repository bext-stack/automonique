// SPDX-License-Identifier: Elastic-2.0

use nix::fcntl::{Flock, FlockArg};
use nix::unistd::Uid;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;
const GENESIS_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    Synthetic,
    Authoritative,
}

impl Authority {
    fn as_str(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::Authoritative => "authoritative",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "synthetic" => Some(Self::Synthetic),
            "authoritative" => Some(Self::Authoritative),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Started,
    AdapterEvent,
    SimulationEvent,
    CancelRequested,
    Terminal,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::AdapterEvent => "adapter_event",
            Self::SimulationEvent => "simulation_event",
            Self::CancelRequested => "cancel_requested",
            Self::Terminal => "terminal",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "started" => Some(Self::Started),
            "adapter_event" => Some(Self::AdapterEvent),
            "simulation_event" => Some(Self::SimulationEvent),
            "cancel_requested" => Some(Self::CancelRequested),
            "terminal" => Some(Self::Terminal),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    run_id: String,
    sequence: u64,
    at_millis: u64,
    kind: EventKind,
    authority: Authority,
    payload: Vec<u8>,
    digest: [u8; 32],
}

impl Event {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn at_millis(&self) -> u64 {
        self.at_millis
    }
    pub const fn kind(&self) -> EventKind {
        self.kind
    }
    pub const fn authority(&self) -> Authority {
        self.authority
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunState {
    Ready,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl RunState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    run_id: String,
    state: RunState,
    last_sequence: u64,
}

impl Status {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub const fn state(&self) -> RunState {
        self.state
    }
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

#[derive(Debug)]
pub enum SpoolError {
    Io(std::io::Error),
    UnsafeDirectory,
    UnsafeFile,
    AlreadyOpen,
    Corrupt,
    LimitExceeded,
    AlreadyTerminal,
    CursorAhead { requested: u64, available: u64 },
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "spool I/O failed: {error}"),
            Self::UnsafeDirectory => {
                formatter.write_str("spool directory is not a private owned directory")
            }
            Self::UnsafeFile => {
                formatter.write_str("spool file is not a private owned regular file")
            }
            Self::AlreadyOpen => formatter.write_str("spool already has an active writer"),
            Self::Corrupt => formatter.write_str("spool event stream is corrupt"),
            Self::LimitExceeded => formatter.write_str("spool byte limit exceeded"),
            Self::AlreadyTerminal => formatter.write_str("spool already contains a terminal event"),
            Self::CursorAhead {
                requested,
                available,
            } => write!(formatter, "cursor {requested} is ahead of {available}"),
        }
    }
}

impl std::error::Error for SpoolError {}
impl From<std::io::Error> for SpoolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct Spool {
    root: PathBuf,
    run_id: String,
    file: Flock<File>,
    events: Vec<Event>,
    bytes: u64,
    max_bytes: u64,
    terminal: bool,
}

impl Spool {
    pub fn open(
        root: impl Into<PathBuf>,
        run_id: &str,
        max_bytes: u64,
    ) -> Result<Self, SpoolError> {
        let root = root.into();
        create_or_validate_directory(&root)?;
        let event_path = root.join("events.ndjson");
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&event_path)?;
        validate_private_file(&file)?;
        let mut file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| SpoolError::AlreadyOpen)?;
        let original_bytes = file.metadata()?.len();
        if original_bytes > max_bytes {
            return Err(SpoolError::LimitExceeded);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        let complete_bytes = raw
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        let events = parse_events(&raw[..complete_bytes], run_id)?;
        if complete_bytes < raw.len() {
            file.set_len(u64::try_from(complete_bytes).map_err(|_| SpoolError::Corrupt)?)?;
            file.sync_data()?;
        }
        let bytes = u64::try_from(complete_bytes).map_err(|_| SpoolError::Corrupt)?;
        let terminal = events
            .last()
            .is_some_and(|event| event.kind == EventKind::Terminal);
        let mut spool = Self {
            root,
            run_id: run_id.to_owned(),
            file,
            events,
            bytes,
            max_bytes,
            terminal,
        };
        spool.write_status(state_from_events(&spool.events))?;
        Ok(spool)
    }

    pub fn append(
        &mut self,
        kind: EventKind,
        authority: Authority,
        payload: &[u8],
    ) -> Result<Event, SpoolError> {
        let at_millis = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| SpoolError::Corrupt)?
                .as_millis(),
        )
        .map_err(|_| SpoolError::Corrupt)?;
        self.append_at(kind, authority, payload, at_millis)
    }

    pub(crate) fn append_at(
        &mut self,
        kind: EventKind,
        authority: Authority,
        payload: &[u8],
        at_millis: u64,
    ) -> Result<Event, SpoolError> {
        if self.terminal {
            return Err(SpoolError::AlreadyTerminal);
        }
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(SpoolError::LimitExceeded);
        }
        let sequence = u64::try_from(self.events.len())
            .map_err(|_| SpoolError::LimitExceeded)?
            .checked_add(1)
            .ok_or(SpoolError::LimitExceeded)?;
        let mut event = Event {
            run_id: self.run_id.clone(),
            sequence,
            at_millis,
            kind,
            authority,
            payload: payload.to_vec(),
            digest: GENESIS_DIGEST,
        };
        let previous = self
            .events
            .last()
            .map_or(GENESIS_DIGEST, |event| event.digest);
        event.digest = chained_digest(&event, &previous);
        let encoded = encode_event(&event, &previous);
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| SpoolError::LimitExceeded)?;
        if self
            .bytes
            .checked_add(encoded_len)
            .is_none_or(|value| value > self.max_bytes)
        {
            return Err(SpoolError::LimitExceeded);
        }
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.bytes += encoded_len;
        self.terminal = kind == EventKind::Terminal;
        self.events.push(event.clone());
        self.write_status(state_from_events(&self.events))?;
        Ok(event)
    }

    pub fn events_after(&self, cursor: u64) -> Result<Vec<Event>, SpoolError> {
        let available = self.events.last().map_or(0, Event::sequence);
        if cursor > available {
            return Err(SpoolError::CursorAhead {
                requested: cursor,
                available,
            });
        }
        Ok(self
            .events
            .iter()
            .filter(|event| event.sequence > cursor)
            .cloned()
            .collect())
    }

    pub fn status(&self) -> Status {
        Status {
            run_id: self.run_id.clone(),
            state: state_from_events(&self.events),
            last_sequence: self.events.last().map_or(0, Event::sequence),
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn write_status(&mut self, state: RunState) -> Result<(), SpoolError> {
        let sequence = self.events.last().map_or(0, Event::sequence);
        let content = format!(
            "{{\"protocol\":\"automonique.runner.status\",\"version\":1,\"run_id_hex\":\"{}\",\"state\":\"{}\",\"last_sequence\":{}}}\n",
            hex(self.run_id.as_bytes()),
            state.as_str(),
            sequence
        );
        let temporary = self
            .root
            .join(format!(".status.{}.tmp", std::process::id()));
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(SpoolError::Io(error)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, self.root.join("status.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn create_or_validate_directory(path: &Path) -> Result<(), SpoolError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(SpoolError::Io(error)),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(SpoolError::UnsafeDirectory);
    }
    Ok(())
}

fn validate_private_file(file: &File) -> Result<(), SpoolError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(SpoolError::UnsafeFile);
    }
    Ok(())
}

fn state_from_events(events: &[Event]) -> RunState {
    let Some(last) = events.last() else {
        return RunState::Ready;
    };
    if last.kind != EventKind::Terminal {
        return RunState::Running;
    }
    match last.payload.as_slice() {
        b"completed" => RunState::Completed,
        b"cancelled" => RunState::Cancelled,
        b"timed_out" => RunState::TimedOut,
        _ => RunState::Failed,
    }
}

fn encode_event(event: &Event, previous: &[u8; 32]) -> Vec<u8> {
    format!("{{\"protocol\":\"automonique.runner.event\",\"version\":1,\"run_id_hex\":\"{}\",\"seq\":{},\"at\":{},\"kind\":\"{}\",\"authority\":\"{}\",\"payload_hex\":\"{}\",\"previous_sha256\":\"{}\",\"sha256\":\"{}\"}}\n", hex(event.run_id.as_bytes()), event.sequence, event.at_millis, event.kind.as_str(), event.authority.as_str(), hex(&event.payload), hex(previous), hex(&event.digest)).into_bytes()
}

fn parse_events(raw: &[u8], expected_run_id: &str) -> Result<Vec<Event>, SpoolError> {
    debug_assert!(raw.is_empty() || raw.ends_with(b"\n"));
    let text = std::str::from_utf8(raw).map_err(|_| SpoolError::Corrupt)?;
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line
            .strip_prefix(
                "{\"protocol\":\"automonique.runner.event\",\"version\":1,\"run_id_hex\":\"",
            )
            .ok_or(SpoolError::Corrupt)?;
        let (run_id_hex, line) = line.split_once("\",\"seq\":").ok_or(SpoolError::Corrupt)?;
        let run_id = String::from_utf8(unhex(run_id_hex).ok_or(SpoolError::Corrupt)?)
            .map_err(|_| SpoolError::Corrupt)?;
        if run_id != expected_run_id {
            return Err(SpoolError::Corrupt);
        }
        let (sequence, line) = line.split_once(",\"at\":").ok_or(SpoolError::Corrupt)?;
        let sequence = sequence.parse::<u64>().map_err(|_| SpoolError::Corrupt)?;
        let expected = u64::try_from(events.len()).map_err(|_| SpoolError::Corrupt)? + 1;
        if sequence != expected {
            return Err(SpoolError::Corrupt);
        }
        let (at_millis, line) = line.split_once(",\"kind\":\"").ok_or(SpoolError::Corrupt)?;
        let at_millis = at_millis.parse::<u64>().map_err(|_| SpoolError::Corrupt)?;
        let (kind, line) = line
            .split_once("\",\"authority\":\"")
            .ok_or(SpoolError::Corrupt)?;
        let kind = EventKind::parse(kind).ok_or(SpoolError::Corrupt)?;
        let (authority, line) = line
            .split_once("\",\"payload_hex\":\"")
            .ok_or(SpoolError::Corrupt)?;
        let authority = Authority::parse(authority).ok_or(SpoolError::Corrupt)?;
        let (payload_hex, line) = line
            .split_once("\",\"previous_sha256\":\"")
            .ok_or(SpoolError::Corrupt)?;
        let payload = unhex(payload_hex).ok_or(SpoolError::Corrupt)?;
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(SpoolError::Corrupt);
        }
        if events
            .last()
            .is_some_and(|event: &Event| event.kind == EventKind::Terminal)
        {
            return Err(SpoolError::Corrupt);
        }
        let (previous_hex, line) = line
            .split_once("\",\"sha256\":\"")
            .ok_or(SpoolError::Corrupt)?;
        let offered_previous = digest_bytes(previous_hex)?;
        let offered_digest = digest_bytes(line.strip_suffix("\"}").ok_or(SpoolError::Corrupt)?)?;
        let event = Event {
            run_id,
            sequence,
            at_millis,
            kind,
            authority,
            payload,
            digest: offered_digest,
        };
        let expected_previous = events
            .last()
            .map_or(GENESIS_DIGEST, |event: &Event| event.digest);
        if offered_previous != expected_previous
            || offered_digest != chained_digest(&event, &expected_previous)
        {
            return Err(SpoolError::Corrupt);
        }
        events.push(event);
    }
    Ok(events)
}

fn chained_digest(event: &Event, previous: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"automonique.runner.event/v1\0");
    hasher.update(previous);
    hasher.update((event.run_id.len() as u64).to_be_bytes());
    hasher.update(event.run_id.as_bytes());
    hasher.update(event.sequence.to_be_bytes());
    hasher.update(event.at_millis.to_be_bytes());
    hasher.update(event.kind.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(event.authority.as_str().as_bytes());
    hasher.update([0]);
    hasher.update((event.payload.len() as u64).to_be_bytes());
    hasher.update(&event.payload);
    hasher.finalize().into()
}

fn digest_bytes(value: &str) -> Result<[u8; 32], SpoolError> {
    let bytes = unhex(value).ok_or(SpoolError::Corrupt)?;
    bytes.try_into().map_err(|_| SpoolError::Corrupt)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
