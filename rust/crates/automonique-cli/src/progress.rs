// SPDX-License-Identifier: Elastic-2.0

//! Operator client for the daemon's live progress endpoint.
//!
//! This is the client half of `automonique_daemon::progress_hub`, and it carries
//! the same discipline the endpoint does, from the other end of the wire:
//!
//! - **The path is judged before the connection.** Absolute, free of `.`, `..`
//!   and symlinks, short enough for `sun_path`, inside a private owned
//!   directory, and itself an owned mode-`0600` socket. A path that fails any of
//!   these is refused without a `connect`.
//! - **The greeting is checked before a request byte is written.** An endpoint
//!   that does not open with a [`StreamMessageKind::Greeting`] is refused and is
//!   never told which run the operator wanted.
//! - **Every rendered word is a closed spelling or a decoded value.** Nothing
//!   the endpoint sends is echoed as bytes: a frame is decoded by the protocol's
//!   own decoder and re-rendered, and its display text is escaped, so an
//!   embedded newline cannot forge a second line of output.
//!
//! # This verb streams, and that changes one rule
//!
//! Every other verb in this CLI renders nothing until it has a complete answer.
//! This one cannot: a subscription is one request and an unbounded sequence of
//! answers, and holding them to render at the end would be holding them
//! forever. So frames are written as they arrive, and a failure part-way leaves
//! what was already written on stdout. That is the honest trade for a `tail`,
//! and it is stated here rather than discovered.
//!
//! # How it ends
//!
//! On the endpoint's own terminal message — `retired`, `lagged`, `refused` or
//! `resync_required` — or when the operator interrupts it. A run that is simply
//! quiet produces nothing and the client keeps waiting, because a silent run is
//! not a finished one.
//!
//! **Interrupting it cancels nothing.** Disconnecting from this endpoint is not
//! a cancellation of anything; `automonique cancel` is.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use automonique_protocol::codec::{FrameDecode, LENGTH_PREFIX_BYTES, decode_frame, encode_frame};
use automonique_protocol::progress_api::{
    MAX_PROGRESS_STREAM_CANONICAL_BYTES, StreamMessage, SubscribeRequest,
};
use automonique_protocol::tools::RunId;
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

use crate::runs::render_frame;

/// Deadline for the handshake: the greeting, the request and the answer.
///
/// It deliberately does not apply to the stream itself. A run that says nothing
/// for a minute is a run that said nothing, not a broken endpoint, and a client
/// that gave up on it would be the wrong kind of honest.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes taken from the endpoint in one syscall.
const READ_CHUNK_BYTES: usize = 4 * 1024;

/// Usable bytes of `sockaddr_un::sun_path` on Linux, excluding the terminator.
const MAX_SOCKET_PATH_BYTES: usize = 107;

/// Why one subscription produced no further output.
///
/// Every category is a `'static` word. None carries a socket path, a run
/// identifier or any byte the endpoint or the operator supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProgressError {
    /// An operator-supplied field is outside its grammar. Nothing was connected
    /// to or read.
    Field(&'static str),
    /// The named endpoint is missing, is not a private owned socket, or its
    /// transport failed.
    Endpoint(&'static str),
    /// The endpoint answered outside the bounded wire protocol.
    Protocol(&'static str),
    /// The endpoint answered with one of its own typed refusal categories.
    Refused(&'static str),
}

impl ProgressError {
    const fn category(self) -> &'static str {
        match self {
            Self::Field(category)
            | Self::Endpoint(category)
            | Self::Protocol(category)
            | Self::Refused(category) => category,
        }
    }

    /// Usage-shaped failures exit 2 like the rest of this CLI; everything the
    /// endpoint or the transport decided exits 1.
    const fn exit_code(self) -> u8 {
        match self {
            Self::Field(_) => 2,
            Self::Endpoint(_) | Self::Protocol(_) | Self::Refused(_) => 1,
        }
    }
}

/// One operator subscription against one progress endpoint.
#[derive(Clone)]
pub(crate) enum Operation {
    Subscribe {
        socket_path: OsString,
        run_id: OsString,
        cursor: Option<OsString>,
    },
}

/// Watch one run, writing frames as they arrive.
pub(crate) fn run<W: Write, E: Write>(operation: &Operation, stdout: &mut W, stderr: &mut E) -> u8 {
    let Operation::Subscribe {
        socket_path,
        run_id,
        cursor,
    } = operation;
    match subscribe(socket_path, run_id, cursor.as_deref(), stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "automonique progress refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Connect, hand shake, then render until the endpoint says the stream is over.
fn subscribe<W: Write>(
    socket_path: &OsStr,
    run_id: &OsStr,
    cursor: Option<&OsStr>,
    stdout: &mut W,
) -> Result<(), ProgressError> {
    let run_id = run_id
        .to_str()
        .and_then(|value| RunId::new(value).ok())
        .ok_or(ProgressError::Field("invalid_run_id"))?;
    let cursor = match cursor {
        None => 0,
        Some(value) => value
            .to_str()
            .and_then(parse_unsigned)
            .ok_or(ProgressError::Field("invalid_cursor"))?,
    };

    let path = Path::new(socket_path);
    validate_socket_path(path)?;
    let mut stream = UnixStream::connect(path).map_err(|_| ProgressError::Endpoint("io"))?;
    let credentials = getsockopt(&stream, sockopt::PeerCredentials)
        .map_err(|_| ProgressError::Endpoint("insecure_socket"))?;
    if credentials.uid() != geteuid().as_raw() || credentials.pid() <= 0 {
        return Err(ProgressError::Endpoint("insecure_socket"));
    }
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| ProgressError::Endpoint("io"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| ProgressError::Endpoint("io"))?;

    let mut buffered = Vec::new();
    // The greeting is read before the request is written, so an endpoint that
    // does not speak this protocol learns nothing about the operator's intent.
    let StreamMessage::Greeting { capability } = read_message(&mut stream, &mut buffered)? else {
        return Err(ProgressError::Protocol("greeting_mismatch"));
    };
    write_message(
        &mut stream,
        &SubscribeRequest::new(run_id.clone(), cursor)
            .to_canonical_bytes()
            .map_err(|_| ProgressError::Field("invalid_request"))?,
    )?;
    line(
        stdout,
        &format!(
            "Automonique progress: run_id={} cursor={cursor} capability={capability}",
            run_id.as_str()
        ),
    )?;

    match read_message(&mut stream, &mut buffered)? {
        StreamMessage::Live { from } => line(stdout, &format!("live from: {from}"))?,
        StreamMessage::ResyncRequired {
            snapshot_from,
            snapshot_to,
        } => {
            line(
                stdout,
                &format!(
                    "resync required: snapshot_from={snapshot_from} snapshot_to={snapshot_to}"
                ),
            )?;
            return Err(ProgressError::Refused("resync_required"));
        }
        StreamMessage::Refused { refusal } => return Err(ProgressError::Refused(refusal.as_str())),
        _ => return Err(ProgressError::Protocol("unexpected_message")),
    }

    // The stream itself has no deadline: see `HANDSHAKE_TIMEOUT`.
    stream
        .set_read_timeout(None)
        .map_err(|_| ProgressError::Endpoint("io"))?;
    let mut previous = cursor;
    loop {
        match read_message(&mut stream, &mut buffered)? {
            StreamMessage::Frame(frame) => {
                // Frames after a cursor strictly increase. A stream that repeats
                // or rewinds would make the cursor an operator resumes from lose
                // frames, so it is refused rather than rendered.
                if frame.sequence() <= previous {
                    return Err(ProgressError::Protocol("stream_disordered"));
                }
                previous = frame.sequence();
                line(stdout, &render_frame(&frame))?;
            }
            StreamMessage::Lagged { delivered_through } => {
                line(
                    stdout,
                    &format!("lagged: delivered_through={delivered_through}"),
                )?;
                return Err(ProgressError::Refused("lagged"));
            }
            StreamMessage::Retired { delivered_through } => {
                return line(
                    stdout,
                    &format!("retired: delivered_through={delivered_through}"),
                );
            }
            StreamMessage::Refused { refusal } => {
                return Err(ProgressError::Refused(refusal.as_str()));
            }
            // A greeting, a live answer or a second resync mid-stream is not
            // this protocol; the closed kind set is what makes that decidable.
            StreamMessage::Greeting { .. }
            | StreamMessage::Live { .. }
            | StreamMessage::ResyncRequired { .. } => {
                return Err(ProgressError::Protocol("unexpected_message"));
            }
        }
    }
}

fn line<W: Write>(stdout: &mut W, text: &str) -> Result<(), ProgressError> {
    writeln!(stdout, "{text}").map_err(|_| ProgressError::Endpoint("io"))
}

/// Read exactly one length-prefixed message, buffering whatever came with it.
///
/// `buffered` carries bytes the kernel handed over beyond one frame, so a
/// second message that arrived in the same read is decoded rather than lost.
fn read_message(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
) -> Result<StreamMessage, ProgressError> {
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        match decode_frame(buffered) {
            Ok(FrameDecode::Frame { payload, consumed }) => {
                let message = StreamMessage::from_canonical_bytes(payload)
                    .map_err(|_| ProgressError::Protocol("malformed_message"))?;
                buffered.drain(..consumed);
                return Ok(message);
            }
            Ok(FrameDecode::NeedMore { .. }) => {}
            Err(_) => return Err(ProgressError::Protocol("malformed_message")),
        }
        // Checked before every read, so at most one chunk is ever held past the
        // ceiling and a flooding endpoint cannot grow this buffer.
        if buffered.len() > LENGTH_PREFIX_BYTES + MAX_PROGRESS_STREAM_CANONICAL_BYTES {
            return Err(ProgressError::Protocol("message_too_large"));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|_| ProgressError::Endpoint("io"))?;
        if read == 0 {
            return Err(ProgressError::Endpoint("stream_closed"));
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

fn write_message(stream: &mut UnixStream, payload: &[u8]) -> Result<(), ProgressError> {
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    encode_frame(payload, &mut framed).map_err(|_| ProgressError::Field("invalid_request"))?;
    stream
        .write_all(&framed)
        .map_err(|_| ProgressError::Endpoint("io"))?;
    stream.flush().map_err(|_| ProgressError::Endpoint("io"))
}

/// Refuse a path that cannot name a live private endpoint, before `connect`.
///
/// The same rule `attempt` applies to the runner's control socket, spelled
/// against this endpoint's own path.
fn validate_socket_path(path: &Path) -> Result<(), ProgressError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ProgressError::Field("invalid_socket_path"));
    }
    if path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(ProgressError::Field("invalid_socket_path"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ProgressError::Field("invalid_socket_path"));
            }
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProgressError::Endpoint("socket_unavailable")
            } else {
                ProgressError::Endpoint("insecure_socket")
            }
        })?;
        // A symlink anywhere in the path means the inode connected to is not the
        // one inspected here.
        if metadata.file_type().is_symlink() {
            return Err(ProgressError::Endpoint("insecure_socket"));
        }
        if current != path && !metadata.is_dir() {
            return Err(ProgressError::Endpoint("insecure_socket"));
        }
    }
    let directory = path
        .parent()
        .ok_or(ProgressError::Field("invalid_socket_path"))?;
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| ProgressError::Endpoint("socket_unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(ProgressError::Endpoint("insecure_socket"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProgressError::Endpoint("socket_unavailable"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ProgressError::Endpoint("insecure_socket"));
    }
    Ok(())
}

/// Canonical unsigned decimal: no sign, no leading zero, no separator.
fn parse_unsigned(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > 20 {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::progress_api::StreamMessageKind;

    #[test]
    fn every_stream_kind_this_client_can_meet_is_handled() {
        // The closed set is the client's contract too: a kind added to the
        // protocol without a case here would be rendered as
        // `unexpected_message`, and this is what makes that a decision rather
        // than an oversight.
        assert_eq!(StreamMessageKind::ALL.len(), 7);
        for kind in StreamMessageKind::ALL {
            let terminal = matches!(
                kind,
                StreamMessageKind::ResyncRequired
                    | StreamMessageKind::Lagged
                    | StreamMessageKind::Retired
                    | StreamMessageKind::Refused
            );
            assert_eq!(kind.is_terminal(), terminal, "{kind}");
        }
    }

    #[test]
    fn canonical_unsigned_spellings_are_the_only_ones_accepted() {
        assert_eq!(parse_unsigned("0"), Some(0));
        assert_eq!(parse_unsigned("18446744073709551615"), Some(u64::MAX));
        for spelling in ["", "00", "01", " 1", "1 ", "+1", "-1", "1_000", "0x1"] {
            assert_eq!(parse_unsigned(spelling), None, "accepted {spelling:?}");
        }
    }

    #[test]
    fn a_private_owned_socket_is_the_only_path_that_survives_validation() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let directory = tempfile::tempdir().expect("directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let socket = directory.path().join("progress.sock");
        let _listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("private socket");
        assert_eq!(validate_socket_path(&socket), Ok(()));

        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
            .expect("widen socket");
        assert_eq!(
            validate_socket_path(&socket),
            Err(ProgressError::Endpoint("insecure_socket"))
        );
        assert_eq!(
            validate_socket_path(&directory.path().join("missing.sock")),
            Err(ProgressError::Endpoint("socket_unavailable"))
        );
        assert_eq!(
            validate_socket_path(Path::new("relative/progress.sock")),
            Err(ProgressError::Field("invalid_socket_path"))
        );
    }
}
