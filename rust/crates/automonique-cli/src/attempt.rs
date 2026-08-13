// SPDX-License-Identifier: Elastic-2.0

//! Operator client for the runner's per-attempt control socket.
//!
//! This is the client half of [`automonique_runner::control`], and it carries
//! the same discipline the server does, from the other end of the wire:
//!
//! - **The path is judged before the connection.** Absolute, free of `.`, `..`
//!   and symlinks, short enough for `sun_path`, inside a private owned
//!   directory, and itself an owned mode-`0600` socket. A path that fails any
//!   of these is refused without a `connect`, so a mistyped or hostile path
//!   never gets a request byte.
//! - **The greeting is checked before a request byte is written.** A server
//!   that answers with anything other than [`CONTROL_GREETING`] is refused and
//!   is never told what the operator wanted.
//! - **One request per connection**, bounded by the endpoint's own
//!   [`MAX_REQUEST_LINE_BYTES`], and one response read capped at
//!   [`MAX_RESPONSE_BYTES`] with read and write deadlines on the socket.
//! - **Nothing the server sends is echoed verbatim.** Every rendered word is
//!   either a `'static` spelling from a closed set or a field this client
//!   re-validated against the endpoint's grammar. Event payloads arrive
//!   hex-encoded: they are rendered as text only when every decoded byte is
//!   printable ASCII, and otherwise as the validated lowercase-hex spelling
//!   behind a `hex:` marker. Raw payload bytes never reach the terminal, and
//!   no refusal message carries server-supplied bytes.
//!
//! Subscription is polling, not streaming, exactly as the endpoint defines it:
//! one bounded page per invocation, and the operator re-runs with the printed
//! next cursor.

use automonique_runner::control::{
    CONTROL_GREETING, MAX_IDENTIFIER_BYTES, MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_BYTES,
    MAX_SUBSCRIBE_PAGE_EVENTS, Refusal,
};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// Deadline for the request write and the response read on one connection.
const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Bytes taken from the endpoint in one syscall while reading a response.
const READ_CHUNK_BYTES: usize = 512;
/// Longest greeting this client reads: the exact versioned greeting plus its
/// terminator. Reads are capped at this, so a server that never terminates its
/// greeting cannot make the client buffer.
const MAX_GREETING_BYTES: usize = CONTROL_GREETING.len() + 1;
/// Usable bytes of `sockaddr_un::sun_path` on Linux, excluding the terminator.
/// The endpoint keeps its own copy of this platform bound private, so the
/// client states it rather than discovering it from a failed `connect`.
const MAX_SOCKET_PATH_BYTES: usize = 107;

/// Why one attempt command produced no output.
///
/// Every category is a `'static` word. None of them carries a socket path, an
/// attempt identifier, an event payload or any other byte the endpoint or the
/// operator supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptError {
    /// An operator-supplied field is outside its bounded grammar. Nothing was
    /// opened, connected to or read.
    Field(&'static str),
    /// The named endpoint is missing, is not a private owned socket, or its
    /// transport failed.
    Endpoint(&'static str),
    /// The endpoint answered outside the bounded wire protocol.
    Protocol(&'static str),
    /// The endpoint answered with one of its own typed refusal categories.
    Refused(Refusal),
}

impl AttemptError {
    /// Stable category spelling written to stderr.
    const fn category(self) -> &'static str {
        match self {
            Self::Field(category) | Self::Endpoint(category) | Self::Protocol(category) => category,
            Self::Refused(refusal) => refusal.as_str(),
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

/// One operator request against one control socket.
#[derive(Clone)]
pub(crate) enum Operation {
    Heartbeat {
        socket_path: OsString,
    },
    Inspect {
        socket_path: OsString,
        attempt_id: OsString,
    },
    Events {
        socket_path: OsString,
        attempt_id: OsString,
        cursor: Option<OsString>,
    },
    Cancel {
        socket_path: OsString,
        attempt_id: OsString,
        request_ref: OsString,
    },
}

/// Answer one attempt operation, writing rendered output only on success.
///
/// A failed operation writes nothing to stdout, so a caller that pipes this
/// command never sees a partial record.
pub(crate) fn run<W: Write, E: Write>(operation: Operation, stdout: &mut W, stderr: &mut E) -> u8 {
    let rendered = match &operation {
        Operation::Heartbeat { socket_path } => heartbeat(socket_path),
        Operation::Inspect {
            socket_path,
            attempt_id,
        } => inspect(socket_path, attempt_id),
        Operation::Events {
            socket_path,
            attempt_id,
            cursor,
        } => events(socket_path, attempt_id, cursor.as_deref()),
        Operation::Cancel {
            socket_path,
            attempt_id,
            request_ref,
        } => cancel(socket_path, attempt_id, request_ref),
    };
    match rendered {
        Ok(text) => {
            if stdout.write_all(text.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique attempt refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Server liveness and binding count. It claims nothing about any attempt.
fn heartbeat(socket_path: &OsStr) -> Result<String, AttemptError> {
    let body = request(socket_path, "heartbeat")?;
    let lines = response_lines(&body)?;
    let [line] = lines.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    let fields: Vec<&str> = line.split(' ').collect();
    let ["heartbeat", uptime_millis, bindings] = fields.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    let uptime_millis = response_unsigned(uptime_millis)?;
    let bindings = response_unsigned(bindings)?;
    Ok(format!(
        "Automonique attempt endpoint: uptime_ms={uptime_millis} bindings={bindings}\n"
    ))
}

/// One status projection of the bound spool.
fn inspect(socket_path: &OsStr, attempt_id: &OsStr) -> Result<String, AttemptError> {
    let attempt_id = identifier_argument(attempt_id, "invalid_attempt_id")?;
    let body = request(socket_path, &format!("inspect {attempt_id}"))?;
    let lines = response_lines(&body)?;
    let [line] = lines.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    let fields: Vec<&str> = line.split(' ').collect();
    let ["status", echoed, run_id, state, last_sequence] = fields.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    // An answer about another attempt is not this attempt's status, however
    // well formed it is.
    if *echoed != attempt_id {
        return Err(AttemptError::Protocol("attempt_mismatch"));
    }
    let run_id = response_identifier(run_id)?;
    let state = state_word(state)?;
    let last_sequence = response_unsigned(last_sequence)?;
    Ok(format!(
        "Automonique attempt: attempt_id={attempt_id} run_id={run_id} state={state} last_sequence={last_sequence}\n"
    ))
}

/// One bounded page of events strictly after the cursor.
fn events(
    socket_path: &OsStr,
    attempt_id: &OsStr,
    cursor: Option<&OsStr>,
) -> Result<String, AttemptError> {
    let attempt_id = identifier_argument(attempt_id, "invalid_attempt_id")?;
    let cursor = match cursor {
        None => 0,
        Some(value) => value
            .to_str()
            .and_then(parse_unsigned)
            .ok_or(AttemptError::Field("invalid_cursor"))?,
    };
    let body = request(socket_path, &format!("subscribe {attempt_id} {cursor}"))?;
    let lines = response_lines(&body)?;
    let Some((last, records)) = lines.split_last() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    // The page bound is the endpoint's, so a server that overran it is not
    // answering this protocol and its extra records are never rendered.
    if records.len() > MAX_SUBSCRIBE_PAGE_EVENTS {
        return Err(AttemptError::Protocol("page_too_large"));
    }
    let mut rendered =
        format!("Automonique attempt events: attempt_id={attempt_id} cursor={cursor}\n");
    let mut previous = cursor;
    for record in records {
        let fields: Vec<&str> = record.split(' ').collect();
        let ["event", sequence, kind, authority, payload] = fields.as_slice() else {
            return Err(AttemptError::Protocol("malformed_response"));
        };
        let sequence = response_unsigned(sequence)?;
        // Events after a cursor are strictly increasing. A page that repeats or
        // rewinds would make the printed next cursor lose records.
        if sequence <= previous {
            return Err(AttemptError::Protocol("page_disordered"));
        }
        previous = sequence;
        let kind = kind_word(kind)?;
        let authority = authority_word(authority)?;
        let payload = render_payload(payload)?;
        rendered.push_str(&format!(
            "- seq={sequence} kind={kind} authority={authority} payload={payload}\n"
        ));
    }
    let fields: Vec<&str> = last.split(' ').collect();
    let ["end", next_cursor, more] = fields.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    let next_cursor = response_unsigned(next_cursor)?;
    let more = match *more {
        "true" => true,
        "false" => false,
        _ => return Err(AttemptError::Protocol("malformed_response")),
    };
    // Resuming from a cursor that is not the last record delivered would either
    // skip records or replay them, so a disagreeing endpoint is refused rather
    // than printed.
    if next_cursor != previous {
        return Err(AttemptError::Protocol("cursor_mismatch"));
    }
    rendered.push_str(&format!("next cursor: {next_cursor} more: {more}\n"));
    Ok(rendered)
}

/// Deliver one cancellation request, exactly once per request reference.
///
/// The rendered outcome is delivery evidence only: it does not say a process
/// exited, that descendants were reaped, or that the run reached a terminal
/// state. `inspect` remains the way to observe that.
fn cancel(
    socket_path: &OsStr,
    attempt_id: &OsStr,
    request_ref: &OsStr,
) -> Result<String, AttemptError> {
    let attempt_id = identifier_argument(attempt_id, "invalid_attempt_id")?;
    let request_ref = identifier_argument(request_ref, "invalid_request_ref")?;
    let body = request(socket_path, &format!("cancel {attempt_id} {request_ref}"))?;
    let lines = response_lines(&body)?;
    let [line] = lines.as_slice() else {
        return Err(AttemptError::Protocol("malformed_response"));
    };
    let outcome = match *line {
        "cancel_result delivered" => "delivered",
        "cancel_result already_delivered" => "already_delivered",
        _ => return Err(AttemptError::Protocol("malformed_response")),
    };
    Ok(format!(
        "Automonique attempt cancel: attempt_id={attempt_id} request_ref={request_ref} outcome={outcome}\n"
    ))
}

/// Validate the path, connect, check the greeting, send one request line and
/// read one bounded response body.
///
/// The greeting decision happens before the request is written, so a server
/// that does not speak this protocol learns nothing about the operator's
/// intent.
fn request(socket_path: &OsStr, line: &str) -> Result<String, AttemptError> {
    let path = Path::new(socket_path);
    validate_socket_path(path)?;
    if line.is_empty() || line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(AttemptError::Field("invalid_request"));
    }
    let mut stream = UnixStream::connect(path).map_err(|_| AttemptError::Endpoint("io"))?;
    let credentials = getsockopt(&stream, sockopt::PeerCredentials)
        .map_err(|_| AttemptError::Endpoint("insecure_socket"))?;
    if credentials.uid() != geteuid().as_raw() || credentials.pid() <= 0 {
        return Err(AttemptError::Endpoint("insecure_socket"));
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| AttemptError::Endpoint("io"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| AttemptError::Endpoint("io"))?;

    let greeting = read_greeting(&mut stream)?;
    if greeting != CONTROL_GREETING.as_bytes() {
        return Err(AttemptError::Protocol("greeting_mismatch"));
    }
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|_| AttemptError::Endpoint("io"))?;
    let body = read_response(&mut stream)?;
    String::from_utf8(body).map_err(|_| AttemptError::Protocol("response_not_utf8"))
}

/// Read the greeting line, capped at its exact length so a server that never
/// terminates it cannot make this client buffer.
fn read_greeting(stream: &mut UnixStream) -> Result<Vec<u8>, AttemptError> {
    let mut buffer = Vec::with_capacity(MAX_GREETING_BYTES);
    let mut chunk = [0_u8; MAX_GREETING_BYTES];
    loop {
        if let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
            buffer.truncate(position);
            return Ok(buffer);
        }
        if buffer.len() >= MAX_GREETING_BYTES {
            return Err(AttemptError::Protocol("greeting_mismatch"));
        }
        let wanted = MAX_GREETING_BYTES - buffer.len();
        let read = stream
            .read(&mut chunk[..wanted])
            .map_err(|_| AttemptError::Endpoint("io"))?;
        // A peer that closes without greeting has not spoken this protocol.
        if read == 0 {
            return Err(AttemptError::Protocol("greeting_mismatch"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Read the response body to end-of-stream under the endpoint's own ceiling.
fn read_response(stream: &mut UnixStream) -> Result<Vec<u8>, AttemptError> {
    let mut body = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| AttemptError::Endpoint("io"))?;
        if read == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..read]);
        // Checked after every chunk, so at most one chunk is ever held past the
        // ceiling and a flooding endpoint cannot grow this buffer.
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(AttemptError::Protocol("response_too_large"));
        }
    }
}

/// Split a body into newline-terminated lines, mapping a refusal line to a
/// typed error.
///
/// Every line must be terminated and non-empty, so a truncated response is a
/// refusal rather than a short page.
fn response_lines(body: &str) -> Result<Vec<&str>, AttemptError> {
    if body.is_empty() || !body.ends_with('\n') {
        return Err(AttemptError::Protocol("malformed_response"));
    }
    let lines: Vec<&str> = body[..body.len() - 1].split('\n').collect();
    if lines.iter().any(|line| line.is_empty()) {
        return Err(AttemptError::Protocol("malformed_response"));
    }
    if let [single] = lines.as_slice()
        && let Some(category) = single.strip_prefix("refused ")
    {
        return Err(refusal(category));
    }
    Ok(lines)
}

/// Map a refusal category to the endpoint's closed set.
///
/// The table is closed on this side too: a category this client does not know
/// is reported as unrecognised rather than printed, so no server-chosen bytes
/// reach the operator's terminal. A category added to the endpoint therefore
/// needs a line here before it can be named.
fn refusal(category: &str) -> AttemptError {
    let refusal = match category {
        "field_invalid" => Refusal::FieldInvalid,
        "unknown_operation" => Refusal::UnknownOperation,
        "malformed_request" => Refusal::MalformedRequest,
        "request_too_large" => Refusal::RequestTooLarge,
        "target_unknown" => Refusal::TargetUnknown,
        "cursor_ahead" => Refusal::CursorAhead,
        "cancel_conflict" => Refusal::CancelConflict,
        "cancel_unavailable" => Refusal::CancelUnavailable,
        "ledger_full" => Refusal::LedgerFull,
        "internal" => Refusal::Internal,
        _ => return AttemptError::Protocol("refused_unrecognised"),
    };
    debug_assert_eq!(refusal.as_str(), category);
    AttemptError::Refused(refusal)
}

/// Refuse a path that cannot name a live private endpoint, before `connect`.
fn validate_socket_path(path: &Path) -> Result<(), AttemptError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(AttemptError::Field("invalid_socket_path"));
    }
    if path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(AttemptError::Field("invalid_socket_path"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(AttemptError::Field("invalid_socket_path"));
            }
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AttemptError::Endpoint("socket_unavailable")
            } else {
                AttemptError::Endpoint("insecure_socket")
            }
        })?;
        // A symlink anywhere in the path means the inode connected to is not
        // the one inspected here.
        if metadata.file_type().is_symlink() {
            return Err(AttemptError::Endpoint("insecure_socket"));
        }
        if current != path && !metadata.is_dir() {
            return Err(AttemptError::Endpoint("insecure_socket"));
        }
    }
    let directory = path
        .parent()
        .ok_or(AttemptError::Field("invalid_socket_path"))?;
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| AttemptError::Endpoint("socket_unavailable"))?;
    // The endpoint creates and validates its socket inside a private owned
    // directory, so a socket that is not in one is not that endpoint.
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(AttemptError::Endpoint("insecure_socket"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AttemptError::Endpoint("socket_unavailable"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(AttemptError::Endpoint("insecure_socket"));
    }
    Ok(())
}

/// Bounded identifier grammar for an operator-supplied field.
///
/// This mirrors the endpoint's own grammar, which that module keeps private:
/// spelling a request the endpoint would refuse is caught here, before a
/// connection is opened.
fn identifier_argument<'a>(
    value: &'a OsStr,
    category: &'static str,
) -> Result<&'a str, AttemptError> {
    value
        .to_str()
        .filter(|value| is_identifier(value))
        .ok_or(AttemptError::Field(category))
}

/// Same grammar applied to an identifier the endpoint sent back, so a field
/// outside it is never rendered.
fn response_identifier(value: &str) -> Result<&str, AttemptError> {
    if is_identifier(value) {
        Ok(value)
    } else {
        Err(AttemptError::Protocol("malformed_response"))
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
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

fn response_unsigned(value: &str) -> Result<u64, AttemptError> {
    parse_unsigned(value).ok_or(AttemptError::Protocol("malformed_response"))
}

/// Closed set of run-state spellings. The rendered word is always `'static`.
fn state_word(value: &str) -> Result<&'static str, AttemptError> {
    match value {
        "ready" => Ok("ready"),
        "running" => Ok("running"),
        "completed" => Ok("completed"),
        "failed" => Ok("failed"),
        "cancelled" => Ok("cancelled"),
        "timed_out" => Ok("timed_out"),
        _ => Err(AttemptError::Protocol("malformed_response")),
    }
}

/// Closed set of event-kind spellings.
fn kind_word(value: &str) -> Result<&'static str, AttemptError> {
    match value {
        "started" => Ok("started"),
        "adapter_event" => Ok("adapter_event"),
        "simulation_event" => Ok("simulation_event"),
        "cancel_requested" => Ok("cancel_requested"),
        "terminal" => Ok("terminal"),
        _ => Err(AttemptError::Protocol("malformed_response")),
    }
}

/// Closed set of authority spellings.
fn authority_word(value: &str) -> Result<&'static str, AttemptError> {
    match value {
        "synthetic" => Ok("synthetic"),
        "authoritative" => Ok("authoritative"),
        _ => Err(AttemptError::Protocol("malformed_response")),
    }
}

/// Render one hex payload field for a terminal.
///
/// `-` is the endpoint's empty payload and stays `-`. Otherwise the field is
/// decoded from lowercase hex — a spelling outside that grammar is refused, not
/// printed — and rendered as `text:` only when every decoded byte is printable
/// ASCII. Anything else keeps its validated hex spelling behind `hex:`, so no
/// control byte, escape sequence or non-UTF-8 sequence from a payload ever
/// reaches the terminal.
fn render_payload(field: &str) -> Result<String, AttemptError> {
    if field == "-" {
        return Ok("-".to_owned());
    }
    let decoded = decode_hex(field)?;
    if decoded
        .iter()
        .all(|byte| (0x20..=0x7e).contains(&u32::from(*byte)))
    {
        let text =
            String::from_utf8(decoded).map_err(|_| AttemptError::Protocol("malformed_payload"))?;
        return Ok(format!("text:{text}"));
    }
    Ok(format!("hex:{field}"))
}

fn decode_hex(field: &str) -> Result<Vec<u8>, AttemptError> {
    if field.is_empty() || !field.len().is_multiple_of(2) {
        return Err(AttemptError::Protocol("malformed_payload"));
    }
    let mut decoded = Vec::with_capacity(field.len() / 2);
    for pair in field.as_bytes().chunks_exact(2) {
        decoded.push(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?);
    }
    Ok(decoded)
}

fn hex_digit(byte: u8) -> Result<u8, AttemptError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AttemptError::Protocol("malformed_payload")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_rendering_never_leaves_the_printable_ascii_range() {
        assert_eq!(render_payload("-").expect("empty payload"), "-");
        assert_eq!(
            render_payload("68656c6c6f").expect("printable payload"),
            "text:hello"
        );
        // A control byte, a DEL and a high byte each fall back to hex.
        for hex in ["00ff", "1b5b324a", "7f", "0a"] {
            assert_eq!(
                render_payload(hex).expect("hex fallback"),
                format!("hex:{hex}")
            );
        }
        // An out-of-grammar spelling is refused rather than rendered.
        for spelling in ["0", "00FF", "zz", "0x00", "-1"] {
            assert_eq!(
                render_payload(spelling),
                Err(AttemptError::Protocol("malformed_payload"))
            );
        }
    }

    #[test]
    fn refusal_categories_map_to_the_closed_set() {
        for category in [
            "field_invalid",
            "unknown_operation",
            "malformed_request",
            "request_too_large",
            "target_unknown",
            "cursor_ahead",
            "cancel_conflict",
            "cancel_unavailable",
            "ledger_full",
            "internal",
        ] {
            assert_eq!(refusal(category).category(), category);
            assert_eq!(refusal(category).exit_code(), 1);
        }
        assert_eq!(
            refusal("something_new").category(),
            "refused_unrecognised",
            "an unknown category must not reach the operator verbatim"
        );
    }

    #[test]
    fn a_private_owned_socket_is_the_only_path_that_survives_validation() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let directory = tempfile::tempdir().expect("directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let socket = directory.path().join("control.sock");
        let _listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("private socket");
        assert_eq!(validate_socket_path(&socket), Ok(()));

        // A widened mode, a widened directory and a regular file each refuse.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
            .expect("widen socket");
        assert_eq!(
            validate_socket_path(&socket),
            Err(AttemptError::Endpoint("insecure_socket"))
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("private socket");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .expect("widen directory");
        assert_eq!(
            validate_socket_path(&socket),
            Err(AttemptError::Endpoint("insecure_socket"))
        );
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let regular = directory.path().join("regular");
        std::fs::write(&regular, b"not a socket").expect("regular file");
        assert_eq!(
            validate_socket_path(&regular),
            Err(AttemptError::Endpoint("insecure_socket"))
        );
        assert_eq!(
            validate_socket_path(&directory.path().join("missing.sock")),
            Err(AttemptError::Endpoint("socket_unavailable"))
        );
        assert_eq!(
            validate_socket_path(Path::new("relative/control.sock")),
            Err(AttemptError::Field("invalid_socket_path"))
        );
    }

    #[test]
    fn canonical_unsigned_spellings_are_the_only_ones_accepted() {
        assert_eq!(parse_unsigned("0"), Some(0));
        assert_eq!(parse_unsigned("18446744073709551615"), Some(u64::MAX));
        for spelling in ["", "00", "01", " 1", "1 ", "+1", "-1", "1_000", "0x1"] {
            assert_eq!(parse_unsigned(spelling), None, "accepted {spelling:?}");
        }
    }
}
