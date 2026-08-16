// SPDX-License-Identifier: Elastic-2.0

//! Private control endpoint for live attempt spools.
//!
//! One [`ControlServer`] owns a Unix stream socket inside a private `0700`
//! directory and serves four bounded read-mostly operations — `inspect`,
//! `subscribe`, `heartbeat` and `cancel` — to peers that share its effective
//! UID. Every connected peer is authenticated from kernel-reported credentials
//! *before* a single request byte is read, so a hostile peer cannot reach the
//! parser at all.
//!
//! What this endpoint establishes:
//!
//! - The peer runs under the same non-root effective UID as this process. That
//!   is a transport boundary between cooperating internal components.
//! - `inspect` and `subscribe` answers are projections of the durable spool
//!   this server was handed, never a second parse of the spool files.
//! - A `cancel` answer is *delivery evidence*: it says only that the request
//!   was handed to the bound cancellation sink, or that an identical request
//!   was already handed over. It is not evidence that a process exited, that
//!   descendants were reaped, or that the run reached a terminal state; those
//!   remain separate observations through `inspect`.
//!
//! What it deliberately does **not** establish:
//!
//! - It is not authorization. Same-UID admission is not an operator role, a
//!   tenant check or a policy decision. A caller that fronts this socket for
//!   untrusted operators must apply its own deny-by-default policy first.
//! - It is not a confidentiality boundary against the same UID. That UID can
//!   already read the mode-`0600` spool, `/proc` and this process's memory.
//! - It never launches, adopts, mutates or terminates anything by itself. It
//!   appends no spool event, and dropping the server does not cancel a run.
//! - Peer disconnection is never interpreted as cancellation.
//!
//! # Wire protocol
//!
//! Line-oriented ASCII, one request per connection, then the server closes.
//! On accept the server writes the greeting [`CONTROL_GREETING`] followed by a
//! newline; the client then writes exactly one request line of at most
//! [`MAX_REQUEST_LINE_BYTES`] bytes plus its terminator.
//!
//! ```text
//! inspect   <attempt-id>                  -> status <attempt-id> <run-id> <state> <last-sequence>
//! subscribe <attempt-id> <cursor>         -> provenance <trace-id> <correlation-id> <causation-id>
//!                                            event <sequence> <kind> <authority> <payload-hex>  (0..=8 lines)
//!                                            end <next-cursor> <more>
//! heartbeat                               -> heartbeat <uptime-millis> <binding-count>
//! cancel    <attempt-id> <request-ref> [<observed-sequence>]
//!                                         -> cancel_result delivered | cancel_result already_delivered
//! <anything else>                         -> refused <category>
//! ```
//!
//! `<payload-hex>` is lowercase hex, or `-` for an empty payload, so every line
//! has fixed arity and no trailing field is empty. `<more>` is `true` or
//! `false`. Unsigned fields are canonical decimal with no leading zeros.
//! Refusal categories are the closed set in [`Refusal`]. A peer that fails
//! credential admission receives nothing at all — not even the greeting — and
//! the connection closes with zero request bytes read.
//!
//! `cancel` is the one request with an optional field. `<observed-sequence>` is
//! the spool sequence the requester had seen when it asked, and it participates
//! in idempotency: a reference presented twice against the same attempt but a
//! different observed sequence is a conflict, not a replay. A three-token
//! `cancel` line is accepted and reads as observed sequence `0`, so a client
//! written against the earlier grammar keeps working byte for byte. The field
//! obeys the same canonical-decimal rule as `<cursor>`; a non-canonical
//! spelling is `field_invalid` and never reaches custody.
//!
//! # Divergence from the R2-04 contract
//!
//! `plan/contracts/R2-04.md` was a design input. It names several types and
//! services that do not exist in this repository, so this module implements the
//! sound core and states the gaps rather than faking them:
//!
//! - **Framing.** The contract specifies length-prefixed canonical JSON
//!   `Message` envelopes with a 64 KiB request / 2 MiB response ceiling and a
//!   closed canonical parser. This module uses a line-oriented grammar with a
//!   4 KiB request bound and the same 2 MiB response ceiling. The bounds,
//!   fixed arity and typed refusals are preserved; the JSON codec is not.
//! - **Target.** The contract routes on a five-coordinate target
//!   (`attempt_id`, `host_id`, `run_id`, `run_spec_digest`, `work_id`) and
//!   returns `target_mismatch` when a non-attempt coordinate differs. Only
//!   `attempt_id` exists as a routing key here, so `target_mismatch` is
//!   unreachable and is not part of [`Refusal`].
//! - **Peer policy types.** R1-04 `PeerCredential`, `PeerPolicy` and
//!   `Admission` do not exist. [`PeerIdentity`] and [`admit_peer`] carry the
//!   same rule — exactly the server's own non-root effective UID, with GID and
//!   PID diagnostic only, and no caller-selectable policy.
//! - **Cancellation service.** R1-25 `RequestRef` still does not exist, and
//!   neither does the contract's typed non-wire `AttemptCancelRequest`. What
//!   *does* now exist is both halves of the service: idempotency is expressed as
//!   the [`CancelCustody`] seam, `automonique-store`'s `cancel_ledger`
//!   implements it host-wide and restart-surviving, and
//!   [`CancelDispatcher`](crate::dispatch::CancelDispatcher) is the
//!   server-held, non-cloneable, registration-based owner of the whole
//!   classify-deliver-record sequence. The runner cannot depend on the store
//!   crate — the dependency runs the other way and a SQLite handle has no
//!   business inside a runner — so the trait lives here and the durable
//!   implementation lives daemon-side. What remains diverged:
//!   - **The default is still in-memory.** [`ControlServer::bind`] installs
//!     [`InMemoryCancelCustody`], bounded at [`MAX_CANCEL_LEDGER_ENTRIES`],
//!     because a runner that opened a database on `bind` would put durable
//!     state in the wrong process. A caller that wants durability passes it in
//!     through [`ControlServer::bind_with_custody`], and only then does
//!     idempotency survive a restart or reach across servers.
//!   - **Delivery still precedes recording.** The server classifies against
//!     custody, delivers, and records only what the sink accepted, so an
//!     unavailable sink records nothing and a retry is a real second attempt.
//!     The cost is stated rather than hidden: a crash between delivery and
//!     recording loses the record, and a replay then delivers twice.
//!   - **Custody here is still not a dispatcher.** Each binding carries its own
//!     [`CancelSink`]; custody decides *whether* to call it and never calls it,
//!     and this module holds no containment handle. Composing a sink onto a real
//!     [`RunContainment::kill`](crate::RunContainment::kill) is the backend's
//!     decision, and owning the sequence across servers is
//!     [`crate::dispatch`]'s — a server reaches it by binding a
//!     [`ControlSeat`](crate::dispatch::ControlSeat)'s custody and sinks, which
//!     needs no change to the code here.
//! - **`observed_sequence`.** The contract's cancel body carries an observed
//!   sequence that participates in conflict detection, and custody now records
//!   one, so the wire carries it as an optional fourth `cancel` token
//!   defaulting to `0`. The contract's *heartbeat* observed sequence is still
//!   absent: heartbeat here claims nothing about any attempt. `requested_at_ms`
//!   is deliberately **not** on the wire — it is stamped by the custody
//!   implementation's own clock, so a client cannot backdate a ledger row.
//! - **Custody races.** This module classifies, delivers and records as three
//!   separate calls and holds no lock across them, so two servers sharing one
//!   durable custody can interleave between classify and record. Left alone the
//!   window is stated rather than locked: if the record then replays, the answer
//!   is still `delivered` because this server's sink did fire; if it conflicts,
//!   the answer is `cancel_conflict` even though delivery already happened.
//!
//!   Closing it needs one owner of both halves, which is
//!   [`CancelDispatcher`](crate::dispatch::CancelDispatcher). Servers bound
//!   through [`ControlSeat`](crate::dispatch::ControlSeat)s over one dispatcher
//!   do not double-deliver: the whole sequence runs under the dispatcher's lock
//!   inside the sink call, so the loser of the race is refused a second delivery
//!   instead of granted one. Two things that composition cannot fix from outside
//!   this module, both stated there in full: this server picks its answer at
//!   classify time, so a losing caller is told `delivered` rather than
//!   `already_delivered`; and [`CancelSink::deliver`]'s single error collapses a
//!   conflict or a full ledger *discovered inside* that section into
//!   `cancel_unavailable`. Each needs a change here — an answer taken from one
//!   call, and a richer sink error — and neither can produce a second delivery
//!   or record a delivery that did not happen. Host-wide still means one
//!   dispatcher instance: two dispatchers over one ledger file interleave
//!   exactly as two bare servers do.
//! - **Subscribe pages.** The contract returns exactly one record per request
//!   with digest, byte count and hex fragments. This module returns up to
//!   [`MAX_SUBSCRIBE_PAGE_EVENTS`] whole events per request and omits the
//!   chain digest, encoded length and record timestamp, because
//!   [`Event`](crate::Event) exposes none of the first two publicly and a timestamp would
//!   make a page depend on wall-clock time rather than on appended content. A
//!   client verifying the hash chain reads the durable spool directly.
//!   Subscription remains bounded polling in both designs: no push, no
//!   long-lived stream, resume by cursor.
//! - **Concurrency.** The contract admits up to 8 concurrent workers with
//!   per-worker permits. This server is single-threaded: [`serve_once`] handles
//!   at most one connection per call on the caller's thread, which is why the
//!   [`Spool`]'s exclusive advisory lock can be held by the binding itself and
//!   why no snapshot/re-registration race exists to close. Backpressure is the
//!   listener backlog plus the per-connection deadline.
//! - **Stale-socket probe.** The contract wants a nonblocking connect polled
//!   for exactly 250 ms followed by an `SO_ERROR` read. This module uses a
//!   blocking `connect` probe, treating only `ECONNREFUSED` as stale and
//!   revalidating device, inode, type, owner, mode and link count immediately
//!   before unlinking. Every other outcome is ambiguous and refuses without
//!   unlinking.
//! - **Recovery vocabulary.** `spool_state` here is [`RunState`], which has no
//!   `reconciliation_required` member; recovery classification belongs to the
//!   spool, not to this endpoint.
//!
//! [`serve_once`]: ControlServer::serve_once

use crate::{Authority, EventKind, RunState, Spool, SpoolError};
use automonique_protocol::provenance::{CausationId, CorrelationId, TraceId};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Versioned greeting written to every admitted peer before any request byte
/// is read.
pub const CONTROL_GREETING: &str = "automonique.control/v2";
/// Longest accepted request line, excluding its newline terminator.
pub const MAX_REQUEST_LINE_BYTES: usize = 4 * 1024;
/// Largest response this server will assemble for one request.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Most attempt bindings one server may hold at once.
pub const MAX_BINDINGS: usize = 128;
/// Most distinct cancel request references [`InMemoryCancelCustody`] retains.
///
/// This is the default custody's bound, not a wire bound. Custody supplied
/// through [`ControlServer::bind_with_custody`] carries whatever capacity it
/// was opened with and answers [`CustodyFailure::Full`] at its own ceiling.
pub const MAX_CANCEL_LEDGER_ENTRIES: usize = 1024;
/// Most events returned by one `subscribe` request.
pub const MAX_SUBSCRIBE_PAGE_EVENTS: usize = 8;
/// Longest accepted attempt identifier or cancel request reference.
pub const MAX_IDENTIFIER_BYTES: usize = 64;

/// Deadline for reading a request or writing a response on one connection.
const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Usable bytes of `sockaddr_un::sun_path` on Linux, excluding the terminator.
const MAX_SOCKET_PATH_BYTES: usize = 107;
/// Bytes read from a client in one syscall while looking for the terminator.
const READ_CHUNK_BYTES: usize = 512;
/// Most already-queued request bytes discarded before closing a connection.
const MAX_DRAIN_BYTES: usize = 64 * 1024;
/// Ceiling on one `event` line: fixed fields plus a hex-encoded payload at the
/// spool's own 64 KiB per-event payload limit.
const MAX_EVENT_LINE_BYTES: usize = 64 + 2 * 64 * 1024;
/// Ceiling on the `end` line that closes a subscription page.
const MAX_END_LINE_BYTES: usize = 64;
/// Ceiling on the provenance line that opens a subscription page.
const MAX_PROVENANCE_LINE_BYTES: usize = 3 * 256 + 32;
/// Answer for a cancellation this server handed to a sink.
const DELIVERED_LINE: &str = "cancel_result delivered\n";
/// Answer for a cancellation custody had already recorded.
const ALREADY_DELIVERED_LINE: &str = "cancel_result already_delivered\n";

// A full page can never reach the response ceiling. The runtime preflight in
// `subscribe` is defence in depth for a future change to either bound.
const _: () = assert!(
    MAX_PROVENANCE_LINE_BYTES
        + MAX_SUBSCRIBE_PAGE_EVENTS * MAX_EVENT_LINE_BYTES
        + MAX_END_LINE_BYTES
        <= MAX_RESPONSE_BYTES
);

/// Kernel-reported identity of a connected peer.
///
/// Constructed from `SO_PEERCRED` by the server. It is also constructible
/// directly so that [`admit_peer`] can be exercised against identities this
/// process cannot produce — connecting as another UID needs privilege that a
/// test does not have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    uid: u32,
    gid: u32,
    pid: i32,
}

impl PeerIdentity {
    /// Record one peer identity exactly as the kernel reported it.
    #[must_use]
    pub const fn new(uid: u32, gid: u32, pid: i32) -> Self {
        Self { uid, gid, pid }
    }

    /// Effective UID of the peer. This is the only admission input.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Effective GID of the peer. Diagnostic only; it changes no decision.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// PID of the peer. Diagnostic only; it changes no decision beyond the
    /// plausibility floor in [`admit_peer`].
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }
}

/// Why a connected peer was not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRefusal {
    /// The kernel reported no credentials for this socket.
    CredentialsUnavailable,
    /// The peer runs under a different UID than this server.
    ForeignUid,
    /// The peer is root. Root is refused even when the server is root, which
    /// is why [`ControlServer::bind`] refuses a root server outright.
    RootPeer,
    /// The kernel reported a PID that cannot name a live process.
    ImplausiblePid,
}

impl PeerRefusal {
    /// Stable category spelling. It carries no peer-supplied bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialsUnavailable => "credentials_unavailable",
            Self::ForeignUid => "foreign_uid",
            Self::RootPeer => "root_peer",
            Self::ImplausiblePid => "implausible_pid",
        }
    }
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "control peer refused: {}", self.as_str())
    }
}

impl std::error::Error for PeerRefusal {}

/// Admit exactly `admitted_uid`, which must be this server's own non-root
/// effective UID.
///
/// This is the whole admission rule. There is no configuration point that can
/// widen it, no request field that can assert an identity, and no wildcard.
///
/// # Errors
///
/// Returns the exact [`PeerRefusal`] category. A refused peer is never told
/// which category applied.
pub const fn admit_peer(peer: PeerIdentity, admitted_uid: u32) -> Result<(), PeerRefusal> {
    if peer.pid <= 0 {
        return Err(PeerRefusal::ImplausiblePid);
    }
    if peer.uid == 0 || admitted_uid == 0 {
        return Err(PeerRefusal::RootPeer);
    }
    if peer.uid != admitted_uid {
        return Err(PeerRefusal::ForeignUid);
    }
    Ok(())
}

/// The bound cancellation path reached no target and accepted no signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelUnavailable;

impl fmt::Display for CancelUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cancellation target accepted no signal")
    }
}

impl std::error::Error for CancelUnavailable {}

/// Backend-owned destination for one attempt's cancellation request.
///
/// The server never terminates anything itself. A binding couples a read-only
/// spool observer with one sink, and `cancel` calls the sink at most once per
/// distinct request reference.
///
/// Composing a sink is the backend's decision. A sink over a
/// [`CancellationToken`](crate::CancellationToken) records intent for a
/// cooperative runner; a sink over
/// [`RunContainment::kill`](crate::RunContainment::kill) reaps a real process
/// tree. Either way, returning `Ok(())` is evidence that the request was
/// delivered, never that a process exited.
pub trait CancelSink: Send {
    /// Deliver one cancellation request for `attempt_id`.
    ///
    /// `request_ref` is the caller's idempotency reference, already checked
    /// against this server's ledger: the sink is not called again for a
    /// reference it has already seen.
    ///
    /// # Errors
    ///
    /// Return [`CancelUnavailable`] when no signal was accepted. The server
    /// then answers `refused cancel_unavailable` and does *not* record the
    /// reference, so a later retry with the same reference is delivered again.
    fn deliver(&self, attempt_id: &str, request_ref: &str) -> Result<(), CancelUnavailable>;
}

/// One cancellation request as custody sees it.
///
/// Everything custody needs and nothing it does not: there is no spool handle,
/// no sink and no timestamp. `requested_at_ms` is absent on purpose — a
/// [`CancelCustody`] implementation stamps its own clock, so a client cannot
/// backdate a durable row by lying on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelClaim<'a> {
    /// Attempt this reference cancels.
    pub attempt_id: &'a str,
    /// The requester's idempotency reference. The unique key.
    pub request_ref: &'a str,
    /// Spool sequence the requester had observed when it asked.
    ///
    /// Part of the binding: the same reference presented against the same
    /// attempt at a different observed sequence is a
    /// [`CustodyVerdict::Conflict`], not a replay.
    pub observed_sequence: u64,
}

/// What custody holds for one claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyVerdict {
    /// Custody holds no binding for this reference and has room to record one.
    /// From [`CancelCustody::record`] it means the binding is now held.
    Fresh,
    /// Custody already holds this exact binding. The sink must not be called
    /// again, and [`CancelCustody::record`] wrote nothing.
    Replay,
    /// Custody holds this reference against a different attempt or a different
    /// observed sequence. Nothing was written.
    Conflict,
}

/// Why custody could not answer at all.
///
/// Distinct from [`CustodyVerdict::Conflict`], which is an answer: a conflict
/// is a client bug custody detected, whereas these two say custody itself could
/// not reach a decision. Collapsing them would report a broken ledger as a
/// misbehaving client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyFailure {
    /// Custody holds its full capacity, so a delivery could not be recorded.
    /// Reported to the client as `ledger_full`.
    Full,
    /// Custody is unreachable, corrupt, or otherwise unsound. Reported to the
    /// client as `internal`, because nothing the client sent caused it.
    Unavailable,
}

impl fmt::Display for CustodyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full => "cancel custody holds its full capacity",
            Self::Unavailable => "cancel custody is unavailable",
        })
    }
}

impl std::error::Error for CustodyFailure {}

/// Idempotency custody for cancellation requests.
///
/// This is the seam between an endpoint that must answer a retry the same way
/// it answered the original, and whatever actually remembers that. The server
/// holds one implementation for its whole lifetime and consults it around every
/// `cancel`; it keeps no idempotency state of its own.
///
/// The two methods exist because the server delivers between them:
///
/// 1. [`classify`](CancelCustody::classify) decides one claim and writes
///    nothing. A [`CustodyVerdict::Replay`] answers the client without the sink
///    ever being called, which is what makes idempotency observable rather than
///    merely claimed.
/// 2. [`record`](CancelCustody::record) is called only after a sink accepted
///    delivery, so a delivery that never happened is never remembered as one.
///
/// The ordering costs exactly one thing, and it is stated rather than hidden: a
/// crash between the two loses the record, and a later replay delivers a second
/// time. The alternative — record first — turns every crash into a
/// cancellation that was recorded but never delivered, which is worse for a
/// caller that reads the ledger to decide whether to act.
///
/// An implementation must be consistent across the pair: a claim that
/// `classify` called [`CustodyVerdict::Fresh`] must not become a
/// [`CustodyVerdict::Conflict`] on `record` unless something outside this
/// server wrote in between.
pub trait CancelCustody: Send {
    /// Decide one claim without recording anything.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyFailure::Full`] when custody has no room for a new
    /// binding — refused *before* delivery, because a delivery custody cannot
    /// record would lose idempotency for every later replay — and
    /// [`CustodyFailure::Unavailable`] when custody could not be consulted.
    fn classify(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure>;

    /// Record one claim whose delivery a sink accepted.
    ///
    /// # Errors
    ///
    /// Same categories as [`classify`](CancelCustody::classify).
    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure>;
}

/// Process-local, server-scoped custody. The default.
///
/// Bounded at [`MAX_CANCEL_LEDGER_ENTRIES`] distinct references. It is honest
/// about what it is not: idempotency held here dies with the process and is
/// never host-wide, which is the whole reason [`CancelCustody`] is a trait.
#[derive(Debug)]
pub struct InMemoryCancelCustody {
    entries: HashMap<String, (String, u64)>,
    capacity: usize,
}

impl InMemoryCancelCustody {
    /// Custody bounded at [`MAX_CANCEL_LEDGER_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_CANCEL_LEDGER_ENTRIES)
    }

    /// Custody bounded at `capacity` distinct references.
    ///
    /// A capacity above [`MAX_CANCEL_LEDGER_ENTRIES`] is clamped down to it, so
    /// no caller can widen this process's memory footprint past the module's
    /// own stated bound.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.min(MAX_CANCEL_LEDGER_ENTRIES),
        }
    }

    /// References currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether any reference is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Shared decision for both trait methods, so the pair cannot drift.
    fn verdict(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        match self.entries.get(claim.request_ref) {
            Some((attempt_id, observed_sequence)) => {
                if attempt_id == claim.attempt_id && *observed_sequence == claim.observed_sequence {
                    Ok(CustodyVerdict::Replay)
                } else {
                    Ok(CustodyVerdict::Conflict)
                }
            }
            // Lookup precedes the capacity check so a replay is still a replay
            // in a full ledger: it writes nothing and must never degrade into a
            // refusal.
            None if self.entries.len() >= self.capacity => Err(CustodyFailure::Full),
            None => Ok(CustodyVerdict::Fresh),
        }
    }
}

impl Default for InMemoryCancelCustody {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelCustody for InMemoryCancelCustody {
    fn classify(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        self.verdict(claim)
    }

    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        let verdict = self.verdict(claim)?;
        if verdict == CustodyVerdict::Fresh {
            self.entries.insert(
                claim.request_ref.to_owned(),
                (claim.attempt_id.to_owned(), claim.observed_sequence),
            );
        }
        Ok(verdict)
    }
}

/// Closed set of refusal categories that reach the wire.
///
/// A refusal carries only its category. It never echoes the request, a payload,
/// the socket path, an attempt identifier or any event bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// A field's spelling is outside its bounded grammar.
    FieldInvalid,
    /// The operation word is not one of the four known operations.
    UnknownOperation,
    /// The request was not one newline-terminated UTF-8 line.
    MalformedRequest,
    /// The request line exceeded [`MAX_REQUEST_LINE_BYTES`].
    RequestTooLarge,
    /// No binding holds the supplied attempt identifier.
    TargetUnknown,
    /// The cursor is ahead of the last sequence the spool holds.
    CursorAhead,
    /// Custody binds this request reference to a different attempt or to a
    /// different observed sequence.
    CancelConflict,
    /// The bound cancellation sink accepted no signal.
    CancelUnavailable,
    /// Cancel custody is full, so a delivery could not be recorded.
    LedgerFull,
    /// A server invariant failed. No partial response was written.
    Internal,
}

impl Refusal {
    /// Stable category spelling used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FieldInvalid => "field_invalid",
            Self::UnknownOperation => "unknown_operation",
            Self::MalformedRequest => "malformed_request",
            Self::RequestTooLarge => "request_too_large",
            Self::TargetUnknown => "target_unknown",
            Self::CursorAhead => "cursor_ahead",
            Self::CancelConflict => "cancel_conflict",
            Self::CancelUnavailable => "cancel_unavailable",
            Self::LedgerFull => "ledger_full",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "control request refused: {}", self.as_str())
    }
}

impl std::error::Error for Refusal {}

/// Why a control server could not be constructed or a binding registered.
///
/// These are host-side failures. None of them is reachable from the wire.
#[derive(Debug)]
pub enum ControlError {
    Io(std::io::Error),
    /// `poll` on the listener failed for a reason other than interruption.
    Poll(Errno),
    /// The socket path is not absolute, or names no final component.
    SocketPathNotAbsolute,
    /// The socket path does not fit `sockaddr_un::sun_path`.
    SocketPathTooLong,
    /// The containing directory is not a private, owned, non-symlink directory.
    UnsafeDirectory,
    /// The named socket is not an owned mode-`0600` socket, or its identity
    /// drifted between inspection and unlink.
    UnsafeSocket,
    /// Another process is accepting connections at this path.
    SocketInUse,
    /// This process runs as root. A root server would have to admit root
    /// peers, so it refuses to exist instead.
    RootEffectiveUid,
    /// A host-supplied identifier is outside its bounded grammar. The field
    /// name is static and carries no value bytes.
    InvalidIdentifier(&'static str),
    /// A binding already holds this attempt identifier. Registration never
    /// replaces a live binding.
    DuplicateAttempt,
    /// No binding holds this attempt identifier.
    UnknownAttempt,
    /// The server already holds [`MAX_BINDINGS`] bindings.
    BindingLimit,
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "control I/O failed: {error}"),
            Self::Poll(errno) => write!(formatter, "control listener poll failed: {errno}"),
            Self::SocketPathNotAbsolute => {
                formatter.write_str("control socket path is not an absolute file path")
            }
            Self::SocketPathTooLong => write!(
                formatter,
                "control socket path exceeds {MAX_SOCKET_PATH_BYTES} bytes of sun_path"
            ),
            Self::UnsafeDirectory => {
                formatter.write_str("control socket directory is not a private owned directory")
            }
            Self::UnsafeSocket => {
                formatter.write_str("control socket path is not a private owned socket")
            }
            Self::SocketInUse => {
                formatter.write_str("control socket path already has a live listener")
            }
            Self::RootEffectiveUid => {
                formatter.write_str("control server refused: effective UID is root")
            }
            Self::InvalidIdentifier(field) => {
                write!(formatter, "control {field} is not a bounded identifier")
            }
            Self::DuplicateAttempt => {
                formatter.write_str("control binding already exists for this attempt")
            }
            Self::UnknownAttempt => formatter.write_str("no control binding holds this attempt"),
            Self::BindingLimit => write!(
                formatter,
                "control server already holds {MAX_BINDINGS} attempt bindings"
            ),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<std::io::Error> for ControlError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// What one [`ControlServer::serve_once`] call did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Served {
    /// No peer connected before the timeout expired.
    Idle,
    /// One peer connected and was closed without reading a request byte.
    PeerRefused(PeerRefusal),
    /// One request was answered successfully.
    Answered,
    /// One request was answered with a typed refusal line.
    Refused(Refusal),
    /// The peer disconnected, stalled past the deadline, or its socket failed.
    /// Nothing about the spool or the run changed.
    ClientLost,
}

/// One attempt's read-only spool observer plus its cancellation destination.
struct Binding {
    spool: Spool,
    cancel: Box<dyn CancelSink>,
}

/// A private control endpoint for one host's attempt bindings.
///
/// The server owns its listener, its bindings and the socket inode it created.
/// Dropping it closes the listener and unlinks that inode — and only that
/// inode, verified by device, inode number, type, owner and mode immediately
/// before the unlink. It never cancels a run.
///
/// The server is single-threaded by construction: it borrows the caller's
/// thread for the duration of one [`ControlServer::serve_once`] call. A caller
/// that wants a background endpoint moves the server into a thread it owns and
/// loops, which keeps thread and socket lifetimes explicit.
pub struct ControlServer {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    admitted_uid: u32,
    bindings: HashMap<String, Binding>,
    custody: Box<dyn CancelCustody>,
    started: Instant,
}

impl ControlServer {
    /// Create the private directory if needed, validate it, and bind the
    /// socket at `socket_path` with mode `0600`.
    ///
    /// Cancel idempotency is [`InMemoryCancelCustody`]: server-scoped, lost on
    /// restart, never host-wide. A caller that needs durable custody uses
    /// [`ControlServer::bind_with_custody`] instead — binding a socket must not
    /// be the moment a runner decides to open a database.
    ///
    /// Only the final directory component is created, mirroring
    /// [`Spool::open`]. The parent chain must already exist.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::RootEffectiveUid`] when this process is root,
    /// [`ControlError::SocketPathTooLong`] or
    /// [`ControlError::SocketPathNotAbsolute`] before any filesystem call,
    /// [`ControlError::UnsafeDirectory`] or [`ControlError::UnsafeSocket`] when
    /// the path is not private and owned, and [`ControlError::SocketInUse`]
    /// when a live listener already answers there.
    pub fn bind(socket_path: impl Into<PathBuf>) -> Result<Self, ControlError> {
        Self::bind_with_custody(socket_path, Box::new(InMemoryCancelCustody::new()))
    }

    /// Bind exactly as [`ControlServer::bind`] does, under caller-supplied
    /// cancel idempotency custody.
    ///
    /// This is how durable, host-wide idempotency reaches this endpoint: the
    /// caller opens the ledger, wraps it in a [`CancelCustody`] implementation
    /// and hands it over. Two servers over one durable custody deduplicate
    /// against each other, and a server that restarts over the same custody
    /// answers `already_delivered` for references its predecessor delivered.
    ///
    /// Custody is not consulted here. A custody that is already unreachable
    /// surfaces on the first `cancel` as `refused internal`, not as a bind
    /// failure, because a broken ledger must not take down `inspect`,
    /// `subscribe` and `heartbeat` with it.
    ///
    /// # Errors
    ///
    /// Exactly the categories [`ControlServer::bind`] documents.
    pub fn bind_with_custody(
        socket_path: impl Into<PathBuf>,
        custody: Box<dyn CancelCustody>,
    ) -> Result<Self, ControlError> {
        let socket_path = socket_path.into();
        validate_socket_path(&socket_path)?;
        let admitted_uid = geteuid().as_raw();
        if admitted_uid == 0 {
            return Err(ControlError::RootEffectiveUid);
        }
        let directory = socket_path
            .parent()
            .ok_or(ControlError::SocketPathNotAbsolute)?;
        create_or_validate_directory(directory, admitted_uid)?;
        prepare_socket_path(&socket_path, admitted_uid)?;

        let listener = UnixListener::bind(&socket_path)?;
        // std creates listeners and accepts streams with `SOCK_CLOEXEC`, so no
        // descriptor here survives an `exec`.
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != admitted_uid
            || metadata.mode() & 0o7777 != 0o600
        {
            // The inode that answers this name is not the one just created, so
            // unlinking it would delete a replacement. Refuse without unlink
            // and let the listener descriptor close.
            return Err(ControlError::UnsafeSocket);
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            socket_path,
            socket_identity: (metadata.dev(), metadata.ino()),
            admitted_uid,
            bindings: HashMap::new(),
            custody,
            started: Instant::now(),
        })
    }

    /// Bound socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Effective UID this server admits, and the only one it admits.
    #[must_use]
    pub const fn admitted_uid(&self) -> u32 {
        self.admitted_uid
    }

    /// Live attempt bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Couple one attempt identifier to a spool observer and a cancel sink.
    ///
    /// The server takes the [`Spool`] because a spool holds an exclusive
    /// advisory lock on its event file: sharing one across threads would need
    /// synchronisation this single-threaded server does not have. Reads are
    /// served through the owned spool, which is never appended to here.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::BindingLimit`] at [`MAX_BINDINGS`],
    /// [`ControlError::DuplicateAttempt`] when the identifier is already bound
    /// — registration never silently replaces a live binding — and
    /// [`ControlError::InvalidIdentifier`] when the attempt identifier or the
    /// spool's run identifier is outside the bounded wire grammar.
    pub fn register(
        &mut self,
        attempt_id: &str,
        spool: Spool,
        cancel: Box<dyn CancelSink>,
    ) -> Result<(), ControlError> {
        if !is_identifier(attempt_id) {
            return Err(ControlError::InvalidIdentifier("attempt id"));
        }
        if !is_identifier(spool.status().run_id()) {
            return Err(ControlError::InvalidIdentifier("run id"));
        }
        if self.bindings.contains_key(attempt_id) {
            return Err(ControlError::DuplicateAttempt);
        }
        if self.bindings.len() >= MAX_BINDINGS {
            return Err(ControlError::BindingLimit);
        }
        self.bindings
            .insert(attempt_id.to_owned(), Binding { spool, cancel });
        Ok(())
    }

    /// Release one binding and hand its spool observer back to the caller.
    ///
    /// Custody is not touched: a reference already delivered stays delivered,
    /// so re-registering the same attempt cannot turn a replay into a second
    /// delivery.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::UnknownAttempt`] when no binding holds it.
    pub fn unregister(&mut self, attempt_id: &str) -> Result<Spool, ControlError> {
        self.bindings
            .remove(attempt_id)
            .map(|binding| binding.spool)
            .ok_or(ControlError::UnknownAttempt)
    }

    /// Wait up to `timeout` for one peer, then serve at most one request.
    ///
    /// This never blocks longer than `timeout` plus the per-connection
    /// deadline, so a caller's shutdown flag is observed promptly and a slow or
    /// hostile peer cannot stall the loop indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error only for listener-level failures. A failure caused by
    /// one peer is reported as [`Served::ClientLost`] or
    /// [`Served::PeerRefused`] and the server stays usable.
    pub fn serve_once(&mut self, timeout: Duration) -> Result<Served, ControlError> {
        let millis = u16::try_from(timeout.as_millis()).unwrap_or(u16::MAX);
        let mut fds = [PollFd::new(self.listener.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(millis)) {
            Ok(0) => return Ok(Served::Idle),
            Ok(_) => {}
            // An interrupted wait is not an endpoint failure; the caller polls
            // its shutdown flag and calls again.
            Err(Errno::EINTR) => return Ok(Served::Idle),
            Err(errno) => return Err(ControlError::Poll(errno)),
        }
        match self.listener.accept() {
            Ok((stream, _)) => Ok(self.handle_connection(stream)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(Served::Idle),
            Err(error) => Err(ControlError::Io(error)),
        }
    }

    /// Close the listener and unlink the socket inode this server created.
    ///
    /// Equivalent to dropping the server; it exists so a caller can make the
    /// endpoint's end of life explicit. It does not cancel any run and appends
    /// no spool event.
    pub fn shutdown(self) {
        drop(self);
    }

    /// Authenticate, greet, read one request, answer, close.
    fn handle_connection(&mut self, mut stream: UnixStream) -> Served {
        // Credentials first. No greeting, no deadline and no request byte
        // precedes this decision.
        let identity = match peer_identity(&stream) {
            Ok(identity) => identity,
            Err(refusal) => return Served::PeerRefused(refusal),
        };
        if let Err(refusal) = admit_peer(identity, self.admitted_uid) {
            return Served::PeerRefused(refusal);
        }
        if stream.set_nonblocking(false).is_err()
            || stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            return Served::ClientLost;
        }
        if writeln!(stream, "{CONTROL_GREETING}").is_err() {
            return Served::ClientLost;
        }
        let line = match read_request_line(&mut stream) {
            Ok(line) => line,
            Err(LineError::Transport) => return Served::ClientLost,
            Err(LineError::TooLarge) => {
                return respond_refusal(&mut stream, Refusal::RequestTooLarge);
            }
            Err(LineError::Malformed) => {
                return respond_refusal(&mut stream, Refusal::MalformedRequest);
            }
        };
        match self.answer(&line) {
            Ok(response) => {
                if stream.write_all(response.as_bytes()).is_err() {
                    return Served::ClientLost;
                }
                drain_queued_request(&mut stream);
                Served::Answered
            }
            Err(refusal) => respond_refusal(&mut stream, refusal),
        }
    }

    /// Route one request line to its operation.
    fn answer(&mut self, line: &str) -> Result<String, Refusal> {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.as_slice() {
            ["inspect", attempt_id] => self.inspect(attempt_id),
            ["subscribe", attempt_id, cursor] => self.subscribe(attempt_id, cursor),
            ["heartbeat"] => self.heartbeat(),
            // The observed sequence is the one optional field on this wire. A
            // three-token line is the earlier grammar and reads as sequence
            // zero, so a client that predates this field keeps working.
            ["cancel", attempt_id, request_ref] => self.cancel(attempt_id, request_ref, "0"),
            ["cancel", attempt_id, request_ref, observed_sequence] => {
                self.cancel(attempt_id, request_ref, observed_sequence)
            }
            _ => Err(Refusal::UnknownOperation),
        }
    }

    /// Look up a binding, refusing an invalid spelling before existence.
    ///
    /// The ordering matters: an unbounded or malformed identifier is refused as
    /// `field_invalid` without touching the registry, so a probe cannot use
    /// spelling refusals to learn which attempts exist.
    fn binding(&self, attempt_id: &str) -> Result<&Binding, Refusal> {
        if !is_identifier(attempt_id) {
            return Err(Refusal::FieldInvalid);
        }
        self.bindings.get(attempt_id).ok_or(Refusal::TargetUnknown)
    }

    /// One consistent status projection of the bound spool.
    ///
    /// The projection carries no argv, environment, prompt, credential, path or
    /// event payload — only the run identifier, run state and last sequence.
    fn inspect(&self, attempt_id: &str) -> Result<String, Refusal> {
        let status = self.binding(attempt_id)?.spool.status();
        Ok(format!(
            "status {attempt_id} {} {} {}\n",
            status.run_id(),
            state_word(status.state()),
            status.last_sequence()
        ))
    }

    /// One bounded page of events strictly after `cursor`.
    ///
    /// This is polling, not streaming: the client resumes from `next_cursor`
    /// on a new connection. `more` states whether the spool already holds
    /// further events, so a client never has to guess whether to poll again.
    fn subscribe(&self, attempt_id: &str, cursor: &str) -> Result<String, Refusal> {
        let binding = self.binding(attempt_id)?;
        let cursor = parse_unsigned(cursor)?;
        let events = binding.spool.events_after(cursor).map_err(|error| {
            match error {
                SpoolError::CursorAhead { .. } => Refusal::CursorAhead,
                // A read failure is not a cursor fact and must not be reported
                // as one; an empty page would silently lose events.
                _ => Refusal::Internal,
            }
        })?;
        let status = binding.spool.status();
        let trace_id = TraceId::for_ingress("run", status.run_id());
        let correlation_id =
            CorrelationId::new(format!("attempt:{attempt_id}")).map_err(|_| Refusal::Internal)?;
        let causation_id =
            CausationId::new(format!("run:{}", status.run_id())).map_err(|_| Refusal::Internal)?;
        let mut body = format!("provenance {trace_id} {correlation_id} {causation_id}\n");
        let mut next_cursor = cursor;
        let mut emitted = 0_usize;
        for event in &events {
            if emitted == MAX_SUBSCRIBE_PAGE_EVENTS {
                break;
            }
            let line = format!(
                "event {} {} {} {}\n",
                event.sequence(),
                kind_word(event.kind()),
                authority_word(event.authority()),
                payload_field(event.payload())
            );
            if body.len() + line.len() + MAX_END_LINE_BYTES > MAX_RESPONSE_BYTES {
                if emitted == 0 {
                    // Never truncate a record and never advance past it.
                    return Err(Refusal::Internal);
                }
                break;
            }
            body.push_str(&line);
            next_cursor = event.sequence();
            emitted += 1;
        }
        let more = emitted < events.len();
        body.push_str(&format!("end {next_cursor} {more}\n"));
        Ok(body)
    }

    /// Server liveness and binding count.
    ///
    /// Repeated calls append nothing, advance no cursor and mutate no status.
    /// The answer is deliberately about this server only: it claims nothing
    /// about any attempt, provider session or process being healthy.
    fn heartbeat(&self) -> Result<String, Refusal> {
        let uptime_millis =
            u64::try_from(self.started.elapsed().as_millis()).map_err(|_| Refusal::Internal)?;
        Ok(format!(
            "heartbeat {uptime_millis} {}\n",
            self.bindings.len()
        ))
    }

    /// Deliver one cancellation request, exactly once per request reference.
    ///
    /// The answer is delivery evidence only. `delivered` does not mean the
    /// process exited, that descendants were reaped, or that the spool reached
    /// a terminal state.
    ///
    /// Every idempotency decision here is [`CancelCustody`]'s. This method
    /// holds no reference state of its own, so what the client is told follows
    /// from the custody verdict and nothing else: a replay verdict answers
    /// without touching the sink, a conflict verdict refuses without touching
    /// the sink, and only a fresh verdict reaches the sink at all.
    fn cancel(
        &mut self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: &str,
    ) -> Result<String, Refusal> {
        if !is_identifier(request_ref) {
            return Err(Refusal::FieldInvalid);
        }
        let observed_sequence = parse_unsigned(observed_sequence)?;
        // Existence of the target is checked before custody so that an unbound
        // attempt cannot mint a custody entry.
        self.binding(attempt_id)?;
        let claim = CancelClaim {
            attempt_id,
            request_ref,
            observed_sequence,
        };
        match self.custody.classify(claim).map_err(custody_refusal)? {
            CustodyVerdict::Replay => return Ok(ALREADY_DELIVERED_LINE.to_owned()),
            // Reusing a reference against another attempt, or against another
            // observed sequence, is a client bug rather than a second delivery.
            // Refuse rather than deliver.
            CustodyVerdict::Conflict => return Err(Refusal::CancelConflict),
            CustodyVerdict::Fresh => {}
        }
        self.binding(attempt_id)?
            .cancel
            .deliver(attempt_id, request_ref)
            .map_err(|CancelUnavailable| Refusal::CancelUnavailable)?;
        // Recorded only now: an unavailable delivery leaves custody untouched,
        // so a retry is a real second attempt rather than a false replay.
        match self.custody.record(claim).map_err(custody_refusal)? {
            // A record that replays means another writer bound the same claim
            // between the two calls. This server's sink did fire, so the answer
            // stays delivery evidence.
            CustodyVerdict::Fresh | CustodyVerdict::Replay => Ok(DELIVERED_LINE.to_owned()),
            CustodyVerdict::Conflict => Err(Refusal::CancelConflict),
        }
    }

    /// Unlink the socket only while it is still the exact inode created here.
    ///
    /// A replacement observed by this check survives. The remaining
    /// check-to-unlink window is a same-UID race, which is outside this
    /// endpoint's threat model rather than a closed hole.
    fn remove_socket(&self) {
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.uid() == self.admitted_uid
            && metadata.mode() & 0o7777 == 0o600
            && (metadata.dev(), metadata.ino()) == self.socket_identity
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.remove_socket();
    }
}

impl fmt::Debug for ControlServer {
    /// Deliberately narrow: no spool contents, no attempt identifiers and no
    /// custody references reach a debug rendering.
    ///
    /// The custody entry count is gone rather than proxied through the trait:
    /// counting a durable ledger is a fallible query, and a `Debug` rendering
    /// is not a place to perform one.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlServer")
            .field("bindings", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

/// Write one typed refusal line and close.
fn respond_refusal(stream: &mut UnixStream, refusal: Refusal) -> Served {
    if writeln!(stream, "refused {}", refusal.as_str()).is_err() {
        return Served::ClientLost;
    }
    drain_queued_request(stream);
    Served::Refused(refusal)
}

/// Discard request bytes the kernel has already queued, before closing.
///
/// Closing a stream socket that still holds unread bytes resets the
/// connection, and a reset discards whatever the peer had not yet read —
/// including the refusal line just written. That is exactly the case for an
/// over-long request, where the server stops reading before the peer stops
/// writing, so without this drain the typed refusal would be replaced by a
/// bare connection reset.
///
/// The drain is doubly bounded and never waits: the socket is switched to
/// nonblocking, so only already-queued bytes are taken and a peer that keeps
/// writing cannot hold this thread, and it gives up after
/// [`MAX_DRAIN_BYTES`]. A peer that floods past either bound still gets a
/// reset; that is its own doing and costs this server nothing.
fn drain_queued_request(stream: &mut UnixStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut discarded = 0_usize;
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    while discarded < MAX_DRAIN_BYTES {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => discarded += read,
        }
    }
}

/// Why one request line could not be read.
enum LineError {
    /// The peer disconnected, stalled past the deadline, or its socket failed.
    Transport,
    /// The line exceeded [`MAX_REQUEST_LINE_BYTES`] before a terminator.
    TooLarge,
    /// Not valid UTF-8, or bytes followed the terminator. Exactly one request
    /// per connection is accepted, so a pipelined second request is refused
    /// rather than silently discarded.
    Malformed,
}

/// Read exactly one newline-terminated request line under a bounded ceiling.
fn read_request_line(stream: &mut UnixStream) -> Result<String, LineError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let read = stream.read(&mut chunk).map_err(|_| LineError::Transport)?;
        if read == 0 {
            return Err(LineError::Transport);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
            if position > MAX_REQUEST_LINE_BYTES {
                return Err(LineError::TooLarge);
            }
            if position + 1 != buffer.len() {
                return Err(LineError::Malformed);
            }
            let line =
                std::str::from_utf8(&buffer[..position]).map_err(|_| LineError::Malformed)?;
            return Ok(line.to_owned());
        }
        if buffer.len() > MAX_REQUEST_LINE_BYTES {
            return Err(LineError::TooLarge);
        }
    }
}

/// Read kernel peer credentials for an accepted stream.
fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, PeerRefusal> {
    let credentials = getsockopt(stream, sockopt::PeerCredentials)
        .map_err(|_| PeerRefusal::CredentialsUnavailable)?;
    Ok(PeerIdentity::new(
        credentials.uid(),
        credentials.gid(),
        credentials.pid(),
    ))
}

/// Refuse a path that cannot be bound before touching the filesystem.
fn validate_socket_path(path: &Path) -> Result<(), ControlError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ControlError::SocketPathNotAbsolute);
    }
    if path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(ControlError::SocketPathTooLong);
    }
    Ok(())
}

/// Create the final directory component if absent, then require that it is a
/// private, owned, non-symlink directory.
fn create_or_validate_directory(path: &Path, admitted_uid: u32) -> Result<(), ControlError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(ControlError::Io(error)),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != admitted_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(ControlError::UnsafeDirectory);
    }
    Ok(())
}

/// Clear a stale socket, or refuse.
///
/// Absent is fine. A live listener refuses. Only a refused connection proves
/// staleness, and even then the exact inode is revalidated immediately before
/// the unlink so a replacement is never deleted.
fn prepare_socket_path(path: &Path, admitted_uid: u32) -> Result<(), ControlError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != admitted_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ControlError::UnsafeSocket);
    }
    let identity = (metadata.dev(), metadata.ino());
    match UnixStream::connect(path) {
        Ok(_) => Err(ControlError::SocketInUse),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.uid() != admitted_uid
                || current.mode() & 0o7777 != 0o600
                || current.nlink() != 1
                || (current.dev(), current.ino()) != identity
            {
                return Err(ControlError::UnsafeSocket);
            }
            fs::remove_file(path)?;
            Ok(())
        }
        // Permission denied, timeout or any other error is ambiguous: it does
        // not prove the socket is dead, so nothing is unlinked.
        Err(error) => Err(ControlError::Io(error)),
    }
}

/// Bounded identifier grammar shared by attempt identifiers, run identifiers
/// and cancel request references.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

/// Wire category for a custody failure.
///
/// The split is the point: a full custody is a bound the client can see and
/// retry against, while an unavailable one is this host's own custody being
/// unsound. Reporting the second as `cancel_conflict` — or as any other
/// client-shaped category — would blame the caller for our storage.
const fn custody_refusal(failure: CustodyFailure) -> Refusal {
    match failure {
        CustodyFailure::Full => Refusal::LedgerFull,
        CustodyFailure::Unavailable => Refusal::Internal,
    }
}

/// Canonical unsigned decimal: no sign, no leading zero, no separator.
fn parse_unsigned(value: &str) -> Result<u64, Refusal> {
    if value.is_empty() || value.len() > 20 {
        return Err(Refusal::FieldInvalid);
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(Refusal::FieldInvalid);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Refusal::FieldInvalid);
    }
    value.parse::<u64>().map_err(|_| Refusal::FieldInvalid)
}

/// Wire spelling of a run state.
///
/// This mirrors the spool's own durable spellings, which are private to that
/// module. The byte-exact protocol tests pin every word here, so a divergence
/// fails a test rather than silently changing the wire.
const fn state_word(state: RunState) -> &'static str {
    match state {
        RunState::Ready => "ready",
        RunState::Running => "running",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
        RunState::TimedOut => "timed_out",
    }
}

/// Wire spelling of an event kind.
const fn kind_word(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Started => "started",
        EventKind::AdapterEvent => "adapter_event",
        EventKind::SimulationEvent => "simulation_event",
        EventKind::CancelRequested => "cancel_requested",
        EventKind::Terminal => "terminal",
    }
}

/// Wire spelling of an event's authority.
const fn authority_word(authority: Authority) -> &'static str {
    match authority {
        Authority::Synthetic => "synthetic",
        Authority::Authoritative => "authoritative",
    }
}

/// Hex-encode a payload, or `-` when it is empty, so the field is never blank
/// and every line keeps fixed arity.
fn payload_field(payload: &[u8]) -> String {
    if payload.is_empty() {
        return "-".to_owned();
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(payload.len() * 2);
    for byte in payload {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}
