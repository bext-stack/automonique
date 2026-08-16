// SPDX-License-Identifier: Elastic-2.0

//! The spool as the progress record: appended frames, re-opened, re-verified.
//!
//! Nothing here needs a sandbox, a cgroup or a process. The claim being tested
//! is the one everything downstream rests on — that a progress frame written
//! into the hash-chained log comes back out of it byte-for-byte, at the sequence
//! it was given, and that a reader who takes no lock sees exactly what the
//! writer wrote.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use automonique_protocol::event::{
    Authority as FrameAuthority, EventKind as FrameKind, RetryCategory, RetryContext, StepStatus,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    MAX_PROGRESS_CANONICAL_BYTES, ProgressBody, ProgressBodyParts, ProgressFrame,
    ProgressFrameParts, ProgressText,
};
use automonique_protocol::tools::RunId;
use automonique_runner::{
    Authority, Event, EventKind, MAX_EVENT_PAYLOAD_BYTES, Spool, SpoolError, read_events,
};

const MAX_SPOOL_BYTES: u64 = 1024 * 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-spool-progress-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("a private temporary directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private mode");
        Self(path)
    }

    fn root(&self) -> PathBuf {
        self.0.join("spool")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_id() -> RunId {
    RunId::new("run-spool-progress").expect("a valid run identity")
}

/// One frame per shape a producer actually writes: a step, a message, a fault.
fn frames() -> Vec<ProgressFrame> {
    let step = ProgressBody::new(
        FrameKind::ToolCallStarted,
        ProgressBodyParts {
            text: Some(ProgressText::new("read_file").expect("plain text")),
            step: Some(StepStatus::InProgress),
            retry: None,
        },
    )
    .expect("a tool call with its step");
    let delta = ProgressBody::new(
        FrameKind::AssistantMessageDelta,
        ProgressBodyParts {
            text: Some(ProgressText::new("half a sen").expect("plain text")),
            step: None,
            retry: None,
        },
    )
    .expect("a delta with its text");
    let fault = ProgressBody::new(
        FrameKind::ProviderFault,
        ProgressBodyParts {
            text: Some(ProgressText::new("upstream said no").expect("plain text")),
            step: None,
            retry: Some(
                RetryContext::new(RetryCategory::RateLimited, true, Some(4_000), 2)
                    .expect("a coherent context"),
            ),
        },
    )
    .expect("a fault with its context");

    [
        (
            2,
            FrameAuthority::Authoritative,
            FrameKind::ToolCallStarted,
            step,
        ),
        (
            3,
            FrameAuthority::Synthetic,
            FrameKind::AssistantMessageDelta,
            delta,
        ),
        (
            4,
            FrameAuthority::Authoritative,
            FrameKind::ProviderFault,
            fault,
        ),
    ]
    .into_iter()
    .map(|(sequence, authority, kind, body)| {
        ProgressFrame::new(ProgressFrameParts {
            run_id: run_id(),
            sequence,
            at_ms: EpochMillis::from_millis(
                1_700_000_000_000 + i64::try_from(sequence).expect("a small sequence"),
            ),
            authority,
            kind,
            body,
        })
        .expect("a stamped frame")
    })
    .collect()
}

const fn spool_authority(authority: FrameAuthority) -> Authority {
    match authority {
        FrameAuthority::Authoritative => Authority::Authoritative,
        FrameAuthority::Synthetic => Authority::Synthetic,
    }
}

/// Write a `started`, the three frames, then the terminal event.
fn write_attempt(root: &Path) -> Vec<Vec<u8>> {
    let mut spool =
        Spool::open(root, run_id().as_str(), MAX_SPOOL_BYTES).expect("a fresh spool opens");
    spool
        .append(EventKind::Started, Authority::Authoritative, b"pid=1")
        .expect("the started event");
    let mut payloads = Vec::new();
    for frame in frames() {
        let payload = frame.to_canonical_bytes().expect("a frame encodes");
        let appended = spool
            .append(
                EventKind::AdapterEvent,
                spool_authority(frame.authority()),
                &payload,
            )
            .expect("a frame appends");
        assert_eq!(
            appended.sequence(),
            frame.sequence(),
            "the frame's own sequence must be the position it was stored at"
        );
        payloads.push(payload);
    }
    spool
        .append(EventKind::Terminal, Authority::Authoritative, b"completed")
        .expect("the terminal event");
    payloads
}

#[test]
fn appended_frames_survive_a_reopen_that_reverifies_the_chain() {
    let temporary = TempDir::new("roundtrip");
    let written = write_attempt(&temporary.root());

    // `Spool::open` parses every line and refuses a chain that does not verify,
    // so re-opening is the verification rather than a step before it.
    let reopened =
        Spool::open(temporary.root(), run_id().as_str(), MAX_SPOOL_BYTES).expect("it re-opens");
    let events = reopened.events_after(0).expect("every event");
    assert_eq!(events.len(), 5, "started, three frames, terminal");
    assert!(reopened.is_terminal());

    let frames: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind() == EventKind::AdapterEvent)
        .collect();
    assert_eq!(frames.len(), written.len());
    for (event, payload) in frames.iter().zip(&written) {
        assert_eq!(event.payload(), payload.as_slice(), "a payload changed");
        let decoded =
            ProgressFrame::from_canonical_bytes(event.payload()).expect("a stored frame decodes");
        assert_eq!(decoded.sequence(), event.sequence());
        assert_eq!(
            decoded.to_canonical_bytes().expect("it re-encodes"),
            *payload,
            "a frame does not re-encode to the bytes it was stored as"
        );
    }
}

#[test]
fn paging_from_a_cursor_yields_byte_identical_frames() {
    let temporary = TempDir::new("paging");
    write_attempt(&temporary.root());
    let reopened =
        Spool::open(temporary.root(), run_id().as_str(), MAX_SPOOL_BYTES).expect("it re-opens");

    let whole = reopened.events_after(0).expect("every event");
    for cursor in 0..=whole.len() as u64 {
        let page = reopened.events_after(cursor).expect("a page");
        let expected: Vec<Event> = whole
            .iter()
            .filter(|event| event.sequence() > cursor)
            .cloned()
            .collect();
        assert_eq!(page, expected, "cursor {cursor} paged differently");
    }
    // A cursor past the end is a refusal naming both positions, never an empty
    // success that reads as "there is nothing more".
    assert!(matches!(
        reopened
            .events_after(99)
            .expect_err("a cursor past the end"),
        SpoolError::CursorAhead {
            requested: 99,
            available: 5
        }
    ));
}

/// The lock-free reader sees exactly what the writer wrote.
#[test]
fn a_reader_that_takes_no_lock_reads_the_same_record() {
    let temporary = TempDir::new("reader");
    write_attempt(&temporary.root());

    let locked =
        Spool::open(temporary.root(), run_id().as_str(), MAX_SPOOL_BYTES).expect("it re-opens");
    let through_the_writer = locked.events_after(0).expect("every event");
    // Still holding the exclusive lock: a second `Spool::open` would be refused,
    // and this reader is not a second writer. Matched rather than unwrapped
    // because a `Spool` holds a locked file and is deliberately not `Debug`.
    assert!(
        matches!(
            Spool::open(temporary.root(), run_id().as_str(), MAX_SPOOL_BYTES),
            Err(SpoolError::AlreadyOpen)
        ),
        "a second writer was admitted"
    );
    let through_the_reader =
        read_events(temporary.root(), run_id().as_str()).expect("a lock-free read");
    assert_eq!(through_the_reader, through_the_writer);

    // And a reader naming a different run is refused rather than served
    // somebody else's transcript.
    assert!(matches!(
        read_events(temporary.root(), "some-other-run").expect_err("a foreign run"),
        SpoolError::Corrupt
    ));
}

/// The frame ceiling is inside the spool's, which is what lets a producer
/// compose a frame and know it will fit.
#[test]
fn a_maximal_frame_is_inside_the_payload_ceiling() {
    const { assert!(MAX_PROGRESS_CANONICAL_BYTES <= MAX_EVENT_PAYLOAD_BYTES) };
    let temporary = TempDir::new("ceiling");
    let mut spool = Spool::open(temporary.root(), run_id().as_str(), MAX_SPOOL_BYTES)
        .expect("a fresh spool opens");
    let payload = vec![b'x'; MAX_PROGRESS_CANONICAL_BYTES];
    spool
        .append(EventKind::AdapterEvent, Authority::Synthetic, &payload)
        .expect("a maximal frame appends");
    assert!(matches!(
        spool
            .append(
                EventKind::AdapterEvent,
                Authority::Synthetic,
                &vec![b'x'; MAX_EVENT_PAYLOAD_BYTES + 1],
            )
            .expect_err("over the spool's own ceiling"),
        SpoolError::LimitExceeded
    ));
}

/// The budget is spent, and the spool says so rather than growing.
#[test]
fn an_exhausted_budget_refuses_the_append_and_leaves_the_record_intact() {
    let temporary = TempDir::new("budget");
    // Room for a handful of lines and no more.
    let mut spool =
        Spool::open(temporary.root(), run_id().as_str(), 4096).expect("a small spool opens");
    let payload = vec![b'x'; 512];
    let mut appended = 0_u64;
    loop {
        match spool.append(EventKind::AdapterEvent, Authority::Synthetic, &payload) {
            Ok(_) => appended += 1,
            Err(SpoolError::LimitExceeded) => break,
            Err(error) => panic!("unexpected refusal: {error}"),
        }
        assert!(appended < 64, "the budget never stopped the writer");
    }
    assert!(appended > 0, "nothing fit at all");
    // The refusal changed nothing: the record still verifies and still holds
    // exactly what was accepted.
    assert_eq!(spool.status().last_sequence(), appended);
    assert!(spool.remaining_bytes() < 4096);
    drop(spool);
    let events = read_events(temporary.root(), run_id().as_str()).expect("it still verifies");
    assert_eq!(events.len() as u64, appended);
}
