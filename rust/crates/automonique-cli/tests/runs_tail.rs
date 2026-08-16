// SPDX-License-Identifier: Elastic-2.0

//! `automonique runs tail`, over a real spool this test writes.
//!
//! The verb opens no socket — the frames are in the run's own hash-chained
//! spool and reading them is a local read — so the whole of it is exercisable
//! here: a real directory, a real chain, real canonical frame bytes, and the
//! exact rendered lines an operator sees.
//!
//! The rendering is asserted byte-for-byte on purpose. It is the operator's
//! view of a run's progress and the first thing a script parses, so a change to
//! it should be a change somebody made rather than one that happened.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use automonique_cli::run_with_input;
use automonique_protocol::event::{
    Authority as FrameAuthority, EventKind as FrameKind, RetryCategory, RetryContext, StepStatus,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
};
use automonique_protocol::tools::RunId;
use automonique_runner::{Authority, EventKind, Spool};

const RUN: &str = "run-tail-1";
const MAX_SPOOL_BYTES: u64 = 1024 * 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-runs-tail-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("a private temporary directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private mode");
        Self(path)
    }

    fn spool_root(&self) -> PathBuf {
        self.0.join("spool")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(
        arguments.iter().copied(),
        b"".as_slice(),
        &mut stdout,
        &mut stderr,
    );
    (
        exit,
        String::from_utf8(stdout).expect("utf-8 stdout"),
        String::from_utf8(stderr).expect("utf-8 stderr"),
    )
}

fn frame(
    sequence: u64,
    kind: FrameKind,
    authority: FrameAuthority,
    parts: ProgressBodyParts,
) -> Vec<u8> {
    ProgressFrame::new(ProgressFrameParts {
        run_id: RunId::new(RUN).expect("a valid run identity"),
        sequence,
        at_ms: EpochMillis::from_millis(1_700_000_000_000),
        authority,
        kind,
        body: ProgressBody::new(kind, parts).expect("the body its kind requires"),
    })
    .expect("a stamped frame")
    .to_canonical_bytes()
    .expect("a frame encodes")
}

/// A complete attempt: started, three frames, terminal.
fn write_attempt(root: &Path) {
    let mut spool = Spool::open(root, RUN, MAX_SPOOL_BYTES).expect("a fresh spool opens");
    spool
        .append(EventKind::Started, Authority::Authoritative, b"pid=1")
        .expect("the started event");
    // The frame's authority and the spool event's are one fact: the durable
    // event says how much its payload may be relied upon, and a payload that
    // said something else would be two answers to one question.
    for (kind, authority, parts) in [
        (
            FrameKind::ToolCallStarted,
            FrameAuthority::Authoritative,
            ProgressBodyParts {
                text: Some(ProgressText::new("read_file").expect("plain text")),
                step: Some(StepStatus::InProgress),
                retry: None,
            },
        ),
        (
            FrameKind::AssistantMessageDelta,
            FrameAuthority::Synthetic,
            ProgressBodyParts {
                // A newline is content the frame admits, and one line per frame
                // is the rendering rule — so this is the case that proves the
                // renderer escapes rather than forges a second line.
                text: Some(ProgressText::new("first\nsecond").expect("plain text")),
                step: None,
                retry: None,
            },
        ),
        (
            FrameKind::ProviderWarning,
            FrameAuthority::Synthetic,
            ProgressBodyParts {
                text: Some(ProgressText::new("slow down").expect("plain text")),
                step: None,
                retry: Some(
                    RetryContext::new(RetryCategory::RateLimited, true, Some(1_000), 2)
                        .expect("a coherent context"),
                ),
            },
        ),
    ] {
        let sequence = spool.status().last_sequence() + 1;
        spool
            .append(
                EventKind::AdapterEvent,
                match authority {
                    FrameAuthority::Authoritative => Authority::Authoritative,
                    FrameAuthority::Synthetic => Authority::Synthetic,
                },
                &frame(sequence, kind, authority, parts),
            )
            .expect("a frame appends");
    }
    spool
        .append(EventKind::Terminal, Authority::Authoritative, b"completed")
        .expect("the terminal event");
}

#[test]
fn a_terminal_attempt_renders_every_frame_it_recorded() {
    let temporary = TempDir::new("render");
    write_attempt(&temporary.spool_root());
    let root = temporary.spool_root();
    let (exit, stdout, stderr) = run(&["runs", "tail", root.to_str().expect("utf-8 path"), RUN]);
    assert_eq!(exit, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(
        stdout,
        concat!(
            "Automonique progress: run_id=run-tail-1 frames=3 last_sequence=5\n",
            "seq=2 at_ms=1700000000000 authority=authoritative kind=tool_call_started \
             step=in_progress retry=- text=read_file\n",
            "seq=3 at_ms=1700000000000 authority=synthetic kind=assistant_message_delta \
             step=- retry=- text=first\\nsecond\n",
            "seq=4 at_ms=1700000000000 authority=synthetic kind=provider_warning \
             step=- retry=rate_limited/retryable/attempt=2 text=slow down\n",
        )
    );
}

#[test]
fn a_cursor_renders_only_what_follows_it() {
    let temporary = TempDir::new("cursor");
    write_attempt(&temporary.spool_root());
    let root = temporary.spool_root();
    let path = root.to_str().expect("utf-8 path");
    let (exit, stdout, _) = run(&["runs", "tail", path, RUN, "3"]);
    assert_eq!(exit, 0);
    assert!(stdout.contains("frames=1"), "{stdout}");
    assert!(stdout.contains("kind=provider_warning"), "{stdout}");
    assert!(!stdout.contains("kind=tool_call_started"), "{stdout}");

    // A cursor past the end is an empty page rather than a refusal: the spool
    // is a record, and "nothing after here yet" is a true answer about one.
    let (exit, stdout, _) = run(&["runs", "tail", path, RUN, "99"]);
    assert_eq!(exit, 0);
    assert!(stdout.contains("frames=0"), "{stdout}");
}

/// Nothing rendered comes from anywhere but the protocol's own decoder.
#[test]
fn a_spool_naming_another_run_is_refused_rather_than_rendered() {
    let temporary = TempDir::new("foreign");
    write_attempt(&temporary.spool_root());
    let root = temporary.spool_root();
    let (exit, stdout, stderr) = run(&[
        "runs",
        "tail",
        root.to_str().expect("utf-8 path"),
        "run-tail-2",
    ]);
    assert_eq!(exit, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(stderr, "automonique runs refused: spool_corrupt\n");
}

#[test]
fn an_absent_spool_is_reported_as_unreadable() {
    let temporary = TempDir::new("absent");
    let root = temporary.spool_root();
    let (exit, stdout, stderr) = run(&["runs", "tail", root.to_str().expect("utf-8 path"), RUN]);
    assert_eq!(exit, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(stderr, "automonique runs refused: spool_unreadable\n");
}

#[test]
fn the_arguments_are_judged_before_the_file_is_opened() {
    let temporary = TempDir::new("arguments");
    let root = temporary.spool_root();
    let path = root.to_str().expect("utf-8 path");
    for (arguments, category) in [
        (vec!["runs", "tail", path, ""], "invalid_run_id"),
        (vec!["runs", "tail", path, RUN, "many"], "invalid_cursor"),
        (vec!["runs", "tail", path, RUN, "-1"], "invalid_cursor"),
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not a usage refusal: {stderr}");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert_eq!(
            stderr,
            format!("automonique runs refused: {category}\n"),
            "{arguments:?}"
        );
    }
}

#[test]
fn the_verb_shape_is_closed_and_documented() {
    for arguments in [
        vec!["runs", "tail"],
        vec!["runs", "tail", "/tmp"],
        vec!["runs", "tail", "/tmp", RUN, "0", "extra"],
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert!(
            stderr.starts_with("usage: automonique doctor"),
            "{arguments:?} did not report usage: {stderr}"
        );
    }
    let (_, _, stderr) = run(&["runs"]);
    assert!(
        stderr.contains("automonique runs tail <spool-root> <run-id> [cursor]"),
        "usage omits the tail verb: {stderr}"
    );
}
