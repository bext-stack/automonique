// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof that a supervised workload's stdout becomes durable frames.
//!
//! A scripted fake provider writes fixture JSONL into a real pipe, a real reader
//! thread drains it, and what is asserted is the **re-opened spool** — the same
//! discipline `tests/backend.rs` uses, for the same reason: the durable record
//! is the claim, not the supervisor's memory of it.
//!
//! The mapper here is deliberately trivial. The provider grammar lives in
//! `automonique-agents`, which depends on this crate and therefore cannot be
//! used from it; what this file proves is the *plumbing* — that piping stdout
//! does not stop the workload, that frames reach the spool at the sequences
//! their payloads claim, that a publisher sees exactly what was appended, and
//! that a run whose progress outgrows its budget still reaches its own terminal
//! state. The grammar's own projection is proved in the daemon's suite.
//!
//! Like every other proof over a real sandboxed workload this needs a delegated
//! cgroup v2 domain, and degrades loudly without one:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner \
//!   --test backend_progress -- --test-threads=1
//! ```

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use automonique_protocol::event::{
    Authority as FrameAuthority, EventKind as FrameKind, RetryCategory, RetryContext,
};
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressText,
};
use automonique_runner::backend::{
    CapturedFrame, DirectProcessBackend, ExecutionOutcome, PROGRESS_BUDGET_WARNING,
    ProgressCapture, ProgressMapper, ProgressPublisher,
};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    Authority, CancellationToken, ContainmentDomain, ContainmentError, ContainmentLimits, Event,
    EventKind, LaunchPlan, RunState, Spool,
};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const MAX_SPOOL_BYTES: u64 = 1024 * 1024;
const BOUNDED_RUN: Duration = Duration::from_secs(30);

/// The transcript the fake provider writes, one object per line.
///
/// Copied from `automonique-agents/tests/provider_stream.rs` so the bytes a
/// pipe carries here are the bytes that suite normalizes there.
const FIXTURE_LINES: [&str; 6] = [
    "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}",
    "{\"type\":\"turn.started\"}",
    "{\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}",
    "{\"type\":\"item.updated\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"partial\"}}",
    "{\"type\":\"item.completed\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"fixture answer\"}}",
    "{\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":1,\"input_tokens\":2,\"output_tokens\":3}}",
];

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-backend-progress-{label}-{}-{serial}",
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

fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("p{}-{label}-{serial}", std::process::id())
}

/// The delegated domain, or a loud, contract-checked degradation.
fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match ContainmentDomain::discover() {
        Ok(found) => {
            eprintln!(
                "[backend-progress] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[backend-progress] NOT PROVEN {proof}: {error}");
            assert!(
                matches!(
                    error,
                    ContainmentError::DomainNotDelegated
                        | ContainmentError::NotUnifiedCgroupV2
                        | ContainmentError::MissingAtomicKill
                ),
                "undelegated environments must refuse with a typed reason, got {error:?}"
            );
            assert!(
                std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run against a \
                 delegated cgroup v2 domain, but none was available: {error}"
            );
            None
        }
    }
}

/// A plan that runs a busybox script emitting `lines` on stdout.
fn emitting_plan(lines: &[&str]) -> LaunchPlan {
    let script = lines
        .iter()
        .map(|line| format!("{BUSYBOX} printf '%s\\n' '{line}'"))
        .collect::<Vec<_>>()
        .join("; ");
    LaunchPlan::new(BUSYBOX)
        .expect("an absolute program")
        .argument("sh")
        .expect("an argument")
        .argument("-c")
        .expect("an argument")
        .argument(&script)
        .expect("an argument")
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .expect("the busybox grant")
}

/// One frame per complete line, carrying that line's `type` value.
///
/// Not a grammar: it splits on newlines and reads one quoted value, because
/// what this file measures is the pipe, the thread and the log. A line that
/// carries no readable type becomes a synthetic frame naming nothing, which is
/// still a frame the spool must hold.
#[derive(Default)]
struct LineMapper {
    pending: Vec<u8>,
}

impl LineMapper {
    fn frame(line: &str) -> Option<CapturedFrame> {
        let marker = line
            .split_once("\"type\":\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map_or_else(|| "unreadable".to_owned(), |(value, _)| value.to_owned());
        let body = ProgressBody::new(
            FrameKind::AssistantMessageDelta,
            ProgressBodyParts {
                text: ProgressText::sanitized(&marker),
                step: None,
                retry: None,
            },
        )
        .ok()?;
        Some(CapturedFrame {
            // Preview-only by construction: the frame constructor refuses an
            // authoritative record of this kind, which is the invariant under
            // test as much as the plumbing is.
            authority: FrameAuthority::Synthetic,
            kind: FrameKind::AssistantMessageDelta,
            body,
        })
    }
}

impl ProgressMapper for LineMapper {
    fn push(&mut self, chunk: &[u8]) -> Vec<CapturedFrame> {
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=index).collect();
            let Ok(line) = std::str::from_utf8(&line) else {
                continue;
            };
            frames.extend(Self::frame(line.trim_end()));
        }
        frames
    }

    fn finish(&mut self) -> Vec<CapturedFrame> {
        Vec::new()
    }
}

/// A mapper that produces far more preview than any budget admits.
struct FloodMapper {
    remaining: usize,
}

impl ProgressMapper for FloodMapper {
    fn push(&mut self, _chunk: &[u8]) -> Vec<CapturedFrame> {
        let batch = self.remaining.min(64);
        self.remaining -= batch;
        (0..batch)
            .filter_map(|index| {
                let body = ProgressBody::new(
                    FrameKind::AssistantMessageDelta,
                    ProgressBodyParts {
                        text: ProgressText::sanitized(&format!("{index}{}", "preview ".repeat(64))),
                        step: None,
                        retry: None,
                    },
                )
                .ok()?;
                Some(CapturedFrame {
                    authority: FrameAuthority::Synthetic,
                    kind: FrameKind::AssistantMessageDelta,
                    body,
                })
            })
            .collect()
    }

    fn finish(&mut self) -> Vec<CapturedFrame> {
        Vec::new()
    }
}

/// One republished frame: the sequence it was appended at and its bytes.
type Published = (u64, Vec<u8>);

/// Everything a publisher was handed, for comparison against the spool.
#[derive(Clone, Default)]
struct RecordingPublisher(Arc<Mutex<Vec<Published>>>);

impl RecordingPublisher {
    fn taken(&self) -> Vec<Published> {
        self.0.lock().expect("the publisher log").clone()
    }
}

impl ProgressPublisher for RecordingPublisher {
    fn publish(&self, sequence: u64, payload: &[u8]) {
        if let Ok(mut taken) = self.0.lock() {
            taken.push((sequence, payload.to_vec()));
        }
    }
}

fn replay(temporary: &TempDir, id: &str) -> Vec<Event> {
    let spool = Spool::open(temporary.spool_root(), id, MAX_SPOOL_BYTES)
        .expect("the recorded spool re-opens and its chain verifies");
    spool.events_after(0).expect("the whole run replays")
}

#[test]
fn a_scripted_provider_transcript_becomes_durable_frames() {
    let Some(domain) = enforcement_domain("a_scripted_provider_transcript_becomes_durable_frames")
    else {
        return;
    };
    let temporary = TempDir::new("transcript");
    let id = run_id("transcript");
    let publisher = RecordingPublisher::default();
    let prepared = DirectProcessBackend::new(HELPER)
        .expect("an absolute helper")
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            emitting_plan(&FIXTURE_LINES),
            Spool::open(temporary.spool_root(), &id, MAX_SPOOL_BYTES).expect("a fresh spool"),
        )
        .expect("preparation creates the run cgroup")
        .with_progress(
            ProgressCapture::new(Box::new(LineMapper::default()))
                .publishing_to(Box::new(publisher.clone())),
        );
    let observed = prepared.observed_sequence();
    let report = prepared
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("the supervisor reached a decision");

    // Piping stdout must not change what the run *is*: the workload still ran
    // to completion, and the terminal record still says so.
    assert_eq!(report.outcome(), ExecutionOutcome::Completed);
    assert_eq!(report.status().state(), RunState::Completed);

    let events = replay(&temporary, &id);
    assert_eq!(events.first().map(Event::kind), Some(EventKind::Started));
    assert_eq!(events.last().map(Event::kind), Some(EventKind::Terminal));
    assert_eq!(
        observed.get(),
        report.status().last_sequence(),
        "the observed position must be the one the spool reached"
    );

    let frames: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind() == EventKind::AdapterEvent)
        .collect();
    assert_eq!(
        frames.len(),
        FIXTURE_LINES.len(),
        "one frame per emitted line, saw {}",
        frames.len()
    );
    for (event, line) in frames.iter().zip(FIXTURE_LINES) {
        assert_eq!(event.authority(), Authority::Synthetic);
        let frame =
            ProgressFrame::from_canonical_bytes(event.payload()).expect("a stored frame decodes");
        // The sequence inside the payload is the position the spool stored it
        // at, which is the property that makes it a resumption cursor.
        assert_eq!(frame.sequence(), event.sequence());
        assert_eq!(frame.run_id().as_str(), id);
        let expected = line
            .split_once("\"type\":\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(value, _)| value)
            .expect("the fixture names a type");
        assert_eq!(
            frame.body().text().map(ProgressText::as_str),
            Some(expected)
        );
    }

    // The publisher saw exactly the appended frames, at the same sequences and
    // with the same bytes — it is an echo of the record, not a second one.
    let published = publisher.taken();
    assert_eq!(published.len(), frames.len());
    for ((sequence, payload), event) in published.iter().zip(&frames) {
        assert_eq!(*sequence, event.sequence());
        assert_eq!(payload.as_slice(), event.payload());
    }
}

#[test]
fn a_preview_flood_never_costs_the_run_its_terminal_record() {
    let Some(domain) =
        enforcement_domain("a_preview_flood_never_costs_the_run_its_terminal_record")
    else {
        return;
    };
    let temporary = TempDir::new("flood");
    let id = run_id("flood");
    // A budget small enough that the flood must hit it, and large enough that
    // the run's own two lifecycle events comfortably fit.
    let budget = 32 * 1024;
    let prepared = DirectProcessBackend::new(HELPER)
        .expect("an absolute helper")
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            emitting_plan(&["one", "two", "three", "four", "five", "six"]),
            Spool::open(temporary.spool_root(), &id, budget).expect("a small spool"),
        )
        .expect("preparation creates the run cgroup")
        .with_progress(ProgressCapture::new(Box::new(FloodMapper {
            remaining: 4096,
        })));
    let report = prepared
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("the supervisor reached a decision");

    // The whole claim: a run that streamed more than it could afford is still a
    // run that completed and said so.
    assert_eq!(report.outcome(), ExecutionOutcome::Completed);
    assert_eq!(report.status().state(), RunState::Completed);

    let spool = Spool::open(temporary.spool_root(), &id, budget)
        .expect("the record re-opens and its chain verifies");
    let events = spool.events_after(0).expect("the whole run replays");
    assert_eq!(events.last().map(Event::kind), Some(EventKind::Terminal));
    assert_eq!(
        events.last().map(Event::payload),
        Some(b"completed".as_ref())
    );

    // And the silence is explained exactly once, so a reader can tell a stream
    // that ended from a stream that was cut off.
    let warnings: Vec<&Event> = events
        .iter()
        .filter(|event| {
            event.kind() == EventKind::AdapterEvent
                && ProgressFrame::from_canonical_bytes(event.payload())
                    .is_ok_and(|frame| frame.kind() == FrameKind::ProviderWarning)
        })
        .collect();
    assert_eq!(warnings.len(), 1, "the budget warning is recorded once");
    let warning = ProgressFrame::from_canonical_bytes(warnings[0].payload()).expect("it decodes");
    assert_eq!(
        warning.body().text().map(ProgressText::as_str),
        Some(PROGRESS_BUDGET_WARNING)
    );
    assert_eq!(
        warning.body().retry().map(RetryContext::category),
        Some(RetryCategory::Internal)
    );
    assert_eq!(
        warning.body().retry().map(RetryContext::retryable),
        Some(false)
    );
}
