// SPDX-License-Identifier: Elastic-2.0

//! Typed, test-only fault injection for the generation handoff.
//!
//! This module exists only under the `reload-fault-injection` feature, which
//! the integration tests of the `automonique` binary crate enable and which no
//! shipping build does. A build without the feature has no hook field, no
//! script parser and no way to reach any of this; it additionally refuses to
//! open a daemon while [`RELOAD_FAULT_ENV`](crate::RELOAD_FAULT_ENV) is set,
//! so a scripted fault can never be silently ignored.
//!
//! Every action here is an *external* fault applied at a named point: a
//! process is killed, a process aborts or hangs, or a competing writer holds
//! the main database. No action makes a phase report an outcome it did not
//! reach — the protocol discovers what broke through its own next step, which
//! is what makes the failure matrix these serve a matrix of real behaviour.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rusqlite::Connection;

/// Points in the ten-step handoff at which a script is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadFaultPoint {
    /// The candidate reported warm and validated the transferred descriptors.
    /// The durable lease still names the source.
    CandidateWarm,
    /// The source has quiesced intake; the lease transfer is about to run.
    BeforeLeaseTransfer,
    /// The durable lease names the candidate; authority has not been
    /// confirmed to it and it is not serving.
    AfterLeaseTransfer,
    /// The candidate proved active; the source is about to drain and retire.
    BeforeSourceDrain,
}

impl ReloadFaultPoint {
    /// Stable spelling used in the environment script.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateWarm => "candidate_warm",
            Self::BeforeLeaseTransfer => "before_lease_transfer",
            Self::AfterLeaseTransfer => "after_lease_transfer",
            Self::BeforeSourceDrain => "before_source_drain",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [
            Self::CandidateWarm,
            Self::BeforeLeaseTransfer,
            Self::AfterLeaseTransfer,
            Self::BeforeSourceDrain,
        ]
        .into_iter()
        .find(|point| point.as_str() == value)
    }
}

/// What a script does at a point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadFaultAction {
    /// Nothing; the protocol proceeds.
    Continue,
    /// `SIGKILL` the candidate process.
    KillCandidate,
    /// Abort this (source) process immediately.
    AbortSource,
    /// Never return: the source refuses to proceed for as long as it lives.
    HangSource,
    /// Hold an exclusive write transaction on the main database for the
    /// duration, from another connection in this process, then release it.
    HoldMainDatabaseWriteLock(Duration),
}

impl ReloadFaultAction {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "continue" => Some(Self::Continue),
            "kill_candidate" => Some(Self::KillCandidate),
            "abort_source" => Some(Self::AbortSource),
            "hang_source" => Some(Self::HangSource),
            other => other
                .strip_prefix("hold_main_database_write_lock_ms=")
                .and_then(|millis| millis.parse::<u64>().ok())
                .filter(|millis| (1..=60_000).contains(millis))
                .map(|millis| Self::HoldMainDatabaseWriteLock(Duration::from_millis(millis))),
        }
    }
}

/// A script consulted at every point; it answers with the action to apply.
pub type ReloadFaultHook = Box<dyn FnMut(ReloadFaultPoint) -> ReloadFaultAction + Send>;

/// Refusal category for a script the closed grammar does not accept.
pub const MALFORMED: &str = "reload_fault_injection_malformed";

/// Parse [`RELOAD_FAULT_ENV`](crate::RELOAD_FAULT_ENV) into a one-shot script.
///
/// Absent means no script. A present value that [`hook_from_script`] does not
/// accept is a refusal rather than a no-op, for the reason the whole feature
/// is gated: a fault that was asked for and did not fire is worse than none.
pub fn hook_from_environment() -> Result<Option<ReloadFaultHook>, &'static str> {
    let Some(value) = std::env::var_os(crate::RELOAD_FAULT_ENV) else {
        return Ok(None);
    };
    let value = value.to_str().ok_or(MALFORMED)?;
    hook_from_script(value).map(Some)
}

/// Parse one `<point>:<action>` script into a one-shot hook.
///
/// The action fires the first time its point is reached; every other
/// consultation, at that point or any other, continues. The grammar is
/// closed: both halves must be exact spellings from
/// [`ReloadFaultPoint::as_str`] and [`ReloadFaultAction::parse`], and the
/// lock-hold duration is bounded to one minute.
pub fn hook_from_script(script: &str) -> Result<ReloadFaultHook, &'static str> {
    let (point, action) = script.split_once(':').ok_or(MALFORMED)?;
    let point = ReloadFaultPoint::parse(point).ok_or(MALFORMED)?;
    let action = ReloadFaultAction::parse(action).ok_or(MALFORMED)?;
    let mut armed = true;
    Ok(Box::new(move |reached| {
        if armed && reached == point {
            armed = false;
            action
        } else {
            ReloadFaultAction::Continue
        }
    }))
}

/// `SIGKILL` one process and wait briefly for the kernel to reap it.
pub fn kill_process(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
    // The candidate is this process's child, so it stays a zombie until
    // waited on; what matters here is that its channel end is closed, which
    // the kernel does on death regardless. The short pause lets that happen
    // before the next phase talks to it.
    std::thread::sleep(Duration::from_millis(50));
}

/// Hold `BEGIN IMMEDIATE` on `database` for `duration` from a helper thread.
///
/// Returns once the lock is held, so the caller's next write meets a busy
/// database rather than racing the helper for the lock.
pub fn hold_write_lock(database: &Path, duration: Duration) -> Result<(), &'static str> {
    let database = database.to_path_buf();
    let (held_sender, held_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("automonique-reload-fault-lock".to_owned())
        .spawn(move || {
            let Ok(connection) = Connection::open(database) else {
                let _ = held_sender.send(false);
                return;
            };
            if connection.execute_batch("BEGIN IMMEDIATE").is_err() {
                let _ = held_sender.send(false);
                return;
            }
            let _ = held_sender.send(true);
            std::thread::sleep(duration);
            let _ = connection.execute_batch("ROLLBACK");
        })
        .map_err(|_| "reload_fault_lock_thread")?;
    match held_receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(true) => Ok(()),
        _ => Err("reload_fault_lock_unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_fires_once_at_its_point_and_continues_everywhere_else() {
        let mut hook = hook_from_script("after_lease_transfer:kill_candidate").expect("script");
        assert_eq!(
            hook(ReloadFaultPoint::CandidateWarm),
            ReloadFaultAction::Continue
        );
        assert_eq!(
            hook(ReloadFaultPoint::BeforeLeaseTransfer),
            ReloadFaultAction::Continue
        );
        assert_eq!(
            hook(ReloadFaultPoint::AfterLeaseTransfer),
            ReloadFaultAction::KillCandidate
        );
        assert_eq!(
            hook(ReloadFaultPoint::AfterLeaseTransfer),
            ReloadFaultAction::Continue,
            "one shot: the point is reached again and nothing fires"
        );
        assert_eq!(
            hook(ReloadFaultPoint::BeforeSourceDrain),
            ReloadFaultAction::Continue
        );
    }

    #[test]
    fn every_point_and_action_spelling_round_trips() {
        for point in [
            ReloadFaultPoint::CandidateWarm,
            ReloadFaultPoint::BeforeLeaseTransfer,
            ReloadFaultPoint::AfterLeaseTransfer,
            ReloadFaultPoint::BeforeSourceDrain,
        ] {
            assert_eq!(ReloadFaultPoint::parse(point.as_str()), Some(point));
        }
        assert_eq!(
            ReloadFaultAction::parse("continue"),
            Some(ReloadFaultAction::Continue)
        );
        assert_eq!(
            ReloadFaultAction::parse("kill_candidate"),
            Some(ReloadFaultAction::KillCandidate)
        );
        assert_eq!(
            ReloadFaultAction::parse("abort_source"),
            Some(ReloadFaultAction::AbortSource)
        );
        assert_eq!(
            ReloadFaultAction::parse("hang_source"),
            Some(ReloadFaultAction::HangSource)
        );
        assert_eq!(
            ReloadFaultAction::parse("hold_main_database_write_lock_ms=3000"),
            Some(ReloadFaultAction::HoldMainDatabaseWriteLock(
                Duration::from_millis(3_000)
            ))
        );
        assert_eq!(
            ReloadFaultAction::parse("hold_main_database_write_lock_ms=60000"),
            Some(ReloadFaultAction::HoldMainDatabaseWriteLock(
                Duration::from_secs(60)
            ))
        );
    }

    #[test]
    fn a_malformed_script_is_a_refusal_not_a_no_op() {
        for script in [
            "",
            "candidate_warm",
            ":kill_candidate",
            "candidate_warm:",
            "somewhere:kill_candidate",
            "candidate_warm:explode",
            "Candidate_Warm:kill_candidate",
            "candidate_warm:kill_candidate:again",
            "candidate_warm: kill_candidate",
            "candidate_warm:hold_main_database_write_lock_ms=",
            "candidate_warm:hold_main_database_write_lock_ms=0",
            "candidate_warm:hold_main_database_write_lock_ms=60001",
            "candidate_warm:hold_main_database_write_lock_ms=-1",
            "candidate_warm:hold_main_database_write_lock_ms=soon",
        ] {
            assert_eq!(
                hook_from_script(script).err(),
                Some(MALFORMED),
                "{script:?} must be refused"
            );
        }
    }
}
