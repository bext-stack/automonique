// SPDX-License-Identifier: Elastic-2.0

//! When a ticket job's status read is worth a journal event.
//!
//! Everything the daemon does at the end of a ticket job (the completion
//! reply in Slack, the check mark, releasing the ticket) starts from one read
//! of that job's status in Manage. A read that fails is retried on the next
//! poll, which is right, but it used to fail without a word: a job whose
//! status was refused on every poll stayed "running" for good and nothing
//! anywhere said why (activ#1120, 2026-10-05).
//!
//! This counts consecutive failures per job and emits one native journal
//! event (`structured_log::emit_ticket_status_read`) on the first failure and
//! then at each power of ten, so a job that is simply gone does not fill the
//! journal. A job that becomes readable again gets one closing event. The
//! daemon's standard error is not a journal: a hot-reloaded generation runs
//! with it closed.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Jobs tracked at once; beyond it the oldest entries make room.
const MAX_TRACKED_JOBS: usize = 256;

static FAILURES: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

/// What one read deserves in the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Observation {
    Unreadable { category: String, failures: u32 },
    ReadableAgain { failures: u32 },
}

/// Record one status read of `job_id` and journal it when it is worth it.
pub(crate) fn note(job_id: &str, outcome: Result<(), &str>) {
    let observation = {
        let Ok(mut failures) = FAILURES.lock() else {
            return;
        };
        observe(&mut failures, job_id, outcome)
    };
    let _ = match observation {
        Some(Observation::Unreadable { category, failures }) => {
            crate::structured_log::emit_ticket_status_read(
                "unreadable",
                job_id,
                &category,
                failures,
            )
        }
        Some(Observation::ReadableAgain { failures }) => {
            crate::structured_log::emit_ticket_status_read(
                "readable_again",
                job_id,
                "recovered",
                failures,
            )
        }
        None => Ok(()),
    };
}

/// Pure, so the cadence is testable.
fn observe(
    failures: &mut BTreeMap<String, u32>,
    job_id: &str,
    outcome: Result<(), &str>,
) -> Option<Observation> {
    match outcome {
        Ok(()) => failures
            .remove(job_id)
            .map(|failures| Observation::ReadableAgain { failures }),
        Err(reason) => {
            if !failures.contains_key(job_id) && failures.len() >= MAX_TRACKED_JOBS {
                failures.pop_first();
            }
            let count = failures.entry(job_id.to_owned()).or_insert(0);
            *count = count.saturating_add(1);
            let count = *count;
            is_power_of_ten(count).then(|| Observation::Unreadable {
                category: category(reason),
                failures: count,
            })
        }
    }
}

fn is_power_of_ten(mut value: u32) -> bool {
    if value == 0 {
        return false;
    }
    while value.is_multiple_of(10) {
        value /= 10;
    }
    value == 1
}

/// A reason as a journal category: `FieldOutOfBounds` and `job_missing` both
/// become lowercase words joined by underscores; anything else is `other`.
fn category(reason: &str) -> String {
    let mut out = String::new();
    for (index, character) in reason.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_' {
            out.push(character);
        } else {
            return String::from("other");
        }
    }
    if out.is_empty() || out.len() > 64 {
        String::from("other")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "f95267b4-c3e3-4284-8097-5ae54ea54f62";

    #[test]
    fn a_failing_read_is_journalled_at_once_then_ever_more_rarely() {
        let mut failures = BTreeMap::new();
        let mut seen = Vec::new();
        for attempt in 1..=1_000_u32 {
            if let Some(observation) = observe(&mut failures, JOB, Err("FieldOutOfBounds")) {
                seen.push((attempt, observation));
            }
        }
        assert_eq!(
            seen.iter().map(|(attempt, _)| *attempt).collect::<Vec<_>>(),
            vec![1, 10, 100, 1_000]
        );
        assert_eq!(
            seen[1].1,
            Observation::Unreadable {
                category: String::from("field_out_of_bounds"),
                failures: 10
            }
        );
    }

    #[test]
    fn a_read_that_works_again_closes_the_streak_once() {
        let mut failures = BTreeMap::new();
        assert!(observe(&mut failures, JOB, Ok(())).is_none());
        for _ in 0..3 {
            let _ = observe(&mut failures, JOB, Err("manage_unavailable"));
        }
        assert_eq!(
            observe(&mut failures, JOB, Ok(())),
            Some(Observation::ReadableAgain { failures: 3 })
        );
        assert!(observe(&mut failures, JOB, Ok(())).is_none());
        // A new streak starts over and is journalled at once.
        assert!(observe(&mut failures, JOB, Err("job_missing")).is_some());
    }

    #[test]
    fn reasons_become_categories_and_the_table_stays_bounded() {
        assert_eq!(category("job_missing"), "job_missing");
        assert_eq!(category("UnexpectedStatus"), "unexpected_status");
        assert_eq!(category("secret=abc def"), "other");
        assert_eq!(category(""), "other");
        let mut failures = BTreeMap::new();
        for index in 0..(MAX_TRACKED_JOBS + 50) {
            let _ = observe(&mut failures, &format!("job-{index}"), Err("job_missing"));
        }
        assert!(failures.len() <= MAX_TRACKED_JOBS);
    }
}
