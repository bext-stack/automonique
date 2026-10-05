// SPDX-License-Identifier: Elastic-2.0

//! A journal line when a ticket job's status cannot be read.
//!
//! Everything the daemon does at the end of a ticket job (the completion
//! reply in Slack, the check mark, releasing the ticket) starts from one read
//! of that job's status in Manage. A read that fails is retried on the next
//! poll, which is right, but it used to fail without a word: a job whose
//! status was refused on every poll stayed "running" for good and nothing
//! anywhere said why (activ#1120, 2026-10-05).
//!
//! This keeps a count of consecutive failures per job and writes one line to
//! standard error, which the service journal keeps, on the first failure and
//! then at each power of ten, so a job that is simply gone does not fill the
//! journal. A job that becomes readable again gets one closing line. The line
//! carries the job id and a short reason category, never response content.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Jobs tracked at once; beyond it the oldest entries make room.
const MAX_TRACKED_JOBS: usize = 256;

static FAILURES: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

/// Record one status read of `job_id` and journal it when it is worth a line.
pub(crate) fn note(job_id: &str, outcome: Result<(), &str>) {
    let Ok(mut failures) = FAILURES.lock() else {
        return;
    };
    if let Some(line) = line_for(&mut failures, job_id, outcome) {
        eprintln!("{line}");
    }
}

/// The line one read deserves, if any. Pure, so the cadence is testable.
fn line_for(
    failures: &mut BTreeMap<String, u32>,
    job_id: &str,
    outcome: Result<(), &str>,
) -> Option<String> {
    let job = token(job_id, 64, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'-'
    });
    match outcome {
        Ok(()) => failures
            .remove(&job)
            .map(|count| format!("ticket status readable again: job={job} after_failures={count}")),
        Err(reason) => {
            if !failures.contains_key(&job) && failures.len() >= MAX_TRACKED_JOBS {
                failures.pop_first();
            }
            let count = failures.entry(job.clone()).or_insert(0);
            *count = count.saturating_add(1);
            let count = *count;
            is_power_of_ten(count).then(|| {
                let reason = token(&reason.to_ascii_lowercase(), 64, |byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                });
                format!(
                    "ticket status unreadable: job={job} reason={reason} consecutive_failures={count}; \
                     its completion reply and check mark wait on this read"
                )
            })
        }
    }
}

fn is_power_of_ten(mut value: u32) -> bool {
    if value == 0 {
        return false;
    }
    while value % 10 == 0 {
        value /= 10;
    }
    value == 1
}

/// `value` when it is a short token of allowed bytes, else `invalid`.
fn token(value: &str, max: usize, allowed: impl Fn(u8) -> bool) -> String {
    if !value.is_empty() && value.len() <= max && value.bytes().all(allowed) {
        value.to_owned()
    } else {
        String::from("invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "f95267b4-c3e3-4284-8097-5ae54ea54f62";

    #[test]
    fn a_failing_read_is_journalled_at_once_then_ever_more_rarely() {
        let mut failures = BTreeMap::new();
        let mut lines = Vec::new();
        for attempt in 1..=1_000_u32 {
            if let Some(line) = line_for(&mut failures, JOB, Err("FieldOutOfBounds")) {
                lines.push((attempt, line));
            }
        }
        assert_eq!(
            lines
                .iter()
                .map(|(attempt, _)| *attempt)
                .collect::<Vec<_>>(),
            vec![1, 10, 100, 1_000]
        );
        assert_eq!(
            lines[0].1,
            format!(
                "ticket status unreadable: job={JOB} reason=fieldoutofbounds consecutive_failures=1; \
                 its completion reply and check mark wait on this read"
            )
        );
    }

    #[test]
    fn a_read_that_works_again_closes_the_streak_once() {
        let mut failures = BTreeMap::new();
        assert!(line_for(&mut failures, JOB, Ok(())).is_none());
        for _ in 0..3 {
            let _ = line_for(&mut failures, JOB, Err("manage_unavailable"));
        }
        assert_eq!(
            line_for(&mut failures, JOB, Ok(())).as_deref(),
            Some(format!("ticket status readable again: job={JOB} after_failures=3").as_str())
        );
        assert!(line_for(&mut failures, JOB, Ok(())).is_none());
        // A new streak starts over and is journalled at once.
        assert!(line_for(&mut failures, JOB, Err("job_missing")).is_some());
    }

    #[test]
    fn nothing_but_short_tokens_reaches_the_journal_and_the_table_stays_bounded() {
        let mut failures = BTreeMap::new();
        let line =
            line_for(&mut failures, "job\nINJECTED line", Err("secret=abc def")).expect("line");
        assert_eq!(
            line,
            "ticket status unreadable: job=invalid reason=invalid consecutive_failures=1; \
             its completion reply and check mark wait on this read"
        );
        for index in 0..(MAX_TRACKED_JOBS + 50) {
            let _ = line_for(&mut failures, &format!("job-{index}"), Err("job_missing"));
        }
        assert!(failures.len() <= MAX_TRACKED_JOBS);
    }
}
