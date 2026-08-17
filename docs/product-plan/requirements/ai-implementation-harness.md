# Optional AI implementation harness

## Purpose

Automonique may provide a development harness for long-running, isolated agent
work. The harness is a product capability and an experiment; it is not the
required way humans or agents develop this repository.

Normal repository work follows `AGENTS.md`. It does not require a work graph,
claim, lease, packet, role split, evidence file, metric budget, merge train, or
harness approval.

## Capability

When used, the harness should be able to:

- run an agent in an isolated worktree with bounded filesystem, process,
  network, credential, time, and resource access;
- pin the source revision, model/provider configuration, and requested task;
- retain logs and outcomes without storing secrets or private data;
- expose pause, resume, cancel, retry, and cleanup controls; and
- return a candidate change plus the checks that actually ran.

The harness may coordinate parallel work, review, retries, and integration, but
those features are optional policy choices for a particular run rather than a
universal development ceremony.

## Safety

- Model output never becomes an unrestricted shell command. Execution uses
  typed operations or explicit argument vectors through the sandbox boundary.
- A candidate cannot grant itself more authority, change the policy judging
  its own run, obtain production or repository-administration credentials, or
  claim checks and review that did not occur.
- Failure, timeout, cancellation, and restart clean up owned processes and
  preserve enough state to explain the terminal outcome.
- Metrics such as tokens, cost, duration, commits, and lines changed are
  descriptive. They are not correctness scores and unavailable values stay
  unavailable rather than becoming zero or pass.

## Self-improvement

The daemon's shipped self-improvement path is separate from this optional
development harness. An agent proposal alone cannot activate a release. The
runtime approval and activation behavior is specified in
[`self-hosting-and-bootstrap.md`](self-hosting-and-bootstrap.md), with the
operator procedure in [`../../self-improvement-workflow.md`](../../self-improvement-workflow.md).

## Current status

The executable-plan experiment has been removed. The remaining isolated
executor is an optional product capability; ordinary repository work does not
use it.
