<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — foreground lifecycle implementation

| Field | Decision |
|---|---|
| Status | approved for `R0-03` and one publication |
| Expected base | `0b02b10564baeb2cf79864bbe88af64763c6dd07` |
| Work ID | `R0-03` — foreground lifecycle spike |
| Dependency evidence | `BOOT-001` is done with evidence; `R0-03` is listed in `plan/ready.md` and has no blocking gate |
| Objective | implement and measure portable foreground readiness, fenced handoff, failure fallback, bounded drain, signal shutdown, and cleanup |
| Allowed paths | `spikes/foreground-lifecycle/`, `.github/workflows/plan.yml`, `plan/`, derived `.automonique/dev/program.yaml` |
| Licence class | `Elastic-2.0` |
| Budget | one dependency-free Python fixture; each lifecycle wait at most five seconds and the full CI test at most thirty seconds; no network, model/provider call, credential, persistent socket, service-manager operation, sudo, or unrelated process interaction |
| Tests | direct integration trial, protocol/unit tests, pre-ready and post-ready failure injection, process cleanup, plan/DAG regression, Python compilation and diff/secret/path hygiene |
| Review | zero independent reviewers; explicit owner-supervised continuation |

## Execution and cleanup

The controller launches only fixture modules from this repository using
explicit argument arrays and inherited Unix socket pairs. Every child starts a
new process session. A bounded `finally` path requests typed shutdown, waits for
exit, and uses a process-group kill only as a recorded cleanup failure fallback.
No filesystem socket, service unit, port, credential, database, or production
identifier is used.

## Publication authorization

After the exact candidate passes locally, create one ordinary third commit on
`main` and push it to `origin/main` only when the remote still equals the
expected base. Do not force, rewrite, tag, release, publish a package, or change
repository settings.

## Stop conditions

Stop if a child cannot be bounded to its own process session, if ownership can
be active in two generations, if cleanup needs privilege or an unrelated PID,
if the fixture depends on service-manager state, if any required observation is
missing, or if the remote base changes.
