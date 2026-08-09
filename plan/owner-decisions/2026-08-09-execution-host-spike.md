<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — execution-host ownership spike

| Field | Decision |
|---|---|
| Status | approved for local implementation under `R0-04` |
| Expected base | `f76eebdb55514b7d978b5b3590c64584cc8eea72` |
| Harness admission | score 92 at threshold 70; five nodes runnable; previous loop state stopped with `unchanged_evidence` |
| Work ID | `R0-04` — execution-host ownership spike |
| Dependency evidence | `BOOT-001` is done with evidence; `R0-04` is selectable and has no blocking gate |
| Objective | prove opaque host discovery across controller reconnect, typed status/cancel, bounded descendant cleanup, launch-failure truthfulness and null optional capabilities |
| Allowed paths | `spikes/execution-host/`, `plan/`, derived `.automonique/dev/program.yaml` and `.automonique/dev/objectives.json` |
| Licence class | `Elastic-2.0` |
| Budget | one dependency-free Python fixture; five-second lifecycle waits and 30-second test bound; no network, model/provider call, credential, arbitrary command, service manager, cgroup mutation, privilege, persistent socket or unrelated process interaction |
| Tests | environment/capability record, controller disconnect/reconnect, registry/socket discovery, typed cancellation of runner descendants, launch failure, cleanup, plan/DAG regression, compilation and hygiene |
| Review | zero independent reviewers; owner-supervised implementation |

## Execution boundary

The controller starts only repository fixture modules with fixed argument
vectors. The runner starts one fixed synthetic workload in a distinct process
session; the workload's fixed grandchild shares that owned process group. A
mode-0700 temporary directory contains an atomic registry/status record and a
mode-0600 Unix control socket. The runner verifies same-user peer credentials
where the kernel exposes them.

Cancellation is a typed control message. The runner signals only the recorded
workload process group, waits within the declared bound, records any escalation,
updates terminal state and exits. The controller may bound and terminate only
the runner session it created during final cleanup.

## Stop conditions

Stop if the immutable base or lease drifts, a child cannot be isolated in a
recorded process group, reconnect requires a privileged/global registry, a
typed request would carry arbitrary model-supplied argv, optional supervisor or
cgroup features become required, cleanup touches an unrelated PID, or a check
fails without an in-scope correction.

## Publication

This decision authorizes local implementation and a local candidate only. It
does not authorize a push or any other external repository mutation.
