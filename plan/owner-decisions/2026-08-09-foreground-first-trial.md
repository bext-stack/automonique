<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — foreground-first implementation trial

| Field | Decision |
|---|---|
| Status | approved for architecture reconciliation, `R0-17`, and one publication |
| Expected base | `a1dee042101ec2d9e4853ba051e3a6c692142602` |
| Requested | 2026-08-09 through the owner-controlled repository workspace |
| Work ID | `R0-17` — executable implementation DAG |
| Dependency evidence | `BOOT-001` is `done` in `plan/work-graph.toml` with `plan/evidence/BOOT-001.json` present |
| Objective | make direct foreground execution the portable baseline, move service-manager integration behind optional adapters, and generate the implementation-harness DAG |
| Allowed paths | `.automonique/dev/`, `.github/workflows/plan.yml`, `tools/`, `plan/`, `docs/product-plan/` |
| Licence class | `Elastic-2.0` |
| Budget | one bounded architecture reconciliation plus one standard-library Python generator; no product runtime, dependency, credential, model call, privileged operation, or host-service mutation |
| Tests | DAG coverage/edge/authority/reproducibility/drift tests, plan integrity/self-tests, generated-file equality, Python compilation, diff and secret/path hygiene |
| Review | zero independent reviewers; explicit owner-supervised trial |

## Runtime decision

The required baseline is `automonique daemon --foreground`: a long-running
process role that does not self-daemonize and does not require installation as
an operating-system service. Direct terminal execution, tests, containers, and
process supervisors all exercise the same lifecycle contract.

systemd, launchd, container orchestration, and desktop/session launchers are
optional deployment adapters. They may add activation, restart, credential, or
resource features, but core correctness, runner ownership, reload, recovery,
and admin protocols cannot depend on one adapter. The word “daemon” describes
the process role only; it is not an installation requirement.

Existing work IDs are retained but service-specific Phase 0 work is rewritten
as foreground lifecycle and supervisor-adapter compatibility work. No host unit,
socket, service, or persistent configuration is created by this decision.

## Publication authorization

After the exact candidate passes its checks, create the repository’s second
commit on `main` and push it normally to `origin/main` only if the remote still
equals the expected base. Do not force, rewrite, tag, publish a package, create
a release, or change repository settings.

## Stop conditions

Stop if the executable graph lacks a required harness field, if foreground-first
wording would weaken durable ownership or cleanup invariants, if implementation
requires a new dependency, if any check fails, or if `origin/main` moves from
the expected base.
