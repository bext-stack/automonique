# Autonomous development and self-healing

## Definition

Automonique is functionally self-hosting when its trusted stable generation can
plan, implement, review, build, test, launch and evaluate a candidate while all
development state survives process failure and generation replacement.

A candidate may build and test itself. It cannot be its own sole reviewer,
provenance authority, merger, release signer or production promoter.

## Bootstrap command

```text
./automonique bootstrap \
  --provider openai \
  --model gpt-5.6-sol \
  --reasoning high \
  --budget-eur 25 \
  --unattended
```

The command is idempotent. It inspects, verifies, installs, initializes,
enables and health-checks the stable supervisor. Repeated invocation converges
on the same desired state. Once healthy, systemd restarts the process and the
durable coordinator resumes leases, sessions and effects; an operator does not
attach to individual workers.

## Development roles

- Author changes only leased paths at an immutable base.
- Reviewer observes a frozen candidate and cannot modify it.
- Fixer resolves blocking findings without dismissing them.
- Builder reproduces checks in an isolated environment.
- Merger performs one compare-and-swap integration and cannot author.

Routine integration requires independent review evidence against the exact
candidate tree. Credentials are separate by role and unavailable to candidate
code. Unknown push, PR or merge outcomes are queried and reconciled before any
retry.

## Provider baseline

The initial author and reviewer adapter uses the pinned Codex CLI with
`gpt-5.6-sol`, high reasoning, structured final output, JSONL events,
workspace-write sandboxing and ephemeral session state. The coordinator passes
a fixed argv array and bounded stdin prompt. Provider credentials are injected
only at the trusted process boundary and never enter the repository, candidate
worktree, prompt, evidence or log.

## Stable/candidate loop

1. Stable reserves budget and leases a ready work item.
2. Author produces a candidate in an isolated worktree.
3. Builders measure the declared checks against its exact tree digest.
4. Independent reviewers return typed findings.
5. Fixer iterations are bounded and create a new immutable candidate digest.
6. Stable launches a candidate namespace with synthetic state and fake effects.
7. Candidate proves restart, self-build and recovery behavior.
8. Independent evidence makes the candidate eligible for routine integration.
9. Merger applies exactly once if the protected base is unchanged.
10. The DAG records completion and unlocks direct dependants.

## Failure and repair

- Process crash: service manager restarts; journal replay resumes.
- Worker crash: lease expires after liveness check; a new attempt adopts work.
- Provider interruption: preserve provider/session cursor when supported;
  otherwise create a bounded fresh attempt with prior evidence.
- Build failure: enqueue a narrow repair item; do not weaken the check.
- Candidate crash/readiness failure: quarantine candidate and return to stable.
- Update failure: atomically reactivate the last known-good version.
- Ambiguous external effect: mark reconciliation-required and never blind retry.
- Repeated unchanged failure or oscillation: stop the loop and create a
  root-cause item within the same budget envelope.

## Authority ceiling

Routine bot-authored pull requests may be autonomously reviewed and merged when
all repository gates pass. Licensing, governance, credentials, required checks,
budgets, security boundaries, releases and production deployments remain
outside the candidate's authority and require their separate exact-revision
decision or broker.
