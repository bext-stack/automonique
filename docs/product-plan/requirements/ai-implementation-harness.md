# AI implementation harness and commit metrics

## Purpose

The plan is too large to execute safely as a sequence of unstructured agent prompts. Automonique therefore ships its own development harness, provisionally `automonique-lab`, before broad implementation begins. The harness turns the work breakdown into bounded, repeatable write-review-verify-integrate loops and makes progress measurable without granting agents uncontrolled access to the repository, CI, releases or production.

The approach adapts two useful ideas to Automonique:

- large ports become tractable when mechanical guidance, independent adversarial review, compiler/test failures and regression suites are explicit work queues, as described in [Rewriting Bun in Rust](https://bun.com/blog/bun-in-rust);
- long-running agents improve when they receive continuous, reproducible objectives, persist unfinished work, reload their harness without losing sessions and expose honest harness/resource metrics, as demonstrated by [Jcode](https://jcode.sh/).

This is implementation infrastructure, not a production self-modification permission. Production Automonique never edits or activates its own release merely because an agent proposed a patch.

The staged trust and promotion cycle that lets this harness build and reload Automonique itself is defined separately in [Self-hosting and bootstrap](self-hosting-and-bootstrap.md).

## Repository layout

The target `bext-stack/automonique` repository reserves:

```text
tools/automonique-lab/          Rust orchestrator, CLI and optional TUI
scripts/automonique-dev         temporary first-run entry; later forwards to Rust
tools/bootstrap-seed/           finite Bun seed coordinator, retired after SH0
packages/dev-harness/           generated TypeScript client and scenario DSL
.automonique/dev/
├─ program.yaml                 machine-readable phase/epic/work DAG
├─ policies/                    command, path, resource and merge policies
├─ guides/                      porting, state-machine and compatibility guides
├─ ownership/                   shard/file/crate ownership declarations
├─ scenarios/                   parity, failure and performance objectives
├─ baselines/                   signed comparison manifests
└─ prompts/                     versioned role prompts with token measurements
artifacts/dev-runs/             local ignored run artifacts; CI uses artifact storage
```

`program.yaml` is generated from the checked work breakdown and then validated bidirectionally: a plan ticket cannot disappear from the executable graph, and an executable task cannot exist without an owner, specification, dependencies, acceptance gate and security classification.

## Harness architecture

`automonique-lab` is a small Rust control plane using the same provider-adapter interfaces, event vocabulary and generated schemas planned for the product, but a separate development database and credential domain. It starts sandboxed agent workers through the execution-host contract and exposes a TypeScript SDK so repository scripts and CI can participate without private protocols.

The harness owns:

- a durable work DAG, attempts, leases, budgets, checkpoints and terminal evidence;
- isolated worktrees or sparse worktrees with declared file/crate ownership;
- provider/model selection and distinct implementer/reviewer contexts;
- a build/test broker with resource-aware queues and shared immutable caches;
- diff, review, verification and commit manifests;
- merge-train serialization and conflict re-planning;
- metrics collection, baseline comparison and progress dashboards;
- pause, resume, drain, cancel, retry and harness-generation reload.

It does not own GitHub merge authority, production deployment credentials or direct writes to `main`. Those remain separate reviewed actions.

## Executable work unit

Every work unit contains:

- stable ticket and objective IDs, phase, dependencies and affected contracts;
- immutable base revision and allowed paths/crates;
- source-of-truth references and relevant parity/capability-ledger rows;
- measurable objective, baseline and regression budgets;
- required test layers, platforms and fault injections;
- sandbox, network, credential, token, cost, wall-time and compute budgets;
- implementer, reviewer and fixer role policy;
- explicit forbidden shortcuts and completion evidence;
- integration order and rollback/abandon behavior.

An objective receives a `hill_climbability` score from 0 to 100 plus a written metric. A low score blocks autonomous looping until the work is decomposed or a deterministic harness is added. The score is planning evidence, not a claim of correctness.

## Write-review-verify-integrate loop

```text
select ready work from the dependency DAG
  -> materialize isolated base and baseline metrics
  -> implement in one bounded context
  -> run fast local checks through the build broker
  -> freeze candidate diff and provenance manifest
  -> review in at least two fresh adversarial contexts
  -> classify findings; fixer applies accepted findings
  -> rerun affected checks plus required regression gates
  -> compare metrics and inspect threshold violations
  -> create one scoped commit with metrics attestation
  -> enter serialized merge train
  -> run integration/CI/shadow gates
  -> mark evidence or enqueue the next concrete failure
```

The implementer does not approve its own work. Reviewers receive the original contract, source baseline, frozen diff and test evidence but not the implementer's persuasive narrative. At least one review checks behavioral equivalence/security invariants and another checks Rust/TypeScript correctness, failure paths and maintainability. Provider diversity is preferred for high-risk changes but independence of context and role is mandatory.

Findings are structured as reproducible defects, invariant violations, missing evidence or non-blocking improvements. A fixer cannot dismiss a blocking finding without new evidence or an explicit human decision.

## Queue types

The harness supports specialized loops rather than one universal prompt:

1. Contract/guide extraction and cross-document consistency.
2. Mechanical TypeScript-to-Rust behavior porting with side-by-side fixtures.
3. Crate/module scaffolding and dependency-cycle reduction.
4. Compiler, clippy and generated-schema error queues grouped by crate, file or root cause.
5. Unit, property, parity and integration failure queues grouped by invariant.
6. Provider/connector/protocol conformance queues.
7. Reload, crash, replay and sandbox fault-injection queues.
8. Performance, memory, prompt/cache and binary-size regression queues.
9. Security review, fuzzing, mutation testing and dependency remediation.
10. Documentation, examples, SDK coverage and migration-evidence queues.

The durable result of a loop iteration is never merely “agent says done.” It is a changed tree plus machine-readable evidence and remaining failures.

## Bootstrap sequence

1. Freeze porting, state-machine, naming, security and test-preservation guides; review them independently.
2. Build the minimal harness around current Claude, Codex, opencode and Jcode backends without depending on the unfinished Automonique daemon.
3. Trial three representative units: one mechanical port, one durable-state transition and one provider/transport boundary.
4. Compare outcomes manually, correct prompts/policies/ownership and rerun the trial from the same bases.
5. Enable at most one loop and a small worker count; raise concurrency only after conflict, resource and review metrics stay within budget.
6. Use the harness to build its target Rust/SDK interfaces, then migrate it onto those interfaces through a compatibility adapter.
7. Require the harness itself to survive generation reload while workers/builds continue, before using reload as product acceptance evidence.
8. Freeze the first passing harness as the signed SH0 seed; use it to build a digest-named candidate lab, then require candidate self-build/reload plus an independent rebuild before broader autonomous work.

Steps 1–3 begin through the reviewed [initial development launcher](../reference/initial-development-launcher.md). Its finite `seed-program.yaml` cannot extend itself and relinquishes development-program ownership as soon as the verified Rust lab is ready.

The legacy Bun service keeps receiving fixes throughout. Translation and new feature work are separate queue classes so a mechanical parity unit cannot opportunistically redesign behavior.

The SH0 seed remains the development authority while a candidate is under test. Candidate code submits bounded evidence to stable but cannot change its own required checks, independent-verification state or promotion state. Stable/candidate databases, sockets, credentials and workspaces never overlap.

## Concurrency and repository safety

- A worker may edit only paths leased to its work unit; overlapping ownership is rejected or serialized.
- Use a bounded number of worktrees/sparse worktrees, one immutable base per shard and an explicit disk budget.
- Shared Cargo/Bun caches are immutable or broker-written; builds use CPU, memory, PID, I/O and disk quotas.
- Expensive builds/tests are scheduled centrally to prevent many agents from exhausting the host.
- Workers cannot run `git reset`, `git stash`, force-push, rewrite history, switch branches or merge. The Git broker accepts only typed stage/commit requests for the leased paths and expected base.
- No worker may delete/skip/ignore tests, weaken assertions, refresh goldens, add broad `allow` attributes, stub behavior, insert `todo!`/`unimplemented!`, or widen unsafe code merely to make a queue green without explicit ticket authority.
- Generated files are accepted only when their generator and reproducibility check are part of the same unit.
- Merge conflicts invalidate the affected review evidence; the unit rebases through the broker, reruns relevant reviews/checks and produces a new candidate digest.

## Persistent completion loop

Each unit has a durable todo graph with initial confidence, current confidence and cited validation. If an agent turn ends while actionable todos remain, the harness resumes it with the smallest relevant failure bundle. Transient provider/network failures use bounded backoff; deterministic failures become queue items; budget exhaustion pauses for review.

A large confidence jump without corresponding tests, compiler progress, benchmark movement or resolved review findings triggers an additional fresh-context review. The harness stops when:

- all acceptance gates pass and reviewers have no unresolved blockers;
- a declared budget or retry ceiling is reached;
- the objective is invalidated by a newer contract/base;
- repeated failures reveal missing architecture or human authority;
- a safety policy, secret scan or repository-integrity gate fails.

It never loops indefinitely on the same unchanged evidence.

## Differential parity and shadow oracle

During migration, sanitized inputs run against the legacy implementation and candidate Rust components. The harness compares semantic state transitions, actions, receipts, message rendering and normalized provider events while masking approved nondeterministic fields. It records:

- exact, equivalent, intentionally changed or unexplained outcome;
- fixture and policy revisions;
- state/event/action diffs;
- timing/resource measurements that are comparable;
- human decision for each intentional behavior change.

Shadow execution has no external mutation authority. An unexplained difference reopens its work unit and blocks the relevant parity row.

## Commit metrics contract

Every harness-authored commit contains compact Git trailers:

```text
Automonique-Work: R4-07
Automonique-Run: devrun_01...
Automonique-Checks: pass
Automonique-Review: 2-pass/0-blocking
Automonique-Metrics: sha256:<metrics-manifest-digest>
```

Human commits may use the same contract, and commits that change production Rust/SDK behavior must have an equivalent CI attestation even when they were not authored by the harness. The digest resolves to a versioned `automonique.dev-metrics/v1` manifest retained in CI/artifact storage and linked from the PR check. Git notes alone are insufficient because ordinary fetches may omit them.

The manifest records exact command, environment class, base/candidate revision, warm/cold status, sample count and uncertainty where applicable. Missing or incomparable data is `null` with a reason; it is never reported as zero.

### Correctness and parity

- tests, assertions and files passed/failed/skipped/deleted, with zero silent skip/deletion as a gate;
- completed/total parity and capability-ledger rows affected by the commit;
- differential fixtures exact/equivalent/intentional/unexplained;
- property, mutation, fuzz corpus/executions/crashes and sanitizer/Miri results;
- review findings opened/resolved/waived, reviewer independence and evidence digest;
- compiler errors and warnings before/after, schema/API coverage and documentation-example results.

### Agent-product performance

- daemon cold/warm startup, readiness and generation reload phase latency;
- accepted-input acknowledgement, routing, first-event and terminal-report latency;
- runner spawn, session attach/detach/reconnect and N-pane event-to-render latency;
- idle daemon RSS/PSS/CPU/file descriptors/tasks and incremental PSS per active session;
- SQLite transaction/event/outbox throughput, lock wait and backlog recovery;
- binary, installer, desktop and SDK bundle size;
- clean/incremental build time and peak build memory/disk I/O;
- zero lost accepted inputs, duplicate business effects, orphan hosts, unreconciled receipts and sandbox leaks in fault runs.

### Prompt, model and harness efficiency

- pinned provider/model/reasoning mode and harness/prompt revisions;
- base instruction, tool schema, memory/reference and total context tokens;
- input/output/cache-write/cache-read tokens, reusable-prefix ratio and cache-hit estimate;
- model calls, turns, tool calls/failures, agent workers, review/fix cycles and retries;
- wall time, aggregate agent compute time, build/test time, cost and budget utilization;
- todo completion, initial/final confidence, hill-climbability objective and objective movement per iteration.

### Security and maintainability

- safe/unsafe Rust lines and blocks, newly introduced unsafe sites and documented invariant owner;
- `panic!`, `unwrap`, `expect`, `todo!`, `unimplemented!`, broad lint allow and ignored-test deltas in production paths;
- dependency additions/removals, advisories, licenses and supply-chain/provenance result;
- sandbox, secret-scan, RBAC/tenant, replay/idempotency and protocol-fuzz gate results;
- source/generated/documentation lines and files changed as descriptive context, never a quality score.

## Baselines and regression budgets

Metrics compare to a pinned baseline on the same platform class. PR checks show absolute values, deltas, noise bands and the reason a comparison is unavailable. Each subsystem declares budgets, for example:

- no correctness, parity, security or lost/duplicate-effect regression;
- no undocumented increase in unsafe code, prompt prefix or privileged surface;
- reload, acknowledgement, attach and event-render p95 remain inside their service objectives;
- idle and per-session resource growth remain inside reviewed thresholds;
- performance wins require repeated samples and correctness equivalence.

Metrics guide investigation; they do not reward raw commits, lines, tokens, tool calls or agent count. A smaller correct patch with fewer resources is preferable. Agents cannot change the metric definition, baseline or budget in the same unit whose result is judged by it without a separately reviewed metrics-contract change.

## Dashboard and audit

The harness CLI/TUI and CI summary show:

- dependency DAG and ready/running/review/fix/blocked/integrated queues;
- compiler/test/parity/error burndown by phase and root cause;
- current worktree/file leases, resource pressure and merge train;
- reviewer findings and confidence/evidence mismatches;
- cost/token/cache/resource burn versus budget;
- commit-by-commit correctness, latency, memory, binary, prompt and safety trends;
- reproducible links to sanitized transcripts, diffs, logs, benchmark samples and attestations.

Public dashboards may publish aggregate methods, transcripts and failures only from consented, secret-scanned fixtures. Tenant data, hidden reasoning, credentials and proprietary source never enter public metrics.

## Exit gate

The harness is ready to drive broad implementation when three trial units and one multi-worker shard prove:

- independent author/reviewer/fixer roles and deterministic finding resolution;
- no overlapping write ownership, unsafe Git operation or unbounded resource use;
- harness reload/restart with preserved work, agent sessions, build tasks and evidence;
- reproducible metrics manifests and commit trailers with no secret-bearing output;
- failure queues improve monotonically without skipped/deleted tests or stubs;
- serialized integration reproduces local evidence on CI and can abandon/roll back a bad candidate cleanly.
- the first immutable SH0 seed builds an isolated candidate and hands its lifecycle into the independently verified self-hosting gates rather than treating a successful local build as trust.
