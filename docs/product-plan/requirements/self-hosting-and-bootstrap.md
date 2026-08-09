# Self-hosting and bootstrap

## Purpose and definition

Automonique is intended to become functionally self-hosting: a trusted Automonique generation can plan, implement, review, build, test, launch and evaluate a candidate generation of Automonique while preserving its own development sessions and work. The candidate may then continue development from the same durable program after reload or promotion.

Self-hosting does not mean that a production daemon rewrites its installed binary or that a candidate declares itself trustworthy. Automonique still depends on external trust roots—operating system, CPU/kernel, source control, Rust/TypeScript toolchains, dependency registries, model providers and initial signing authority. The design makes those roots explicit and minimizes the mutable authority held by the generation under test.

The governing rule is:

> A candidate may build, test and self-review, but it cannot mint its own
> protected-integration, release-signing or production-promotion authority.

This document extends the [AI implementation harness](ai-implementation-harness.md), [reload protocol](reload-protocol.md) and [release architecture](target-architecture.md).

## Self-hosting levels

| Level | Capability | Required authority |
|---|---|---|
| SH0 seed | External tools and reviewed human actions create the repository, bootstrap manifest and first signed `automonique-lab` release | human/repository/release owners |
| SH1 assisted | The seed executes work units and evidence collection; humans request commits and candidates | trusted seed plus humans |
| SH2 self-building | Automonique edits, reviews, builds, tests and prepares commits for its own source | development policy and Git broker |
| SH3 self-reloading | A candidate development control plane reloads while sessions, workers, builds and evidence survive or reconcile | stable lifecycle owner and dev leases |
| SH4 self-verifying | Stable and candidate evaluate the same revision; an optional clean builder can add a third comparison; candidate self-rebuild and recovery pass | stable verifier plus owner-configured build policy |
| SH5 autonomous canary | Policy may integrate approved units into a bot-owned branch and operate a credential-isolated canary | explicit development integration policy |
| SH6 production proposal | Automonique prepares signed-source evidence and a release/promotion proposal | external protected-branch, signing and deployment approval |

SH0–SH4 are core implementation goals. SH5 is opt-in per repository. SH6 never implies automatic production promotion. A deployment may choose stricter policy at every level.

## Trust and process topology

```text
immutable seed/current stable release
  ├─ stable automonique-lab control plane
  │    ├─ durable development DAG/state
  │    ├─ isolated implementer/reviewer/fixer hosts
  │    ├─ build and Git brokers
  │    └─ candidate coordinator/verifier
  │
  ├─ candidate namespace <source-fingerprint>
  │    ├─ candidate lab/daemon/API/TUI as required
  │    ├─ cloned or synthetic state and artifact store
  │    ├─ fake or canary connectors
  │    └─ no stable/promotion/production credentials
  │
  ├─ independent rebuild/CI platform
  │    └─ isolated build, test, provenance and digest evidence
  │
  └─ external promotion authority
       ├─ protected branch
       ├─ release signing/transparency
       └─ production deployment broker
```

The stable development generation and candidate use different databases, sockets, runtime directories, process identities, credential audiences, transport installations, workspace registries, artifact namespaces, leases and outboxes. Candidate processes are named by immutable source/build digest and cannot bind a stable or production endpoint.

The bootstrap verifier is upgraded less frequently than the product. It accepts
only signed manifests, immutable paths, expected digests and typed lifecycle
operations. A stable lab or optional launcher owns candidate lifecycle during
self-hosting; the foreground baseline does not require a permanently installed
launcher. The old verifier must build/verify its replacement and remain
available for rollback.

## Repository and bootstrap layout

The target repository contains:

```text
.automonique/
├─ bootstrap/
│  ├─ bootstrap.toml              signed source/toolchain/build contract
│  ├─ bootstrap.schema.json       generated schema
│  ├─ trusted-builders.toml       builder identities and allowed levels
│  ├─ trusted-signers.toml        release policy; no private keys
│  └─ stages/                     checked stage transition fixtures
├─ dev/                           implementation DAG/policies/guides/scenarios
└─ release/                       reproducibility and promotion policies

rust/crates/
├─ automonique-bootstrap/         manifest verifier and fresh-host bootstrap CLI
└─ automonique-dev-protocol/      self-host/build/candidate/promotion contracts

packages/dev-harness/             generated TypeScript development SDK
crates/automonique-lab/           durable development control plane and brokers
```

The source distribution includes the source and build instructions required by the repository's licence boundary (checked-in `LICENSE-POLICY.md`: product `Elastic-2.0`, `sdk/` and `integrations/` `Apache-2.0`). A bootstrap may download a signed seed binary for convenience, but a source path using an explicitly installed verified toolchain remains documented and tested.

## Bootstrap manifest

`bootstrap.toml` is signed or covered by the repository/release attestation and contains:

- schema revision and minimum compatible seed/bootstrap version;
- canonical repository and exact source revision/tree digest;
- Rust toolchain channel/version/components/target and installer/checksum metadata;
- Bun/Node versions where TypeScript assets or SDKs are built;
- locked dependency, registry/mirror and vendoring policy;
- container/Nix/system image digest or complete host environment class;
- build commands as program plus argument arrays, never a downloaded shell string;
- normalized locale, timezone, paths, user/group, `SOURCE_DATE_EPOCH` and remap flags;
- expected source, schema, generated-file, binary, package and asset outputs;
- minimum kernel, process-control, optional supervisor and sandbox capabilities for tests;
- required test, parity, security, metrics and candidate stages;
- accepted builder/signer identities and provenance formats;
- adjacent-version protocol/database compatibility and rollback requirements.

The manifest contains no secret and does not grant authority. An agent cannot modify the manifest, its judging baseline and the implementation under judgement in one work unit.

## Fresh-host bootstrap

The `automonique-bootstrap init` command performs an explicit, resumable sequence:

1. Inspect platform, disk, kernel/process-control, optional supervisor, compiler/toolchain and network policy without mutation.
2. Verify repository identity, requested revision and bootstrap manifest signature/digest.
3. Acquire the declared seed/toolchains/dependencies from allowlisted sources, or verify locally supplied artifacts.
4. Create a dedicated development user/runtime/state directory and credential descriptors.
5. Build the minimal protocol and `crates/automonique-lab` Cargo workspace member in an isolated bootstrap environment.
6. Run bootstrap unit/sandbox/schema and secret scans.
7. Initialize an empty development database and import only the machine-readable program, policies and public fixtures.
8. Start the stable lab in foreground mode on a local protected socket and issue a one-time operator enrollment.
9. Ask the lab to rebuild the exact revision and compare outputs/evidence.
10. Mark SH0 complete only after a human verifies the bootstrap and recovery bundle.

The bootstrap command supports `inspect`, `plan`, `apply`, `verify`, `resume`, `export-recovery` and `uninstall --plan`. The plan is reviewable before mutation. Installation never pipes unauthenticated remote content into a shell and never discovers sudo credentials from files.

## Source and build identity

Every build references a `SourceState` containing repository ID, worktree/base revision, tree digest, dirty patch digest, submodule/dependency locks, generated-source digest and changed paths. Dirty development builds are allowed only in candidate namespaces and are never release-promotable.

The build coordinator snapshots `SourceState` before compilation and verifies it again before publication. If source changes, the result is `superseded`, not failed or eligible. Equivalent build requests deduplicate by environment, target, profile and source fingerprint; attached watchers receive the original result.

Published candidates are immutable directories addressed by artifact digest. Stable/current/candidate names are verified indirections updated only after the required state transition.

## Candidate lifecycle

The development store models:

```text
proposed
  -> queued
  -> building
  -> built
  -> smoke_verified
  -> isolated_testing
  -> shadowing
  -> self_hosting
  -> owner_verified
  -> promotable
  -> promoted

Any nonterminal state -> rejected | superseded | quarantined | rolled_back
```

Transitions are monotonic except explicit rollback to a previous signed stable release. Each transition records source/build/environment digests, actor, generation, required evidence, metrics manifest and action receipt. The candidate can submit evidence but cannot write `owner_verified`, `promotable` or `promoted` for itself.

`self_hosting` means the candidate successfully:

- starts its own development session against the exact candidate source;
- reads the durable work DAG and performs a bounded no-op or fixture work unit;
- queues and observes a background build/test;
- builds the same source revision again through its own interfaces;
- reloads/reconnects without losing sessions, builds, review state or receipts;
- reports the same source/build/protocol identity after reload;
- fails back to stable when deliberately crashed or given an incompatible candidate.

## Self-development session

A session gains `self_development` only through an explicit repository-scoped profile and eligible actor. The session records:

- stable and candidate generation/build IDs;
- repository, worktree and `SourceState` fingerprint;
- development level and allowed targets;
- Git/build/test/promotion-proposal capabilities;
- provider/model/profile/prompt revisions and budgets;
- candidate namespace and synthetic/cloned data policy;
- pending builds, tests, reload context and recovery directive.

The session exposes typed actions:

- `bootstrap.inspect|plan|verify|status`;
- `selfdev.status|build|test|launch|shadow|compare|reload|rollback`;
- `selfdev.request_integration|request_promotion`;
- background `list|wait|tail|cancel`;
- evidence `inspect|export|compare`.

There is no generic `selfdev exec`. Build and test recipes come from reviewed repository policy; temporary experimental commands run through the normal sandboxed tool contract and cannot become promotion evidence unless recorded by an accepted scenario.

Before candidate reload, the stable coordinator persists task context, session ID, provider turn, background task IDs, build/source identity and cursor. After reconnect, the candidate receives a recovery directive and must inspect surviving tasks before reissuing work.

## Candidate data and external effects

Candidate modes are progressively enabled:

1. `fixture`: synthetic inputs, fake providers/connectors and disposable workspaces;
2. `replay`: sanitized recorded inputs with effects projected into shadow outboxes;
3. `shadow`: copied live events after durable production handling, still no effects;
4. `canary`: explicit test tenant/channel/repository and non-production credentials;
5. `development-integration`: bot-owned Git branch and development artifacts only.

Candidates never receive production Slack/Telegram/Teams/Discord, Support, fleet, deployment, release-signing or protected-branch credentials. They cannot consume production transport leases or send from a production outbox. A canary environment has unique visual identity and destination allowlists so its messages cannot be mistaken for production.

Database migrations run first against cloned/synthetic state. Destructive or non-rollback-compatible migrations make a candidate ineligible until expand/contract and recovery evidence exists. Candidate artifacts never enter the stable store merely by path; promotion imports verified digests through a typed action.

## Self-build and reproducibility verification

For source revision R:

1. Stable generation S0 builds candidate artifact A1 in builder environment E.
2. A1 runs as candidate S1 and builds R again in E, producing A2.
3. When configured, a clean builder B builds R from a fresh source acquisition
   in declared environment E, producing A3 and provenance P3.
4. The verifier compares the available A1/A2/A3 artifacts, manifests,
   dependency resolution, generated source and test evidence.

The long-term gate is bit-for-bit equality for declared reproducible outputs. Until every artifact is reproducible, the policy lists known nondeterministic fields and requires normalized component hashes plus semantic/protocol/parity equivalence; a mismatch can never be silently ignored or normalized after seeing the candidate result.

Release artifacts require isolated, authenticated provenance generated by the build control plane rather than the candidate workload. Provenance binds source, resolved dependencies, parameters, builder identity, subjects/digests, timestamps and invocation. Public releases attach provenance, SBOM, vulnerability/license result and corresponding-source reference.

## Recursive improvement loop

Automonique may propose its own development work from bounded sources:

- compiler, clippy, schema and documentation failures;
- unit/property/parity/conformance/chaos/security/fuzz/mutation failures;
- capability/parity ledger gaps with approved priority;
- reload, recovery, idempotency or sandbox invariant violations;
- performance, memory, build, binary, prompt/cache, cost or reliability regressions;
- unresolved reviewer or operator findings;
- repeated operational incidents converted to sanitized regression fixtures;
- incomplete SDK, TUI, connector or runbook coverage.

The proposal records objective, evidence, hill-climbability, affected authority, likely paths, budgets and stop conditions. Policy may auto-queue narrow deterministic remediation in a bot-owned development branch. Product scope, security/authorization policy, data retention, legal/license decisions, acceptance metric definitions, privilege boundaries, release signing and production deployment always require external review.

The loop cannot recursively spawn without depth, concurrency, token, cost and time limits. Repeated unchanged evidence, oscillating metrics or recurring fixes trigger root-cause review and pause rather than infinite attempts.

## Integration and promotion policy

Repository policy selects one ceiling:

- `proposal_only`: prepare patch/commit/PR evidence; human performs all integration;
- `development_branch`: Git broker may integrate fully reviewed commits into a bot-owned branch;
- `canary_release`: release service may publish an unsigned or development-signed internal canary with no production eligibility;
- `production_proposal`: prepare immutable release candidate and promotion plan for external approval.

Protected `main`, stable release tags, public package publication, signing keys
and production deployment remain outside candidate credentials at every
ceiling. Required-status policies enforce the checks and review count selected
by the owner; separate build/review identities are optional hardening.

Promotion is a typed two-step operation: `prepare_promotion(candidate, expected_revision)` creates a bounded plan; `approve_promotion(plan_revision)` revalidates source, checks, provenance, signatures, compatibility, recovery and current stable before changing an indirection. Unknown outcome is reconciled by action receipt, never blindly retried.

## Recovery and anti-corruption boundary

Retain at least:

- last known-good stable and bootstrap verifier binaries;
- their exact source, bootstrap/release manifests and dependency locks;
- readable previous/current development database schemas;
- encrypted/recoverable development credentials, never candidate secrets;
- independent recovery bundle with checksums and operator instructions;
- candidate crash/reload/promotion journal and immutable evidence.

If the candidate corrupts its own state, stable ignores that state and reconstructs candidate projections from signed source/evidence or abandons the namespace. If stable development state is damaged, bootstrap recovery starts disconnected, restores the latest consistent development backup and does not activate candidates until receipts and repository heads reconcile.

The old stable binary must be able to reject or safely ignore candidate-written optional fields during the supported overlap. A self-hosting feature cannot force an irreversible schema migration of the only recovery controller.

## Security invariants

- Candidate code never runs inside the stable verifier/lifecycle-owner process.
- Candidate identity cannot read stable, signing, protected-branch, production transport or deployment credentials.
- A candidate cannot modify its source fingerprint after build, its evidence after attestation or the baseline that judges its current work unit.
- Implementer, reviewers, fixer, builder and promoter have truthful recorded
  roles; the owner-configured policy states which passes are required and which
  identities, if any, must differ.
- Candidate-supplied logs, metrics, tests and provenance are untrusted claims until observed or signed by their owning control plane.
- Self-development does not enable global tool/network/filesystem access; every worker and build retains an attested sandbox and budget.
- Generated patches, build scripts, dependency changes and workflow changes receive the same adversarial/supply-chain review as product code.
- A candidate may request rollback; the stable lifecycle owner performs it.
- No bootstrap path consumes a password file, arbitrary shell command, unsigned installer or mutable latest-version URL as authority.

## SDK, CLI, TUI and dashboard

The TypeScript SDK exposes read models and typed actions for bootstrap inspection, self-host sessions, build queues, candidates, comparisons, evidence and promotion proposals. It never receives signing material or a direct branch/ref mutation primitive.

CLI:

```text
automonique-bootstrap inspect|plan|apply|verify|resume
automonique self-host status|doctor|build|test|launch|compare|reload|rollback
automonique self-host promotion prepare|inspect|approve
```

TUI/dashboard views show stable/candidate topology, source/build fingerprints, stage/gate progress, workers/background builds, metric deltas, review identities, independent rebuild status and rollback readiness. Candidate surfaces use an unmistakable canary banner and never render a candidate-generated “approved” badge without authoritative promotion state.

## Metrics

In addition to the development commit metrics, self-hosting records:

- fresh-host time to verified stable lab;
- seed/toolchain/dependency cache hit and downloaded bytes;
- stable build, candidate self-build and independent build duration/resources;
- reproducible output matches/mismatches by component;
- candidate startup/readiness, self-host task and reload/reconnect latency;
- surviving/reconciled sessions, builds, todos, receipts and cursors;
- candidate crash, quarantine and rollback time;
- source supersession/deduplication/conflict rates;
- review independence, blocking findings and promotion-gate age;
- autonomous loop attempts, objective movement, budget and stop reason.

These metrics describe trust and operability. Faster self-promotion never outweighs a missing independent check or recovery path.

## Delivery sequence and exit gates

### Gate 1 — seed reproducibility

The repository, license/provenance files and bootstrap manifest exist; a clean host verifies toolchains, builds the minimal lab and exports a recovery bundle.

### Gate 2 — stable builds candidate

Stable builds an immutable candidate from an exact source fingerprint, detects source changes, deduplicates equivalent work and refuses dirty promotion.

### Gate 3 — isolated candidate operation

Candidate runs with distinct state/sockets/credentials, completes fixture and replay suites and cannot reach stable/production authority.

### Gate 4 — self-host cycle

Candidate performs the bounded self-host fixture, builds itself, reloads, preserves/reconciles all development work and falls back cleanly under injected failure.

### Gate 5 — reproducibility verification

The stable verifier, plus a clean builder when configured, records provenance;
reproducible or declared normalized comparisons pass with no unexplained
mismatch.

### Gate 6 — development integration

Policy-controlled integration into a bot-owned branch survives conflicts,
current CI and any configured review. Candidate cannot modify required checks
or protected branches.

### Gate 7 — production proposal

Automonique creates a complete immutable release/promotion proposal with compatibility, recovery and rollback evidence. An external authority performs signing, merge and deployment.

No later gate is implied by an earlier one, and failure returns to the last trusted stable release without destroying candidate evidence.
