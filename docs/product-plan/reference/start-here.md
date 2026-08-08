# Automonique: start-here brief for the bootstrap agent
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md`). GPL statements below remain historical.

## How to use this document

Give this file to the agent that will start the Automonique project and tell it:

> Execute `AUTOMONIQUE_START_HERE.md`. Work through its gates in order, preserve evidence, and stop at every explicitly named owner decision. Do not make Automonique public, deploy it, or touch production.

This is the stage-zero operating brief. It tells an agent how to create the new repository, establish a safe source baseline and implement the initial development launcher. The detailed plans under `docs/` remain authoritative when this summary omits a detail.

Passing this brief with an instruction to execute it authorizes read-only discovery, disposable local audit candidates, creation of the **private and empty** canonical repository, and local implementation work described below. It does not authorize public visibility, production deployment, credential rotation, signing-key creation, package publication, merging without review, or destructive changes to the legacy repository.

## Portable bootstrap bundle

If the agent will not run inside this checkout, do not pass this file alone. Build the deterministic, secret-free handoff archive:

```bash
./scripts/build-automonique-bootstrap-bundle
```

The command writes a versioned archive and checksum under `dist/`. The archive contains this brief, the legacy repository rules, both complete planning trees, fixed decisions, the brand-kit checksum, an exact first-agent prompt, source revision metadata and an offline verifier. It deliberately excludes the brand archive, Git history, application source, credentials, databases and runtime data.

The recipient extracts the archive, runs `./handoff/verify.sh`, reads `handoff/FIRST_AGENT_PROMPT.md` and then follows this document. In the source checkout, `bootstrap/automonique-handoff/README.md` defines the transport procedure; inside the archive, the same instructions are at `handoff/README.md`.

## Fixed decisions

Do not ask the owner to decide these again:

| Item | Decision |
|---|---|
| Product | Automonique |
| Assistant/mascot | Monique |
| GitHub repository | `bext-stack/automonique` |
| Initial visibility | Private staging |
| Code license | GNU GPL v3.0 or later (`GPL-3.0-or-later`) |
| Official site | `https://automonique.fr` |
| Founding sponsor | Inklura, `https://inklura.fr` |
| Primary runtime | Rust |
| Browser application and SDK | TypeScript where appropriate |
| Legacy source | The private legacy checkout |
| Brand source | `<owner-controlled brand archive path>` |

The GitHub organization owns the upstream. Sponsorship grants Inklura no repository, tenant, security-report, signing or runtime authority. The legacy repository remains private production/recovery evidence until the migration plan explicitly retires it.

## Decisions that still need an owner

Discover whether these have since been recorded. If not, prepare a recommendation and request one consolidated decision before the affected mutation:

- brand-asset and trademark license, ownership and permitted use;
- sanitized-history import versus a clean initial product import;
- organization administrators, recovery owners and initial team access;
- package/container namespaces and official publishers;
- private-stage and public-launch settings for issues, discussions and advisories;
- later public-visibility and production-cutover dates.

Use the documented defaults where they do not create an external commitment: private staging, separate trademark terms, least privilege and sanitized history only when it can be proven safe and intelligible. Never infer approval to make the repository public.

## Read this source material before acting

Read each selected document completely. Record its source commit and digest in the bootstrap journal.

1. `AGENTS.md` — safety rules for this live legacy checkout.
2. `docs/automonique-rebrand/README.md` — identity, decisions and completion contract.
3. `docs/automonique-rebrand/repository-strategy.md` — private repository and import gates.
4. `docs/automonique-rebrand/compatibility-contract.md` — durable identity and rename rules.
5. `docs/automonique-rebrand/migration-and-work-breakdown.md` — phases B0–B8 and work IDs.
6. `docs/rust-rewrite/README.md` — architecture index and global completion gates.
7. `docs/rust-rewrite/goals-and-invariants.md` and `target-architecture.md`.
8. `docs/rust-rewrite/sandbox-management.md` and `operations-and-governance.md`.
9. `docs/rust-rewrite/ai-implementation-harness.md` and `self-hosting-and-bootstrap.md`.
10. `docs/rust-rewrite/initial-development-launcher.md` — the first-command specification.
11. `docs/rust-rewrite/work-breakdown.md` and `verification-and-rollout.md`.

Then read the remaining documents routed from the two README indexes before implementing their corresponding subsystem. Do not replace the detailed work breakdown with a new improvised roadmap.

## Non-negotiable safety contract

- Treat the current checkout as a live private production repository, not as publishable source.
- Never copy its Git directory, database, `.env`, logs, sessions, tickets, customer data, provider transcripts or deployment configuration into Automonique.
- Never print secret values. Redact findings and revoke exposed live credentials before considering history rewriting complete.
- Do not initialize the new remote from the current checkout and do not use `gh repo create --source ... --push`.
- Do not push either import candidate until its audit report has been reviewed and the import choice approved.
- Do not alter, restart or stop the production service for repository extraction. Follow `AGENTS.md` if diagnostics are needed.
- Do not rename or mutate durable legacy IDs. Compatibility is additive before it is subtractive.
- Canonical Rust crates, packages, modules, binaries, schemas, metrics and new paths use `automonique`, not legacy product names. Legacy names exist only in documented compatibility shims and fixtures.
- Agent/provider processes do not receive GitHub administration, push, merge, release, signing, production or secret-management authority.
- GitHub administration, candidate promotion, merge, release, deployment and visibility are separate reviewed effects.
- Use explicit argv arrays or typed APIs. Do not generate shell command strings from model output.
- Use disposable directories and named worktrees. Never reset, clean, stash, delete or overwrite unrelated user work.
- Every network effect and every generated artifact must be attributable to a work ID and journal entry.

If any instruction conflicts with the detailed plans, choose the safer interpretation, record the conflict and stop before the mutation.

## Stage 0 — inspect and freeze evidence

Start read-only:

1. Confirm the legacy checkout, current branch, exact commit, dirty state, remotes and reachable refs without displaying credentials.
2. Confirm `gh` authentication and access to the `bext-stack` organization. Do not display the token.
3. Check whether `bext-stack/automonique` already exists. If it does, inspect its visibility, default branch, refs and rules; never delete or recreate it automatically.
4. Hash the brand-kit archive without extracting it into this repository.
5. Inventory source licenses, generated code, binary assets and all legacy identifiers.
6. Inventory sensitive paths and history categories using redacted counts and digests, not contents.
7. Create a private bootstrap journal outside both repositories with command, timestamp, actor, input digest, result and next gate.
8. Produce a machine-readable B0 evidence manifest with the fixed decisions, source commit, reachable-ref digest, brand-kit digest, tool versions and unresolved owner decisions.

The working tree must remain unchanged during inspection. If it is already dirty, attribute every change and do not absorb it into an import candidate silently.

## Stage 1 — create the private empty upstream

Only proceed when organization ownership/access and initial private visibility are confirmed. Repository creation is an explicit infrastructure effect and must be journaled.

If the repository does not exist, create it without a starter README, license, `.gitignore`, source import or push. A suitable command shape is:

```bash
gh repo create bext-stack/automonique --private --description "Sovereign multi-agent automation platform" --homepage "https://automonique.fr"
```

Do not add `--source`, `--push`, `--public` or generated starter files. Immediately verify through GitHub that:

- the full name is exactly `bext-stack/automonique`;
- visibility is private;
- there are no branches, tags or releases;
- unexpected collaborators/apps/actions secrets are absent;
- deletion and visibility changes remain organization-owner operations.

If it already exists, adopt it only when all facts match. An unexpected commit, fork relationship, public visibility, owner or collaborator is a stop condition.

Create a separate local working directory for Automonique. Do not add the new remote to the live legacy checkout. Repository rules that require a branch are configured immediately after the approved first push; until then, restrict access at the organization/repository level.

## Stage 2 — build two import candidates

Work in disposable clones or exports outside the live checkout. Produce both candidates before choosing:

### Candidate A: sanitized history

- filter prohibited blobs, paths and metadata from every reachable ref;
- replace organization-specific configuration with synthetic reserved examples;
- preserve safe authorship and chronology;
- retain a private old-to-new commit map for incident response;
- prove prohibited objects are unreachable after garbage-collection-equivalent verification.

### Candidate B: clean product import

- export only reviewed product source and planning material;
- establish one honest initial commit with AUTHORS/NOTICE/provenance;
- record privately that legacy history was not imported;
- retain attribution required by copyright and third-party licenses.

Run equivalent checks against both candidates:

- full-history secret, token, PII, customer, email, hostname, path and binary-metadata scans;
- dependency, copied-code, generated-code, font, image and asset license review;
- repository size, object/ref inventory and high-risk manual review;
- scan for private Slack, Telegram, Support, ticket and production content;
- build/test feasibility with no private network, production credentials or host-specific paths;
- comprehensibility, attribution and future-bisect value.

The report contains redacted counts, tool/rule versions, digests and dispositions. It never embeds detected secrets. Revoke a real credential before marking its finding resolved.

Stop for the owner’s sanitized-history versus clean-import decision. Do not push either candidate before this gate.

## Stage 3 — establish the private baseline

After the import choice is approved:

1. Make the selected candidate the sole local baseline.
2. Add `LICENSE` with the standard `GPL-3.0-or-later` text and SPDX identifiers to source files where policy requires them.
3. Add `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, governance/maintainer policy, AUTHORS/NOTICE, changelog/versioning, privacy/telemetry and dependency policies.
4. Add separate brand/trademark terms only after the owner decision; do not claim the GPL governs trademarks automatically.
5. Import approved brand assets into `brand/` with source digest, rights, transformations, formats and accessible alternatives.
6. Use `automonique.fr` as product/homepage metadata and acknowledge Inklura as founding sponsor without implying authority.
7. Add synthetic `.env.example` and fixtures. Use reserved domains, users, IDs and addresses.
8. Add architecture, threat-model, data-flow, bootstrap, recovery and contributor documentation.
9. Add deterministic Rust/Bun/toolchain locks, dependency policy, SBOM/provenance configuration and fork-safe CI.
10. Add `.automonique/bootstrap/`, `.automonique/dev/`, the finite seed program, and the source needed to implement the temporary seed coordinator.

Before the first push, rerun all source/history/license/privacy checks and inspect the complete candidate diff. Create a reviewed initial commit containing metrics derived from actual command output. Push only the approved baseline to the private upstream, then configure the default branch, least-privilege access, required reviews/checks, secret scanning, dependency review and protected release environments.

Do not configure long-lived production or signing credentials in Actions. Prefer OIDC and protected environments later. Do not enable public visibility.

## Stage 4 — implement the stage-minus-one launcher

The launcher plan is not executable code yet. Implement these reviewed files in the private upstream:

```text
scripts/automonique-dev
tools/bootstrap-seed/
.automonique/dev/seed-program.yaml
.automonique/dev/policies/seed.yaml
.automonique/dev/guides/
.automonique/dev/scenarios/seed/
```

Follow `docs/rust-rewrite/initial-development-launcher.md` exactly. The initial implementation must provide:

- `inspect`, `plan`, digest-bound `apply`, `start`, `resume`, `status`, `logs`, `attach`, `stop`, `doctor`, `handoff-status` and preview-only cleanup;
- strict TTY/non-interactive confirmation behavior;
- XDG-scoped durable state and repository fingerprints;
- transient user-systemd ownership with resource ceilings and descendant cancellation;
- one provider adapter sufficient to start plus a deterministic fake; all four planned adapters before the permanent-lab exit gate;
- explicit Git/build brokers, one write lease, isolated worktrees and no remote Git authority;
- budget, time, CPU, memory, PID, disk and provider limits;
- no production credentials/data and a minimal provider environment;
- restart/reboot recovery and a one-way handoff receipt;
- ShellCheck, Bats, provider fakes, adversarial refusal tests and clean-host scenarios.

The temporary Bun coordinator is finite scaffolding. It may execute only the reviewed eight-unit seed DAG and cannot add work to itself. It must retire after the verified Rust bootstrap/lab takes ownership.

## Stage 5 — start bounded development

Only after the private baseline and launcher acceptance suite pass, print the exact plan and ask the operator for its digest-bound approval. The expected interactive entry point is:

```bash
./scripts/automonique-dev start --provider auto --workers 1 --budget-eur 25
```

The operator must see repository/source digests, selected provider/model, effects, forbidden effects, worker/resource/token/cost/wall-time ceilings and cleanup behavior before typing `apply <digest>`. Redirected stdin, no TTY or `CI=1` never implies consent.

The seed DAG then implements only the permanent minimum:

1. canonical Cargo workspace and bounded protocols;
2. SQLite development DAG, attempts, leases and events;
3. sandboxed provider adapter plus fake;
4. file/worktree leases and typed Git/build brokers;
5. `automonique-bootstrap inspect|plan|apply|verify|resume`;
6. the Rust `automonique-lab` control plane;
7. clean-host, restart, recovery, secret and three-trial harness verification;
8. immutable SH0 build, full-program import and one-way coordinator retirement.

Do not let the seed path implement general product features before the Rust lab owns scheduling. Repeated `start` must attach to the existing lab rather than create a competing controller.

## Development and review loop

For each work item:

1. Select a ready ID from the canonical work breakdown and record dependency evidence.
2. Generate a bounded plan with allowed paths, forbidden effects, acceptance tests and budgets.
3. Give the implementer a dedicated worktree and minimum tool/capability set.
4. Run deterministic formatting, lint, unit, integration, scenario, security and relevant chaos tests.
5. Freeze the candidate diff and have fresh-context functional and adversarial reviewers inspect it.
6. Route findings to a bounded fixer; never let the implementer self-certify completion.
7. Re-run the complete affected gate and compare behavior/metrics to the last accepted baseline.
8. Commit only reviewed scope. Push/PR/merge remain separate policy-controlled actions.
9. Persist receipts, logs, artifacts, test counts and dispositions under the development run.

Commit messages should carry measured trailers such as:

```text
Automonique-Work: <work IDs>
Automonique-Checks: <actual pass/fail counts and named suites>
Automonique-Metrics: <relevant measured latency/resource/reliability deltas>
Automonique-Review: <functional/adversarial/provenance dispositions>
```

Never invent a metric and never optimize only for line or commit counts. Track behavior useful to an agent platform: task success, refusal correctness, approval integrity, duplicate effects, crash recovery, reload continuity, sandbox escapes, provider/tool latency, tokens/cost, CPU/RSS/disk and test/coverage changes.

## Required status artifacts

Maintain these machine-readable or Markdown artifacts in the new private repository, with sensitive evidence referenced by digest from protected storage rather than embedded:

- decision and import-evidence manifest;
- source/history/license/privacy audit comparison;
- approved import choice and attribution record;
- brand manifest and rights status;
- repository/settings/ruleset verification receipt;
- work-DAG status and dependency graph;
- implementation trial and clean-host reports;
- threat model, sandbox profile inventory and exception register;
- provider-adapter conformance matrix;
- handoff/recovery receipts and latest measured metrics;
- open owner decisions, blockers and next exact command.

At the end of every agent run, report:

1. current stage and completed work IDs;
2. exact repositories/branches/commits touched;
3. local and remote effects performed;
4. checks and measured results;
5. sensitive findings by redacted identifier and disposition;
6. unresolved decisions/blockers;
7. rollback/recovery state;
8. the next safe command and whether it needs human approval.

## Stop conditions

Stop safely and request direction if:

- organization/repository identity, access or visibility differs from this brief;
- the target repository already has unexpected content or a fork relationship;
- an owner decision is required for import, rights, publication, packages or production;
- a real credential or customer/private artifact is found and not yet contained;
- history cannot be sanitized with credible unreachable-object proof;
- the legacy worktree has unattributed changes overlapping the extraction;
- a requested operation needs repository administration, signing, release, production or destructive authority not granted here;
- tests, provenance, sandbox isolation or rollback evidence fail;
- two schedulers, services or agents could own the same work/lease/effect;
- continuing would make a public, external or irreversible claim.

Do not paper over a stop condition with a model judgment. Preserve the run, release local leases where safe and provide the evidence needed for a human decision.

## Stage-zero completion

This brief is complete when:

- `bext-stack/automonique` exists as a private, governed, non-fork canonical upstream;
- the approved audited import is its sole baseline and contains no production/private coupling;
- licensing, provenance, brand, governance, security, CI and bootstrap inputs meet the private-stage gates;
- canonical code identifiers are Automonique identifiers, with legacy names only in declared compatibility surfaces;
- `scripts/automonique-dev` passes its refusal, recovery, resource, provider-fake and clean-host suites;
- one reviewed invocation builds the minimal Rust lab, detaches/resumes safely and records a one-way handoff;
- a repeated invocation attaches to the Rust lab rather than spawning another controller;
- no public visibility, package release, production deployment or legacy-repository mutation has occurred.

From that point, the Rust lab and the canonical work breakdown—not this bootstrap agent—own implementation scheduling.
