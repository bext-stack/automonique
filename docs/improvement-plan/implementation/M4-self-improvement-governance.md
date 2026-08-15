# M4 — Self-improvement governance

Implementation plan for GitHub issues
[#25](https://github.com/bext-stack/automonique/issues/25),
[#26](https://github.com/bext-stack/automonique/issues/26),
[#27](https://github.com/bext-stack/automonique/issues/27) and
[#28](https://github.com/bext-stack/automonique/issues/28), derived from
[`../audit-findings.md`](../audit-findings.md) F-02 (S0) and F-12, and from the
M4 section of [`../roadmap.md`](../roadmap.md) (roadmap items 22–25).

The milestone's subject is the pipeline that lets an administrator say
"improve Automonique …" and have the product modify, merge and deploy itself.
Today that pipeline verifies its own work with two commands, merges to public
`main` without consulting CI, and deploys by restarting the service — which is
the exact mechanism the rewrite exists to eliminate.

**Scope correction, read this first.** The self-improvement pipeline is *not*
the `automonique-lab` harness the requirements corpus describes. The daemon
imports exactly one module from that crate — `improvement_executor` — while
`harness_claim`, `program`, `build`, `state`, `controller`, `workspace_lease`
and `worktree` (~11k lines) form a separate proposal-only control plane with no
call site in the product path. Every issue in M4 is about the daemon pipeline.
Issue #27 has to say which of the two is the governed artifact, or the milestone
governs the wrong code.

---

## #25 — Align the improvement executor's verification recipes with CI

### Current state

The candidate's verification gate is a two-entry table:

`rust/crates/automonique-lab/src/improvement_executor.rs:285-291`

```rust
let recipes: &[(&str, &[&str])] = &[
    (
        "cargo fmt --all -- --check",
        &["fmt", "--all", "--", "--check"],
    ),
    ("cargo test --workspace", &["test", "--workspace"]),
];
```

It is executed by `run_checks` (`improvement_executor.rs:272-311`), called from
`ImprovementExecutor::execute` at `improvement_executor.rs:226`. The daemon
always selects `VerificationProfile::RustWorkspace`
(`rust/crates/automonique-daemon/src/improvement_worker.rs:146`), so this table
is the whole local gate for every candidate release.

The real CI gate set spans three workflows, not one:

| Workflow | Job | Gates |
|---|---|---|
| `.github/workflows/rust.yml:26-34` | `workspace` | `cargo fetch --locked`, `cargo metadata --no-deps --offline --locked`, `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --offline --locked`, `cargo test --workspace --all-targets --offline --locked`, `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` |
| `.github/workflows/rust.yml:36-41` | `workspace` | lockfile byte-reproducibility |
| `.github/workflows/plan.yml:24-28` | `licence-boundary` | `python3 tools/check_licenses.py`, `python3 -m unittest -v tools.test_check_licenses` |
| `.github/workflows/scrub.yml:25-29` | `development-scrub` | `python3 -m unittest discover -s tools/scrub -p 'test_*.py'`, `python3 tools/scrub/scan.py` |

Four problems beyond the missing commands, each verified against the tree:

1. **Flag drift.** The two recipes that do exist omit `--locked`, `--offline`
   and `--all-targets`. The release build in the same pipeline *does* use
   `--locked` (`rust/crates/automonique-daemon/src/release_builder.rs:142-144`),
   so the pipeline is inconsistent with itself as well as with CI.

2. **Ordering makes an added scrub gate vacuous.** `run_checks` runs at
   `improvement_executor.rs:226`, *before* `git add --all` at
   `improvement_executor.rs:228-234`. `tools/scrub/scan.py` reads content
   through the index — `git ls-files --stage` then `cat-file blob`
   (`tools/scrub/scan.py:225,242`) — so a scan run at that point would inspect
   the base tree and pass without ever seeing the candidate's edits.
   `tools/check_licenses.py:36-51` uses `ls-files --cached --others
   --exclude-standard` and reads bytes from disk, so it happens to work
   pre-staging; the scrub does not. Adding the gates without fixing the order
   would install a green tick that proves nothing.

3. **No pinned toolchain.** The sandboxed Codex agent gets `CARGO_HOME`,
   `RUSTUP_HOME` and `PATH` set explicitly
   (`rust/crates/automonique-lab/src/codex_app_server.rs:143-174`). The host's
   `run_checks` sets no environment at all
   (`improvement_executor.rs:294-299`) and inherits the daemon's. There is no
   `rust-toolchain.toml` anywhere in the tree, while CI pins 1.93.1
   (`rust.yml:20-24`). The candidate's compiler, the verifier's compiler and
   CI's compiler can all be different versions — which matters most for the
   gate this issue most wants to add, `clippy -D warnings`.

4. **No wall-clock budget.** `bounded_output`
   (`improvement_executor.rs:458-464`) caps output bytes only; nothing caps
   runtime. The recipes about to be added are the expensive ones, and a hung
   `cargo test` currently blocks the improvement lane indefinitely. The shape to
   copy already exists in the same crate: `run_bounded` with `CHECK_WALL_LIMIT`
   at `rust/crates/automonique-lab/src/harness_claim.rs:503,517`.

Separately, the check results are computed and thrown away.
`ImprovementExecutionReceipt.checks` (`improvement_executor.rs:95`) is returned
through `improvement_worker.rs:171-175` and then dropped: the release-candidate
recording at
`rust/crates/automonique-daemon/src/telegram_bridge.rs:4420-4431` persists shas,
tree, manifest digest and PR coordinates, but no check evidence.

### Approach

**Stage before verifying.** Move `git add --all`
(`improvement_executor.rs:228-234`) to immediately after the non-empty
`changed_paths` check at `improvement_executor.rs:223-225`, so every gate sees
exactly the bytes that will be committed. This is safe: `ensure_no_commit`
(`improvement_executor.rs:222`, `:349-354`) has already refused a candidate that
created a commit, and the post-commit `status_is_clean` assertion
(`improvement_executor.rs:253`) still catches anything left behind.

**Generalize the recipe entry.** Two of the new gates are `python3`, not
`cargo`, and run from the repository root rather than `rust/`. Replace the
`(&str, &[&str])` tuple with

```rust
struct Recipe {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    dir: RecipeDir,          // RustWorkspace | RepositoryRoot
}
```

and extend the table to the full CI set: `cargo fmt --all -- --check`,
`cargo check --workspace --all-targets --offline --locked`,
`cargo clippy --workspace --all-targets --offline --locked -- -D warnings`,
`cargo test --workspace --all-targets --offline --locked`,
`python3 tools/check_licenses.py`,
`python3 -m unittest -v tools.test_check_licenses`,
`python3 -m unittest discover -s tools/scrub -p 'test_*.py'`,
`python3 tools/scrub/scan.py`. Keep the cheap-first ordering the current table
already has (fmt, then check, then clippy, then test) so a candidate fails fast.

**Pin the environment.** Give cargo recipes the lab config's `cargo_home` and
`rustup_home` (already carried on `CodexRuntimePin`,
`improvement_worker.rs:120-122`) and give python recipes the `env_clear()` +
minimal-`PATH` + `PYTHONHASHSEED=0` discipline that `harness_claim.rs:494-502`
already uses. Land `rust-toolchain.toml` here if M5 #33 has not; if it has not
and this cannot wait, record `rustc -Vv` in the check receipt so a clippy
disagreement between candidate and CI is diagnosable rather than mysterious.

**Budget each recipe.** Wrap execution in the bounded-process helper from
`harness_claim.rs:517-540` and add a typed `CheckTimeout` variant to
`ImprovementExecutionError` (`improvement_executor.rs:510-525`).

**Stop the drift recurring.** Two mechanisms were considered. Generating the
workflows from a shared manifest requires modelling GitHub Actions YAML
semantics for very little gain. Prefer a **drift test**: a workspace test that
parses `rust.yml`, `plan.yml` and `scrub.yml`, extracts every `cargo …` and
`python3 …` gate command, and asserts set-equality against the Rust recipe table
modulo an explicit, commented `CI_ONLY` allowlist. Two gates genuinely belong on
that allowlist and should say why in the code: lockfile reproducibility
(`rust.yml:36-41`, needs a scratch copy outside the worktree) and
`publication-scrub` (`scrub.yml:31-51`, needs repository secrets the candidate
host must never hold). Any other divergence fails the test on whichever side
moved.

**Persist the evidence.** Write the `Vec<CheckReceipt>` to the improvement store
(see the shared schema-V2 migration under #26 and cross-cutting note 4), so
"which gates ran, and did they pass" is durable rather than inferred.

Deliberately *not* added: the `SafetyCheck::ALL` list at
`harness_claim.rs:227-251` (`plan/check.py --verify`, `tools/program.py
--verify`, `tools/guides.py --verify`). None of those is a CI gate, `plan/check.py`
is red today (audit F-09), and that list belongs to the unwired lab control
plane that #27 must rule on.

### Testing

- **Drift test** as described; it fails when either CI or the recipe table
  changes without the other. This is the issue's stated acceptance criterion.
- **Testability refactor first.** The three existing tests
  (`improvement_executor.rs:664-712`) all use `VerificationProfile::None`
  because a `RustWorkspace` fixture would need a real compilable workspace.
  Make the executor take its recipe table as a parameter (or add a
  test-only profile carrying `&'static [Recipe]`) so tests can inject
  `/bin/true` and `/bin/false` recipes and assert the runner's behaviour
  without a two-minute compile.
- **Negative fixtures**, in the existing `FakeAgent` style: a candidate that
  introduces a clippy warning, one that adds a file with no SPDX header, and one
  that writes a value matching `tools/scrub/synthetic-rules.json`. Each must
  fail with `CheckFailed` carrying the right label.
- **Ordering regression test**: the scrub-triggering fixture must fail. Written
  against today's code it passes, which is the bug — write it before moving the
  staging step so the fix is demonstrated.
- **Budget test**: a recipe pointing at a sleeping program with a small wall
  limit returns `CheckTimeout` rather than hanging.

### Effort

2–3 days. The table and generalized runner are small; the drift test and the
recipe-injection refactor are most of it. Add ~1 day if `rust-toolchain.toml`
lands here rather than in M5 #33.

### Dependencies

Soft on **M5 #33** (`rust-toolchain.toml`, supply-chain gates) — without a pin,
`clippy -D warnings` becomes an intermittent gate rather than a real one; land
#33 first or alongside. Soft on **M1 #5** (publication scrub on every push) and
**M5 #32** (tools suite in CI), which change what "the CI set" means and will
trip the new drift test by design. No dependency on #26, #27 or #28.

---

## #26 — Gate release activation on remote CI green

### Current state

The release gate does merge and activation in one uninterrupted callback
handler, `telegram_bridge.rs:4243-4330`:

1. `merge_implementation(pr_number, implementation_head_sha)`
   (`telegram_bridge.rs:4250-4258`) → `improvement_github.rs:210-218` →
   `merge` at `improvement_github.rs:360-397`, a squash merge with GitHub's
   `sha` precondition.
2. Merged-tree equality assertion (`telegram_bridge.rs:4263-4266`).
3. `start_activation` (`telegram_bridge.rs:4274`).
4. `worker.activate(&activating, &digest)` (`telegram_bridge.rs:4288`).

Nothing consults CI at any point.

Four facts make this tractable:

- **The commit CI runs on is exactly the commit that gets merged.**
  `telegram_bridge.rs:4418` asserts `pr.head_sha ==
  receipt.execution.candidate_sha` before recording, so
  `implementation_head_sha` is both the tested candidate SHA and the PR head
  that check runs attach to.
- **The pipeline's GitHub path already admits the endpoint.** This pipeline does
  not use `automonique-github-connector` — that crate's `GitHubOperation`
  (`rust/crates/automonique-github-connector/src/request.rs:724-751`) is
  thirteen issue/search/user operations with no check-run, commit-status or
  workflow-run capability. The pipeline uses the `gh api` broker at
  `improvement_github.rs:421-506`, whose `safe_endpoint` grammar
  (`improvement_github.rs:508-518`) already permits any `repos/…` path
  containing `-`, `?`, `=`, `&` and `%`. `repos/{owner}/{repo}/commits/{sha}/check-runs`
  needs no grammar change.
- **CI does fire on the PR.** All three workflows trigger on `pull_request`
  (`rust.yml:8`, `plan.yml:8`, `scrub.yml:7`). The candidate branch push alone
  triggers only `scrub.yml` (unrestricted `push:`), since `rust.yml` and
  `plan.yml` restrict pushes to `main`.
- **The approval is single-use.** `ImprovementStore::approve`
  (`rust/crates/automonique-store/src/improvements.rs:892-970`) consumes the
  challenge (`consumed_at_ms`, `:939-943`) and increments the revision
  (`:944-955`). There is no second button to press, so any design that defers
  activation must resume itself.

Two store facts constrain the design:

- **No migration ladder exists.** `initialize_or_validate_schema`
  (`improvements.rs:1574-1601`) creates `SCHEMA_V1` on an empty database and
  refuses any other `user_version`. The ladder pattern to copy lives in
  `rust/crates/automonique-store/src/lib.rs:3903-3945` (`SCHEMA_V2` plus
  `MIGRATE_V*_TO_V*` batches replayed in order, with per-step
  `migrate_vN_to_vN+1` functions).
- **`ReleaseApproved` has exactly one exit.** `require_transition`
  (`improvements.rs:1087-1119`) permits `ReleaseApproved → Activating` and
  nothing else; `Failed` is reachable only from `Activating` and `Implementing`.
  A red-CI refusal has nowhere to go today.
- **One event per revision.** `improvement_events` carries
  `UNIQUE (improvement_id, revision)` (`improvements.rs:86`), so a polling loop
  cannot append an event per attempt at a fixed revision.

### Approach

**Add a typed CI verdict to the broker.** New method on
`ImprovementGitHubBroker` (`improvement_github.rs:78`), alongside
`source_base_sha` and `merge_implementation`:

```rust
pub fn commit_ci_verdict(&mut self, sha: &str) -> Result<CiVerdict, ImprovementGitHubError>
```

calling `GET repos/{source_repo}/commits/{sha}/check-runs?per_page=100`, and
reducing to `Green | Pending | Red`:

- `Green` — every run is `status == "completed"` with `conclusion` in
  {`success`, `neutral`, `skipped`}, **and** every name in a required-check
  allowlist is present.
- `Red` — any `conclusion` in {`failure`, `timed_out`, `cancelled`,
  `action_required`, `stale`}.
- `Pending` — anything else: a run still in flight, a required check absent, an
  empty array, or a `conclusion` string the code does not recognize.

**Fail closed, explicitly.** An empty check-run list must be `Pending`, never
`Green` — the same "the empty set is the most restrictive state" rule the
roadmap asserts for M8 #53. Pair it with a **required-check allowlist** checked
in beside the recipe table: `["workspace", "licence-boundary",
"development-scrub"]`, the three job names. This is what makes the gate more
than "GitHub said green": a workflow that is deleted, renamed or never triggered
yields `Pending`, not a vacuous pass.

**Gate the merge, not only the activation.** The issue asks for activation to
wait; put the check *before* `merge_implementation` as well. Squash-merging a
red commit into a public `main` is itself the harm, and the merge is
irreversible in a way the link switch is not.

**Resume without a second press.** Because the challenge is consumed and the
revision has advanced, `Pending` must not dead-end. Two options:

- *(a) Refuse and require a manual resume.* Answer "CI still running", leave the
  record in `ReleaseApproved`, and let the owner send `IMP-000001: continue` —
  the resume verb `docs/self-improvement-workflow.md:66-69` already defines for
  the missing-lab case. Cheapest; the existing transition table already allows
  `ReleaseApproved → Activating` later.
- *(b) A bounded background poller* in the daemon's improvement lane: records in
  `ReleaseApproved` with a recorded `ci_head_sha` are re-checked on the existing
  daemon tick, with a capped attempt count and a wall deadline (suggest 60
  minutes). `Green` → merge, `start_activation`, activate. `Red` or deadline →
  `Failed` with reason `ci_red` / `ci_timeout`.

**Recommend (b), with (a) as the manual override.** The two-press gate is the
UX the pipeline was designed around; making the owner babysit CI erodes it.

**Store changes (schema V2), landed as one migration.** Introduce the ladder in
`improvements.rs` modelled on `lib.rs:3903-3945`, then add:

- `ci_head_sha TEXT`, `ci_verdict TEXT CHECK (ci_verdict IN ('pending','green','red'))`,
  `ci_evidence TEXT` (canonical JSON of run id / name / conclusion / html_url),
  `ci_checked_at_ms INTEGER`, and a poll-attempt counter column.
- The invariant as a table CHECK, not an `if` in the bridge:
  `CHECK (state NOT IN ('activating','completed') OR ci_verdict = 'green')`.
  This crate already encodes its state invariants this way
  (`improvements.rs:65-75`); doing it here means no code path — including a
  future one — can activate without green evidence.
- `(ReleaseApproved, Failed)` added to `require_transition`
  (`improvements.rs:1087-1119`) so a red verdict has a destination.
- **Do not** write an `improvement_events` row per poll: `UNIQUE
  (improvement_id, revision)` (`improvements.rs:86`) forbids it. Keep attempt
  state in columns; write one event when the verdict resolves.

**Type the refusal.** `telegram_bridge.rs:4260-4261` collapses every failure
into `improvement_unavailable`. Add distinct answers for "CI still running",
"CI failed", and "a required check never ran" — the three cases have different
owner actions.

### Testing

- **Broker verdict tests** against the existing `GitHubApi` trait
  (`improvement_github.rs:421-430`), which already supports a fake `api` in
  tests: all-success → `Green`; one `in_progress` → `Pending`; one `failure` →
  `Red`; empty array → `Pending`; required name missing → `Pending`; unknown
  conclusion string → `Pending`.
- **Migration test**: open a V1 database, assert a clean upgrade to V2 with rows
  preserved; assert an unknown future `user_version` still refuses.
- **CHECK-constraint test**: inserting `state='activating'` with `ci_verdict`
  other than `'green'` must be rejected by SQLite, not by Rust.
- **Transition test** for `ReleaseApproved → Failed`.
- **Bridge test**: a fake broker returning `Red` must not call
  `merge_implementation` at all — assert on the fake's call log, not on the
  answer text.
- **Poller test** with an injected clock: a persistently `Pending` record
  becomes `Failed`/`ci_timeout` at the deadline and no earlier.

### Effort

4–6 days. Broker query and verdict ~1 day; the store ladder and V2 columns
1–2 days (this is the first migration in this store, so the ladder itself is
new); poller and its failure paths ~2 days; tests throughout.

**Verify one thing live before building the poller.** Whether GitHub Actions
actually fires for the candidate branch and PR depends on the identity that
pushes and opens them — `improvement_publish.rs:113-119` pushes over HTTPS with
ambient credentials and the PR is opened via `gh`
(`improvement_github.rs:462-463`). Some GitHub identities' pushes do not trigger
workflows; if that is the case here, every improvement would sit at `Pending`
and time out, turning the gate into a deadlock. One dry run settles it and
decides whether option (b) is viable at all.

### Dependencies

No hard dependency. Benefits from **#25**: a candidate that has already run the
CI gate set locally will rarely be red remotely, which keeps the poller path
cold. Shares its schema-V2 migration with #25's check receipts — land them
together. Interacts with **M1 #5**: if the publication scrub becomes a required
check, add it to the allowlist in the same change.

---

## #27 — Bring self-improvement under the self-hosting ladder [owner-decision]

### Current state

Two requirements in the corpus govern this pipeline, and both are contradicted.

`docs/product-plan/requirements/ai-implementation-harness.md:12`:

> This is implementation infrastructure, not a production self-modification
> permission. Production Automonique never edits or activates its own release
> merely because an agent proposed a patch.

`docs/product-plan/requirements/self-hosting-and-bootstrap.md:9-13`:

> A candidate may build, test and self-review, but it cannot mint its own
> protected-integration, release-signing or production-promotion authority.

The ladder itself is at `self-hosting-and-bootstrap.md:18-28` (SH0 seed → SH6
production proposal). Its integration ceilings are at
`self-hosting-and-bootstrap.md:238-248`: `proposal_only`, `development_branch`,
`canary_release`, `production_proposal` — with "Protected `main`, stable release
tags, public package publication, signing keys and production deployment remain
outside candidate credentials at every ceiling" (`:245-248`). Its candidate
lifecycle (`:138-154`) runs `proposed → … → shadowing → self_hosting →
owner_verified → promotable → promoted`, and states plainly that "The candidate
can submit evidence but cannot write `owner_verified`, `promotable` or
`promoted` for itself" (`:154`). Promotion is a two-step typed operation,
`prepare_promotion` then `approve_promotion` (`:250`).

What shipped instead: an eight-state machine
(`improvements.rs:121-131`) that ends in a squash merge to public `main`
(`improvement_github.rs:382-387`), an atomic release-link switch and a systemd
restart (`release_activation.rs:159-213`), driven by two Telegram button
presses.

**What the implementation gets right, and it is not trivial.** The sandboxed
candidate holds no GitHub, SSH-agent, deployment or production credential
(`improvement_executor.rs:5-9`, `improvement_publish.rs:5-7`); it cannot create
a commit, and attempting to is a typed refusal
(`improvement_executor.rs:222`, `:349-354`); the approved plan is byte-bound by
digest (`improvement_executor.rs:55-69`); both gates are challenges bound to
actor, chat, revision and artifact digest with single-use replay protection
(`improvements.rs:892-937`); the merge refuses a head that moved after approval
(`improvement_github.rs:371-373`). The *credential-isolation* invariants of the
ladder are substantially honoured.

**What it does not have.** No candidate namespace, no isolated candidate run, no
`fixture`/`replay`/`shadow`/`canary` mode (`self-hosting-and-bootstrap.md:192-198`),
no independent rebuild or reproducibility comparison (`:204-217`), no
`owner_verified`/`promotable` separation, and the merge into protected `main` is
performed by the same process that proposed the change. Measured against the
ceilings at `:238-243`, the shipped pipeline sits **above `production_proposal`**:
it performs the integration the ladder reserves for an external authority.

And, as noted at the top: the pipeline is not the `automonique-lab` harness the
requirements describe. Only `improvement_executor` is imported by the product.

### Owner-decision options

**Option A — Subordinate to `proposal_only`.** Remove `merge_implementation`
from the automated path; the pipeline stops at "PR opened, release built,
evidence attached". A human merges. Activation becomes a separate operator
action. Declares the pipeline SH2 (self-building) at ceiling `proposal_only`.
*Cost:* 1–2 days, mostly deletion and doc work; the second Telegram gate is
re-labelled "approve this release for operator activation".
*Consequence:* loses the unattended end-to-end loop, which appears to be the
feature the owner wanted.

**Option B — Build to `development_branch` plus explicit promotion.**
Automation merges into a bot-owned branch rather than `main`; promotion to
`main` and activation become the ladder's two-step `prepare_promotion` /
`approve_promotion` (`self-hosting-and-bootstrap.md:250`) with recorded
evidence. #26's CI verdict becomes the "required-status policy" the ladder names
at `:247-248`, and a candidate state the automation cannot write for itself
gives `:154` a mechanism.
*Cost:* 1–2 weeks. Branch target change in `improvement_github.rs:56-58`, two
new states in `improvements.rs:121-131` and `:1087-1119`, the promotion verbs.
*Consequence:* keeps the automation and restores the ladder's authority
separation. This is the option under which the shipped design and the corpus
agree without either being weakened.

**Option C — Amend the requirements to bless the shipped design.** Record a
provenanced amendment adding a fourth ceiling ("owner-gated direct
integration") whose preconditions are exactly what the pipeline enforces:
digest-bound double approval, credential-free candidate, no candidate commit
authority, CI green from #26, atomic link switch with rollback. Revise
`ai-implementation-harness.md:12` to say what it now means.
*Cost:* 2–3 days of careful doc work using the corpus's
`transferred_sha256`/`amended_per` provenance scheme.
*Consequence:* honest — the pipeline's real safety properties are substantial.
But it deletes the one sentence currently preventing an agent-proposed patch
from reaching production, and it should not be chosen while F-01 (the public
repository publishes private client identifiers) and F-03 (no parity harness)
are open. Those are precisely the failure classes an external integration
authority would have caught.

**Recommendation: B, with A as an immediate stopgap.** Stop merging to `main`
now; build the promotion path over the following milestone. Whichever is chosen,
the decision must also record **which implementation is governed** — the daemon
pipeline or the `automonique-lab` control plane — and the other should be
archived or explicitly labelled non-product.

### Testing

Determined by the decision. For A: a test asserting no automated path reaches
`merge_implementation` against the source repository. For B: transition tests
that the automation identity cannot write `owner_verified` or `promotable`,
mirroring `self-hosting-and-bootstrap.md:154`, plus a test that the merge target
is the bot-owned branch. For C: the corpus provenance checkers (M1 #7) accept
the amendment and the `tools/` derived-artifact checks stay green.

### Effort

The decision is the blocker. A ~2 days; B ~1–2 weeks; C ~3 days. Then, in every
case, reconcile `docs/self-improvement-workflow.md` with the corpus and give the
subsystem a place in the precedence table.

### Dependencies

**M1 #7** (repair the authority stack; fold shipped-but-unspecified subsystems
into the corpus) names self-improvement as one of those three subsystems — #27
and #7 decide the same question and should be decided together. Option B has
**#26** as a prerequisite for its required-status policy. #28's deviation note
(below) rides along with whichever doc change this produces.

---

## #28 — Activate releases via generation handoff, not service restart

### Current state

**The restart path.** `ImprovementWorker::activate`
(`improvement_worker.rs:210-234`) branches on release kind. Skill-only releases
activate hot through `skill_runtime::activate`
(`improvement_worker.rs:229-232`) and return
`ActivationDisposition::HotActive` — no restart, and out of scope for this
issue. Code and mixed releases go to `schedule_code_activation`
(`improvement_worker.rs:236-262`), which spawns

```
/usr/bin/systemd-run --user --collect --unit automonique-improvement-<id> \
    --property Type=oneshot <current_exe> improvement-activate --state-dir … \
    --improvement-id … --revision … --manifest …
```

That helper's entry point is `rust/crates/automonique/src/main.rs:8-39`. It
sleeps a fixed 2 s to let the Telegram reply commit
(`improvement_worker.rs:318-320`), reloads config, re-validates revision, state
and manifest digest (`improvement_worker.rs:330-335`), then calls
`activate_code_now` (`improvement_worker.rs:264-276`).

**The restart itself.** `SystemdUserSupervisor`
(`release_activation.rs:99-127`): `restart` is `systemctl --user restart
<unit>`, `ready` is `systemctl --user is-active --quiet <unit>`.
`CodeReleaseActivator::activate` (`release_activation.rs:159-213`) flips the
`current` symlink via `install_link` (`:278-288`), restarts, and on failed
readiness calls `restore_link` (`:290-300`) and restarts again, returning
`ActivationRolledBack` (`:209`).

The transient unit and the whole out-of-band helper exist for one reason: the
process performing the activation cannot survive its own `systemctl restart`.

**The seam is already generic.** `CodeReleaseActivator<S: ReleaseSupervisor>`
(`release_activation.rs:129-133`) is parameterized over
`trait ReleaseSupervisor { fn restart(&mut self, unit: &str); fn ready(&mut self, unit: &str) }`
(`release_activation.rs:91-94`). And `verify()` (`release_activation.rs:215-275`)
already produces exactly what a handoff needs: the verified release directory,
`binary_sha256`, `source_sha`, `plan_digest` and the manifest digest.

**The target contract** is `docs/product-plan/requirements/reload-protocol.md`:
`automonique reload <release>` sends "the immutable release path and expected
manifest hash through the active generation's admin endpoint" (`:21`); a reload
epoch is created transactionally (`:23-25`); N+1 proves non-mutating readiness
(`:42`); N quiesces (`:69-75`); leases transfer transactionally with incremented
epochs (`:83-88`); N+1 proves active readiness beyond process liveness
(`:108-126`); and a failure matrix (`:145-154`) leaves N active in every
candidate-failure case. None of it is implemented (F-12), which is issue **#46**.

The invariant being violated is goal #1 and #22 of
`docs/product-plan/requirements/goals-and-invariants.md:19,22`, and its metric
target — "Interrupted active jobs during reload | 0" — is at `:255`.

### Approach

**Step 1, now, no dependencies: record the deviation.** The corpus contains no
statement that restart-based activation is accepted; `docs/self-improvement-workflow.md:26-30`
describes the restart as ordinary behaviour. Add an accepted-temporary-deviation
entry naming the mechanism (`release_activation.rs:194-195`), the invariant it
violates (`goals-and-invariants.md:19,255`), the blast radius (every in-flight
Telegram, Slack, Support turn and provider run in the restarted generation is
lost), and its retirement condition (#46 lands). Link it from the workflow doc.
This ships with #27's documentation work.

**Step 2, optional, only if #46 is more than a milestone away: shrink the blast
radius.** The fixed 2 s sleep at `improvement_worker.rs:318-320` exists purely
to let a Telegram reply commit. Replacing it with a bounded drain — refuse to
restart while the daemon reports in-flight work, up to a deadline — turns a
guaranteed interruption into a usually-clean one. This is a mitigation, not
handoff, and the deviation note must not be softened on its account.

**Step 3, after #46: swap the supervisor.** Widen the trait, because a handoff
needs the release path and manifest digest that `systemctl restart` does not
take:

```rust
pub trait ReleaseSupervisor {
    fn activate(&mut self, release: &VerifiedCodeRelease, root: &Path)
        -> Result<(), ReleaseActivationError>;
    fn ready(&mut self) -> Result<bool, ReleaseActivationError>;
}
```

Add `GenerationHandoffSupervisor`, which sends the verified release path plus
expected manifest digest to the active generation's admin endpoint — the *same*
input `automonique reload <release>` takes, so the improvement pipeline and the
operator verb share one code path rather than growing two. Keep
`SystemdUserSupervisor` as the issue's "explicit fallback", selected by config:
add an `activation: "handoff" | "restart"` field to `improvement-lab.json`
(schema bump from `automonique.improvement-lab-config/v1`,
`improvement_worker.rs:103`), defaulting to handoff once available.

**Keep the link discipline.** `install_link` / `restore_link`
(`release_activation.rs:278-300`) stay: the `current` symlink is how a process
started by any means finds the release bytes, and
`docs/self-improvement-workflow.md:32-36` requires `ExecStart` to resolve it.
Handoff changes who starts N+1, not where the bytes live.

**Let the protocol own rollback.** `ActivationRolledBack` today means "we
restarted, readiness failed, we restored the link and restarted again". Under
handoff, the protocol's failure matrix (`reload-protocol.md:145-154`) already
guarantees N stays active on every candidate failure, so the activator's
rollback shrinks to restoring the symlink and the double restart disappears. The
store's `RolledBack` state (`improvements.rs:130`, reached at
`improvement_worker.rs:342-352`) keeps its current meaning.

**Delete the helper.** With the active generation performing the reload and
surviving to record the outcome, `schedule_code_activation`
(`improvement_worker.rs:236-262`), `ActivationDisposition::Scheduled`
(`improvement_worker.rs:69`), the 2 s sleep, the out-of-band re-validation in
`run_scheduled_activation` (`improvement_worker.rs:325-335`) and the
`improvement-activate` argv parser (`main.rs:8-39`) all collapse into an
in-process call — roughly 120 lines removed, and with them the window in which a
transient systemd unit holds authority the daemon has already relinquished.

### Testing

- **Supervisor level.** `release_activation.rs:578` already exercises
  `activator.activate(&candidate)` with an injectable supervisor. Add a
  `FakeHandoffSupervisor` covering: readiness fails → link restored →
  `ActivationRolledBack`; handoff refused outright → link restored, N
  unaffected.
- **Config.** Both `activation` values parse; an unknown value refuses — the
  config struct is already `deny_unknown_fields`
  (`improvement_worker.rs:29`).
- **The test that distinguishes this issue from the status quo**: activate a
  code release while a synthetic long-running turn is in flight and assert the
  turn survives. Write it inside **#46's** fault-injection matrix rather than
  duplicating a reload harness here.
- **Regression**: skill-only releases must still take the untouched `HotActive`
  path.

### Effort

Deviation note ~0.5 day (ships with #27). Bounded drain, if taken, ~2 days.
Supervisor swap plus deletions ~3–4 days once #46 exists. The in-flight-survival
test belongs to #46's budget, not this one.

### Dependencies

**Hard on #46** (M8 — generation handoff and reload) for step 3. Steps 1 and 2
have no dependency. See cross-cutting note 9: the roadmap's inline dependency
reference for this item is wrong.

---

## Cross-cutting notes

1. **Three fixed check lists, no shared source.** `improvement_executor.rs:285-291`
   (two cargo recipes), `harness_claim.rs:227-251` (three `python3 … --verify`
   checks CI never runs, one of which — `plan/check.py` — is red per F-09), and
   the three CI workflows. #25 aligns the first with the third. The second
   belongs to the unwired lab control plane and should stay out of the recipe
   table until #27 rules on it.

2. **The pipeline is not the harness the requirements describe.** The daemon
   imports exactly one module from `automonique-lab`; ~11k lines of
   `harness_claim`, `program`, `build`, `state`, `controller`, `workspace_lease`
   and `worktree` have no product call site. Every M4 issue is about the daemon
   path. #27 must say so explicitly or the milestone governs the wrong artifact.
   This is the same class of finding as F-06's unwired automation triad and
   belongs in the same wire-or-archive conversation.

3. **Verification evidence is computed and dropped.**
   `ImprovementExecutionReceipt.checks` (`improvement_executor.rs:95`) never
   reaches the store; `telegram_bridge.rs:4420-4431` records shas, tree,
   manifest digest and PR coordinates but no check results. #25 and #26 both
   need durable evidence — add one `improvement_check_receipts` table in the
   shared migration rather than two.

4. **The improvements store has no migration ladder.**
   `improvements.rs:1574-1601` creates V1 or refuses. #26 is the first change
   that needs V2. Introduce the ladder once, modelled on
   `automonique-store/src/lib.rs:3903-3945`, and land #25's check receipts and
   #26's CI columns in the same step.

5. **Invariants belong in the table, not the caller.** The improvements schema
   already encodes state/field invariants as CHECK constraints
   (`improvements.rs:65-75`). #26's "activation requires green" should be a
   CHECK, not an `if` in `telegram_bridge.rs`. That is the difference between a
   gate and a convention, and this crate has chosen the former everywhere else.

6. **One approval, one press.** `approve` consumes the challenge and bumps the
   revision (`improvements.rs:938-955`), and `improvement_events` is
   `UNIQUE (improvement_id, revision)` (`improvements.rs:86`). Any M4 design
   that makes activation wait — for CI (#26) or for a reload window (#28) — must
   resume without a second button and must not write per-attempt events at a
   fixed revision. Missing this surfaces as an opaque store error at runtime.

7. **The environment is pinned for the agent and unpinned for the verifier.**
   The sandboxed Codex agent gets `CARGO_HOME`/`RUSTUP_HOME`/`PATH` explicitly
   (`codex_app_server.rs:143-174`); the host's verification recipes set no
   environment at all (`improvement_executor.rs:294-299`), and neither does the
   release build (`release_builder.rs:142-144`). With no `rust-toolchain.toml`
   in the tree, the candidate's compiler, the verifier's compiler and CI's
   pinned 1.93.1 (`rust.yml:20-24`) can all differ. Adding `clippy -D warnings`
   without fixing this converts a real gate into an intermittent one.

8. **No wall-clock budget on verification.** `bounded_output`
   (`improvement_executor.rs:458-464`) caps output size only, and #25 adds the
   expensive recipes. `harness_claim.rs:517` already has the bounded-process
   shape to copy.

9. **Roadmap assumption to correct.** `../roadmap.md` M4 item 25 reads
   "(Depends on item 44.)" — item 44 is sandbox uid separation (issue #47). The
   real dependency is item 43, generation handoff and reload (issue #46), which
   is what the roadmap's own *Sequencing and dependencies* section says ("M4
   items 22–23 are independent; item 25 depends on M8 item 43") and what issue
   #28 says. The inline reference should be corrected to item 43.

10. **A live prerequisite for #26 that code review cannot settle.** Whether
    GitHub Actions fires for the candidate branch and PR depends on the identity
    that pushes and opens them (`improvement_publish.rs:113-119` pushes over
    HTTPS with ambient credentials; `improvement_github.rs:462-463` opens the PR
    via `gh`). If that identity's events do not trigger workflows, every
    improvement sits at `Pending` and times out — the gate becomes a deadlock.
    One dry run settles it, and it decides whether the background-poller design
    is viable.
