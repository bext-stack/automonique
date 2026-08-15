# Historical gates and capability conditions

This file preserves the gates used by the former executable-plan workflow.
They remain useful as requirements for the specific capability claim they
describe, but they do not prevent ordinary product development from starting,
being committed, or being pushed. `plan/check.py` may still interpret them as
blocking when someone explicitly opts into the archived graph workflow.

A capability claim is supported only when its **closing evidence** exists. An
unsupported assertion does not become true merely because the gate is no
longer a development admission control.

| Gate | Closed by | Blocks |
|---|---|---|
| [`GATE-BASELINE`](#gate-baseline) | `BOOT-001` | ~~all work~~ **closed** |
| [`GATE-IDENTITY`](#gate-identity) | `BOOT-002` | advisory identity-hardening claim only |
| [`GATE-SCRUB`](#gate-scrub) | `BOOT-003` | making the repository public |
| [`GATE-ORACLE`](#gate-oracle) | `BOOT-004` | archive-differential parity, fixture capture |
| [`GATE-HARNESS`](#gate-harness) | owner decision | further self-host harness work (`R0-19`…`R0-40`) |
| [`GATE-LICENCE`](#gate-licence) | first distribution contract | advisory release-readiness claim only |

---

### GATE-BASELINE

**State: closed 2026-08-09 by `BOOT-001`.**

The executable plan must be checked in, internally consistent, and verified by
CI before any work item can claim an immutable base.

Blocks: everything. No item is selectable while this gate is open.

Closing evidence, **amended 2026-08-15** to the state that is actually
measurable. The two amended bullets asserted CI wiring that has never existed;
they are corrected rather than deleted, so the difference between what was
claimed and what is true stays visible:

- `plan/work-graph.toml` is checked in and regenerable from
  `docs/product-plan/reference/work-breakdown.md`;
- ~~`python3 plan/check.py --verify` exits zero in CI on every push~~ —
  **amended.** No workflow runs `plan/check.py --verify`. `.github/workflows/plan.yml`
  (workflow name `source-policy`) runs the licence checker in its
  `licence-boundary` job and, since 2026-08-15, the tools test suite and the six
  derived-artifact checkers in its `derived-artifacts` job — but not this one. It
  exits zero when run on demand. What *is* wired into CI on every push is the
  one rule of that checker which is about the published tree rather than plan
  bookkeeping: `python3 plan/check.py --identifiers`, run by the
  `development-scrub` job in `.github/workflows/scrub.yml`;
- ~~drift in either direction fails the build, demonstrated by a deliberately
  broken commit that CI rejects~~ — **amended.** No CI job rejects such a
  commit, because no CI job runs the checker. Drift detection is demonstrated
  instead by `python3 plan/selftest.py`, which breaks a scratch copy of the
  plan thirteen distinct ways and requires the checker to refuse each one — and
  which is itself guarded against passing vacuously by a baseline control it
  runs first. That is a stronger demonstration than one broken commit, and it
  is also not a build gate: nothing runs it automatically either. Since
  2026-08-15 drift *is* a build failure for the derived artifacts generated from
  the product corpus — the parity ledger, identifier inventory, contract and
  surface inventories, capability ledger and oracle boundary, all verified by
  the `derived-artifacts` job — but not for `plan/work-graph.toml`, which is
  what this bullet claimed.

Making the first amended bullet true again is a workflow change, not a plan
change: add a job running `plan/check.py --verify`. It is deliberately not done
here, because `--verify` also refuses a stale `plan/ready.md` and warns on the
25 items recorded as done without gate evidence, and turning that into a push
gate is a decision about the archived plan's status, not a truth repair.

---

### GATE-IDENTITY

**State: advisory/open.** Current commits are unsigned, dedicated workload
identities have not been configured, and `main` has no protected write
boundary.

`GOVERNANCE.md` defines logical implementer, reviewer, fixer, builder and
integration roles, but permits them to coincide when the owner chooses. This
gate records optional identity separation; it does not require it.

Blocks: only a claim that dedicated workload-identity separation is active.
It does **not** block implementation, harness work, review, local commits or
owner-configured protected integration.

Closing evidence:

| Condition | State |
|---|---|
| every identity claimed as distinct has separate credentials | **met, vacuously** — `.github/identity/register.toml` claims no separation, and `check_identity.py` refuses a claim it cannot back |
| signatures, when enabled, verify against a published trust root | **not met** — signing is not enabled, so nothing verifies |
| a test proves non-integration credentials cannot write the protected branch | **not met** — there is no protected branch to be refused by |
| `PROVENANCE.md` § Repository identity describes the achieved state | **met** — and a check refuses it when it drifts from the register |

The first and last conditions are closable from inside the repository and are
closed. The middle two are external administrative facts, and no amount of
repository-side work can produce them.

#### What the repository now enforces

`.github/identity/register.toml` is the register of record: which identity
holds which `GOVERNANCE.md` § Roles role, whether it is `shared` or
`dedicated`, what it signs with, and which pre-rule commits are excused by
exact SHA. `.github/identity/check_identity.py` — run by
`.github/workflows/identity.yml`, which exists as of 2026-08-15; this citation
was made true by creating it, not by finding it — refuses:

- a `separation_claimed = true` that no dedicated credential backs, and two
  `dedicated` identities sharing one fingerprint or one address;
- a commit whose author or committer is not a registered identity, unless a
  pinned exception names it, that exception still applies, and the commit
  predates `rule_effective_commit`;
- a commit-message attribution trailer;
- a declared signing method whose commits `git verify-commit` will not accept,
  and — in the other direction — a signed commit under a `signing = "none"`
  declaration;
- a `PROVENANCE.md` § Repository identity that no longer states what the
  register states;
- `plan/evidence/*.json` that claims independent review with zero reviewers.

Wiring it into `plan/check.py` is the integrator's follow-up; it is standalone
and importable so that wiring it needs no rewrite.

**Amended 2026-08-15.** The checker itself currently exits 1 with seven
unsupported claims: three merge commits made through the GitHub interface have
an author the register does not list, a committer it does not list, and a
web-flow signature while every registered identity declares `signing = "none"`.
The workflow therefore runs against a recorded pending count rather than a
clean pass — it refuses an eighth failure and refuses a silent drop to six, and
warns on every run that it is not evidence the register is truthful. Registering
those identities requires writing a real name and email into a tracked file and
redistributing the five `GOVERNANCE.md` roles, which is an owner action; the
options and the exact steps are in
[`plan/owner-decisions/2026-08-15-identity-register-reconciliation.md`](owner-decisions/2026-08-15-identity-register-reconciliation.md).
None of this changes the gate's state: steps 3 and 4 below are still the gate.

#### Owner checklist — the external half

Repository administration is an external action under `GOVERNANCE.md`. None of
the following can be performed or verified from inside a worktree, and none of
it is claimed here. Measured read-only against the configured remote on
2026-08-11: `GET /branches/main/protection` answered `404 Branch not
protected`, `GET /rulesets` answered `[]`, the repository is public, and 79 of
79 commits reported `verified: false` with reason `unsigned`. The ambient
developer credential in this environment holds `admin` and `push` on the
repository, so today any credential that can reach the remote can write `main`.

| # | Step | What it would prove | How to verify afterwards |
|---|---|---|---|
| 1 | Create a dedicated integration credential (machine account or app) with no key material shared with the implementer identity | two labels are two credentials, not one | add it to the register as `dedicated` with its fingerprint; `check_identity.py` refuses the entry if the fingerprint is empty or duplicated |
| 2 | Publish the trust root (allowed-signers file or key set) and enable signing for the identities that sign | a signature can be traced to a published root rather than asserted | set `signing` and `signing_effective_commit` in the register; `git verify-commit` must accept every commit after it, which `check_identity.py` requires |
| 3 | Restrict writes to `main` to the integration credential via branch protection or a ruleset, and require the `source-policy`, `rust`, `scrub` and `identity` checks | only the integration credential can advance the protected branch | `GET /branches/main/protection` returns 200 instead of today's 404, and lists those four required checks |
| 4 | Attempt one push to `main` with a non-integration credential and keep the transcript | the boundary is real rather than configured | the push is rejected; the transcript is the closing evidence, because configuration that has never refused anything is a forbidden shortcut for this gate |
| 5 | Update the register and `PROVENANCE.md` to the achieved state | the claim and the configuration agree | `python3 .github/identity/check_identity.py` exits 0 with `separation_claimed = true` |

Steps 3 and 4 are the gate. Until a rejected push exists, this gate stays open
however good the configuration looks.

---

### GATE-SCRUB

**State: open.** Two manual sanitization passes have run
(`docs/product-plan/README.md` § Plan transfer). Nothing prevents a third
identifier from being reintroduced.

Blocks: making the repository public. It does not block private development.

Closing evidence:

- an automated scan runs in CI over every tracked file;
- protected scan rules derived from both sanitization passes are configured
  without committing or logging private values and fail on reintroduction;
- the scan covers commit messages and file contents, not file contents alone;
- a deliberately reintroduced identifier is rejected in a test commit.

Measured at `606ff48` by `BOOT-003`, running `python3 tools/scrub/scan.py` and
`python3 -m unittest discover -s tools/scrub -p 'test_*.py'` (36 tests, 0
failures):

| Closing condition | State |
|---|---|
| automated scan in CI over every tracked file | met — `.github/workflows/scrub.yml` runs `tools/scrub/scan.py` over every stage-zero blob, every blob reachable from any ref, and tracked path bytes; the clean run over the staged candidate covered 704 blobs and found 0 |
| protected rules from both sanitization passes, configured without committing or logging a private value | **not met — zero protected rules are installed** |
| commit messages as well as file contents | met — the same run covered 84 reachable commit messages, and a reintroduction in a non-tip message is a checked failure |
| a deliberately reintroduced identifier is rejected in a test commit | met **for values some installed rule fingerprints**; with zero protected rules that set is the four public synthetic values, and no private identifier is in it |

The second row is the gate, and it makes the fourth narrower than it reads. A
scan's coverage is exactly its installed rules: a fixture that reintroduced an
identifier into both a tracked file and a commit message still exited zero in
development mode, and exited one naming rule, file and line as soon as a
protected rule covered that value. So today's green scan means the scanner
works, not that the tree is clean, and the scanner now says so on every run
that has no protected rules.

Closing needs two things no one inside the repository can supply: the family
values from the two sanitization passes, which appear in no permitted input, and
an observed pass of the `publication-scrub` job on protected `main` once they
are installed. `tools/scrub/provision.py` turns an owner-held private file of
those values into the two `scrub-publication` secrets without printing,
committing or putting one on a command line. Until then
`python3 tools/scrub/scan.py --require-protected` exits 2, which is this gate
holding rather than a defect.

**Amended 2026-08-15.** Three changes to what the rows above measure.

The first row is now met more strongly than it reads: `scrub.yml` gained a
`protected-push-scrub` job that runs on every push and pull request, scanning
the tracked tree and the pushed commit range, in protected mode when the
secrets exist and in development mode with a loud warning when they do not. CI
therefore hardens the moment the owner provisions, with no further edit. The
`development-scrub` job additionally runs `plan/check.py --identifiers`, which
needs no secret and refuses the first-party legacy name outside its sanctioned
homes on every push including a fork's.

The second row's blocker had a second half that is now removed. `provision.py`
refuses to fingerprint a value still present in the tracked tree — correct in
general, but it made a *deliberately retained* value unfingerprintable, since
such a value is by definition still there. The rule schema now carries an
optional per-rule `homes` list, and `provision.py` a matching `@home`
annotation, so the legacy name can be fingerprinted while its sanctioned copies
below are exempt. What remains is the owner action itself.

**The gate blocks making the repository public, and the repository is public.**
That is a standing conflict, not a new one. The options, the recommendation
(private until the scrub is green, as the only mitigation that works today),
and the exact provisioning steps are recorded in
[`plan/owner-decisions/2026-08-15-repository-visibility-while-scrub-red.md`](owner-decisions/2026-08-15-repository-visibility-while-scrub-red.md).
Whichever way the owner decides, it is recorded there and this gate should be
read against it — a gate everyone knows is being operated against teaches
readers that gates are decorative, which costs more than the decision does.

Retained by decision, and therefore not scan failures:

| Retained | Reason |
|---|---|
| `Monique` | first-party mascot; product identity |
| `bext-stack` | real repository organization, required by `SECURITY.md` |
| `legacy*` | dormant compatibility identifiers, neutral by construction |
| legacy source filenames | structural references permitted by `AGENTS.md` |
| legacy environment and command names | same permission; `reference/legacy-inventory.md` documents the mandatory `JEAN_DB` override, and an operator who cannot see the real variable name cannot apply the safety instruction |

The last entry is the one to watch. It is permitted because removing it would
make a live safety instruction unusable, not because environment names are
generally safe to publish. A future entry justified the same way needs the same
test: does redacting it destroy the reader's ability to act correctly?

**Location rule.** `reference/legacy-inventory.md` is the single sanctioned
place for exhaustive legacy names — table, environment, command, route and
companion identifiers — because `R0-13` requires classifying every one of them
and a redacted inventory cannot be classified. Everywhere else, prose uses the
neutral description. A legacy identifier appearing outside that file is a scan
failure even when the same identifier is permitted inside it.

Client, customer and third-party product names are **never** permitted, in that
file or anywhere else. The distinction is ownership: first-party legacy
identifiers are migration data, other people's names are not ours to publish.

---

### GATE-ORACLE

**State: open.** Three of four closing conditions are implemented and measured
by `BOOT-004` (`tools/oracle/`); the fourth is not met.

`PROVENANCE.md` permits a parity oracle to execute privately against synthetic
inputs while exposing "only bounded behavior results." The AI harness
(`docs/product-plan/requirements/ai-implementation-harness.md` § Differential
parity and shadow oracle) depends on that comparison. Until `BOOT-004` nothing
separated the oracle's output from the legacy source it runs against, so
running one would have contaminated the clean room it is meant to protect.

Blocks: `R0-02` and `R0-07` fixture capture, and **archive-differential**
parity work — any comparison that requires reading, executing, or receiving
output derived from the private legacy archive on the custody host.

**Scope re-stated 2026-08-15** by
[`plan/owner-decisions/2026-08-15-gate-oracle-scope.md`](owner-decisions/2026-08-15-gate-oracle-scope.md).
This line previously read "and all differential parity work", which was broader
than the hazard: live-traffic shadow comparison observes only what the legacy
bot publishes into shared channels this daemon is already a member of — the same
bytes every workspace member receives — so it needs no custody-host access, no
archive credential, and no cooperation from the custodian. It never crosses this
boundary, so this gate never governed it. What the gate blocks is unchanged in
substance; what it *claimed* to block was wider than what it protects. The
narrowing is to the blocking claim only: nothing below is relaxed, and the
boundary mechanism itself is untouched.

Closing evidence:

- a documented process boundary naming what holds legacy source, what strips
  oracle output, and who owns each side;
- the stripping mechanism is tested against a deliberate leak attempt covering
  source text, credentials, private identifiers and stack traces;
- oracle output is content-scanned before it reaches any agent context;
- the configured review record or explicit owner acceptance is bound to the
  exact boundary candidate.

Measured against those four, at the `BOOT-004` candidate:

| Condition | State | Evidence |
|---|---|---|
| documented boundary with owners | met | `tools/oracle/README.md` names the custody side (repository owner, as archive custodian), the clean side (primary session and its implementers), and the trust transition (`release.parse`) |
| deliberate leak attempt | met | 74 adversarial tests in `tools/oracle/test_boundary.py`, covering source text, credentials, private identifiers and tracebacks across three attack surfaces; 15 deliberate mutations of the boundary itself, 14 caught by a named test |
| content scan before agent context | met | `tools/oracle/scan.py` refuses any string in a verdict that is not identity-equal to a clean-side constant, and `release.parse` refuses the verdict if the scan does |
| review record or owner acceptance | **not met** | the candidate records 0 reviewers, there is no owner acceptance under `plan/owner-decisions/`, and an uncommitted candidate has no exact revision for one to be bound to |

The gate therefore stays open. It closes when an owner accepts an exact
revision of this boundary, or a configured review runs against it, and
`BOOT-004` completes — `plan/baseline.py` derives a gate's closure from the
status of the item that closes it, so no edit to this file can close it alone.

Closing it will not by itself make the work it blocks selectable. Measured from
`plan/work-graph.toml`: `R0-02` also waits on `R0-01` and has no contract;
`R0-07` has no contract. This gate is one of three conditions for `R0-02` and
one of two for `R0-07`.

Two channels around the release channel are measured and remain open, and the
boundary does not claim them: the custody process can still write files a
reader might later find, and its wall-clock time is observable unless the
channel holds each release to its deadline. `tools/oracle/README.md` § What this
does not contain records both, with the deployment control for each.

---

### GATE-HARNESS

**State: open 2026-08-10 by owner decision.**

`R0-19`…`R0-40` build the machine that develops Automonique: the lab, its
brokers and leases, self-hosting levels, candidate lifecycle, promotion
protocol and recursive-improvement policy. That work is legitimate and stays in
the graph. It had also become the only work the repository was doing.

Measured at the decision base:

| | lines |
|---|---|
| `rust/crates/automonique-lab/` | 22,230 |
| `tools/*.py` | 11,489 |
| `sdk/typescript/packages/lab/` | 1,920 |
| product domain (`automonique-protocol`, `-policy`) | 1,993 |

Eleven of 375 items were done, nine of them harness or discovery. `R0-19` was
still not complete after 22,230 lines. Twenty-plus `R1` product items were
dependency- and gate-clear the whole time, unselectable only because nobody had
written their contract.

Blocks: starting or extending any `track = "harness"` item. It does **not**
block using the harness that already exists, fixing it when it breaks product
work, or `R0-01`…`R0-18` discovery.

Closing evidence:

- an owner decision under `plan/owner-decisions/` naming the exact revision;
- the product milestone that justifies reopening — at minimum every `R1`
  contract written and epic `R1` complete;
- a statement of which specific harness items the milestone requires, so the
  gate reopens a named subset rather than the whole tail.

The gate exists because a harness measures its own progress with its own
instruments, and always reports success. Only work outside it can say whether
it was worth building.

---

### GATE-LICENCE

**State: advisory/open.**

`LICENSE-POLICY.md` states a precise boundary — product `Elastic-2.0`, `sdk/`
`Apache-2.0`. The intentionally lightweight development check validates source
SPDX headers against that root, and refuses a declared root that is not a
directory in the tree, so the boundary cannot read as green while gating
nothing.

**Amended 2026-08-15** by
[`plan/owner-decisions/2026-08-15-connector-licence-boundary.md`](owner-decisions/2026-08-15-connector-licence-boundary.md).
This quoted the boundary as also covering `integrations/` and `connectors/`.
Neither directory ever existed, so that part of the boundary gated nothing; the
provider connectors shipped as Elastic-2.0 crates under `rust/crates/` and stay
there.

Blocks: only a claim that an artifact is ready for distribution. It does not
block product, SDK, connector, or release-tooling implementation.

Evidence required by the first distribution contract, as applicable:

- package metadata and source headers declare the intended licence;
- shipped dependencies and required notices are inventoried;
- code moved across the product/Apache boundary has explicit owner review;
- an SBOM is generated when the artifact or distribution channel requires it.
