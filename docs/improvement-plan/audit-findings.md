# Deep audit — findings register (2026-08-15)

Status: point-in-time audit of the repository at `c2f8b16`. Produced by a
three-track audit (product-plan corpus, Rust workspace, repository periphery)
with every load-bearing claim verified against the tree, the running tools, or
the GitHub API. Companion documents: [`state-of-the-art.md`](state-of-the-art.md)
(external survey) and [`roadmap.md`](roadmap.md) (the improvement program built
from these findings; each finding ID below maps to a GitHub issue).

Naming: this document follows the corpus's neutral-term rule — **"the legacy
ticket bot"** and **"the Support backend"**. Where a finding is *about* a
private identifier appearing in the tree, the identifier is referenced by
file and line, never repeated here.

Severity scale: **S0** actively harmful now · **S1** blocks the launch
roadmap's own rules · **S2** material risk or large waste · **S3** hygiene.

---

## S0 — Actively harmful now

### F-01 · The public repository publishes private client identifiers, against its own open gate
- The repository is **public** (verified via the GitHub API), while
  `plan/gates.md` records GATE-SCRUB as **open** and explicitly "Blocks: making
  the repository public", with zero protected rules installed.
- Real client hostnames and the legacy bot's real name appear in shipped
  source and docs, e.g. `rust/crates/automonique-daemon/src/slack.rs:1471`
  (a real management-console URL in a Block Kit button),
  `slack.rs:1968,2022` (a real tenant string), the support-connector crate
  doc comment (`rust/crates/automonique-support-connector/src/lib.rs:3`),
  ~20 user-facing message strings across `slack.rs` and
  `telegram_bridge.rs` using the legacy bot's real name, and
  `docs/memory-operations.md` / `docs/slack-monique-rollout.md`.
- `plan/gates.md` §identifier-location says legacy identifiers are permitted
  in exactly one file, and client/third-party names **nowhere**. Both rules
  are violated in public source. The `publication-scrub` CI job only runs on
  manual dispatch, so pushes never re-check this.
- Two commit messages on `main` also carry the real names (`7216c35`,
  `e4f4fd8`); history rewriting is an owner decision, but new commits must
  stop adding occurrences.

### F-02 · The self-improvement pipeline's verification gate is weaker than CI
- `rust/crates/automonique-lab/src/improvement_executor.rs:285-291` verifies
  candidate releases with exactly two commands: `cargo fmt --all -- --check`
  and `cargo test --workspace`. CI (`.github/workflows/rust.yml`) additionally
  gates `cargo check`, `clippy -D warnings`, the licence boundary, and the
  development scrub.
- `docs/self-improvement-workflow.md` describes that path ending in a pushed
  commit, an opened PR, and an atomic release-link switch + **systemd service
  restart** — so an autonomous release can activate locally, then fail CI, and
  its activation mechanism is precisely the hard-restart deploy that
  `requirements/goals-and-invariants.md` lists as the gap the rewrite exists
  to close. It also bypasses the SH0–SH6 self-hosting ladder in
  `requirements/self-hosting-and-bootstrap.md`
  ("Production Automonique never edits or activates its own release merely
  because an agent proposed a patch", `ai-implementation-harness.md:12`).

---

## S1 — Violates the launch program's own rules

### F-03 · The strangler's parity gate is bypassed: no shadow harness exists
- The one governing rule of `docs/product-plan/launch-roadmap.md` is
  parity-gated strangler — shadow-verify before any scope becomes primary.
- Increment 3 (Slack ingest **in shadow**, zero outbound) was skipped:
  Slack outbound landed (`d49e8da`, `550265b`) with no shadow-comparison run.
  Increments 4 and 5 shipped customer-facing surfaces (Slack posting, Support
  ticket intake/drafting, GitHub issue actions) without any scope passing the
  four-condition gate in `launch-roadmap.md` §parity-gate.
- No shadow-comparison harness exists anywhere in the tree; `GATE-ORACLE`
  (blocking all differential parity work) is open with zero reviewers. The
  legacy bot already demonstrates the mechanism (a router shadow-mode flag
  recorded in `reference/legacy-inventory.md`), so this is a build task, not
  research.
- The four deliberately-re-specified safety properties (fail-closed deploy
  channel, announce-target-before-mutation, separately-authorized deletion,
  scheduler pause/cancel core) have **no implementation and no spec** yet.

### F-04 · The status documents describe a more constrained system than the one running
- `README.md` (last truthful at `1981e73`) still claims provider execution
  and transport networking are not connected; the daemon now runs Slack,
  Telegram, GitHub actions, Support intake, and contained provider runs.
- `docs/product-plan/execution-unlock.md` says "awaiting owner decision /
  nothing has been acted on" while Gates B and C were plainly opened
  (`9b0cbfb` is titled after Gate C).
- `rust/crates/automonique-daemon/src/lib.rs:1-12` claims the daemon
  "deliberately performs no external effects yet".
- Anyone making a risk decision from these documents will underestimate the
  blast radius. 22 of 31 product-plan files are frozen at the 2026-08-09
  baseline while 28 subsequent commits touched 113 files under `rust/`.

### F-05 · Authority stack and licence boundary contradict the tree
- `docs/product-plan/README.md` places `plan/gates.md` and the work graph at
  authority layers 2–3; `AGENTS.md` and `GOVERNANCE.md` dissolved them into
  "planning history". The precedence table was never updated.
- `README.md`, `LICENSE-POLICY.md`, `AGENTS.md`, and
  `tools/check_licenses.py:33` all assert `connectors/` and `integrations/`
  as Apache-2.0 roots; **neither directory exists**, and the real connectors
  shipped as Elastic-2.0 Rust crates. This needs an owner decision (move,
  relicense, or re-document), not a silent doc edit.
- Three shipped subsystems (durable memory + its CLI, the Slack v2 rollout
  config, the self-improvement pipeline) live in loose docs under `docs/`
  with no requirements coverage and no place in the precedence table.

---

## S2 — Material risk or large waste

### F-06 · ~16k lines of control surface that nothing reads
- The automation / approval / batch triad (protocol + store + CLI + daemon
  lanes) records decisions no scheduler, executor, or approval consumer acts
  on — the daemon's own doc comment says so
  (`rust/crates/automonique-daemon/src/lib.rs:639-663`).
- Two Telegram verbs are typed-unavailable because of this: `/cancel`
  (no admin cancel verb, although a working host-wide cancellation
  dispatcher exists) and `/deny` (approval wiring). Deciding whether to wire
  or delete the triad is worth more than any refactor in this register.

### F-07 · No randomized testing on the untrusted-input surface
- 3,298 tests, all example-based; zero property tests, zero fuzzing, and no
  PRNG anywhere. The protocol crate (68k lines, hand-rolled canonical JSON,
  SHA-256, framing) parses untrusted wire input across a sandbox boundary;
  exhaustive-enumeration tests only find bugs someone already imagined.
- `requirements/verification-and-rollout.md` specifies 17 test layers
  including property tests, fuzzing, a reload injection matrix, and a chaos
  suite; none are implemented.

### F-08 · Credential-redaction and HTTP substrate duplicated across connectors
- Three independent copies of the credential-redaction `scrub` function
  (github/slack/support connector `token.rs`), six of `map_ureq_error`, five
  of `read_bounded_body`/`strict_json`, three of `push_json_string` — a
  redaction gap fixed in one connector silently persists in two. Inside
  `automonique-protocol`, 21 identical `bounded()` validators differ only in
  a constant.

### F-09 · CI has silent gaps and undeclared dependencies
- `rust.yml` installs no JavaScript toolchain, yet protocol codegen tests
  shell out to `bun`/`node`/`npx tsc`. The cross-language suite returns
  early with an invisible `GAP:` note and **passes** when the toolchain is
  missing; it currently works because the GitHub runner image happens to
  ship node. The SDK's own `VERDICT.md` lists the missing CI step.
- Nothing in CI runs the ~454 tools/ tests, the six derived-artifact
  checkers, the identity checker (red today with 7 unsupported claims and
  referenced by a workflow that does not exist), `plan/check.py`
  (red, ~45 identifier-location failures), or `plan/selftest.py`
  (fails its own baseline control, making all 13 mutation cases vacuous).
- No `cargo-audit`/`cargo-deny`: with every dependency exact-pinned,
  security advisories will never be noticed. No `rust-toolchain.toml`; no
  CODEOWNERS, PR template, or issue templates.

### F-10 · Sandbox: honest about gaps, but the same-uid gap is the big one
- Implemented and composed: cgroup v2 kill-tree, descriptor closure with
  verification, Landlock fs (ABI 3) + TCP (ABI 4), seccomp socket-family
  filter, memfd prompt delivery, env allowlist.
- Not implemented: user namespaces / uid separation (workload runs as the
  supervisor's uid, so any same-uid process can read
  `/proc/<pid>/environ` and fd 0), rlimits/`cpu.max`, mount namespaces.
  Admission forces callers to pre-acknowledge the unenforced budgets —
  honest, but the uid gap deserves a scheduled fix, and the agents crate
  names its own TOCTOU gap (plan hashes the executable; the runner execs the
  path, not the hashed bytes).

### F-11 · Observability is a requirement with no exporter
- ~45 metrics are required "before rollout" by
  `requirements/verification-and-rollout.md`; the observability crate serves
  19 metric names over the local admin socket only. No exporter, no tracing,
  no dashboards, no runbooks. About half the crate's public API has no call
  site outside its own tests.

### F-12 · Generation handoff — the founding requirement — has no implementation
- Goal #1 and the primary requirement of the corpus (reload without killing
  work) has no `reload`/`rollback`/`generations` CLI verbs and no handoff
  code; meanwhile the self-improvement path deploys by service restart
  (see F-02). Increment 7 depends on this.

---

## S3 — Hygiene and drift

### F-13 · Stale pins, stale fixtures, dead state
- `spikes/provider-surfaces/` is load-bearing product state (digest-pinned
  in `automonique-lab`), but the capture is stale: `provider_inventory.py
  verify` fails with 8 drifted artifacts; re-capturing requires updating the
  pinned digest.
- One red test in tools/ (`tools/identifiers/test_inventory.py:326`, stale
  fixture after the 2026-08-12 `AGENTS.md` rewrite).
- Crate doc drift: the daemon and all three connectors under-describe their
  own method sets; a dead `Unavailable::GitHubManagementWiring` variant.
- `Result<_, String>` in 107 places (concentrated in
  `daemon/src/github_actions.rs`) against a codebase of 136 typed error
  enums; four crates hand-copy the workspace lint block; `sha2` pinned in
  three places.
- Local environment: 16 stale git worktrees (106 MB) under `.claude/`,
  71 GB `rust/target`, orphaned `__pycache__` in `spikes/recovery/`.

### F-14 · Underused assets worth either adopting or archiving
- `spikes/recovery/anonymous_*` (~133 KB sealed-execution design, absent
  from its own README); the backup-ordering rules exist only there.
- `@automonique/lab` TS package: 29 passing tests run by nothing; the
  Rust↔TS interop test is double-gated behind env vars nothing sets.
- `tools/identifiers/inventory.py` and `tools/parity/ledger.py` are exactly
  the machinery for F-01 and F-03, tested and green, wired into nothing.
- `tools/build_chat_provider.sh` (newest tool in the tree) is referenced by
  nothing.
- The planned-vs-actual crate map has diverged (30 planned, 19 actual, 7
  unplanned); the TUI — the most detailed requirements doc — has no crate;
  the SDK has 2 of 12 planned packages.

---

## What is genuinely strong (keep doing this)

- **The durable core.** Three epoch-fenced leases, transactional outbox,
  "an expired lease is an ambiguity, not a free slot", reconcile-only
  closure of ambiguous effects, ladder-replayed migrations, STRICT tables,
  16 isolated databases, single-writer discipline with zero in-process
  locking.
- **The sandbox composition path** and its unsafe-free fork/exec via a
  separate single-threaded entry helper; refusal-first APIs everywhere.
- **Code hygiene:** zero production `unwrap`, zero `unsafe`, 136 typed error
  enums with stable categories, lockfile byte-reproducibility in CI.
- **Candid documentation** of residual attack surface — most findings above
  were discovered *from* the code's own prose, which is the mark of a
  trustworthy codebase.
