# M5 — Test depth & CI hardening (implementation plan)

Implementation plan for GitHub issues #29–#35 (milestone "M5 — Test depth & CI
hardening"), addressing findings F-07 (no randomized testing on the
untrusted-input surface), F-08 (credential redaction and HTTP substrate in
triplicate), and F-09 (silent CI gaps and undeclared dependencies). Every claim
below was verified against the tree: the tools suite was run (454 tests,
37.06 s, exactly one failure), both plan verifiers were run (`plan/selftest.py`
exit 1; `plan/check.py --verify` exit 1 with 69 identifier-location FAILs), the
29 lab tests pass under bun 1.3.13, and every duplicated helper was located by
grep.

## Measurement corrections to the register

Six numbers in `audit-findings.md` / `roadmap.md` were re-measured and differ.
Where they differ, this plan uses the measurement.

| Register says | Measured | Why it matters |
|---|---|---|
| `plan/selftest.py` has "13 mutation cases" made vacuous | **12** cases, and they are *unreached* — the baseline returns before the loop | Changes #34 from a rewrite to a verified half-day fix |
| `check.py` fails on rotted fingerprints + a stale generated registry | Those two failures occur **only in the incomplete scratch tree**; both guards pass against the real tree | Prevents refreshing security-relevant rule data for a non-existent problem |
| "~45 identifier-location failures" | **69**, all one rule | Sizes M1 item 1 correctly |
| "six derived-artifact checkers" | **eight** green, ~0.75 s combined | Two more gates available for free |
| "ten `GAP:` sites" | **17** (16 + 1) | Sizes #31's conversion work |
| CI's gaps are JS-toolchain-shaped | Also: **CI runs zero of the 203 doctests**, ~30 of which are `compile_fail` security proofs | A one-line fix nobody had named |

A seventh: F-09 frames the JS problem as "CI installs no toolchain". The
repository pins **no TypeScript compiler anywhere**, so the typecheck half
runs against an ambient one (measured: 6.0.3 from a global npm cache) while
asserting exact compiler diagnostic text. Both this and the doctest gap belong
in F-09's text.

## Recommended order

1. **#32 first** (S, ~half a day): fixes the milestone's only red test and
   turns the 454-test tools suite plus six derived-artifact checkers into a CI
   floor everything else lands on.
2. **Track A — CI files:** #33 → #31 → #35. #33 and #31 both edit
   `.github/workflows/rust.yml`, so sequence them (single-sourced toolchain
   first, then the JS-toolchain job); #35 is independent but shares the
   `.github/` review context. #29's `fuzz.yml` joins this file family with no
   ordering constraint.
3. **Track B — Rust code:** #29 → #30. The protocol property suite is the
   safety net under #30's `bounded()` collapse and helper migrations; land
   #29's `tests/properties.rs` (or at least its canonical-JSON and framing
   properties) before #30 touches protocol internals. #30's six migration
   steps are individually revertible commits.
4. **Track C — governance:** #34 starts its rule-data repairs immediately
   (fingerprints, the generated-alias rule, the selftest scratch copy), but
   its identifier-location bulk is blocked on M1's scrub issue (#4) and its
   final repair-vs-archive wiring is an **[owner]** decision — raise that
   decision request early so it does not serialize the milestone's tail.

### Issue #29 — Property and fuzz testing on the protocol codecs

**Current state:** 3,298 workspace tests, all example-based; zero property
tests, zero fuzzing, no PRNG anywhere. `automonique-protocol` has zero
dependencies and zero dev-dependencies and hand-rolls all three codecs the
targets need: canonical JSON in `src/wire.rs` (`parse_canonical` at
`wire.rs:160`, `JsonValue::to_canonical_bytes` at `wire.rs:85`,
`Envelope::from_canonical_bytes` at `wire.rs:469`,
`from_canonical_bytes_admitted` at `wire.rs:517`), length-prefixed framing in
`src/codec.rs` (`encode_frame` at `codec.rs:287`, `decode_frame` at
`codec.rs:318`, `MAX_FRAME_BYTES` = 8 MiB), and SHA-256 in `src/digest.rs`
(369 lines; one-shot `digest`, incremental `update`/`finish`). Note the module
names are the reverse of intuition: `codec.rs` is framing/envelopes, `wire.rs`
is canonical JSON. Golden fixtures already exist at
`rust/crates/automonique-protocol/fixtures/wire-v1.json` (hex `fixtures`,
`generated_fixtures`, `enum_fixtures`, `frame_fixtures`) plus four sibling
fixture files. The platform-inbound parsers facing untrusted bytes are
`parse_telegram_updates` (`rust/crates/automonique-transports/src/lib.rs:353`)
and the `decode_*(bytes)` family
(`rust/crates/automonique-slack-connector/src/response.rs:239-391`).

**Approach:** Add `proptest` (exact-pinned, dev-dependency only — stays out of
the shipped 11-dep graph) plus `sha2.workspace` as a second dev-dep for
differential hashing. Property targets, in a new `tests/properties.rs`:

1. Canonical-JSON round-trip: for arbitrary bounded `JsonValue` trees,
   `parse_canonical(v.to_canonical_bytes()) == v` (decode∘encode = id).
2. Permutation invariance: an object built in any insertion order encodes
   byte-identically (the total-ordering property).
3. Strictness: mutate a canonical encoding (whitespace, reordered keys,
   alternate escapes, floats, leading zeros) and assert refusal with
   `NonCanonicalJson`/`MalformedJson`, never silent acceptance.
4. Never-panic on arbitrary bytes for `parse_canonical`, `decode_frame`,
   `Envelope::from_canonical_bytes`, and `from_canonical_bytes_admitted`.
5. Frame round-trip `decode_frame(encode_frame(p)) == p` for payloads up to
   `MAX_FRAME_BYTES`, plus truncated/oversized-prefix behaviour.
6. Differential SHA-256: the hand-rolled `digest.rs` equals RustCrypto `sha2`
   for arbitrary inputs and arbitrary incremental chunk splits.

Fuzz targets via `cargo-fuzz` in a new `rust/fuzz/` crate (own Cargo.toml,
excluded from the workspace so the 19-member workspace and the
lockfile-reproducibility CI step are untouched): `fuzz_decode_frame`,
`fuzz_parse_canonical`, `fuzz_envelope_decode`, `fuzz_telegram_updates`, and
`fuzz_slack_decode`. Corpora seed from `fixtures/wire-v1.json` via a small
extraction script writing into `rust/fuzz/corpus/<target>/` (checked in), and
for the connector targets from the inline JSON response fixtures in the
transports/slack test modules. New scheduled workflow
`.github/workflows/fuzz.yml` (weekly cron + `workflow_dispatch`): install
nightly, `cargo fuzz run <target> -- -max_total_time=300` per target, upload
crash artifacts; any panic found gets its input checked in under
`fuzz/regressions/` and replayed by a normal `#[test]`.

**Testing:** the deliverable is tests. The property suite runs inside the
existing `cargo test --workspace` CI step (case counts bounded — e.g. 256
default with a `PROPTEST_CASES` override — so runtime stays sane); a fuzz
corpus-replay smoke (`-runs=0`) can run per-PR, long fuzzing only on schedule.

**Effort:** L.

**Dependencies:** none. Land before #30 — the properties are the safety net
for #30's `bounded()` collapse and any refactor touching codec internals.
Risks: proptest pulls a transitive dev-dep tree (rand et al.) into
`Cargo.lock` — justify in the PR against the exact-pin convention (dev-only,
exact-pinned). cargo-fuzz needs nightly; keep it strictly inside the scheduled
job so the pinned 1.93.1 stable path never depends on it. Cap generated
payload sizes below `MAX_FRAME_BYTES` in properties or round-trip time will
dominate CI. Test code may use `expect()` like the existing suites (the
zero-unwrap rule is about production code).

### Issue #30 — Shared connector substrate: one credential redaction, one HTTP helper set

**Current state:** verified copy counts (all located by grep, test code
excluded): `scrub` ×3 — `automonique-github-connector/src/token.rs:104`,
`automonique-slack-connector/src/token.rs:168`,
`automonique-support-connector/src/token.rs:97` (note: it is a memory-zeroing
overwrite of a rendered header buffer, i.e. secret hygiene, not log
redaction); `map_ureq_error` ×6 — github `client.rs:638`, slack `client.rs:413`
and `connections.rs:337`, support `client.rs:342`, transport-runtime
`https_client.rs:994`, chat-provider `lib.rs:492`, all mapping onto the same
closed vocabulary {TimedOut, ResponseTooLarge, Unavailable} (chat-provider
collapses the last two into `Transport`); `read_bounded_body` ×5 — github
`client.rs:623`, slack `client.rs:398` and `connections.rs:326`, support
`client.rs:327`, transport-runtime `https_client.rs:983`, each with its own
per-crate MAX constant; `strict_json` ×5 — github `response.rs:628`, slack
`response.rs:682`, support `response.rs:654`, transports `lib.rs:481`, agents
`normalize.rs:286` (the last takes `&str` not `&[u8]`); `push_json_string` ×3 —
github `lib.rs:592`, support `lib.rs:333`, transport-runtime
`https_client.rs:924`; `split_scheme`/`split_port` ×3 — github `target.rs`,
slack `target.rs`, support `base.rs`. Inside the protocol crate, ~21
`fn bounded(value: &str, field: &'static str)` copies (one per module) share
one body shape and differ only in the per-module MAX constant and the error
enum constructed from `primitives::ValueError` (which already exists). Four
crates hand-copy the workspace lint block instead of inheriting:
`automonique-policy`, `automonique-protocol`, `automonique-runner`,
`automonique-sandbox` (blocks verbatim-identical to the workspace's). `sha2`
is pinned in three places: `rust/Cargo.toml:41` (workspace),
`automonique-sandbox/Cargo.toml:12`, `automonique-runner/Cargo.toml:15`.

**Approach:** new workspace crate `rust/crates/automonique-connector-substrate`
(Elastic-2.0 like its consumers; deps `serde`, `serde_json`, `ureq` — all
existing workspace pins, no new external deps). API surface:
`secret::scrub_rendered(String)`;
`json::push_json_string(&mut String, &str)`;
`json::strict_json(&[u8]) -> Result<serde_json::Value, StrictJsonError>` (the
`DeserializeSeed`-based duplicate-key / trailing-bytes / non-finite refuser);
`http::read_bounded_body(reader, max_bytes) -> Result<Vec<u8>, TransportFailure>`;
`http::map_ureq_error(ureq::Error) -> TransportFailure` with
`TransportFailure = {TimedOut, ResponseTooLarge, Unavailable}`;
`url::{split_scheme, split_port}`. Each consumer keeps its typed failure enum
and adds a `From<TransportFailure>` / mapping — no error-type flattening.
Migration order, one reviewable step each:

1. Crate + `scrub` into all three connectors (highest security value first).
2. `push_json_string` (github, support, transport-runtime).
3. `map_ureq_error` + `read_bounded_body` + `strict_json` across
   github / slack (two files) / support / transport-runtime / chat-provider;
   decide per-site whether `automonique-agents/src/normalize.rs:286` joins
   (harmonize the `&str` signature or leave with a comment).
4. `split_scheme`/`split_port`.
5. **Separately, inside the protocol crate** — which is zero-dependency and
   must NOT depend on the substrate: collapse the ~21 `bounded()` copies into
   one `primitives::bounded_value(value: &str, max_bytes: usize) ->
   Result<(), ValueError>`; each module keeps a 2-line wrapper mapping into
   its own error enum (most already have a `Field { field, error: ValueError }`
   variant; `schema.rs:732` collapses to `FieldInvalid` — preserve each
   module's exact error shape). This delivers the "~250 lines removed"
   acceptance line and should be its own commit/PR.
6. Lint inheritance: swap the four hand-copied lint blocks for
   `[lints] workspace = true`, and change `sha2 = "=0.10.9"` to
   `sha2.workspace = true` in `automonique-sandbox` and `automonique-runner`.

**Testing:** move the existing per-copy unit tests (each connector `token.rs`
has a `tests` mod with fixture secrets) into the substrate crate, keeping one
thin per-connector test proving the wiring. The whole workspace suite (3,298
tests) must stay green with zero behavioural diff — that is the acceptance.
Grep-proof in the PR:
`grep -rn "fn scrub\|fn map_ureq_error\|fn push_json_string" rust/crates --include=*.rs`
shows only the substrate. #29's property tests guard the `bounded()` collapse.

**Effort:** L.

**Dependencies:** #29 (ordering preference, not a hard block — protocol
properties before the protocol-internal collapse). Risks: (a) the M1
licence-boundary owner decision (Apache-2.0 `connectors/` roots, roadmap
item 5 / issue #8) could later move or relicense the connectors — an
Elastic-2.0 substrate under `rust/crates/` is correct today, but flag the
coupling in the PR so that decision can account for it; (b) `read_bounded_body`
limits differ per crate — take `max_bytes` as a parameter, never unify the
constants; (c) diff the five `strict_json` bodies before unifying — any
intentional divergence becomes a named parameter, not a silent change.

### Issue #31 — Pin the JS toolchain in CI; make cross-language GAPs fail loudly

**Current state:** `.github/workflows/rust.yml` installs only the Rust
toolchain, yet the protocol test suites shell out to bun/node/npx tsc:
`javascript_runtime()` probes `["bun", "node"]` (`tests/cross_language.rs:365`,
`tests/codegen.rs:38`) and a tsc helper runs `npx --offline tsc`
(`tests/codegen.rs:46`). When the toolchain is missing, sites print an
invisible `GAP:` note and pass. **Measured: 17 `GAP:` strings — 16 in
`codegen.rs`, 1 in `cross_language.rs`** — at `cross_language.rs:823` and
`codegen.rs:397, 423, 470, 484, 688, 1330, 2743, 4649, 6950, 6982, 9263,
9295, 12763, 12795`, plus one intentional regeneration-skip at
`codegen.rs:894` that must stay. Budget for all of them, not ten. The
`@automonique/lab` package's 29 tests pass under bun 1.3.13 in ~52 ms and are
run by nothing in CI; the Rust↔TS interop test is double-gated on
`AUTOMONIQUE_RUN_RUST_INTEROP=1` + `AUTOMONIQUE_LAB_BIN`
(`sdk/typescript/packages/lab/test/rust-interop.test.ts:13-14`, spawning
`automonique-lab serve-once` per request). Neither SDK package has a lockfile
or local `node_modules`, and no `typescript` dependency is declared anywhere
under `sdk/typescript/`.

**This is worse than "CI installs no toolchain".** Measured:
`npx --offline tsc --version` in `packages/protocol` resolves **TypeScript
6.0.3** from the developer's *global npm cache*. So the typecheck half does
not GAP out — it **runs against whichever compiler the ambient environment
happens to supply**, which differs between a developer's machine and the
runner image and can change under the repository with no commit. That is
load-bearing because the negative cases assert **exact compiler diagnostic
text**: `codegen.rs:438` `"is not assignable to type 'TurnId'"`, `:441`
`"Type 'TurnId' is not assignable to type 'SessionId'"`, `:445`
`"Property 'text' does not exist on type"`, `:449` `"is not assignable to
parameter of type 'never'"`. A TypeScript major bump can reword any of these
and flip a security-relevant conformance result. `VERDICT.md` compounds it by
recording the measurement as made under "the TypeScript compiler resolved
offline by `npx --offline tsc`" — a description naming no version, so the
record cannot be reproduced. `generated/VERDICT.md` constraint 4 says no schema
digest is embedded "because the crate has no hash implementation" — a stale
premise, since `src/digest.rs` now hand-rolls SHA-256; constraint 5 asks for a
CI zero-diff regeneration step. The regeneration switch is
`AUTOMONIQUE_PROTOCOL_REGENERATE` (`src/codegen.rs:752`).

**Approach:** three legs.

1. **Pin:** add `oven-sh/setup-bun@v2` with `bun-version: 1.3.13` (the version
   VERDICT.md measured) and `actions/setup-node@v4` with an exact LTS pin to
   `rust.yml`; pin `typescript` as an exact devDependency in both
   `sdk/typescript/packages/{protocol,lab}/package.json` with a committed
   `bun.lock` and a `bun install --frozen-lockfile` CI step, so
   `npx --offline tsc` resolves the local install instead of runner luck.
2. **Fail loudly:** one env var (e.g. `AUTOMONIQUE_REQUIRE_JS_TOOLCHAIN=1`)
   honoured at the two helper choke-points — `javascript_runtime()` and the
   tsc runner — so a missing runtime/tsc panics with the current GAP text
   instead of returning `None`. Routing through the two helpers converts all
   17 GAP sites except the intentional regeneration-skip at `codegen.rs:894`
   — check each one, since several (`codegen.rs:1330, 4649, 6950, 9263,
   12763`) sit at per-surface `tsc -p` calls that build their own `Command`
   rather than going through the shared helper at `codegen.rs:46`. Set the
   var in CI; locally the honest-GAP
   behaviour is preserved. Additionally emit a `::warning::`-prefixed line
   when unset so GAPs surface as annotations on any runner.
3. **Run the TS surface + digest:** new steps in `rust.yml`: `bun test ./test`
   in the lab package, `npm run typecheck` for both packages, and the interop
   test — `cargo build --offline --locked -p automonique-lab --bins`, then
   `AUTOMONIQUE_RUN_RUST_INTEROP=1
   AUTOMONIQUE_LAB_BIN=$PWD/rust/target/debug/automonique-lab bun test
   ./test/rust-interop.test.ts`. For the schema digest: in the
   `AUTOMONIQUE_PROTOCOL_REGENERATE`-gated writer, compute the digest of the
   canonical schema-description input with the crate's own `digest.rs` and
   emit `export const SCHEMA_DIGEST` into `generated/index.ts`; add a codegen
   test asserting checked-in digest == recomputed; update the VERDICT.md
   constraint-4 note. Add the constraint-5 zero-diff step: CI runs
   `AUTOMONIQUE_PROTOCOL_REGENERATE=1 cargo test -p automonique-protocol
   --test codegen` then `git diff --exit-code` over
   `sdk/typescript/packages/protocol/generated/`.

**Testing:** the acceptance is the negative control — a scratch-branch run
with node/bun absent (or the setup steps commented out) must fail loudly; the
interop suite's runtime appears in the job log as measured, not GAP'd; the
digest test goes red when generated files are stale. Two more: assert
`npx --offline tsc --version` prints the *pinned* version as a test rather
than a README line, so an ambient compiler can never be silently substituted
again; and on a scratch branch bump the pinned `typescript` a major version
and confirm the negative-case diagnostic assertions (`codegen.rs:438-449`)
are what break — if they do not, they were not measuring what they claim.

**Effort:** M.

**Dependencies:** none; coordinate the `rust.yml` edit with #33 (same file).
Risks: verify `npx --offline` against a bun-managed `node_modules` locally
before committing to the pattern (today it works via a global install the CI
runner will not have). Regenerating `generated/*` to add the digest is a real
diff to reviewed generated files — keep it as its own commit. Recommend
requiring bun (the measured runtime) rather than a node fallback in CI.

### Issue #32 — Run the tools test suite and derived-artifact checkers in CI

**Current state:** nothing in CI runs the tools suite; `plan.yml`'s only job
is the licence boundary. Verified: the suite runs **454 tests in ~37 s with
exactly one failure**. Note the invocation — `tools/` has no `__init__.py`,
so the obvious `python3 -m unittest discover -s tools -p 'test_*.py'` raises
`ImportError: Start directory is not importable` on Python 3.12, and
`discover -s . -p 'test_*.py'` from the repository root reports
`NO TESTS RAN` and **exits 0**. The working invocation is
`python3 -m unittest discover -s tools -t tools -p 'test_*.py'`; the CI step
should assert the reported test count, because a discovery line that silently
finds zero is exactly the failure mode that produced this gap. The one
failure is —
`tools/identifiers/test_inventory.py:313`
(`test_a_citation_outside_the_permitted_corpus_is_refused`) plants a
`Cited("automonique-lab", …, "AGENTS.md", …)` fixture expecting the "outside
the permitted corpus" refusal, but the 2026-08-12 AGENTS.md rewrite removed
the string, so the earlier "cited entry 'automonique-lab' no longer occurs in
AGENTS.md" refusal fires first (assertion fails at `test_inventory.py:326`).
**Eight** derived-artifact checkers were run individually and exit 0 today —
two more than the audit counted — totalling **~0.75 s**:
`tools/contract_inventory/check.py` (288 ms),
`tools/parity/ledger.py` (130 ms, prints findings but exits 0),
`tools/identifiers/inventory.py verify` (76 ms),
`tools/surface_inventory/verify.py` (65 ms),
`tools/capability_ledger.py` (58 ms),
`tools/guides.py` (57 ms),
`tools/oracle/check_boundary.py` (42 ms), and
`tools/runtime_topology.py --verify` (34 ms — note the bare invocation exits
2, `--verify` is required). A ninth,
`tools/provider_inventory.py verify --capture-date <date>`, is **red**
(8 drifted artifacts, `opencode/*.txt` missing, `claude` capture date
differing); that is F-13, owned by M7 item 41, which re-captures and re-pins
the digest — do not gate on it here.

**A gap the audit did not name: CI runs no doctests.** `rust.yml:33` is
`cargo test --workspace --all-targets`, and `--all-targets` **excludes
doctests**. Measured: **203 doctests, all passing, in ~1.1 s** on a warm
target — 104 + 85 in `automonique-protocol`, 8 + 4 in `automonique-runner`,
one each in `automonique-policy` and `automonique-store`. Roughly 30 are
`compile_fail` blocks, and those are the *only* executable proof of the
crate's type-level security properties: `primitives.rs:662-682` proves
`SecretText` has no `Display` and no field access, `primitives.rs:243-252`
proves one `OpaqueId` domain cannot be assigned to another, and `tools.rs`,
`workspace.rs` and `release_trust_root.rs` carry a dozen more. None has ever
run in CI; if one were broken — by a `Display` impl added in passing —
nothing would notice.

**Approach:** fix the red test first, or the first CI run is red for an
unrelated reason. Two ways, and the second is recommended:

- *Minimal:* plant a cited spelling that still occurs in today's `AGENTS.md`
  (only the bare token `automonique` survives the rewrite), so the
  corpus-membership check is reached. Cheap, and re-breaks the next time
  `AGENTS.md` is rewritten — which M1 items 3–4 will do.
- *Durable (recommended):* hoist the corpus-membership check for `cited.file`
  to before the `read()` at `inventory.py:1197`, or into `Cited`'s
  construction. `build()` checks *occurrence* first
  (`inventory.py:1196-1206`) and only reaches the corpus rule inside
  `record()` (`inventory.py:1140-1144`); a citation's *location* is a static
  property of the `CITED` table, so discovering it after reading the file is
  the wrong order regardless of the test. The existing message already
  contains both strings the test asserts, so **the test needs no edit at
  all** — which is the sign the fix is in the right place.

Then add a `tools-suite` job to `.github/workflows/plan.yml` (setup-python
3.12, matching the existing job): the discover line above, followed by the
eight checkers as separate named steps so a failure names its artifact. And
add one line to `rust.yml` after line 33 —
`cargo test --workspace --doc --offline --locked` — which costs ~1.1 s and
turns on 203 tests. Also capture the two
`automonique.harness-recovery-receipt/v1` JSON blobs `tools/test_harness_loop.py`
prints to stdout, so the CI log stays readable.

**Testing:** the suite is the test. Negative controls, one per gate:
hand-edit a derived artifact (e.g. `plan/inventory/identifiers.json`) on a
scratch branch and confirm the job goes red; revert the `inventory.py` fix
and confirm the tools job goes red; add a `Display` impl to `SecretText` and
confirm the doctest step goes red at `primitives.rs:662`. Record each new
job's measured wall time in the PR so a later CI-duration regression has a
baseline.

**Effort:** S.

**Dependencies:** none — this is the milestone's quick win; land first so
#30/#34 changes get tools-suite coverage. Note: M2's parity-tools issue
(roadmap item 12) also wires the parity ledger and identifier inventory into
CI as parity gates — this issue runs them as drift checks in `plan.yml`; note
the overlap in both PRs so M2 extends rather than duplicates.

### Issue #33 — Supply-chain gates: cargo-audit, rust-toolchain.toml, coverage

**Current state:** all 11 external dependencies are `=`-pinned in
`rust/Cargo.toml`, so advisories never arrive on their own, and nothing checks
them. No `rust-toolchain.toml` anywhere — the 1.93.1 pin lives inline in
`rust.yml`'s install step. No coverage measurement. `rust/Cargo.lock` carries
125 packages.

**Approach:**

1. `rust/rust-toolchain.toml` with `channel = "1.93.1"`,
   `profile = "minimal"`, `components = ["rustfmt", "clippy",
   "llvm-tools-preview"]`; simplify `rust.yml`'s install step to defer to the
   file so the pin is single-sourced.
2. Prefer `cargo-deny` over bare cargo-audit — this repo has a licence
   boundary worth machine-checking, and deny covers
   advisories+licenses+bans+sources in one config. Add `rust/deny.toml`
   (advisories deny; licences allowing Elastic-2.0 plus the 11 pins' licence
   set, in warn mode until the M1 connector-licence owner decision lands;
   bans warn initially) and a new `.github/workflows/audit.yml` running
   `cargo deny check` on a weekly cron, on `workflow_dispatch`, and on
   pushes/PRs touching `rust/Cargo.lock` or `rust/deny.toml` — under exact
   pins the cron is the only path an advisory ever surfaces on, which is the
   finding's point. Install the tool via a pinned prebuilt-binary action
   (e.g. `taiki-e/install-action` at an exact version/SHA) — never
   `cargo install` in CI.
3. Coverage: a job running `cargo llvm-cov --workspace --locked --offline
   --summary-only` plus an lcov artifact upload; report-only, no threshold —
   the floor is a later decision once the number is known.

**Testing:** negative controls — on a scratch branch, temporarily pin a
dependency version with a known RUSTSEC advisory and confirm
`cargo deny check advisories` fails; confirm `rustup show` in a clean checkout
resolves 1.93.1 from the file; confirm the coverage summary appears in the job
log.

**Effort:** M.

**Dependencies:** none; coordinate `rust.yml` edits with #31 (same file).
Risks: `rust-toolchain.toml` makes every tool invocation under `rust/`
auto-download 1.93.1 — intended, but worth noting for contributors. The
deny.toml licence policy must match `LICENSE-POLICY.md` and must not pre-empt
the unresolved M1 connector-licence decision. Instrumented coverage on this
workspace will be slow — keep it off the PR critical path (schedule or
non-required job) if it exceeds a few minutes.

### Issue #34 — Fix or retire the plan verifier

**Current state:** verified by running both scripts, and then by reproducing
and fixing the failure in a scratch copy. `plan/selftest.py` exits 1 at
`FAIL baseline: an unmodified copy does not pass` (`selftest.py:184-189`),
which returns **before the mutation loop starts** — so the cases are not
merely vacuous, they never execute. The ledger holds **12** cases
(`selftest.py:153-170`), not 13, plus a baseline control and a
working-tree-unchanged control.

**The root cause is a two-file omission in the test harness, not rot in the
verifier.** `scratch()` (`selftest.py:29-38`) builds the disposable tree from
exactly `plan/` plus `docs/product-plan/reference/work-breakdown.md`. Two
anti-vacuity guards in `check.py` read files outside that set:
`check.py:291-294` requires the legacy-identifier fingerprints to match
something inside `docs/product-plan/reference/legacy-inventory.md`, and
`check.py:295-298` requires
`rust/crates/automonique-protocol/src/compat/generated.rs` to contain at
least one generated `LEGACY_*` spelling. Neither file is copied, so both
guards fire — correctly, by their own logic, since a rule matching nothing
measures nothing.

**Both guards pass against the real tree.** Measured:
`python3 plan/check.py --verify` exits 1 with **69 FAIL lines that are all
the identifier-location rule** (`check.py:277-279`) and **zero** anti-vacuity
failures. The fingerprints at `check.py:112` have *not* rotted and
`compat/generated.rs` *does* generate a `LEGACY_*` spelling; those two
failures are an artifact of the incomplete scratch tree and appear nowhere
else. Do not re-fingerprint and do not regenerate the registry on this
evidence — that would be changing security-relevant rule data to fix a
problem that does not exist.

**The fix is verified.** Copying those two files into the scratch tree and
re-running produces `ok baseline: unmodified copy passes` followed by all 12
cases detected and `ok working tree unchanged`. So `check.py` detects every
drift it claims to, and has all along.

The 69 real failures span `daemon/tests/telegram_control.rs`,
`store/src/bin/automonique-memory.rs`,
`support-connector/src/{client,request,response}.rs` and
`transport-runtime/src/telegram_control.rs` — the F-01 occurrences M1's scrub
issue removes — alongside a wall of "done but never passed through the gate"
warnings. Seven live tools/ modules use `plan/` as their data store, so the
directory cannot simply be deleted.

**Owner options and recommendation:**

- **Repair** (recommended, matching the audit's lean — repair the data path,
  archive nothing yet): (1) fix `scratch()` (`selftest.py:29-38`) to copy
  `docs/product-plan/reference/legacy-inventory.md` and
  `rust/crates/automonique-protocol/src/compat/generated.rs`, with a comment
  naming `check.py:291-298` as the reason so a future reader knows the copies
  are load-bearing. This is the whole of the self-test repair and it is
  verified to work; **no fingerprint refresh and no registry regeneration is
  needed**, because both guards already pass against the real tree.
  (1b) add the two missing mutation cases — the identifier-location rules
  (`check.py:266-289`) are the only rules in `check.py` with no case in
  `CASES`, and they are the rules GATE-SCRUB and F-01 turn on: one case writes
  a fingerprinted identifier into a non-permitted file, one writes a
  hand-written `LEGACY_*` literal into shipped Rust, taking the ledger from 12
  to 14. (2) wire `python3 plan/selftest.py` into CI **immediately** — it runs
  against a scratch tree, so it is green today with fix (1) and is not blocked
  on M1; (3) after M1's scrub (issue #4) lands, re-run `check.py` — the remaining
  identifier-location failures are the "legitimate product code colliding
  with a GATE-SCRUB-era rule" class: extend the permitted-homes list
  (`plan/check.py:101`) deliberately, one line of justification per addition;
  (4) refresh the two stale `plan/gates.md` claims and note the
  completion-ledger stop (2026-08-12) — in particular `gates.md:37`, whose
  GATE-BASELINE closing evidence asserts "`python3 plan/check.py --verify`
  exits zero in CI on every push" when no workflow runs it and it does not
  exit zero; `gates.md:9-11` already says an unsupported assertion does not
  become true by the gate ceasing to be admission control, so the file's own
  rule dictates the fix; (5) wire `python3 plan/check.py --verify` into
  `plan.yml` last, as part of M1's scrub PR, when it goes green.
- **Archive** (if the owner prefers): move `check.py`, `selftest.py`,
  `test_gate.py` to `plan/attic/`, delete the stale gate claims in the same
  commit, and keep every data directory (`plan/inventory`, `ledgers`,
  `decisions`, `contracts`, `evidence`) that the seven tools/ modules and the
  six #32 checkers depend on.

**Testing:** `python3 plan/selftest.py` green is the deliverable — its 12
(soon 14) mutation cases become the regression suite for check.py itself once
the baseline passes; `python3 plan/check.py --verify` exit 0 on main; the #32
tools job stays green under either option.

**Effort:** S — half a day. The `scratch()` fix is ~30 minutes and already
proven; the two new mutation cases are ~2 hours; the CI wiring and the
`gates.md:37` correction are ~1 hour.

**Dependencies:** the self-test repair and its CI wiring are **not** blocked
on M1 — `selftest.py` runs against a scratch tree and is independent of the
69 real failures. Only step (3) and the `check.py --verify` CI wiring wait on
M1's scrub issue (#4). **[owner]** decision
repair-vs-archive before the final wiring commit. Risks: do not "fix"
check.py by loosening rules to match the tree — every permitted-home addition
is a deliberate exception with a reason. The fingerprints are digest-based
precisely so the legacy system's real name never appears in `check.py`; any
refresh must preserve that property (the name stays out of the public tree).

### Issue #35 — Repository furniture: CODEOWNERS, templates, dependabot

**Current state:** verified — `.github/` contains only `identity/` and
`workflows/`; no CODEOWNERS, no PR template, no issue templates, no
dependabot config. The improvement program alone carries six pending
owner decisions with no template to record them. Current workflows reference
actions by mutable tags (`@v4`/`@v5`).

**Approach:** add (1) `.github/CODEOWNERS` assigning the owner (the handle
recorded for the owner identity in `.github/identity/register.toml`) to
`docs/product-plan/` (the requirements corpus lives under it), the governance
set (`GOVERNANCE.md`, `AGENTS.md`, `LICENSE*`, `LICENSES/`, `NOTICE`,
`TRADEMARKS.md`, `LICENSE-POLICY.md`), `tools/oracle/`,
`rust/crates/automonique-sandbox/`, `rust/crates/automonique-runner/`, and
`.github/` itself; (2) `.github/pull_request_template.md` with the
affected-area checklist — licence boundary touched? (run
`tools/check_licenses.py`), scrub-sensitive strings touched? (development
scrub green, no legacy/client identifiers introduced), and a docs-truth line
(does README / execution-unlock still describe the system after this
change?); (3) `.github/ISSUE_TEMPLATE/`: `bug.yml`, `enhancement.yml`,
`owner-decision.yml` (fields: decision needed, options considered, chosen
option, provenance line — matching the corpus's amendment scheme), plus
`config.yml`; (4) `.github/dependabot.yml` for `github-actions`, weekly.

**Testing:** rendering check — open a draft issue/PR against a scratch branch
and confirm the forms render; dependabot config confirmed by its first weekly
run or a dry-run; CODEOWNERS syntax validated by GitHub on push.

**Effort:** S.

**Dependencies:** none. CODEOWNERS enforcement needs branch protection to mean
anything — protection rules are an owner/settings action outside the tree
(F-01 already records zero protected rules); say so in the PR rather than
pretending the file alone gates. Propose the pin-actions-to-SHA switch in the
same PR and let dependabot track the pins (cheap now, annoying later). All
templates are public-facing text: neutral terms only, and the owner-decision
template's description should warn against pasting private identifiers into
public issues.

## Cross-cutting notes

- **Workflow-file contention:** #31 and #33 both edit `rust.yml`; #32 edits
  `plan.yml`; #29 adds `fuzz.yml`; #33 adds `audit.yml`; #34 may later touch
  `plan.yml`. Sequence merges within Track A and rebase deliberately.
- **M1 couplings:** #34's identifier-location bulk is downstream of M1's
  scrub (issue #4); #30's substrate crate licensing touches the M1
  connector-licence owner decision (roadmap item 5) — Elastic-2.0 under
  `rust/crates/` is right today (the repo is Elastic-2.0-authoritative), but
  the coupling should be named in both PRs.
- **M2 coupling:** #32 runs the parity ledger and identifier inventory as
  drift checks; M2's roadmap item 12 wires the same tools as parity gates.
  Drift checks here, gates there — note the split in both PRs.
- **Conventions honoured throughout:** no async runtime introduced; all new
  dependencies are dev-only or CI-tool binaries, exact-pinned; typed error
  enums preserved (the substrate exposes small typed errors that consumers map
  into their own enums, never `Result<_, String>`); integration tests stay
  under `tests/`; the four hand-copied lint blocks are replaced by workspace
  inheritance as part of #30.
- **Hard rule:** every new file, template, corpus entry, and commit message in
  this milestone is public — the legacy bot's real name and client hostnames
  appear nowhere, and #34's fingerprint refresh must keep the digest-based
  indirection that keeps them out.
- **The doctest line deserves promotion out of #32.** One line in `rust.yml`,
  ~1.1 s, turns on 203 tests including ~30 `compile_fail` blocks that are the
  only executable proof of the crate's type-level secrecy and
  domain-separation properties. If M5 is descoped for any reason this should
  still ship — consider splitting it into its own trivial issue so it cannot
  be descoped by accident.
- **Preserve the three separate credential types through #30.**
  `github-connector/src/token.rs:1-12` states the reason they are not shared:
  "a connector should not be able to send another service's credential to
  GitHub by passing the wrong value of a shared type." Share the `scrub`
  mechanism; leave `GitHubToken` / `SlackToken` / `FleetToken` alone. A
  reviewer seeing three near-identical types after #30 should read that
  comment before proposing to merge them.
- **`automonique-protocol`'s zero-dependency posture is a stated design
  property, not an accident.** `digest.rs:5-8` explains SHA-256 is
  implemented in-crate specifically so the crate can declare no dependencies.
  #29's `proptest` dev-dependency does not change the shipped graph but does
  make that sentence false-as-written — amend it to say *shipped*
  dependencies in the same commit. (The same stale premise is what
  `VERDICT.md` constraint 4 gets wrong in the other direction.)
- **Anti-vacuity is this codebase's house style; every new gate should honour
  it.** `check.py:291-298` refuses to let a rule matching nothing report
  success; `selftest.py:4-9` exists to prove the checker can fail;
  `codegen.rs:117-120` uses an exhaustive `match` so a new refusal category
  cannot reach the generated surface untested;
  `run_spec_v1_mutations.rs:10-15` asserts every mutation string is unique
  before applying it. Every gate M5 adds ships with a demonstration that it
  can fail — which is why a negative control appears in every **Testing**
  section above.
- **CI wall-clock budget:** M5 adds roughly 37 s (tools) + 1 s (derived
  artifacts) + 1 s (doctests) + ~30 s (property suite) + a JS install/test
  job + `cargo-deny` + coverage (which roughly doubles compile time). Put
  coverage and `cargo-deny` in their own jobs so they run concurrently rather
  than extending the critical path, and record each job's measured duration
  in its PR.
- Nothing in M5 blocks M6–M8; the milestone is parallelizable behind M1 per
  the roadmap.
