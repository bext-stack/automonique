# M1 — Disclosure closure & truth reconciliation (implementation plan)

Status: implementation plan for milestone M1 (GitHub issues #4–#9), grounded in the
tree at `c2f8b16`. Every file:line below was verified against that revision, and the
two anchor measurements were re-run live: `python3 plan/check.py --verify` exits 1
with exactly **69 identifier-location FAILs** across 10 files, and
`python3 .github/identity/check_identity.py` exits 1 with exactly the **7 unsupported
identity claims** issue #9 describes. Naming follows the corpus's neutral-term rule —
"the legacy bot name", "the client tenant", "the client hostnames" — identifiers are
cited by file and line, never repeated here.

## Recommended order

1. **Day 0 — two owner decisions, before any code:** visibility-while-red (#5 —
   flipping the repository private is the only mitigation that works today) and the
   connector-licence option (#8). Neither blocks on engineering.
2. **#4 first and alone.** It is the S0 bleed; every push widens it, and both #5's
   fingerprint provisioning (`tools/scrub/provision.py` refuses while values are in
   the tracked tree) and the truth statements in #6/#7 build on the scrubbed tree.
3. **#6, #8-engineering, #9 in parallel with #4.** Disjoint surfaces (status docs /
   licence docs + checker / identity register + workflow). Collisions to sequence:
   `README.md` (#6 status section vs #8 licensing lines) and the daemon crate doc
   comment (#6 lands after #4).
4. **#5's scanner and workflow code in parallel;** protected-rule activation strictly
   after #4 merges and the owner provisions. The `plan/check.py --identifiers` CI step
   can turn on the moment #4 takes the 69 FAILs to 0.
5. **#7 last.** It is the milestone's record of the final truthful state and should be
   the last editor of `plan/gates.md`, after #5 wires scrub CI and #9 makes
   `identity.yml` real.

Critical path: decisions → #4 → provisioning (#5 activation) → #7. Everything else is
width, not length; roughly two weeks with one implementer per lane.

### Issue #4 — Scrub private client identifiers from source, docs, and UI strings

**Current state.** `plan/check.py --verify` reports 69 identifier-location FAILs in 10
files: 13 in `rust/crates/automonique-daemon/src/slack.rs`, 9 in
`rust/crates/automonique-daemon/src/telegram_bridge.rs`, 17 in
`rust/crates/automonique-daemon/tests/telegram_control.rs`, 16 in
`rust/crates/automonique-store/src/bin/automonique-memory.rs`, 5 in
`rust/crates/automonique-transport-runtime/src/telegram_control.rs`, 5 across the
support-connector sources, and 4 across `docs/memory-operations.md` /
`docs/slack-monique-rollout.md`. On top of that (the location rule only fingerprints
the legacy bot name), client identifiers appear at: `slack.rs:1471` (real
management-console URL in a Block Kit button), `slack.rs:1968,2022,2503,2526` (client
tenant fallback literals), `telegram_bridge.rs:158` (`MEMORY_TENANT` constant),
`site_inventory.rs:32` (client-named profile-app constant, sent as `x-bext-app-id` at
`:105`), the support-connector crate doc (`lib.rs:3`), store tests
(`agent_memory.rs`, ~22 sites; `tests/agent_memory_cli.rs`, 7 sites), and real
agency-org/client-repo GitHub URLs in daemon test fixtures
(`tests/telegram_control.rs:1745`).

**Approach.** Three mechanisms, matched to how each identifier is used.

1. *Deployment values become configuration*, following the daemon's established
   strict key=value loaders (`slack/slack.conf` at `slack.rs:111`,
   `support/fleet.conf` at `ticket_intake.rs:94`, `telegram/bot.conf` at
   `telegram.rs:116`):
   - New optional `manage/manage.conf` (loader modeled on `FleetConfig::load`,
     `ticket_intake.rs:264`) with `url=` — replacing the hardcoded console URL at
     `slack.rs:1471`; absent file ⇒ the "Open Manage" button is omitted — and
     `profile_app=`, replacing `MANAGE_PROFILE_APP` at `site_inventory.rs:32`;
     absent ⇒ `manage_profiles` returns its existing typed-unavailable refusal.
   - New `memory/memory.conf` with `tenant=`, replacing the constant at
     `telegram_bridge.rs:158` and the four fallbacks at
     `slack.rs:1968,2022,2503,2526`. Neutral default `"primary"` when absent; the
     production operator sets the real tenant privately so existing memory-DB rows
     (keyed by tenant) stay addressable — no migration.
2. *User-facing strings adopt the product identity.* The ~17 message strings using
   the legacy bot name (`slack.rs:2144,2167,2181,2222,2243`;
   `telegram_bridge.rs:2311,2374,2389,2447,2536,2548,2568,2575,2584,2591,2597,2608`)
   switch to "Monique", which is scrub-allowlisted and already used by the sibling
   fallback string at `slack.rs:1461-1464`. Doc comments naming the legacy bot or the
   Support-backend product go neutral: `telegram_bridge.rs:18,247,3347`;
   support-connector `lib.rs:3`, `request.rs:172`, `response.rs:153`,
   `client.rs:221`.
3. *Durable identifiers.* The memory CLI verb built on the legacy bot name
   (`automonique-memory.rs:75-183`, usage string at `:159`) is renamed to
   `backfill-legacy` (the `legacy*` prefix is retained-by-decision,
   `plan/gates.md:168`). The **wire idempotency prefix** at
   `telegram_bridge.rs:6855` (asserted at daemon `tests/telegram_control.rs:1431`,
   fixed in the connector fixture `request.rs:784`) must keep its exact bytes: move
   the literal into the name registry
   `rust/crates/automonique-protocol/src/compat.rs` — a sanctioned home per
   `plan/check.py:101-107` — and reference the constant from the daemon, so the wire
   contract is unchanged while the spelling leaves the daemon.

Test fixtures get neutral values: channel-label fixtures at
`slack.rs:3314,3330,3340` and `name(...)` sites at `slack.rs:3460-3766`; the
agency-org URLs at `tests/telegram_control.rs:1745` become placeholder org/repo;
transport-runtime `telegram_control.rs:1448,2611-2624` examples get a neutral channel
label; store tests get a neutral fixture tenant. The two loose docs:
`docs/memory-operations.md` (lines 33, 41, 46, 49, 63, 69 — verb rename, `<tenant>`
placeholder, neutral legacy-DB path) and `docs/slack-monique-rollout.md:16` (neutral
`channel=` example; the real channel label is operator configuration, not code).
`tools/identifiers/inventory.py` plus the 69-FAIL list enumerate completeness.
`plan/gates.md:170`'s legacy env-var mention is inside a sanctioned home and may stay.

Files touched: the daemon sources above plus new config modules;
`automonique-protocol/src/compat.rs`; the four support-connector files; the two store
files and their CLI test; the transport-runtime control module; the daemon
integration test; the two loose docs; a history-rewrite decision record under
`plan/owner-decisions/`.

**Testing.** `python3 plan/check.py --verify`: 69 FAILs → 0.
`python3 tools/scrub/scan.py` stays green. `cargo test --workspace` (3,298 tests)
green with updated fixtures. New unit tests for both config loaders in the existing
refusal-first style (absent file ⇒ `Ok(None)`; bad permissions, unknown key, invalid
value ⇒ typed error; button omitted when `url=` is absent). Final review step: a
tree-wide grep sweep for every F-01 value.

**Effort.** M (1–3 days).

**Dependencies.** None. Embedded owner decision: history rewriting — **nine**
commits on `main` carry an identifier in their message, not two (measured at
`c2f8b16`). Two are in the *subject* (`7216c35` — which also carries a second client
hostname that appears nowhere in the tracked tree; `e4f4fd8`), and seven more are in
the *body* (`13b9aee`, `050c722`, `0c8115f`, `1552f82`, `d49e8da`, `817da48`,
`550265b`). `scan.py:259` splits the commit object at the first blank line and scans
everything after it, so bodies are findings exactly like subjects. Forward-only
fixing leaves all nine reachable, and the publication scrub scans all reachable
commit messages and historical blobs (`tools/scrub/scan.py:252-277`), so the
full-history job can never go green without a rewrite or an accepted-findings
mechanism. A nine-commit rewrite spanning the Slack/Support/ticket-intake series is
materially more disruptive than a two-commit one — it invalidates every fork, PR and
local clone — so size the decision against nine. Record it either way. Sharp edges: the idempotency-prefix move
must be byte-exact or previously-sent support emails could repeat on re-poll; the
tenant default must never silently re-key an existing production database (release
note: set `tenant=` before upgrading).

### Issue #5 — Run the publication scrub on every push; decide visibility while red

**Current state.** The `publication-scrub` job only runs on manual dispatch
(`.github/workflows/scrub.yml:35`) with the two `scrub-publication` environment
secrets; the development scrub carries only the four public synthetic rules, so it
cannot catch the F-01 identifiers (`tools/scrub/scan.py:35-45` says so on every run).
Zero protected rules are installed (`plan/gates.md:141`). `provision.py` refuses to
fingerprint values still present in the tracked tree (`provision.py:130-142,177-182`).

**Owner decision — visibility while red.** Options: (a) flip the repository private
until #4 lands and protected rules are provisioned; (b) stay public and accept the
exposure window with #4 expedited. **Recommendation: (a)** — it is the only
mitigation that works *today*, costs nothing, and is reversible the day the scrub is
green. Record the decision under `plan/owner-decisions/` and reference it from
`plan/gates.md` § GATE-SCRUB either way.

**Approach.** Three changes plus a provisioning runbook.

1. *Workflow.* Keep `publication-scrub` (dispatch-only) as the full-history
   publication credential. Add a `protected-push-scrub` job on `push`/`pull_request`
   that also declares `environment: scrub-publication` and runs
   `scan.py --require-protected --scope tree`, plus a commit-message scan over the
   push range. Gate the protected step on secret availability (fork PRs and the
   pre-provisioning window have none; `--require-protected` without secrets exits 2,
   `scan.py:204-206`): when absent, run development mode and emit a loud
   `::warning::`, so CI hardens automatically the moment the owner provisions.
2. *Scanner.* Add `--scope tree|full` to `scan.py` (tree = tracked blobs + path
   names, skipping `historical_blobs`/`commit_messages`; full = today's behavior)
   and an optional `--commits <range>`. Bump the rule schema to v2 with an optional
   per-rule `homes: [paths]` list suppressing file-content findings in named
   sanctioned files. That last part is load-bearing: the legacy bot name legitimately
   lives in `docs/product-plan/reference/legacy-inventory.md` (the location rule,
   `plan/gates.md:177-186`), and `parse_rules` requires all four families
   (`scan.py:27-34`), so a location-blind `legacy-name` rule would be red forever.
   Per-rule homes mirror `plan/check.py`'s `LEGACY_IDENTIFIER_HOMES` and make
   GATE-SCRUB's second closing condition actually closable. `provision.py` gains
   matching `@home` annotations in the values-file grammar (`provision.py:61-103`)
   and emits `homes` in the bundle.
3. *Development-scrub extension.* The bot-name-outside-its-homes check already
   exists as `check_legacy_identifier_location` (`plan/check.py:229`) with a public
   fingerprint: give `check.py` a narrow `--identifiers` flag and run it in the
   development-scrub job on every push — no secrets needed. Client/third-party names
   are covered by the protected HMAC rules.

*Provisioning step (owner, after #4 merges):* write the private values file —
`legacy-name:` the bot name with homes annotations; `third-party-product:` the client
tenant, the two client hostnames (see `slack.rs:1471` and commit `7216c35`), the
profile-app id (`site_inventory.rs:32`), the agency org from the test fixtures;
`internal-product:` / `environment-name:` the pass-2 values from
`docs/product-plan/README.md`'s sanitization table — then
`python3 tools/scrub/provision.py --values <file> --dry-run`, then `--upload`.

**Testing.** `python3 -m unittest discover -s tools/scrub` extended: tree scope skips
history; `--commits` range scanning; schema-v2 homes suppression and rejection of
malformed homes; provision homes grammar. After provisioning, GATE-SCRUB closing
condition 4 (`plan/gates.md:132`) is re-proven with a deliberate synthetic
reintroduction that CI rejects. One rehearsal `workflow_dispatch` run of the
full-history job — expected red on the nine historical commit messages (see #4) and
on every prior revision of the ~11 affected files, which are still reachable blobs;
that redness is the honest record for the history decision in #4. Budget for it: a
full-history scan of this repository measures **98 s** wall clock today (1,638 blobs,
202 commit messages, 4 rules), and `scan.py:296-318` hashes every byte offset once
per distinct `(algorithm, length)` group — so cost scales with the number of distinct
*rule lengths*, and a four-family protected bundle plausibly takes it to 4–5 minutes.
That is affordable for a dispatch-only job and is the main argument for the
`--scope tree` push job proposed above.

**Effort.** M (1–3 days of engineering; owner provisioning is minutes).

**Dependencies.** #4 for activation only (`provision.py` refuses live values); all
code and workflow changes can land first. Hazards: the `scrub-publication`
environment must not gain required-reviewer protection rules or every push job
hangs (alternative: mirror the two secrets at repository level for the push job);
never fingerprint values deliberately retained in sanctioned files without homes
annotations (e.g. the legacy DB override documented at `plan/gates.md:170`), or the
scan is unfixably red.

### Issue #6 — Reconcile status documents with the running system

**Current state.** `README.md:10-36` still claims "Provider execution and transport
networking are not connected yet";
`docs/product-plan/execution-unlock.md:3` says "awaiting owner decision. Nothing in
this document has been acted on"; the daemon crate doc
(`rust/crates/automonique-daemon/src/lib.rs:1-12`) claims "deliberately performs no
external effects yet". Meanwhile the tree ships the Slack bridge (`slack.rs`), the
Telegram bridge and operator commands, GitHub actions (`github_actions.rs`), Support
ticket intake/drafting (`ticket_intake.rs`, `ticket_work.rs`), the egress broker
(commit `7974128`), a real contained provider run (commit `34dc56d`), and the
self-improvement worker. Connector docs undercount their own methods: the Slack
connector claims six while `client.rs:167-272` has nine (`auth_test`,
`conversations_list`/`info`/`history`, `users_info`, `post_message`,
`update_message`, `open_view`, `publish_view`); the support connector's prose lists
five actions against eight `WireAction` variants (`request.rs:43-52`); the GitHub
connector claims thirteen operations against 18 public functions in `client.rs`.

**Approach.** Rewrite README's "Repository status" against the actual daemon, using
the audit's per-subsystem inventory as source text. Amend `execution-unlock.md` by
*appending* a dated Decision record section (not rewriting the brief), recording per
gate what opened, when, evidenced by which commits (Gate C: `9b0cbfb`;
egress/Increment 2: `7974128`, `6702b43`; live provider: `34dc56d`; Slack outbound:
`d49e8da`, `550265b`) and under what authority — where no written authority exists,
record exactly that, for the owner to countersign. Replace the daemon crate doc
comment with a truthful effects list (also check `lib.rs:231`); recount and
enumerate the three connector doc comments. Add the drift ritual: a "Status
reconciled at `<commit>`, `<date>`" stamp line in the README status section plus a
`CONTRIBUTING.md` checklist item ("a PR that adds or enables an external surface
updates the status section in the same PR").

**Testing.** `cargo test --workspace` and clean `cargo doc` (Rust changes are
doc-comment only). Acceptance is a review artifact: every rewritten claim is checked
against a named module or commit. The reconciliation stamp gives future audits a
diffable anchor.

**Effort.** M (1–3 days, low end).

**Dependencies.** None; coordinate `README.md` edits with #8 and land the daemon
doc-comment change after #4 (same lines). The "gates opened without a written
decision record" sentence needs owner sign-off — it is retroactive authority
bookkeeping, not just doc hygiene. Do not upgrade claims while fixing them: several
lanes really are read-only or refusal-wired (`lib.rs:639-663` is honest today).

### Issue #7 — Repair the authority stack; fold shipped subsystems into the corpus

**Current state.** The precedence table (`docs/product-plan/README.md:9-19`) still
places `plan/gates.md` and the work graph at blocking layers 2–3, while
`AGENTS.md:7-10` and `GOVERNANCE.md:24-27` dissolved them into planning history.
Three shipped subsystems live in loose docs with no requirements coverage:
`docs/memory-operations.md`, `docs/slack-monique-rollout.md`,
`docs/self-improvement-workflow.md`. Stale gate claims: GATE-BASELINE's closing
evidence asserts "`plan/check.py --verify` exits zero in CI on every push"
(`plan/gates.md:37`) — no workflow runs it (`plan.yml` is licence-only) and it exits
1 today; GATE-IDENTITY cites a workflow `identity.yml` that does not exist
(`plan/gates.md:75-76`).

**Approach.** Rewrite the precedence table to match the governance that holds: layer
1 unchanged; `plan/gates.md` and the graph out of the blocking order, with gates.md's
real remaining role — capability-claim evidence, per its own header
(`plan/gates.md:3-11`) — kept as an explicitly non-blocking row or footnote;
requirements move up accordingly. Fold the three subsystems: durable memory + CLI →
normative section amended into `requirements/context-memory-and-learning.md`, with
`docs/memory-operations.md` demoted to operator how-to citing it; Slack v2 rollout
config → `requirements/channel-integrations.md` amendment citing
`docs/slack-monique-rollout.md`; self-improvement → a pointer section in
`requirements/self-hosting-and-bootstrap.md` that names the workflow doc and
explicitly records the SH0–SH6 / harness-requirements conflict as an *open
deviation* resolved by M4 (roadmap item 24) — folding gives it a specification home
now without pre-empting that owner decision. Clear the stale gate claims:
GATE-BASELINE's evidence amended to the current truth (runs on demand; wired per
#5's `--identifiers` step); GATE-IDENTITY's citation becomes true via #9 —
reference, don't duplicate.

**Testing.** `python3 tools/identifiers/inventory.py verify` must stay green after
corpus edits (its regions parse specific product-plan sections; if a parsed region
changes, regenerate `plan/inventory/identifiers.json` and commit both).
`python3 plan/check.py --verify` stays at 0 FAILs; `python3 tools/scrub/scan.py`
green. Manual check that each loose doc is reachable from exactly one corpus home.

**Effort.** M (1–3 days).

**Dependencies.** #9 (GATE-IDENTITY wording should describe a workflow that exists)
and #5 (GATE-BASELINE wording should describe CI wiring that exists). Drafting can
start immediately; land last. Note: no formal per-file amendment scheme exists in the
tree (verified — no `transferred_sha256`/`amended_per` anywhere), so amendments carry
a dated "amended" note in-file to preserve the transfer-provenance story; inventing a
heavier scheme is out of scope. Do not resolve the self-improvement policy conflict
here — record it.

### Issue #8 — Resolve the Apache-2.0 connector boundary

**Current state.** `README.md:41-42` and `:286-287`, `LICENSE-POLICY.md:25-26`,
`AGENTS.md:81-82`, `plan/gates.md:286-287` (GATE-LICENCE), and `APACHE_ROOTS` at
`tools/check_licenses.py:33` all assert `connectors/` and `integrations/` as
Apache-2.0 roots. Neither directory exists; the real connectors shipped as
Elastic-2.0 crates under `rust/crates/`.

**Owner decision — three options.**

1. *Move* the three connector crates under a `connectors/` root and relicense
   Apache-2.0 — but `LICENSE-POLICY.md:36-39` itself says a move never relicenses
   implicitly and crossing the boundary requires explicit owner review; this is a
   deliberate relicensing of shipped Elastic code plus workspace churn.
2. *Keep Elastic-2.0 and re-document* — remove the phantom roots everywhere and make
   the checker match.
3. *Split* — thin Apache-2.0 client libraries plus Elastic-2.0 daemon wiring; real
   architecture work.

**Recommendation: option 2.** The connectors are not neutral client libraries — the
support connector is deliberately target-locked to the Support backend's wire
protocol (`rust/crates/automonique-support-connector/src/lib.rs:11-15`) and all three
are consumed only by the daemon; the repository's licence authority is Elastic-2.0
throughout. Option 3 can be revisited if an SDK consumer ever materializes.

**Approach (option-2 shape).** Record the decision under `plan/owner-decisions/`,
then make every surface agree: `LICENSE-POLICY.md:25-26` (drop the two roots, keep
`sdk/`), `README.md:41-42` and `:286-287`, `AGENTS.md:81-82`, GATE-LICENCE's quoted
boundary, and `APACHE_ROOTS` → `{"sdk"}` at `tools/check_licenses.py:33`. Add a
checker guard asserting every declared Apache root exists on disk, so a phantom root
fails instead of silently gating nothing. Sweep the remaining root docs
(`COMMERCIAL.md`, `NOTICE`) for the same phrase.

**Testing.** `python3 tools/check_licenses.py` green;
`python3 -m unittest tools.test_check_licenses` extended with the no-phantom-roots
negative control and an updated boundary fixture.

**Effort.** S (<1 day) under option 2; options 1/3 become M–L (crate moves,
workspace member paths, SPDX rewrites, explicit relicensing review).

**Dependencies.** None; the owner decision is the critical path. Textual conflicts
with #6 (`README.md`) and #7 (`plan/gates.md`, `AGENTS.md`) — sequence the merges.

### Issue #9 — Reconcile the identity register and wire the identity checker

**Current state.** `python3 .github/identity/check_identity.py` exits 1 with 7
unsupported claims: the three GitHub-UI merge commits (`c2f8b167`, `d0fafcfe`,
`da6633b2`) have an unregistered author (the owner's agency-named identity), an
unregistered committer (`GitHub <noreply@github.com>`), and web-flow GPG signatures
while every registered identity declares `signing = "none"` (verified live: `%G?` =
`E`, key absent from the local keyring). No `identity.yml` workflow exists, though
`plan/gates.md:75-76` cites one. `historical_exception` cannot cover the merges:
exceptions must be ancestors of `rule_effective_commit`
(`.github/identity/register.toml:53-58`) and the merges postdate it.

**Approach.** Register what Git records. Add two identities to `register.toml`: the
owner identity (author of the merges) and the web-flow committer, with
`signing = "gpg"` and the GitHub web-flow key fingerprint; set
`signing_effective_commit` to the full SHA of `da6633b` (the first signed merge).
Create `.github/workflows/identity.yml` (name: `identity`; push + PR + dispatch)
that runs `python3 -m unittest discover -s .github/identity` and
`python3 .github/identity/check_identity.py`, with
`actions/checkout@v4` at `fetch-depth: 0` — `read_commits`
(`check_identity.py:351-353`) walks all of `git log HEAD`, so a shallow clone makes
the check measure nothing. No GPG keyring import is needed (see Dependencies). This
makes GATE-IDENTITY's workflow citation true, and is also the prerequisite for step 3
of the owner checklist (`plan/gates.md:109`), which requires the `plan`, `rust`,
`scrub` **and `identity`** checks to be nameable as required status checks. The email question is the owner decision the
issue names: registering the owner identity puts their business email into a source
file, which `AGENTS.md:55-58` ("personal email addresses in source files") arguably
forbids. Recommended resolution: a one-line `AGENTS.md` clarification naming
`.github/identity/register.toml` as the single sanctioned home for registered
commit-identity metadata (the same one-sanctioned-home pattern as the legacy
inventory), since the address is already public in every commit header; the
alternative — checker matching on a SHA-256 digest of the email — is more code for no
real concealment.

**Testing.** `python3 .github/identity/check_identity.py` exits 0 locally (web-flow
key imported) and in the new workflow on `main`;
`python3 -m unittest discover -s .github/identity` green. Negative rehearsal: a
register entry with a wrong fingerprint or a premature `signing_effective_commit` is
still refused.

**Effort.** S (<1 day) once the email decision is made.

**Dependencies.** None. Sharp edges — both resolved by reading the checker, so no
checker change is needed:

- *Roles are exclusive and exhaustive, so adding identities forces a
  redistribution.* `check_roles` (`check_identity.py:283-290`) refuses a role held by
  two identities **and** a role held by none, while `check_identity_entry`
  (`:221`) requires every identity to hold at least one. `candidate` currently holds
  all five (`register.toml:44`), so the edit is not additive: e.g. `candidate` keeps
  `implementer`/`reviewer`/`fixer`, the owner identity takes `merger`, and the
  web-flow identity takes `builder` (truthful — GitHub Actions runs every build and
  test check).
- *No keyring import is required in CI.* `check_signing` selects the commits that
  must verify by **author**, not committer (`check_identity.py:487`:
  `c["author"] in signers`). The merges are authored by the owner (a `signing =
  "none"` identity) and only *committed* by web-flow, so `required` is empty and
  `git verify-commit` is never invoked. Registering any signer at all also retires
  the seventh failure, because the "signed under `signing = "none"`" refusal only
  runs when the register has no signer (`:464-473`). Dropping the
  `https://github.com/web-flow.gpg` fetch removes a network dependency — and a
  security check that passes only because CI fetched a key at runtime is a weak
  link worth not building.
`separation_claimed` stays `false`: the external half (branch protection,
rejected-push transcript, `plan/gates.md:105-114`) is untouched by this issue. Future
merges are covered as long as the owner merges via the GitHub UI; a local unsigned
merge by the owner identity after `signing_effective_commit` would go red — note this
in the workflow.

## Cross-cutting notes

- **Division of enforcement labor.** First-party legacy names are governed by the
  *location* rule (`plan/check.py:229`, public fingerprint, sanctioned homes at
  `plan/check.py:101-107`); client/third-party names are never permitted anywhere
  (`plan/gates.md:184-186`) and are governed by the *protected HMAC scrub rules*.
  #4 fixes the violations, #5 wires both enforcers into every push. Keeping the two
  mechanisms distinct is what lets the sanctioned inventory file keep existing.
- **#4's acceptance signal is guarded by a self-test that currently proves nothing.**
  `plan/selftest.py` exists so that "a checker that has never failed is
  indistinguishable from a checker that cannot fail" — but it exits non-zero on its
  own *baseline* control, with the two anti-vacuity failures from
  `plan/check.py:291-298`. The cause is `scratch()` (`plan/selftest.py:29-37`): it
  copies only `plan/` and `docs/product-plan/reference/work-breakdown.md`, so the
  scratch tree contains neither `reference/legacy-inventory.md` (which the identifier
  rule must still match inside) nor
  `rust/crates/automonique-protocol/src/compat/generated.rs` (which the alias rule
  must still find a spelling in). Because the baseline already fails, all 13 mutation
  cases pass vacuously — including the ones guarding the very rule #4 is measured by.
  The fix is two lines in `scratch()`. The roadmap files this as M5 item 31; pull it
  into #4, otherwise "69 FAILs → 0" is produced by a checker whose self-test is inert.
- **Do not fingerprint a third-party name in a public file.** Both public fingerprint
  mechanisms (`tools/scrub/synthetic-rules.json` and `plan/check.py:112-118`) are
  plain `sha256` of a short lowercase word committed to a public repository — for
  names of this length, a dictionary lookup. Adding the client identifiers there
  would publish them in a slightly harder form. Value-based detection for the
  third-party class belongs entirely to #5's protected HMAC bundle; the public tree
  gets the location rule and shape-based rules only.
- **History is the residual exposure.** Forward-only scrubbing (#4) plus push-scoped
  scanning (#5) makes new pushes safe, but all **nine** identifier-carrying commit
  messages (#4) and every prior revision of the ~11 affected files stay reachable;
  the full-history publication job stays honestly red until the owner decides on a
  rewrite. GATE-SCRUB should be read accordingly.
- **`plan/gates.md` has three editors in this milestone** (#5 GATE-SCRUB reference,
  #7 GATE-BASELINE/GATE-IDENTITY text, #8 GATE-LICENCE quote). #7 goes last and owns
  the final state.
- **`README.md` has two editors** (#6 status section, #8 licensing lines) — different
  sections, sequenced merges.
- **Owner-decision inventory for the whole milestone:** visibility-while-red (#5),
  connector-licence option (#8), history rewrite (#4), gate-opening authority
  countersign (#6), email-in-register rule (#9). All are recordable under
  `plan/owner-decisions/` in the existing dated-file convention.
- **No new runtime dependencies anywhere in M1.** All Rust changes are string,
  doc-comment, and config-loader work in the existing refusal-first style; all
  tooling changes are stdlib Python; the only new CI surface is one workflow file
  and two job definitions.
