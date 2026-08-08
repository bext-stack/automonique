# Migration and work breakdown
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded at genesis. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md` and `GENESIS.md`). GPL statements below remain historical.

Work is ordered by dependency, not date. Repository creation/publication and production identity changes remain explicit owner-approved external actions.

## Phase B0 — decisions and frozen evidence

- Record the exact legacy source commit and full reachable refs.
- Hash/archive the Automonique brand kit in protected project storage.
- Record the decided GitHub repository (`bext-stack/automonique`), code license (`GPL-3.0-or-later`), product site (`https://automonique.fr`) and founding sponsor (Inklura, `https://inklura.fr`); choose initial visibility, brand/trademark license, package/container namespaces and maintainers.
- Freeze a machine-readable inventory of every legacy name in code, history, environment, paths, services, protocols, messages, tests, external apps and documentation.
- Inventory all production state/credential paths without printing values.
- Declare which repository owns emergency production fixes during each later phase.
- Build a deterministic, secret-free stage-zero handoff containing the fixed decisions, complete plans, source/brand digests, first-agent prompt and offline tamper verifier; exclude application source, Git history, credentials, state and the brand archive.

**Exit:** decisions have named owners; evidence is reproducible; no repository or platform identity has changed.

## Phase B1 — candidate repository audits

- Build disposable sanitized-history and clean-import candidates.
- Run full-history secret/PII/customer/path/license/binary scans and manual review.
- Remove production data/defaults and replace examples with reserved synthetic values.
- Produce source attribution, dependency/license and old-to-new commit reports.
- Compare candidate size, history clarity, bisect value and residual disclosure risk.

**Exit:** owner approves one import candidate; every detected real credential is revoked; public-prohibited objects are unreachable.

## Phase B2 — private upstream baseline

- Create the private `bext-stack/automonique` repository without generated starter commits.
- Push the approved candidate and signed/import provenance.
- Add the `GPL-3.0-or-later` license/corresponding-source policy, separate brand terms, security policy, contribution/governance, code of conduct, changelog/versioning and privacy/telemetry docs.
- Configure branch rules, secret scanning, dependency review, provenance/SBOM, release environments and fork-safe CI.
- Import the brand kit into `brand/` with manifest, rights and accessibility evidence.
- Add canonical `automonique.fr` homepage metadata and a non-authoritative Inklura founding-sponsor acknowledgement.
- Add the reviewed bootstrap manifest/schema, fixed toolchain/dependency/build inputs, trusted-builder/signer public identities and clean-host SH0/recovery instructions.
- Add and test the initial `scripts/automonique-dev` plus finite seed program/coordinator; it must run from a clean private clone and cannot create/publish/merge/deploy the repository.

**Exit:** a clean clone builds/tests without production credentials or organization filesystem assumptions; repository remains private.

## Phase B3 — additive product identity

- Add centralized brand metadata/tokens/assets to dashboard, TUI, docs and channel renderers.
- Add canonical `AUTOMONIQUE_*` settings with conflict-detecting `LEGACY_*` fallback.
- Introduce canonical npm/Rust/binary names and generated legacy shims.
- Rename every internal Rust Cargo package/crate/module/feature, binary target, source directory, schema namespace, metric/tracing target, fixture and release/container coordinate from legacy to Automonique before public import; do not publish a parallel legacy crate family.
- Add canonical commands/help while retaining legacy aliases.
- Make fresh installs use Automonique paths/service; keep upgraded state on explicit resolved paths.
- Generate a compatibility manifest and deprecation events.

**Exit:** fresh Automonique install and legacy-name test matrix behave identically at durable boundaries; no state migration yet.

## Phase B4 — state, service and protocol migration

- Implement preview/apply name-migration plans for database/state/runtime paths and systemd units.
- Back up, checksum, migrate, start disconnected/read-only, reconcile, then acquire transports/outboxes.
- Add `automonique.*` protocol major only through expand/contract compatibility with adjacent releases.
- Prove `automoniquectl` and compatibility shims across reload/rollback.
- Prove only one service/unit owns each lease and external token before/after failure injection.

**Exit:** N -> Automonique -> N rollback preserves every input, approval, session, artifact, cursor and action receipt.

## Phase B5 — external identity migration

- Rename Slack app display, add `/automonique`, announce legacy command/channel window and reconcile messages/cards/buttons.
- Update Telegram display/about/commands without replacing stable bot/chat identity unless separately approved.
- Install new Teams/Discord apps under Automonique branding after their connector gates.
- Update GitHub, `automonique.fr`, sponsor, Support, Manage, deployment and documentation links/senders through reviewed configuration.
- Rotate credentials only when required; rotation is separate from display rename and has rollback.

**Exit:** every external surface resolves to the same tenant/actor/durable state; old interactions remain actionable where policy permits.

## Phase B6 — public-release gate

- Run clean-room build/test, full-history rescan, license/SBOM/provenance and documentation-link validation.
- Test self-hosted, disconnected-recovery and air-gapped profiles; verify cloud connector disclosures.
- Review brand claims against measured telemetry/data flows.
- Publish release candidate privately to deployment canaries.
- Require the candidate release to carry stable-build, candidate self-build and independent clean-build provenance/comparison plus self-host reload/rollback evidence.
- Obtain explicit owner/security/legal approval to change repository visibility.

**Exit:** public visibility is the only remaining mutation and has a signed review packet. If approval is withheld, private staging remains canonical without claiming public open source availability.

## Phase B7 — production and public cutover

- Publish signed Automonique release/package/container artifacts.
- Switch production through safe drain/reload with exact rollback release retained.
- Change canonical repository visibility/linking as approved.
- Make the new upstream canonical for all fixes/features.
- Freeze the old repository default branch and add private recovery/upstream guidance.

**Exit:** production and public artifacts point to the same source revision/provenance; rollback and security reporting work.

## Phase B8 — deprecation and retirement

- Measure legacy env/CLI/command/protocol use without collecting user content.
- Remove aliases only after their declared version/time window and rollback barrier.
- Archive—not delete—the old private repository when retention/incident owners approve.
- Publish final migration notes and long-term supported-version matrix.

**Exit:** completion definition in `README.md` passes and no undocumented legacy identifier remains in a supported public surface.

## Ordered implementation tickets

### Repository and governance

- **B0-01 Ownership/license/site/sponsor decision record:** `bext-stack/automonique`, `GPL-3.0-or-later`, `automonique.fr`, and Inklura/`inklura.fr`.
- **B0-02 Legacy source/brand-kit evidence manifest.**
- **B0-03 Complete identifier and external-surface inventory.**
- **B0-04 Portable bootstrap handoff:** deterministic plan archive, machine-readable decisions/source manifests, outer and inner checksums, exact first-agent prompt, exclusion scan and tamper test.
- **B1-01 Full-history secret/PII/customer scan with credential revocation workflow.**
- **B1-02 GPL compatibility plus dependency/code/asset/font license and provenance review.**
- **B1-03 Sanitized-history candidate and unreachable-object verification.**
- **B1-04 Clean-import candidate with attribution/NOTICE.**
- **B1-05 Candidate comparison and owner approval.**
- **B2-01 Private `bext-stack/automonique` repository and organization access/rulesets.**
- **B2-02 Public baseline policies, governance and security reporting.**
- **B2-03 Fork-safe CI, SBOM, signing and protected release publishing.**
- **B2-04 Official-site and sponsor metadata:** canonical `automonique.fr` links, Inklura acknowledgement and tests proving sponsor identity grants no authority.
- **B2-05 Bootstrap trust baseline:** reviewed bootstrap manifest/schema, toolchain/dependency locks, trusted builder/signer public policy, clean-host SH0 and recovery evidence.
- **B2-06 Initial development command:** audited first-run script, finite seed DAG/coordinator, provider fakes, exact confirmation and Rust-lab handoff/retirement contract.

### Brand and public API

- **B3-01 Brand asset manifest/import, optimization and accessibility suite.**
- **B3-02 Central product identity/copy/token service for web/TUI/channel renderers.**
- **B3-03 Canonical npm namespace and legacy forwarding packages.**
- **B3-04 Exhaustive Rust rename:** canonical Cargo packages/crates/modules/features, binaries, directories, schemas, metrics/tracing, fixtures and release/image coordinates; legacy executable shims only where declared.
- **B3-05 Canonical env resolver with conflict/revision/deprecation behavior.**
- **B3-06 Canonical command registry aliases for Slack/Telegram/CLI.**
- **B3-07 Fresh-install Automonique paths, units and release layout.**
- **B3-08 Machine-readable compatibility/deprecation manifest.**
- **B3-09 Legacy-name CI gate:** scan source/generated/public artifacts and reject every undocumented pre-genesis legacy identifier occurrence.

### Runtime/state migration

- **B4-01 State/path discovery and non-mutating migration preview.**
- **B4-02 Backup/checksum/atomic move-or-adopt and rollback mapping.**
- **B4-03 `automonique.service` install and single-owner unit transition.**
- **B4-04 Database/artifact/cursor/action-receipt disconnected verification.**
- **B4-05 Wire/event schema expand/contract and adjacent-release tests.**
- **B4-06 CLI/TUI/SDK current-plus-previous compatibility matrix.**
- **B4-07 Active-work name-migration reload/rollback chaos exercise.**

### External platforms and launch

- **B5-01 Slack display/channel/command migration and old-action reconciliation.**
- **B5-02 Telegram display/command migration with stable identity.**
- **B5-03 Teams/Discord Automonique manifests/assets/install policy.**
- **B5-04 GitHub/Support/Manage/deploy link and sender migration.**
- **B5-05 External credential rotation/uninstall rollback drills.**
- **B6-01 Clean-room public-source and reproducible-build audit.**
- **B6-02 Claim/data-flow/privacy/air-gap review.**
- **B6-03 Private release candidate and production canary.**
- **B6-04 Explicit public visibility approval.**
- **B6-05 Self-host release evidence:** stable build, candidate self-build/reload, independent rebuild/provenance, reproducibility comparison and external promotion packet.
- **B7-01 Signed public release and canonical upstream switch.**
- **B7-02 Production Automonique service cutover/rollback exercise.**
- **B7-03 Legacy repository freeze/recovery guidance.**
- **B8-01 Legacy-use telemetry and removal proposals.**
- **B8-02 Alias removal releases after compatibility barrier.**
- **B8-03 Old repository archive/retention decision.**

## Verification matrix

At minimum test:

- clean Automonique install with no legacy files/variables;
- upgrade with only legacy variables/paths;
- both namespaces equal and both conflicting;
- missing/partial state move and cross-filesystem failure;
- service transition interrupted before/after enablement and lease acquisition;
- active work, pending work approval and provider approval during name reload;
- old Slack/Telegram commands and existing buttons after display rename;
- current/previous CLI, TUI, SDK and connector clients;
- repository clone/build/tests with no private network/credentials;
- clean-host SH0 bootstrap, candidate namespace isolation, self-build/reload/fallback and independent rebuild/provenance comparison;
- initial development start/decline/detach/resume/reboot/failed-handoff/repeat-start flow with no remote Git or production effect;
- repeatable stage-zero bundle build, offline verification, expected-file allowlist, sensitive-content exclusion and single-byte tamper rejection;
- full-history/object scan after import and after public-release candidate;
- dashboard/TUI brand assets at accessibility sizes/themes;
- rollback to legacy release without a second database or repeated outbox effect.

Every test asserts durable IDs/revisions, event/action counts, service/lease ownership, database/artifact path identity and external side-effect count.
