# Repository strategy
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded at genesis. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md` and `GENESIS.md`). GPL statements below remain historical.

## Why not only rename the existing repository

Renaming the existing private GitHub repository would preserve commits, pull requests and redirects and is the simplest choice for a private product rename. It is not sufficient for the stated Automonique direction because the current repository is also a live organization-specific deployment.

The local review found:

- a private repository with production-oriented service/install scripts;
- operator/Inklura-specific paths and integration defaults;
- historical tracking of an operational shell metadata file, even though current secrets/databases are ignored;
- no repository license;
- brand assets derived from a supplied visual without repository-level rights metadata;
- legacy names embedded in environment variables, database defaults, systemd units, commands, protocols, paths and external messages.

Making that repository public in place would combine product extraction, secret/history review, legal publication and production migration in one irreversible event.

## Chosen topology

```text
GitHub organization bext-stack
└─ automonique                 canonical product upstream, private staging → public

current private owner
└─ legacy-repository          private production/recovery source during migration
```

The canonical remote is `https://github.com/bext-stack/automonique`. The new repository becomes canonical after its private staging gate. The old repository may temporarily carry deployment-only compatibility fixes, but new product features land upstream first. After production cutover it becomes read-only and links to the canonical upstream; private deployment configuration lives outside public source or in a narrow private deployment repository that consumes signed Automonique releases.

Do not use a permanent public fork of the private repository. Fork relationships and two writable default branches obscure which security fixes/releases are authoritative.

## Private staging creation gate

Before creating or pushing the new remote:

- record `bext-stack` as repository owner and name organization administrators/recovery owners;
- enable required MFA/SSO and least-privilege team access;
- select the default branch and branch/ruleset policy;
- install `GPL-3.0-or-later` license/provenance policy and separately select brand/trademark terms;
- define package/container namespaces and trusted publishers;
- decide whether issues/discussions/security advisories are enabled at private staging and public launch;
- record the current source commit and brand-kit digest as import inputs.

Create the repository private with no initialized README so the reviewed import determines the root commit/history. Never put production tokens into repository actions while staging.

## Source and history audit

Audit the entire reachable history, tags, notes, large-file objects and pull-request refs where obtainable—not only the current tree.

Required checks:

- secret scanners with verified current rules plus manual high-risk review;
- `.env`, databases/WAL, shell/session metadata, logs, reports, screenshots and generated artifacts in all history;
- private domains, IPs, hostnames, usernames, absolute paths, email addresses and customer identifiers;
- ticket/Slack/Telegram/Support content and approval evidence;
- private knowledge bases, proprietary companion data and internal API schemas;
- dependency licenses, copied snippets, generated code and model/provider SDK redistribution terms;
- binary files and image metadata;
- commit author privacy and signed-commit behavior after rewriting.

Never print discovered secrets during the audit. Revoke a real credential before history rewriting; rewriting alone is not revocation.

## Import choices

Produce and compare two candidate imports in disposable clones:

### Sanitized history

Use history filtering to remove prohibited paths/blobs and replace organization-specific content while preserving safe commit authorship and chronology. Re-run secret/license tests on the rewritten object database. Record old-to-new commit mapping privately for incident response.

Choose this when the resulting history remains understandable and no prohibited content is reachable.

### Clean product import

Create one reviewed initial product commit with attribution/NOTICE and link the private legacy repository in private migration records. Use this when history sanitization would leave misleading commits, disclose customer context or require pervasive rewriting.

Do not pretend the clean import preserved commit history. Preserve copyright/attribution through the selected license, AUTHORS/NOTICE and internal mapping.

The owner approves one candidate after seeing the scanner, license, size and diff reports. Neither candidate is pushed public before approval.

## Public repository baseline

The first public-capable tree includes:

- `LICENSE` containing `GPL-3.0-or-later`, corresponding-source/release notices where applicable, and separate `BRAND-LICENSE.md`/trademark terms;
- `README.md` with honest deployment/data-boundary claims;
- `SECURITY.md` with private vulnerability reporting and supported versions;
- `CONTRIBUTING.md`, code of conduct and governance/maintainer policy;
- architecture, threat model and data-flow diagrams;
- sample configuration containing no production defaults;
- deterministic build/lock files, SBOM/provenance and dependency policy;
- `.automonique/bootstrap/` manifest/schema, public trusted-builder/signer policy, clean-host instructions and recovery contract;
- the audited `scripts/automonique-dev`, finite `.automonique/dev/seed-program.yaml` and temporary `tools/bootstrap-seed` source/tests needed to create SH0 without production coupling;
- changelog/versioning/deprecation policy;
- privacy/telemetry defaults and retention documentation;
- brand asset manifest with hashes, formats, source and accessibility guidance;
- issue/PR templates that do not solicit secrets or customer data.

Public metadata uses `https://automonique.fr` as the product/homepage URL and identifies [Inklura](https://inklura.fr) as founding sponsor. Sponsorship does not imply repository ownership, exclusive licensing, security-report access or production tenant access.

CI uses OIDC/short-lived credentials where possible. Package/container publishing is environment-protected and produces signed provenance. Pull requests from forks never receive release, tenant or platform credentials.

The initial SH0 development seed is built only after private staging passes its source/history/license gate. It may prepare later source changes and release proposals, but cannot change repository rulesets, trusted builder/signer policy, public visibility or production releases. Those remain organization/environment-protected external actions.

## Repository data that stays private

- production `.env`, database and backup material;
- Slack/Telegram/Teams/Discord application credentials and installation coordinates;
- customer knowledge, email/support content and private site inventory;
- internal deployment host paths/IPs and privileged broker policy for a specific customer;
- full raw provider transcripts or diagnostics derived from real work;
- private vulnerability reports and old-to-new sanitized commit mapping.

Public fixtures are synthetic or irreversibly sanitized and carry provenance.

## Release and dependency relationship

After cutover, private deployments consume immutable signed Automonique releases and supply configuration/policy/credentials outside the product tree. If a private companion must remain closed, it crosses a versioned external protocol and is not silently bundled into the open-source artifact.

The public upstream does not depend on `<host-specific path>`, operator domains or a specific Slack channel. Example values use reserved domains/identifiers.

## Old repository retirement

Retire only after:

- production runs from a signed upstream release;
- two-way rollback to the last legacy release has been exercised;
- open pull requests/security fixes are accounted for;
- package, webhook, deployment and documentation links point upstream;
- the old default branch is protected/read-only;
- its README names the canonical upstream and recovery owner;
- retention policy says when it may be archived or deleted.

Repository deletion is not part of the rebrand plan. The private history remains recovery/audit evidence until an explicit retention decision.
