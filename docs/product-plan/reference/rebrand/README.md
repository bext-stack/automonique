# Automonique rebrand and repository migration
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md`). GPL statements below remain historical.

**Status:** proposed migration contract

**Brand kit source:** `<owner-controlled brand archive path>`

**Target product:** Automonique, embodied by the assistant/mascot Monique.

**Canonical owner/repository:** [`bext-stack/automonique`](https://github.com/bext-stack/automonique)

**Code license:** GNU General Public License v3.0 or later (`GPL-3.0-or-later`)

**Official site:** [automonique.fr](https://automonique.fr)

**Founding sponsor:** [Inklura](https://inklura.fr)

This directory is the source of truth for moving the current private legacy production bot into the Automonique product without losing durable work, breaking deployed integrations or publishing production-specific history by accident.

## Decision summary

Automonique will have a new upstream repository in the `bext-stack` GitHub organization, initially private, because the target product is explicitly GPL-licensed open source while the current repository is a private operator deployment containing organization-specific paths, services and integrations.

Do not create a public repository by copying the current checkout. The safe sequence is:

1. record `bext-stack/automonique`, `GPL-3.0-or-later`, `automonique.fr` and Inklura sponsorship in the import evidence;
2. create the private staging repository `bext-stack/automonique`;
3. audit and sanitize code plus history;
4. import the product with authorship/provenance preserved where safe;
5. introduce Automonique names through compatibility aliases rather than an atomic destructive rename;
6. run CI, security, brand, migration and production rollback gates;
7. make the upstream public only after the disclosure/licensing gate;
8. retain the old private repository as the production recovery source until the migration window closes.

No second writable long-lived fork is allowed. During the short transition, one repository is declared canonical for each release line and every cross-repository backport is recorded.

## Documents

1. [Repository strategy](repository-strategy.md) defines why a new upstream is appropriate, how history is sanitized and which governance/supply-chain files block publication.
2. [Compatibility contract](compatibility-contract.md) defines public Automonique names, legacy aliases, durable identifier rules and external-platform migration.
3. [Migration and work breakdown](migration-and-work-breakdown.md) provides phases, ordered tickets, verification and rollback gates.
4. The [Rust rewrite plan](../corpus-index.md) remains the runtime architecture source of truth and consumes these naming/repository decisions.
5. [Self-hosting and bootstrap](../../requirements/self-hosting-and-bootstrap.md) defines how the private upstream produces its first trusted development seed and later candidate/release evidence.

## Non-negotiable outcomes

- Existing approvals, tickets, sessions, action receipts and external message coordinates retain their IDs and authority.
- A rename never starts work, widens an approval, resends an external effect or silently selects a different database.
- `AUTOMONIQUE_*` configuration becomes canonical; conflicting legacy `LEGACY_*` values fail closed.
- Fresh installs use Automonique service/package/path names. Existing installations migrate with explicit backups and compatibility shims.
- Public source contains no production credentials, user/session data, private ticket content, customer-only knowledge or secret-bearing history.
- The private upstream carries a reviewed bootstrap manifest, fixed toolchain/build policy and independently verifiable SH0 seed; self-host candidates never receive repository-administration, signing or production authority.
- Every distributed source/binary release carries the `GPL-3.0-or-later` license, corresponding-source and notice material required by the release policy; dependency and generated-code licenses must be GPL-compatible.
- Brand assets have recorded source, digest, rights/license, transformation history and accessible alternatives.
- Sponsor acknowledgement names Inklura and links to `https://inklura.fr` without granting the sponsor product authority, tenant access or privileged runtime capability.
- Canonical public product links use `https://automonique.fr`; environment-specific API, Support and connector endpoints remain reviewed configuration rather than being inferred from that domain.
- “Open source,” “sovereign” and “air-gapped” claims are tied to testable deployment profiles and channel data-boundary disclosures.
- Slack, Telegram, Teams and Discord display-name changes never substitute for stable external identity mapping.

## Recorded owner decisions

The owner has selected:

- GitHub organization and canonical repository: `bext-stack/automonique`;
- source-code license: `GPL-3.0-or-later`;
- official product site: `https://automonique.fr`;
- founding sponsor: Inklura, `https://inklura.fr`.

These decisions govern the new Automonique upstream. They do not retroactively publish or relicense the current private production repository before the audited import and provenance gate.

## Decisions still requiring the owner

The implementation can prepare everything else, but these external choices must be recorded before repository creation/publication:

- repository visibility timeline;
- brand-asset/trademark license;
- whether public history uses a sanitized filtered history or a clean initial import after the audit comparison;
- trademark ownership and who may publish official packages/images;
- production date for renaming Slack/Telegram and any existing customer-facing endpoints.

The remaining recommended defaults are private staging first, separately documented brand-asset/trademark terms, and sanitized history when it can be proven safe without destroying attribution.

## Completion definition

The rebrand is complete when the canonical repository, packages, binaries, service, dashboard/TUI, documentation and supported channel apps present Automonique; legacy aliases either pass their declared compatibility window or fail with a precise migration message; production state and effects reconcile exactly; the old repository is read-only with recovery instructions; and a clean installation plus an upgraded legacy installation both pass the same Automonique conformance suite.
