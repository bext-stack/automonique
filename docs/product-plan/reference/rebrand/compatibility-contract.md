# Naming and compatibility contract
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md`). GPL statements below remain historical.

## Principle

Automonique is the public product identity. Legacy identifiers are legacy compatibility coordinates, not alternate brands for new surfaces. Rename presentation early; migrate durable/runtime identifiers through an explicit compatibility window.

## Target names

| Surface | Canonical target | Legacy compatibility |
|---|---|---|
| Product | Automonique | legacy product name in migration notices only |
| Assistant/persona | Monique | existing messages remain historical legacy records |
| GitHub | `bext-stack/automonique` | private legacy repository remains recovery source |
| npm | `@automonique/sdk`, `/node`, `/browser`, `/provider`, `/connector`, `/testing` | `@legacy/sdk*` forwarding releases for a declared window |
| Rust crates/modules/features | `automonique-*` and `automonique_*` | no public legacy crate family; internal legacy identifiers are renamed before public import |
| Daemon | `automoniqued` | `legacyd` executable shim during local upgrade window |
| CLI/TUI | `automoniquectl`, `automonique-tui` | `legacyctl`, `legacy-tui` warning shims |
| systemd | `automonique.service`, `automonique-*.socket/service` | `legacy.service` disabled alias/migration unit; never active concurrently |
| Fresh state/config | XDG `automonique/`, `automonique.db` | existing `.legacy`, `legacy.db`, settings/shell files adopted in place through migration record |
| Environment | `AUTOMONIQUE_*` | `LEGACY_*` read-only aliases through declared deprecation window |
| Wire protocols | `automonique.*` next major | `legacy.*` v1 accepted across adjacent compatibility releases |
| Slack | Automonique/Monique, `#automonique`, `/automonique` | existing app/channel IDs, `#legacy`, `/legacy` aliases during rollout |
| Telegram | Automonique/Monique display and commands | stable bot/chat IDs and legacy command aliases |
| Teams/Discord | Automonique from first installation | no legacy display alias needed for not-yet-deployed apps |
| Worker markers | versioned neutral structured protocol | parse existing `LEGACY_*` markers during compatibility window |

Exact executable/crate names are finalized before the first public package release and then treated as compatibility API.

Canonical naming covers source directories, Cargo package/crate/module/feature names, binary targets, package metadata, generated schemas, metrics, tracing targets, environment examples, fixtures, release archives, containers/images, systemd templates, desktop/web assets and documentation. A CI denylist rejects undocumented new legacy identifiers in public artifacts.

Legacy names remain only in an explicit machine-readable compatibility inventory: historical database/table/event/protocol decoding, upgraded-install paths, old external commands and thin forwarding executables/packages. Each occurrence has an owner, reason and removal gate; “internal implementation detail” is not a reason to keep the old brand.

## Durable identifiers and history

Never rewrite durable database IDs, Slack/Telegram message coordinates, GitHub issue references, provider session/turn IDs, idempotency keys, artifact digests or action revisions merely to replace a legacy product word. Historical event payloads retain their original schema/name and remain decodable.

New events use canonical product-neutral or Automonique schema names only after current and previous releases can decode them. UI projections may display Automonique for historical records while preserving the original actor/source in detail/audit export.

## Environment resolution

For each renamed setting:

1. Read `AUTOMONIQUE_X` when present.
2. Otherwise read `LEGACY_X` and emit one redacted deprecation event.
3. If both are set and normalized values differ, fail configuration readiness with the exact variable names but no values.
4. Never copy secrets into logs, generated config or process arguments.
5. Record which namespace supplied the value as non-secret diagnostics.

Generated examples use only canonical variables. The compatibility manifest lists alias, introduced version, warning version and removal version.

## Files and directories

Fresh installs use XDG-compliant Automonique paths. Existing installations do not silently create an empty `automonique.db` while live state remains in `legacy.db`.

Upgrade sequence:

- stop intake through the safe drain/reload protocol;
- take and verify a consistent backup;
- resolve the existing explicit database/state paths;
- write a revisioned migration marker containing old/new path identities and checksums;
- move or reference the same state atomically on one filesystem;
- validate integrity, permissions, artifacts, cursors and action receipts;
- start disconnected/read-only before enabling transports/outboxes;
- retain a rollback mapping until the compatibility window closes.

Symlinks may serve as temporary CLI/operator compatibility, but services resolve and record canonical real paths. A path alias never allows two daemon instances to open the same database as independent deployments.

## Services and process control

Install `automonique.service` beside the old unit only while both are disabled or one is masked. The migration transaction transfers environment/credential references, runtime directories and enablement; it must prove only one unit owns Slack/Telegram polling, scheduler leases and connector credentials.

`legacy.service` becomes either:

- a disabled unit that prints migration guidance; or
- a systemd alias to the same canonical unit when alias semantics are proven safe.

It is never a second live service. `automoniquectl migrate-name --check` is non-mutating; `--apply <plan-id>` revalidates the exact unit/state paths before transition.

## CLI, SDK and protocol compatibility

Legacy commands/packages are thin forwarding layers generated/tested against the same implementation. They cannot accumulate separate behavior.

- `legacyctl` invokes `automoniquectl` with a warning and preserves exit codes/stdout contracts during its window.
- `@legacy/sdk` re-exports the compatible `@automonique/sdk` release and declares deprecation; no duplicated wire types.
- local/remote negotiation advertises canonical and legacy protocol ranges plus removal dates.
- unknown clients become read-only when safe; they never guess renamed mutations.
- examples, connector apps and dashboard use canonical packages immediately.

## User-facing behavior

Centralize brand metadata instead of scattering name/color/tagline constants:

- product/assistant/display names and locale-aware copy;
- logo/avatar/monogram and accessible text;
- color/typography tokens;
- support/legal/documentation URLs;
- channel command/help labels;
- notification sender identity.

Security/error messages stay direct and factual; brand voice never softens approval, denial, data-boundary or incident language.

Existing approvals/cards/buttons continue to target their original revision after display re-render. A brand change alone does not supersede them.

## External platform migration

### Slack

Prefer renaming the existing Slack app/bot display and adding `/automonique` while retaining stable team/app/user/channel IDs. Keep `/legacy` as an alias for the announced window. Channel rename is an administrator operation with permalink/bookmark/workflow audit; never assume `#legacy` text is the identity key.

### Telegram

Preserve the bot ID/token unless a deliberate bot replacement is approved. Update display/about/commands and add canonical commands before removing aliases. Username availability/change is external and must not break stored chat/user identity.

### Teams and Discord

These are new connectors: manifests, applications, commands and assets use Automonique from first install. Tenant/guild installation records remain tied to immutable app IDs, not display name.

### GitHub, Support and deployment

Update repository links, issue templates, report footers, Support sender copy and deployment notifications through revisioned configuration. The canonical product URL is `https://automonique.fr` and sponsor acknowledgements link to `https://inklura.fr`. Email domains/senders, API origins and webhook endpoints require separate ownership/authentication checks; do not infer them from the marketing site.

Sponsor metadata is presentation/provenance only. It never grants an Inklura identity global Automonique authority or changes tenant fencing.

## Brand assets and fonts

Import the supplied kit into a reviewed `brand/` tree only after recording:

- original ZIP hash and each imported asset hash;
- source/reference and creator/rightsholder declaration;
- code/brand/trademark license;
- raster extraction/transformation notes;
- font families, source and redistribution/web-hosting license;
- optimized sizes and dark/light/monochrome variants;
- alt text, contrast, minimum-size and fallback tests.

The large lockup SVG may embed raster data and the wordmark depends on Bitter text rendering; produce deterministic web-safe outputs rather than assuming every SVG is a small portable vector. Do not fetch fonts at runtime in sovereign/air-gapped builds unless that deployment explicitly allows the external request.

The code license is `GPL-3.0-or-later`. Brand artwork, wordmarks, fonts and trademarks are not assumed to inherit the code license merely because they share a repository; their manifest records the separately approved terms and the GPL release excludes any asset whose redistribution rights are unresolved.

## Deprecation and removal gate

A legacy identifier can be removed only when telemetry/audit shows no supported client/config uses it for the declared window, documentation and automated migration exist, rollback no longer requires it, and the removal appears in release notes plus machine-readable compatibility metadata.
