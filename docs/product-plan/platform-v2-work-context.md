<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v2 work-context contract

## Status and compatibility boundary

This document defines the negotiated Platform v2 work-context read model and
the rules later mutation/storage slices must preserve. Platform v1 remains an
installed exact contract: its schema identifier, resource vocabulary, record
shapes, request kinds, response kinds, and 512-resource ceilings are unchanged.

A connection advertises a bounded, strictly ordered set of supported major
versions. An offer may contain bounded future majors that this build does not
yet understand; peers select the highest shared major for which this build has
a known schema. Generated TypeScript exposes the same negotiation function,
distinct types for offered and selectable versions, and a transcript verifier;
a coherent v1 result is still refused as a suboptimal downgrade when both
offers include v2. A v2
implementation that meets a v1-only client
continues to serve the existing v1 resources, session discovery, attachment,
history, commands, and receipts. It does not encode a project or workspace ID
inside `ResourceRecord.summary`, invent a new v1 `ResourceKind`, or imply that a
v1 client received structured work context. No overlap is an explicit
compatibility refusal.

## Identity, authority, revision, and retention

Every new work-context identity is opaque and meaningful only within the
authority serving the projection. IDs never contain a filesystem path,
repository slug, branch name, host address, provider session token, or display
label. References to an existing Platform v1 repository or session preserve
its complete `ResourceCoordinate` (`authority`, expected v1 `kind`, and opaque
`id`); a bare ID would lose authority and is refused. Every record carries a
non-zero monotonic revision; mutations must target the exact identity and
expected revision. Observing a related record never grants authority over it.

Wire decoding intentionally applies only the shared opaque-ID grammar. It
cannot safely reject a string merely because it resembles a legitimate path,
slug, host, or provider spelling: opaque upstream identifiers may contain the
same Unicode. New authoritative work-context identities therefore have a
separate issuance invariant. The authority must call
`issue_work_context_identity_from_random_nonce` with 128 bits obtained directly
from a cryptographically secure random generator; it must not accept a
client-chosen ID or derive the nonce from filesystem, repository, host,
provider/session, credential, or display data. Clients only receive and echo
these identities. Existing Platform v1 coordinates are references and remain
under their original issuer's policy.

| Node | Identity and ownership | Lifecycle | Retention |
| --- | --- | --- | --- |
| `Project` | Durable human grouping owned by Automonique policy; may relate to multiple repositories and host setups | `active → archived`; archive does not cascade-delete descendants | Retained while any workspace, attempt, session, receipt, or policy record refers to it, then according to configured audit retention |
| `HostSetup` | Durable policy-approved execution location within one project; kind is `local`, `ssh`, or `remote_runtime` | `active → archived`; an archived setup admits no new checkout/attempt | Sanitized identity and classification remain; endpoint credentials, addresses, and host paths are outside this projection |
| `Checkout` | Durable authorized source location relating exactly one project, host setup, and repository | `active → archived`; kind is `git_worktree` or `authorized_folder` | Relation and revision remain; real paths stay in the workspace registry and never cross the protocol |
| `UserWorkspace` | Durable human-facing workspace relating exactly one project and checkout | `active → archived`; archive blocks new attempts but does not terminate running work implicitly | Retained across attempts and client reconnects |
| `AttemptWorkspace` | Isolated execution/security boundary for one attempt, relating exactly one user workspace | `preparing → running ↔ hibernated → completed/failed/cancelled` | Retained with its attempt, sandbox attestations, receipts, and audit record; terminal state cannot return to running |
| `Session` | Durable work-context session relating one attempt workspace and one existing Platform v1 session identity | `active ↔ hibernated → completed/failed/cancelled` | Retained at least as long as canonical session history and receipts |
| `Pane` | Presentation/terminal subdivision relating exactly one session; it never owns execution or control | `active → closed` | Closed panes remain while the owning session is retained; focus is client-local and is not lifecycle authority |

The existing internal execution type named `Workspace` remains an
implementation detail. It is not a `UserWorkspace`. When that implementation
is exposed in product or protocol language it is qualified as an
`AttemptWorkspace`; no alias or conversion grants broader filesystem,
credential, network, provider, or model authority.

## Structured relation graph

Relations are closed typed edges, bounded to 16 per record:

```text
Project ──project_repository────────────► Repository (v1 ResourceCoordinate)
HostSetup ──host_setup_project──────────► Project
Checkout ──checkout_project─────────────► Project
         ├─checkout_host_setup──────────► HostSetup
         └─checkout_repository──────────► Repository (v1 ResourceCoordinate)
UserWorkspace ──user_workspace_project──► Project
              └─user_workspace_checkout► Checkout
AttemptWorkspace ──attempt_user_workspace► UserWorkspace
Session ──session_attempt_workspace─────► AttemptWorkspace
        └─session_platform_session──────► Session (v1 ResourceCoordinate)
Pane ──pane_session─────────────────────► Session
```

Required single-parent edges occur exactly once. Project-to-repository edges
may repeat for distinct repositories. Duplicate edges, wrong source/target
kinds, unrecognized relation kinds, missing required parents, and relation-only
repository/session identities presented as top-level work-context records are
refused. Display labels remain bounded presentation text and carry no identity.

## Host setup and checkout semantics

- `local` means the authority's local workspace registry resolved the setup;
  it does not disclose the resolved path.
- `ssh` means a separately authenticated SSH execution adapter owns endpoint,
  host-key, credential, and connection policy. The work-context record exposes
  none of those values.
- `remote_runtime` means a registered remote executor/runtime owns placement
  and attestation. A vendor allocation ID is evidence, not Automonique
  authority.
- `git_worktree` is an isolated checkout based on a repository and immutable
  source revision tracked outside this display projection.
- `authorized_folder` is a registry-approved folder; client input can select
  its opaque checkout ID but cannot submit or derive a host path.

An attempt may only narrow the selected user workspace's filesystem,
credential, network, tool, provider, and model grants. It cannot widen any of
them, even when the host setup supports more capabilities.

## Query and retention-gap contract

Work-context inventory uses its own cursor namespace, independent of Platform
v1 resource subscriptions, session attachments, and session history. A query
contains:

- one to seven record kinds;
- zero or more lifecycle filters;
- optional exact project and parent filters;
- an opaque continuation cursor; and
- a requested limit in `1..=128`.

Each response carries at most the requested limit, the cursor it continued
after, and a `next_cursor` exactly when `has_more` is true. Record identities
inside a page are unique and strictly increasing by their Rust canonical order;
generated TypeScript compares UTF-8 bytes explicitly rather than JavaScript
UTF-16 code units, including for BMP/non-BMP IDs. The server applies
authorization before counting or paging and uses a deterministic stable order.
The protocol helper accepts records that the caller has already authorized,
uses stable identity ordering, and binds each cursor to both the complete
authorized inventory and the normalized filters. A changed inventory, changed
filter, malformed cursor, or unavailable position returns the exact
`resync_required` outcome carrying the expired cursor; it never silently starts
at a new position. Total inventory is unbounded by the old 512-resource
snapshot ceiling: for example, 640 records remain five ordinary 128-item pages.
The helper is deterministic protocol behavior, not a persistence, indexing, or
authorization implementation.

## Mutation contract

Create project, host setup, checkout, user workspace, and attempt workspace;
resume attempt workspace and session; and archive project, host setup, checkout,
and user workspace are distinct typed v2 intents. A caller never supplies a
new record, authoritative lifecycle, revision, or ID. The issuer creates a new
identity while producing the preview. Every existing target and parent carries
its authority-qualified identity and exact expected revision.

`UserWorkspace` archive is one-way. It has no resume or unarchive operation.
Reopening human work under an active `UserWorkspace` means creating a new
`AttemptWorkspace`. An archived `UserWorkspace` itself never reopens; returning
after archive requires a new `UserWorkspace` and then a new attempt. Resume is
reserved for a hibernated `AttemptWorkspace` or `Session`. Archive remains
non-destructive and does not cancel an active attempt implicitly.

Before submission, the server produces a bounded preview of the exact current
record, resulting record, inherited authority, effective authority, and every
resolved parent. Work-context parents carry their complete authoritative
record. Repository parents carry their complete v1 identity, exact revision,
an explicit available/unavailable resolution, and an optional informational
owning project. Unavailable repositories are refused. Checkout creation also
refuses an available repository owned by a different selected project and
proves the selected project's repository relation plus the host setup's project
relation; project creation does not treat the optional owner as exclusive
membership. Actor,
serving resource authority, idempotency key, all six authority axes
(filesystem, credentials, network, tools, providers, and models), and the typed
intent are bound by the canonical request digest. Effective authority must be
a subset of both the authenticated actor ceiling and inherited ceiling.
Approval, when policy requires it, targets the exact preview ID and revision,
the SHA-256 digest of the complete canonical preview body, request digest,
idempotency key, and expiry. Submission and receipt repeat those bindings.
Ambiguous outcomes are reconciled by receipt identity or
idempotency key and never replayed blindly; `unknown` and `resync_required` are
lookup outcomes and cannot be persisted as mutation receipts.

The contract slices now supply the identities and graph, strict negotiation,
exact query/page/resynchronization codecs, deterministic pager over already
authorized input, and lifecycle proposal/preview/approval/submission/receipt
documents. Rust values keep authoritative and binding fields private;
generated TypeScript validates the same canonical bytes and refusal corpus.
`SCHEMA_DIGEST` identifies the complete additive generated surface and
therefore moves when the v2 module changes. The SDK still advertises
`protocolRange: 1` and `automonique.platform/v1`, so its manifest pins the
separately generated `PLATFORM_V1_SCHEMA_DIGEST`; the checked-in Platform v1
module remains byte-identical.

The authoritative SQLite slice stores records, relations, expected revisions,
previews, approvals, receipts, inventory cursors, and external-effect work in
tenant-scoped transactions. Its checked mutation policy names the exact
authenticated actor, selected project, target identities, authority ceilings,
and approval requirement. Policy is rechecked before an idempotency replay or
conflict is disclosed. Approval recording requires a checked lifecycle-approval
authority bound to the same tenant, exact preview body digest, revision, and
expiry. Receipt reconciliation is available both by receipt identity and by
the complete tenant/actor/serving-authority/idempotency scope; absence is an
explicit `unknown` lookup result.

External effects reserve the exact tenant/target/revision/effect tuple before
enqueue. Attempt creation reserves its newly issued `AttemptWorkspace`
identity, not the parent `UserWorkspace`, so separately requested attempts can
run sequentially without weakening same-request replay protection. Workers
discover and atomically claim ready effects under an opaque durable lease
bound to executor identity, serving authority, preview, target revision,
effect kind and document digest, and expiry. Completion consumes that exact
lease, validates the prior accepted receipt and current authoritative snapshot,
and returns the completed receipt idempotently on retry. Lease duration is
bounded. Expiry moves an effect to `ambiguous`, never back to ready: a typed
provider reconciliation tied to the original idempotency key must establish
`not_started` before release, persist exact completion evidence before final
receipt creation, or leave an `unknown` effect unavailable for replay.
After a restart or lost claim response, only the original authenticated
executor or an explicitly privileged tenant-scoped reconciler may reconstruct
an ambiguous lease. Reconstruction validates the canonical receipt, outbox,
reservation, lease, and preview and records the recovering identity without
claiming or replaying the effect. A released effect becomes ready again only
when the prior lease has an exact persisted `not_started` reconciliation whose
evidence digest, receipt identity, and monotonic timestamps revalidate.
Authoritative snapshot
ingestion rejects revision regression, terminal lifecycle rollback, reparenting,
and external owner changes. Durable readers re-encode documents and compare all
duplicated normalized columns before returning a value.

Server routes, retention workers, SDK client ergonomics, and production
clock/random-ID and authentication-policy providers remain separate
integration work. The protocol helpers alone do not claim to implement those
authority or durability boundaries.
