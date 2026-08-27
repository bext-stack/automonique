<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v2 work-context contract

## Status and compatibility boundary

This document defines the negotiated Platform v2 work-context read model and
the rules later mutation/storage slices must preserve. Platform v1 remains an
installed exact contract: its schema identifier, resource vocabulary, record
shapes, request kinds, response kinds, and 512-resource ceilings are unchanged.

A connection advertises a bounded set of supported major versions. Peers select
the highest shared version. A v2 implementation that meets a v1-only client
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
after, and a `next_cursor` exactly when `has_more` is true. The server applies
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

## Mutation contract for the next slice

Create project/setup/checkout/workspace, resume workspace/attempt/session, and
archive project/setup/checkout/workspace operations must be dedicated typed v2
methods. Each request will carry actor authority, exact parent identities,
expected revisions where a record already exists, an idempotency key, and no
host path. Responses use durable receipts with accepted, completed, rejected,
conflict, unknown, and resynchronization-required outcomes.

Before a create or resume is admitted, the server produces a bounded preview
of resulting relations and the effective attempt authority. Approval, when
policy requires it, targets that exact preview revision. Ambiguous outcomes are
reconciled by receipt identity or idempotency key and never replayed blindly.
Archive is non-destructive and does not cancel an active attempt implicitly.

This first contract slice supplies the identities, graph, strict negotiation,
exact query/page/resynchronization codecs, a deterministic pager over already
authorized input, generated TypeScript validators/codecs, and bidirectional
Rust/TypeScript conformance fixtures. `SCHEMA_DIGEST` identifies the complete
additive generated surface and therefore moves when the v2 module changes. The
SDK still advertises `protocolRange: 1` and `automonique.platform/v1`, so its
manifest pins the separately generated `PLATFORM_V1_SCHEMA_DIGEST`; the
checked-in Platform v1 module remains byte-identical.

The mutation methods, durable persistence/index and authorization integration,
SDK client ergonomics, daemon routes, and internal terminology cleanup remain
separate implementation work.
