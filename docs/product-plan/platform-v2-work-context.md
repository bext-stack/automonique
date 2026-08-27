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

## External work and orchestration lineage

Platform v2 keeps three identities separate even when one operator experience
shows them together:

- `ExternalWorkIdentity` is the indivisible tuple `provider + opaque source
  authority/installation + opaque scope + opaque key`. Providers are the
  closed set `github`, `gitlab`, `linear`, and `jira_compatible`. The authority
  component prevents two self-hosted GitLab or Jira-compatible instances from
  colliding even when their scope/key bytes match. A moved item carries its
  complete replacement identity, which may name another supported provider or
  installation when both exact identities are authorized. Durable intake and
  update require that replacement to exist first; dangling targets and moved
  cycles are refused. A closed item has no replacement.
- `UserWorkspaceId` is the durable human workspace to which work is bound. It
  is neither an issue key nor an execution identity, and observing the binding
  grants no provider, repository, filesystem, or execution authority.
- `OrchestrationIdentity` has distinct branded domains for `run`, `task`,
  `dispatch`, `worker`, `heartbeat`, `question`, and `decision_gate`. No generic
  orchestration ID or generic authority string exists.

Internal parentage is closed and typed:

```text
Run ─► Task ─► Dispatch ─► Worker ─► Heartbeat
       ├─► Task (bounded child-task lineage)
       └─► Question ─► DecisionGate
       └────────────────► DecisionGate
```

A run has no parent. Dispatch without a task, worker without a dispatch,
heartbeat without a worker, or question without a task is an orphan and is
refused. A decision gate binds to the exact question or task whose decision it
guards. External work and every internal record independently name the same
`UserWorkspaceId`; their identities are never synthesized from one another.

Every projected record carries explicit freshness (`observed_at_ms`, a positive
staleness interval, and `fresh|stale`) and may carry one latest useful message
bounded to 1,024 UTF-8 bytes. Status is a discriminated value: `working` has no
invented explanation, `blocked` and `waiting` carry a bounded reason, and
`done` carries a bounded outcome. A stale heartbeat cannot prove a worker is
running. Messages are presentation evidence, never IDs, authority, or implicit
state transitions. A `done` outcome cannot change, while later monotonic
freshness observations and useful evidence may advance its revision.

Each external and orchestration record also carries a path-free origin
coordinate: workspace plus optional attempt, session, and pane. Session
requires attempt and pane requires session. A child relation may refine its
parent coordinate but cannot change or discard a parent component. Projections
resolve every moved/external/parent link and reject missing targets and cycles.

## Task-to-workspace create and resume intent

A create intent binds an exact orchestration task and external work identity to
an idempotent intent ID plus distinct opaque base and branch selector IDs. The
selectors are issued by an authorized registry; they do not contain and cannot
be replaced by a host path, repository slug, ref name, provider URL, or command
fragment. A resume intent names the exact task, `UserWorkspaceId`, and non-zero
expected revision. Neither request accepts a generic string selector.

Outcomes are `accepted` or `unknown` polling receipts, `created` or `resumed`
final receipts, or a closed typed conflict. The immutable request digest is
looked up by intent ID before reconciliation. An exact authoritative execution
receipt advances `accepted|unknown` from that admitted snapshot, so a creation
that succeeded remains `created` even if the separately observed source later
moves or closes. Lookup requires negotiated v2 and an authorized
tenant/project/workspace scope; possession of an opaque intent ID grants no
read authority. Stable conflicts
cover duplicate intake, task already bound, workspace absent, revision
mismatch, moved/closed external work, orphan dispatch, stale heartbeat,
pending question, and cancelled creation. Duplicate intake returns the prior
binding or a conflict; it never creates a second workspace. Moved and closed
sources do not silently retarget. Cancellation is terminal for that exact
create intent, while a new authorized intent requires a new identity.

The shared synthetic corpus
`rust/crates/automonique-protocol/fixtures/platform-v2-lineage-v1.json` covers
those boundaries and mixed-version behavior. Offers such as `[1,2,3]` still
downgrade truthfully to a v1-only peer with lineage unavailable; when a peer
later offers v2, negotiation recovers v2 and the structured lineage surface.
The corpus contains opaque test values only and no host paths or live provider
identifiers.

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

This contract slice supplies the identities, graph, strict negotiation,
exact query/page/resynchronization codecs, a deterministic pager over already
authorized input, external-work/orchestration lineage values, generated
TypeScript declarations and fail-closed composite validators, and shared
bidirectional Rust/TypeScript conformance fixtures.
`SCHEMA_DIGEST` identifies the complete
additive generated surface and therefore moves when the v2 module changes. The
SDK still advertises `protocolRange: 1` and `automonique.platform/v1`, so its
manifest pins the separately generated `PLATFORM_V1_SCHEMA_DIGEST`; the
checked-in Platform v1 module remains byte-identical.

`automonique-store::lineage_index` is the authoritative normalized SQLite
index for this slice. It validates current-version tables, indexes, required
columns, foreign keys, and SQLite integrity on open. It keeps external work, internal orchestration, and
workspace intents in separate constrained tables; uses exact idempotent replay
and revision fencing; enforces monotonic observations, immutable terminal
status, and non-zero orchestration revisions; and rebuilds only a bounded
projection for one exact `UserWorkspaceId` after restart. The embedding daemon
must pass its authorization decision through the authority-scoped projection
seam. It stores neither provider payloads nor host paths.

External-provider ingestion, workspace create/resume execution, authorization
and selector registries, daemon routes, SDK client ergonomics, and UI
projection remain separate runtime work. The contract and index do not claim
that a provider item was fetched, a worker is live, or a workspace was created.
