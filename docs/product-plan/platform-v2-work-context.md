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

The additive typed review/attention sub-contract built on these identities is
specified in [Platform v2 review, attention, checks, and pull requests](platform-v2-review-contract.md).

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

## Hosted web cockpit projection

The hosted dashboard uses `POST /api/platform/cockpit` as a bounded,
server-owned JSON projection over the local canonical Platform v2 bridge. The
route accepts the configured Basic principal only; session cookies, mobile
credentials, and bearer credentials cannot enter it. Each read negotiates v2,
queries at most 128 typed work-context records, and refuses to present an
incomplete inventory when the authority reports another page. A selected
opaque `UserWorkspace` is resolved from that inventory, then read through the
exact project-qualified lineage and review operations. Canonical integer
fields are rendered as decimal strings before they cross the browser boundary,
so JavaScript never parses authoritative revisions through `Number`.

Attention filters are advertised as complete only when every workspace in the
bounded inventory has an authority-qualified review projection. The web entry
enriches at most 16 workspaces and gives each non-selected enrichment read a
single 100 ms local-socket wall-clock budget across connect, write, and every
response byte; a trickling peer cannot restart that budget. A larger
inventory, a refusal, or a timed-out workspace produces explicit `partial` or
`unavailable` attention coverage; unknown workspaces receive no inferred
attention state. Canonical `idle` remains a known workspace state while the
four actionable filter counters remain unchanged. The browser keeps the
structured cockpit snapshot separate from the retained Platform v1 snapshot,
so filtering, selecting, and detaching cannot discard either surface. When a
retained session maps to another known workspace, the cached structured shell,
URL, inspector, and conversation selection move together before attachment;
anchors from the previous workspace are removed.

If v2 is refused, unavailable, downgraded, or exceeds the cockpit bound, the
response carries the retained Platform v1 session projection separately and
an explicit degradation category. It returns no projects, hosts, or workspaces
in that mode and never reconstructs them from summaries. Task/attempt create,
attempt resume, and session resume remain disabled with
`platform_v2_lifecycle_adapter_pending`. The daemon conditionally installs the
private-registry-backed production lifecycle adapter; the cockpit reads its
generation-verified, action-specific capability set from the daemon and exposes
only local `create_host_setup` and `create_checkout` through the existing typed
`prepare_mutation` preview and `get_mutation_receipt` reconciliation operations.
An absent, changed, or refused registry leaves those operations unavailable,
and the preview's exact parent revisions plus preview digest/approval and receipt
lookup fences remain authoritative. Review action requests preserve
the exact selected workspace, expected snapshot/review revisions, and
idempotency key on the typed v2 request, but remain visibly unavailable while
the daemon returns `platform_v2_review_adapter_pending`. These are integration
gaps, not browser capabilities.

Within a negotiated v2 response, lineage, review, and attention availability
remain independent. Any selected-workspace refusal, incomplete attention
coverage, or unknown freshness is rendered as partial rather than fully
capable. Canonical stale freshness is called out explicitly and the cockpit
remains read-only.
