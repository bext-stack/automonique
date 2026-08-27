<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v2 review, attention, checks, and pull requests

## Compatibility and scope

`automonique.platform/review/v2` is the current additive sub-contract available
only after Platform major version 2 is negotiated. Historical
`automonique.platform/review/v1` snapshots remain exactly decodable, but their
proposals did not identify a Git authority and are therefore explicitly
non-actionable. No authority is inferred while decoding them. This does not
add a Platform v1 resource kind, field, request, or response, and it never
serializes review meaning into a v1 summary string. A v1-only peer continues to
receive exactly the installed Platform v1 contract and no structured review
projection.

This slice defines shared values, exact canonical codecs, generated TypeScript,
deterministic fixtures, and an authoritative SQLite custody layer. The store
persists only revalidated canonical snapshots; normalizes anchored comments and
their explicit sent-to-agent state; and atomically binds action previews,
approvals, receipts, actor, workspace, expected revision, authority, request
digest, and idempotency key. External provider observations are kept in a
separate table and cannot create local authority grants.

Approval is a checked document rather than an unauthenticated flag. It binds
the preview, workspace, request digest and revision, authenticated approver,
exact authority identity, approved/refused decision, and expiry. The approver's
grant, current snapshot revision, and action target are rechecked in the same
transaction that records the decision. A refusal closes the receipt without
executing the proposal; an expired approval cannot authorize a later write.

There is still no daemon route, git adapter, shell adapter, CI adapter,
pull-request adapter, provider adapter, or client UI. A future daemon must
obtain authority decisions from its local policy registry before installing a
store grant, and adapters must reconcile the existing receipt after ambiguous
writes rather than replaying a mutation.

## One authoritative snapshot

A `ReviewSnapshot` belongs to exactly one `UserWorkspace`, `AttemptWorkspace`,
or work-context `Session` identity and one non-zero revision. Its collections
are bounded, unique, and UTF-8 byte ordered so desktop, web, and mobile render
the same meaning:

| Projection | Shared meaning |
| --- | --- |
| file and hunk | Repository-relative display path, added/modified/deleted/renamed state, staged/unstaged/partially-staged/untracked state, conflict state, and bounded sanitized hunk preview |
| preview | Explicit none/text/binary/image/HTML kind, bounded media type and size, optional image dimensions, and a required sanitization claim for rendered text/image/HTML previews |
| comment | Persisted comment identity and revision, authenticated actor, exact file/hunk/side/line anchor, unread state, and explicit not-sent/pending/sent/refused agent-delivery state |
| proposal | In review/v2, an exact Git-authority-bound stage, unstage, commit, or conflict-resolution proposal over an exact bounded ordered file set; only commit carries a bounded subject |
| check | Typed lifecycle plus owning CI authority and freshness |
| review | Pending/approved/changes-requested/dismissed plus owning review authority and freshness |
| pull request | Absent/draft/open/closed/merged, exact head revision when present, merge readiness, owning PR authority, and freshness |
| delivery | Not-delivered/pending/delivered/failed plus owning delivery authority and freshness |
| attention | Deterministically derived `Idle`, `NeedsYou`, `Working`, `Done`, or `Blocked`, a compatible closed reason, aggregate unread count, and newest source revision; an empty event list is truthfully `Idle` |

Binary bytes, raw HTML, credentials, provider payloads, repository roots, and
host paths have no representation. Paths are repository-relative presentation
values: absolute paths, backslashes, empty components, `.` and `..` are
refused. HTML is metadata-only and must be marked sanitized before a client may
render a separately obtained preview in its own sandbox.

The current bounds are 128 files, 128 hunks per file and 512 hunks total, 512
UTF-8 bytes per sanitized hunk preview, 256 comments, 128 checks, 32 proposals,
and 128 file identities per proposal. Comments must resolve to an exact line
inside the selected side of a file and hunk in the same snapshot. Proposal
files must exist and their staged/unstaged state must permit the proposed
operation. At most 256 bounded attention events are retained. Every event has
a unique identity and an exact typed origin coordinate: origin kind and
identity where applicable, owning authority identity, and source revision.
The reason must agree with the cited authoritative file, comment, check,
review, pull-request, delivery, or complete-snapshot projection. Duplicate IDs
and duplicate reason/origin coordinates, including aliases under different IDs,
are refused. The projection is derived from those events
with `Blocked` taking precedence over `NeedsYou`, then `Working`, then `Done`;
unread counts are summed and the newest event revision is retained. Callers
cannot author a different projection, and no event may cite a revision newer
than the snapshot. Every embedded review, check, pull-request, and delivery
observation is likewise bounded by the aggregate snapshot revision. An
attention reason that relies on one of those projections requires its source
to be explicitly fresh; `Done` requires fresh review, every required check,
pull-request, and delivery state, so stale last-known success cannot complete a
workspace. Authority-bearing and invariant-bearing Rust fields are private;
constructors and both codecs revalidate the same invariants.

## Scoped proposals and actions

Stage, unstage, commit, and conflict-resolution values are review/v2 proposals,
not generic git execution. Each proposal carries its exact Git authority;
review/v1 proposals cannot authorize any of these actions.
This contract exposes no `execute`, command, shell, argument vector, host path,
or arbitrary provider operation.

Mutation requests are a closed union:

| Action | Required independent authority |
| --- | --- |
| add an anchored comment, send one or a batch of persisted comments to the agent, approve a review | review authority |
| stage, unstage, commit, or resolve one conflict from an exact review/v2 proposal | proposal's Git authority |
| rerun one named check at its exact revision | CI authority |
| open, update, or merge one pull request at exact projection/head revisions | pull-request authority |

Every request carries the exact workspace, expected snapshot revision,
authenticated actor, authentication class, owning authority, and idempotency
key. Before a preview or execution is accepted, the exact authority identity,
target identity, target revision, freshness, and target lifecycle are resolved
against the current authoritative snapshot. A provider session authentication
class is refused for every mutation.
Observing or controlling a provider session never grants filesystem, git, CI,
review, delivery, or pull-request authority. Runtime policy may require more
authority or approval; it may not require less.

## Receipts, conflicts, and ambiguous writes

One idempotency key resolves to one durable receipt. Completed receipts carry
the resulting revision. Conflicts carry the current revision. Refusals are
final. Accepted and unknown outcomes carry no claimed revision and explicitly
say `poll_receipt`; clients reconcile that receipt and never blindly replay the
mutation. Actor, action, receipt, and idempotency identities remain attributable
in every outcome. The custody row integrity-binds the canonical request, full
approval policy, duplicated `approval_required` decision, and, when required,
the exact authenticated approval. A separate transactional `start-write`
admission is recorded only while the grant, revision, target, and approval are
current. The admission is its own canonical document and digest, with a unique
admission identity, trusted admission time, workspace, actor, authentication,
exact authority, action identity and kind, expected revision, request and
approval-policy digests. Its explicit replay outcome never licenses a second
external write.
Once admitted, an unknown result can still be recorded and reconciled after the
approval expires. A completed result is final only when its revision is the
authoritative snapshot revision or separately stored evidence from an
authenticated exact-authority service adapter proves that revision. Exact
terminal replays are returned only after current actor authorization is checked.
Every completed receipt read and terminal replay revalidates that durable
basis: the exact historical authoritative snapshot must still exist or the
canonical completion-evidence row must remain intact. A missing or corrupted
basis fails closed after restart. Completion evidence integrity-binds its
trusted observation time alongside the verifier, authority, result revision,
request digest, and bounded sanitized document.
Receipt polling likewise requires the current authenticated actor, exact
authority scope, trusted time, and an active grant; an opaque receipt or
idempotency key is never authority. Receipt canonical bytes, digest, outcome,
result revision, and current revision are revalidated before the terminal fast
path. Grant events have a monotonic revision and authorization identity. An
initial-grant replay cannot change its lifetime, and neither a stale grant nor
a differently timed revocation can resurrect authority. Reauthorization after
expiry or revocation requires a distinct identity, the exact preceding grant
revision, and a later trusted instant. Authorization identities are retained
and cannot be reused by a later grant revision.

Approval and completion-evidence entry points authenticate the caller's exact
workspace, actor, authentication class, and authority before resolving an
opaque preview identity or comparing its bindings. Unauthorized callers
therefore cannot distinguish a missing preview from an existing one.

On every read, snapshot, preview, approval, receipt, completion-evidence and
duplicated normalized fields are re-derived; corruption fails closed across
process restarts. Comment identity, actor and anchor cannot be rewritten across
snapshots; same-revision values are immutable, edits advance exactly one
revision, and sent-to-agent state is monotonic. Each review-store database is
bound at fresh-schema creation to one explicit authority namespace. A missing
namespace singleton in any previously opened or populated database is
corruption, not an invitation to infer or replace the tenant. Hosted
deployments must use a different database for every tenant/authority domain
until a later schema introduces row-level tenancy. The store still has no
daemon route or real git, CI, provider, or pull-request adapter.

## Shared conformance

`fixtures/platform-v2-review-v1.json` preserves the historical non-actionable
wire document and `fixtures/platform-v2-review-v2.json` is produced by the Rust
source of truth for authority-bearing snapshots. The generated TypeScript
decoder distinguishes the versions, preserves both fully decoded values, and
re-encodes their exact canonical bytes. The cross-language corpus also verifies
that review/v1 proposals cannot authorize a Git action, and verifies
the exact-revision/idempotency action, no-replay unknown receipt, provider-only
authorization refusal, authority mismatch, and a coherent-but-inapplicable v1
document. The shared corpus also checks the Rust `u32` boundary used for hunk,
anchor, image-dimension, and unread fields, derived-attention refusal, and
authority-identity target resolution. All clients should use this same
generated contract rather than infer review or attention state from summaries.
