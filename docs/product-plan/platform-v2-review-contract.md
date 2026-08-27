<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v2 review, attention, checks, and pull requests

## Compatibility and scope

`automonique.platform/review/v1` is an additive sub-contract available only
after Platform major version 2 is negotiated. It does not add a Platform v1
resource kind, field, request, or response, and it never serializes review
meaning into a v1 summary string. A v1-only peer continues to receive exactly
the installed Platform v1 contract and no structured review projection.

This slice defines shared values, exact canonical codecs, generated TypeScript,
and deterministic fixtures. It does not implement a daemon route, durable
store, git adapter, CI adapter, pull-request adapter, or client UI. Runtime
implementations must construct these values only from already authorized,
sanitized observations and must persist actions and receipts before claiming an
outcome.

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
| proposal | Typed stage, unstage, or commit proposal over an exact bounded ordered file set; only commit carries a bounded subject |
| check | Typed lifecycle plus owning CI authority and freshness |
| review | Pending/approved/changes-requested/dismissed plus owning review authority and freshness |
| pull request | Absent/draft/open/closed/merged, merge readiness, owning PR authority, and freshness |
| delivery | Not-delivered/pending/delivered/failed plus owning delivery authority and freshness |
| attention | Authoritative `NeedsYou`, `Working`, `Done`, or `Blocked`, a compatible closed reason, unread count, and source revision |

Binary bytes, raw HTML, credentials, provider payloads, repository roots, and
host paths have no representation. Paths are repository-relative presentation
values: absolute paths, backslashes, empty components, `.` and `..` are
refused. HTML is metadata-only and must be marked sanitized before a client may
render a separately obtained preview in its own sandbox.

The current bounds are 128 files, 128 hunks per file and 512 hunks total, 512
UTF-8 bytes per sanitized hunk preview, 256 comments, 128 checks, 32 proposals,
and 128 file identities per proposal. Comments must resolve to a
file and hunk in the same snapshot. Attention cannot cite a revision newer than
the snapshot. Authority-bearing and invariant-bearing Rust fields are private;
constructors and both codecs revalidate the same invariants.

## Scoped proposals and actions

Stage, unstage, and commit values are proposals, not generic git execution.
This contract exposes no `execute`, command, shell, argument vector, host path,
or arbitrary provider operation.

Mutation requests are a closed union:

| Action | Required independent authority |
| --- | --- |
| add an anchored comment, send a persisted comment to the agent, approve a review | review authority |
| rerun one named check at its exact revision | CI authority |
| open, update, or merge one pull request at exact projection/head revisions | pull-request authority |

Every request carries the exact workspace, expected snapshot revision,
authenticated actor, authentication class, owning authority, and idempotency
key. A provider session authentication class is refused for every mutation.
Observing or controlling a provider session never grants filesystem, git, CI,
review, delivery, or pull-request authority. Runtime policy may require more
authority or approval; it may not require less.

## Receipts, conflicts, and ambiguous writes

One idempotency key resolves to one durable receipt. Completed receipts carry
the resulting revision. Conflicts carry the current revision. Refusals are
final. Accepted and unknown outcomes carry no claimed revision and explicitly
say `poll_receipt`; clients reconcile that receipt and never blindly replay the
mutation. Actor, action, receipt, and idempotency identities remain attributable
in every outcome.

## Shared conformance

`fixtures/platform-v2-review-v1.json` is produced by the Rust source of truth.
The generated TypeScript decoder must preserve its fully decoded values and
re-encode its exact canonical bytes. The cross-language corpus also verifies
the exact-revision/idempotency action, no-replay unknown receipt, provider-only
authorization refusal, authority mismatch, and a coherent-but-inapplicable v1
document. All clients should use this same generated contract rather than infer
review or attention state from summaries.
