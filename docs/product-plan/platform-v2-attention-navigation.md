<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v2 authoritative attention navigation

`automonique.platform/attention/v1` is an additive read contract available only
after Platform major version 2 is negotiated. Its typed read method is
`get_attention_source_snapshot`. It does not change Platform v1 or the existing
`automonique.platform/review/v2` document.

The request names one opaque authoritative source, exact project, and exact
`UserWorkspace`. The result is a complete atomic replacement for that tuple,
not a patch and not a client-authored attention list. Its non-zero source
revision names the complete value, `previous_revision` names the exact value it
replaces, and `observed_at_ms` is the source observation instant. Revision one
has no predecessor. Later revisions are strictly monotone and must point to the
exact predecessor accepted by the consumer.

Every item identity is opaque and meaningful only within its source. An issuer
must never reuse an item identity during the source's lifetime. Item revisions
are monotone: changing any field of an existing item requires a greater item
revision; the same item revision is immutable. Removal is represented only by
absence from the next complete source snapshot. The Rust successor validator
checks the source, project, workspace, predecessor, source revision,
observation time, and surviving item revisions before a consumer replaces its
current value. The durable host store additionally retains every previously
issued item identity after removal and refuses later reuse by that source in
any project or `UserWorkspace` tuple. This lifetime custody does not widen
tuple-scoped request authorization.

Each item contains a closed `NeedsYou`, `Working`, `Done`, or `Blocked` state,
a compatible closed reason, an explicit unread boolean, its observation time,
and a bounded ordered nested-agent path. Provider-session sources require an
authority-qualified Platform v1 `session` coordinate on every item. Review and
orchestration sources forbid that coordinate, so clients cannot infer a
provider session from labels, chronology, or summaries.

The contract has no representation for client-local pane, tab, window,
terminal, host path, or workspace-layout identifiers. ShellDeck consumes the
project, `UserWorkspace`, and optional authority-qualified Platform session,
then independently re-resolves those coordinates against its current
authorized workspace/session catalogue. Only after that revalidation may it
select an existing local tab. A stale, foreign, missing, duplicate, or
ambiguous mapping must fail closed, and the item must not be marked read.

Canonical Rust codecs and the
`fixtures/platform-v2-attention-v1.json` corpus reject unknown fields, unknown
enum spellings, wrong schemas, malformed coordinate kinds, oversized frames,
out-of-order item IDs, mixed state/reason pairs, cyclic or over-depth agent
paths, and provider/local coordinate confusion. When explicitly bootstrapped,
the Platform v2 host serves only snapshots validated from its private operator
source registry and tenant-bound durable store. An absent, changed, malformed,
unauthorized, stale, or unregistered bootstrap source refuses explicitly; the
host never synthesizes its observation time or source revision from the request
time. That path remains available for sources outside the runtime conventions.

The production host also projects three runtime-owned source families from the
same tenant-bound durable state used by Platform v2. Review and orchestration
sources use the exact `UserWorkspace` id as their source id. Provider-session
sources use the exact retained `WorkSession` id already present in the bounded
authorized work-context catalogue. A review source exists only when its durable
review snapshot exists; absence refuses rather than becoming an empty review.
Orchestration projection overflow remains explicitly unavailable. A retained
session read revalidates the exact session-to-attempt-to-workspace lineage and
copies only its authority-qualified Platform session coordinate. It never
derives a pane, tab, label, or local layout target.

Runtime snapshots pass through the same atomic attention store. A semantically
unchanged observation replays the exact durable document. A changed complete
item set advances the source revision once, points to the exact predecessor,
advances changed item revisions, and preserves unchanged item revisions and
observation times. One logical orchestration or retained-session record keeps
its current item id across unrelated producer revisions and attention-state
changes. A `Waiting` orchestration record or `Hibernated` session removes that
item atomically; a later reappearance mints a new incarnation instead of
reusing the retired id. A restart therefore cannot reset a source or reuse a
removed item id. The hosted cockpit discovers only those deterministic source
ids from its bounded authorized work-context inventory and renders
`get_attention_source_snapshot` results; it does not substitute review summary
attention. Desktop and mobile consumers and cross-client live acceptance remain
separate milestones.
