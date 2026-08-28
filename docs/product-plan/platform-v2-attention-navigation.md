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
unauthorized, stale, or unregistered source refuses explicitly; the host never
synthesizes observation time or source revision from the request time. This
contract and bootstrap path do not yet provide a runtime producer, source
discovery, hot reload, or a client consumer, so they are foundation work rather
than completion of the live cross-client attention flow.
