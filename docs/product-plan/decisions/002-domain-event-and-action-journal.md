# ADR 002 — domain-event and action journal

**Status:** accepted for implementation planning

## Context

The dashboard, TUI, CLI and TypeScript SDK require resumable global events and reconciliation of mutations whose transport response is lost. Per-run spools provide provider output but cannot represent approvals, settings, reloads, transport state, outboxes or cross-domain ordering.

## Decision

Add one durable domain-event journal and one durable action-receipt registry. They are part of the authoritative transaction boundary, not an observability-only log.

```sql
CREATE TABLE legacy_domain_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  topic TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  entity_revision INTEGER,
  schema_version INTEGER NOT NULL,
  authority TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  causation_event_id INTEGER,
  actor_id TEXT,
  generation_id TEXT,
  occurred_at INTEGER NOT NULL,
  recorded_at INTEGER NOT NULL,
  payload TEXT NOT NULL
);

CREATE TABLE legacy_action_receipts (
  action_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  action_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_revision INTEGER,
  request_schema_version INTEGER NOT NULL,
  request_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  result_event_id INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(idempotency_scope, idempotency_key)
);
```

Names and columns remain provisional, but these semantics are required.

## Transaction rule

Every state transition and its authoritative domain event commit in the same SQLite transaction. An external effect commits its outbox intent and domain event atomically. Event consumers never infer state by scraping logs.

`event_id` is a database commit-order cursor, not a claim about provider occurrence order. Records also carry `occurred_at`, correlation/causation, entity revision and source coordinates. Cross-provider causal relationships use explicit IDs rather than timestamps.

## Subscription and snapshots

- `GetSnapshot` reads a consistent snapshot and returns its event watermark.
- `Subscribe(after_event_id)` begins strictly after that watermark.
- Topic/resource authorization is applied both to snapshots and every streamed event.
- If retention has passed a cursor, return `resync_required` with the relevant snapshot operation.
- Slow consumers use bounded server buffers; the journal remains the replay source.
- Preview provider deltas may use a bounded ephemeral channel, but authoritative completion/state events enter the journal.

## Action receipts

- The server records or finds the receipt before executing a mutation.
- Reusing a key with a different request hash returns an idempotency conflict.
- A lost response is reconciled by action ID/idempotency key.
- Receipt states distinguish accepted, executing, completed, rejected, conflicted, failed and outcome-unknown.
- Completion points to the authoritative result event.
- Retention cannot remove a receipt while its retry window, audit window or referenced outbox remains active.

## Consumer cursors

Durable internal consumers—outbox projections, Manage publication, search indexing and audit export—store named cursors. User UI subscriptions usually keep client cursors and resnapshot after retention. No consumer advances its durable cursor before completing the transactional effect derived from the event.

## Retention and privacy

Event payloads contain bounded projections, not unlimited prompts/transcripts. Sensitive artifacts are referenced by authorized artifact ID. Retention may compact old entity events into snapshots only after audit, replay, legal-hold and action-receipt requirements are satisfied.

## Verification

Inject crashes before and after every state/event/receipt/outbox commit boundary. Prove snapshot-plus-subscribe has no gap, duplicate delivery is harmless, idempotency keys cannot be reused with different content, unauthorized topics never leak, and current/previous generations can consume the same event schemas.
