# ADR 005 — artifacts and attachments

**Status:** accepted for implementation planning

## Context

Automonique handles Slack/Support attachments, screenshots, patches, provider diffs, transcripts, build outputs and current terminal file transfer. These objects are too large or sensitive for ordinary event/database payloads and need provenance, authorization, retention and publication state.

## Decision

Create a content-addressed artifact service owned by Automonique. Metadata is durable in SQLite; bytes live in a private state directory or configured object store. Domain events and provider records reference artifact IDs and hashes.

## Artifact record

Each artifact stores:

- opaque artifact ID, content hash, byte length and media type;
- kind: input attachment, patch, commit bundle, screenshot, log, transcript, report, build output or export;
- tenant/workspace/work/attempt/run/session/turn coordinates;
- source actor/transport/provider and provenance chain;
- created revision/time and producing binary/tool identity;
- scan/validation state and bounded error;
- visibility: internal, approver-reviewable, operator, or client-publishable;
- retention class, expiry, legal hold and deletion state;
- optional encryption/key reference without storing key material.

## Ingestion

- Stream into an exclusive temporary file while hashing and enforcing size limits.
- Reject unsafe names, paths, sparse/device files and unsupported archive structures.
- Detect media type from content and validate claimed type.
- Quarantine external content until policy checks complete.
- Archive extraction is bounded by file count, expanded size, nesting and path rules.
- Deduplication never widens authorization: identical bytes may share storage while retaining separate metadata/access records.

## Workspace and provider use

Artifacts enter a runner only through explicit immutable `RunSpec` grants. Inputs mount/read from verified paths; outputs are captured from allowed workspace paths after the tool completes. Provider raw records may reference artifacts but cannot create arbitrary host paths.

Patches, diffs, screenshots, tests and build outputs form a review bundle tied to the exact base/action revision. Changing any reviewed artifact produces a new review revision.

## Publication and retrieval

- Retrieval is authorized against artifact metadata and actor/resource policy.
- Remote downloads use short-lived scoped URLs or streamed authenticated responses.
- Client-visible publication is an explicit outbox action and never implied by agent generation.
- Raw agent output remains internal unless a typed workflow marks a bounded artifact publishable.
- Every download/publication/deletion produces an audit/domain event.

## Retention and deletion

Retention is policy-driven by kind and terminal state. Failed/security-relevant runs may retain diagnostic artifacts longer; user content follows privacy/deletion rules. Deletion removes access first, then bytes after reference/legal-hold checks. Backups respect tombstones and retention.

## Compatibility with interactive shells

If the current shell/file-transfer feature is retained, upload/download uses this artifact pipeline rather than base64 bodies or arbitrary relative path access. Shell execution remains a separate explicitly authorized facility, not part of ordinary TUI session attachment.

## Verification

Test large streams, hash mismatch, MIME spoofing, malicious archives, symlink/hard-link races, dedup authorization, partial writes, disk full, concurrent delete/read, retention, backup/restore, cross-tenant access and publish-exactly-reviewed behavior.
