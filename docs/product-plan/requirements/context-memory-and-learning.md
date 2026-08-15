# Context, memory and learning

**Status:** accepted product architecture

## Purpose

Automonique provides one cross-provider context contract instead of inheriting four subtly different behaviors from Jcode, Claude Code, Codex and opencode. Provider-native context features remain usable only when their effective inputs, limits and mutations can be observed and reconciled with this contract.

## Context assembly

Every turn persists a `ContextManifest` with ordered, hashed components:

- product/persona and tenant policy revisions;
- actor profile and explicit conversation/session state;
- workspace rules discovered from registered `AGENTS.md`, `.automonique.md`, `CLAUDE.md`, provider-specific rules and an optional user identity file;
- explicitly referenced files, folders, line ranges, Git diffs/commits, artifacts, URLs and prior sessions;
- selected skills and tool/MCP schemas;
- memory snapshots and retrieved session evidence;
- provider capabilities, sandbox summary, remaining budgets and approval state;
- compression lineage and token estimates by component.

Precedence is deterministic and visible. A lower-trust repository or retrieved document can supply task context but cannot override system, tenant, sandbox or approval policy. Each component has source, trust class, byte/token cap, redaction result and content digest.

Project rule discovery is bounded to the registered workspace. Rules from parent/home directories never leak into unrelated projects. Cross-provider portability uses `AGENTS.md` as the preferred shared format; provider-specific files are labelled compatibility inputs rather than silently becoming Automonique policy.

## Explicit context references

TUI, desktop, dashboard, SDK and supported messaging surfaces share typed references:

- `@file`, including line ranges and exact artifact digests;
- `@folder`, with bounded tree/filter/depth and explicit materialization;
- `@diff`, `@staged`, `@commit` and `@branch`;
- `@url`, fetched through the reviewed web capability;
- `@session`, `@turn`, `@run`, `@ticket` and `@artifact`;
- `@workspace` and named multi-folder project references.

References resolve before approval/launch, show size and provenance, and reject secrets, binary confusion, traversal and authorization changes. Large inputs become artifacts or retrieval indexes instead of unbounded inline prompt text.

## Context budgets, caching and compression

The context engine exposes estimated and provider-reported tokens by system policy, rules, skills, memory, tools, MCP, attachments and conversation. Clients show the same breakdown and warn before forced compression.

Compression is a durable operation with source range, compressor provider/model, prompt/template digest, output digest, protected facts and verification status. It never rewrites the audit transcript. The active provider receives a derived conversation view; authoritative original messages remain queryable. Users can request compression, inspect its lineage and fork before compression.

Prompt-cache policy preserves stable prefixes and records cache-read/write telemetry when providers expose it. Mid-session model, tool-schema, persona, policy or workspace changes explicitly invalidate the affected cache and may require a new host/turn revision.

## Conversation controls

Input is a durable per-session queue with IDs and revisions. Authorized clients may add, edit, reorder or withdraw queued input until the provider acceptance boundary. `stop` halts the active turn at the safest supported boundary; `steer` is a separate provider capability. `retry` creates a new attempt linked to the original turn. `undo` changes conversation projection only when the provider/session semantics make this representable and never erases audit evidence.

Every surface exposes new/reset, fork, rename/archive, retry, undo, stop, queued-input management, usage, insights and compression through the command registry—not local regex copies.

## Memory model

Memory is not one text file. It has typed, tenant-scoped stores:

- `user_profile`: communication preferences and stable user facts;
- `workspace_memory`: conventions, environment facts and durable lessons;
- `team_memory`: reviewed knowledge shared with a role/team;
- `task_memory`: bounded state for a goal, automation or work graph;
- `episodic_index`: searchable session/turn references, not duplicated summaries;
- external provider records for optional Honcho, OpenViking, Mem0, Hindsight, Holographic, RetainDB, ByteRover, Supermemory or future adapters.

Entries carry provenance, confidence, sensitivity, visibility, expiry/review date and supersession links. Writes are revisioned proposals governed by actor/tenant policy. Corrections supersede; deletion follows retention/legal-hold rules. Prompt injection can only propose lower-trust memory and cannot promote itself to policy.

SQLite FTS5 provides bounded full-text session search with authorization filters, surrounding-message navigation and exact citations. Optional semantic/vector or external-memory retrieval is an adapter behind the same evidence contract. Any LLM synthesis cites the underlying messages and remains a derived artifact.

### Shipped memory subset — amended 2026-08-15

A first, deliberately narrow implementation of this section ships in the
daemon. It is folded in here so the specification has a home for it; it does
not amend the target above, which stays the goal.

What exists: one tenant-scoped SQLite store per host, holding immutable
external-identity bindings for the two live chat channels, bounded conversation
messages expired on a fixed schedule, revisioned long-term memories carrying
provenance, confidence, sensitivity, visibility, review date and tombstones,
and an audit trail for proposal, approval, denial, supersession and forgetting.
Retrieval is FTS5 only. Operator verbs on the chat surfaces render and review
memory, propose one, tombstone one, and reset the conversation projection
without touching long-term memory. Inbound messages are captured through a
redaction pass, and a heuristic proposes candidate memories at private
visibility rather than accepting them.

How it differs from the target, deliberately and for now: the typed store split
above (`user_profile` / `workspace_memory` / `team_memory` / `task_memory` /
`episodic_index`) is one store, not five; no semantic or external-memory
adapter exists; and the tenant is a single operator-configured value with no
migration between tenants — changing it re-keys nothing and makes existing rows
unaddressable, which is why the operator must set it before an upgrade rather
than after.

Operator procedure for the shipped subset — configuration file, verbs, backup
and the legacy import path — is [`docs/memory-operations.md`](../../memory-operations.md).
That document is a how-to and carries no requirements authority; where it and
this section disagree, this section governs.

Automonique implements the agentskills.io `SKILL.md` format with progressive disclosure:

- bundled, organization, tenant, workspace, user and session scopes;
- catalog/search/inspect/install/update/uninstall/publish operations;
- direct immutable URL/Git repository sources plus allowlisted registries;
- skill bundles that compose named skills with bounded additional instruction;
- conditional/fallback activation based on available capabilities;
- declared scripts, references, assets, secrets, network, tools and platform support;
- signature/provenance, license, digest and vulnerability/revocation state.

Successful complex work, corrections or recovered failures may create a `LearningProposal` containing candidate memory, skill patch or new skill plus source evidence and tests. Policy chooses automatic rejection, human review, sandboxed trial or narrow auto-accept for non-executable personal memory. Agent-created executable skills are never silently activated in production.

A curator tracks use/view/patch counts, last activity, health and overlap. It can mark stale, archive, restore, pin, back up and propose consolidation. It never deletes durable evidence or edits bundled/vendor skills. Consolidation is optional and budgeted.

## Personality and profiles

Persona is versioned content, separate from security policy. Automonique supports named personalities and a canonical `SOUL.md`-compatible import/export, but persona text cannot alter authority.

An **agent profile** packages persona, default provider/model, auxiliary models, tools, skills, memory adapters, channel bindings and non-secret settings. It is distinct from tenant, workspace, sandbox profile and provider account. Profiles can be cloned, exported, imported and distributed with provenance; secrets and user memories are excluded by default. Multiple profiles may run concurrently without sharing sessions, credentials, memory or connector leases unless an explicit grant says otherwise.

## Learning journey and explainability

SDK clients may render a revisioned graph of memories, learned skills, source sessions, corrections, consolidations and outcomes. Nodes are editable only through their typed service. The view never turns inferred personality traits into facts without provenance and user correction/deletion controls.

## Exit gate

Ship only when context assembly is identical across supported providers at the declared abstraction level; token/compression lineage survives reload; queue/retry/undo behavior is capability-correct; FTS and external-memory results are tenant-safe; skill installation and learning proposals pass supply-chain/sandbox review; and every memory/skill/profile mutation is inspectable, reversible where promised and represented in the TypeScript SDK.
