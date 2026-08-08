# Work-DAG crosswalk

Maps every item in `work-dag.toml` to the spec documents that define it.
Paths are relative to this directory. Documents marked *(initial transfer)*
were transferred byte-for-byte on 2026-08-05 at 10:04Z; the remaining corpus
was transferred sanitized later the same day (see `provenance.toml`).

| Work ID | Title (abridged) | Primary spec documents |
|---------|------------------|------------------------|
| BOOT-001 | Idempotent bootstrap, durable supervisor | `../bootstrap/BOOT-001.md`, requirements/self-hosting-and-bootstrap.md, requirements/ai-implementation-harness.md |
| BOOT-002 | Sandboxed worktree, path lease, Git broker | requirements/sandbox-management.md, requirements/target-architecture.md |
| BOOT-003 | Author adapter with durable provider records | requirements/agent-integrations.md, requirements/models-media-and-execution.md *(initial transfer)* |
| BOOT-004 | Independent reviewer/fixer/build evidence loop | requirements/ai-implementation-harness.md, requirements/verification-and-rollout.md |
| BOOT-005 | Publication and exactly-once merger broker | requirements/operations-and-governance.md, reference/work-breakdown.md (see note below) |
| BOOT-006 | Signed self-update, generation health, rollback | requirements/reload-protocol.md, requirements/self-hosting-and-bootstrap.md |
| BOOT-007 | Fault-injected autonomous development proof | requirements/self-hosting-and-bootstrap.md, requirements/verification-and-rollout.md |
| CORE-001 | Identities, revisions, authorization | requirements/state-and-protocols.md |
| CORE-002 | Event journal, action receipts, fenced leases | requirements/state-and-protocols.md |
| CORE-003 | Content-addressed artifacts, retention | requirements/state-and-protocols.md |
| EXEC-001 | Execution hosts, sandbox attestations, provider protocol | requirements/target-architecture.md, requirements/sandbox-management.md, requirements/agent-integrations.md |
| EXEC-002 | Durable work graphs, attempts, budgets, cancellation | requirements/state-and-protocols.md, reference/work-breakdown.md |
| EXEC-003 | Workspace registry, snapshot, integration contracts | requirements/state-and-protocols.md |
| PROVIDER-001 | Provider capability catalog, sessions, reconnect | requirements/agent-integrations.md, requirements/models-media-and-execution.md *(initial transfer)* |
| CONTROL-001 | Authenticated local API, generated schemas | requirements/target-architecture.md, requirements/typescript-sdk.md |
| CONTROL-002 | CLI, doctor, reconciliation, operator recovery | requirements/operations-and-governance.md, requirements/client-experience-and-surfaces.md |
| RELOAD-001 | Overlapping generation handoff, automatic rollback | requirements/reload-protocol.md, requirements/goals-and-invariants.md |
| SDK-001 | Generated TypeScript SDK, conformance transport | requirements/typescript-sdk.md (Apache-2.0 boundary) |
| CLIENT-001 | Operator TUI over shared contracts | requirements/operator-tui.md, requirements/client-experience-and-surfaces.md |
| CLIENT-002 | Web dashboard and browser surface specification | requirements/client-experience-and-surfaces.md, requirements/typescript-sdk.md, CONTROL-001/SDK-001 outputs |
| AUTO-001 | Automations, goals, schedules, trigger intake | requirements/automation-goals-and-triggers.md *(initial transfer)* |
| CONTEXT-001 | Context manifests, memory, skills, profile policy | requirements/context-memory-and-learning.md *(initial transfer)* |
| CONNECTOR-001 | Generic connector SDK, identity, outbox conformance | requirements/connector-catalog.md *(initial transfer)*, requirements/channel-integrations.md (Apache-2.0 boundary) |
| PROTOCOL-001 | ACP, MCP, OpenAI, A2A projection adapters | requirements/public-agent-protocols.md *(initial transfer)*, requirements/tools-extensions-and-hooks.md |
| RELEASE-001 | Reproducible builds, provenance, SBOM, recovery bundle | requirements/verification-and-rollout.md, requirements/self-hosting-and-bootstrap.md, requirements/operations-and-governance.md |
| SEC-001 | Product threat model and security requirements | requirements/sandbox-management.md, requirements/operations-and-governance.md, `../bootstrap/threat-model.md` (bootstrap scope only) |
| PRODUCT-001 | Capability-ledger closure, self-hosting acceptance | requirements/external-capability-ledger.md *(initial transfer)*, reference/corpus-index.md (completion definition), reference/feature-parity.md |
| PRODUCT-002 | End-to-end acceptance incl. security and dashboard specs | PRODUCT-001, SEC-001 and CLIENT-002 outputs |

## Notes

- **BOOT-005** has no standalone requirement doc: its authoritative contract
  is `../bootstrap/BOOT-002-007.md` (publication fencing, exactly-once merger,
  reconciliation), backed indirectly by self-hosting-and-bootstrap and
  operations-and-governance.
- **SEC-001** closes a gap found in the staging gap review: only a
  bootstrap-scope threat model existed. Its output is a product-level threat
  model and security-requirements document under this directory, owned by the
  same precedence rules as other requirements.
- **CLIENT-002** closes the dashboard gap: the browser/web surface was only
  mentioned in passing by client-experience-and-surfaces. Its output is a
  dashboard spec document under this directory.
- **PRODUCT-002** exists because durable plan imports forbid changing an
  existing item's dependencies after import; it extends PRODUCT-001 closure
  over SEC-001 and CLIENT-002 without editing PRODUCT-001.
- `reference/work-breakdown.md` contains the detailed legacy ticket
  ordering from which `work-dag.toml` was derived. The checked `work-dag.toml`
  is canonical; where they disagree, the DAG wins.
- `reference/migration-plan.md` and `reference/feature-parity.md` describe
  parity with the legacy product. The repository's non-goals (maintaining
  the legacy application) take precedence; these docs inform capability
  completeness, not maintenance duty.
- **Legacy compatibility dormancy:** `requirements/state-and-protocols.md`
  presents `legacy_*` tables and `legacy.*` protocol names as a version-1
  compatibility surface inherited from the legacy daemon. This
  clean-room repository does not maintain that daemon, so compatibility
  surfaces are dormant until an owner decision activates legacy migration.
- SDK/connector docs (`typescript-sdk.md`, `channel-integrations.md`,
  `connector-catalog.md`) describe components under the Apache-2.0
  `sdk/`/`integrations/` boundary per `LICENSE-POLICY.md`.

## Reading order for workers

1. checked-in repository policy, governance and bootstrap contracts;
2. `README.md` (precedence), `architecture.md`, `self-development.md`,
   `work-dag.toml`;
3. the primary requirement docs listed above;
4. `reference/` material only for legacy-compatibility context, never as a
   source of new product requirements.
