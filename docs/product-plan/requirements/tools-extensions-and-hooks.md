# Tools, MCP, extensions and hooks

**Status:** accepted product architecture

## Canonical tool runtime

Automonique owns a versioned tool registry independent of any one provider. A `ToolDescriptor` records schema, capability ID, provenance/digest, trust class, side-effect class, required approval, sandbox profile, credential audiences, egress, resource budget, platform support and output/artifact contract.

Toolsets are named policy bundles assignable by tenant, profile, workspace, channel and automation. Effective tools are the intersection of all applicable grants. Messaging surfaces never receive broad tools merely because the CLI profile has them.

Large registries use deferred schema loading. Sessions initially receive a bounded searchable catalog; a BM25/semantic `tool_search` returns authorized candidates and `tool_describe` loads exact schemas. Search cannot reveal inaccessible tool names or mutate the session toolset without a durable event. Tool-schema changes have prompt-cache and provider-capability consequences.

## Built-in capability families

The registry supports, behind explicit policy and adapters:

- safe file read/write/patch/search and artifact operations;
- terminal/process, Git/worktree/review and LSP diagnostics;
- web search/extract and browser automation;
- image/vision, image generation, video generation and document/OCR tooling;
- TTS, transcription and media conversion;
- memory, session search, goals, automations and delegation;
- connector/notification and typed business integrations;
- computer-use through accessibility/screenshot drivers;
- MCP and organization-specific tools.

These are capabilities, not a default allow-all bundle.

## Programmatic tool composition

An `execute_workflow` tool runs a bounded WASI component, JavaScript isolate or Python process in `extension-isolated` mode. The program calls approved tools over an inherited capability socket, allowing loops, filtering and branching without another model turn per call.

The workflow receives no ambient secrets/network/filesystem. Its call graph, maximum calls, recursion prohibition, time/CPU/memory/output budget and eligible tool IDs are fixed in `RunSpec`. It cannot invoke itself, delegation, arbitrary MCP, approval decisions or privilege brokers unless an explicit workflow profile permits a typed operation. Every nested call retains actor/run/causation IDs and ordinary tool approval.

## Native MCP client and server

Automonique is both:

- an MCP client for local stdio and remote Streamable HTTP servers; and
- a scoped MCP server exposing selected Automonique services/tools to authorized external clients.

The client lifecycle includes add/remove/list/test, catalog/install, discovery timeout, reconnect, health, per-tool filtering and explicit environment/credential mapping. Each server runs in its own attested child sandbox or crosses reviewed HTTPS identity. Server-initiated sampling is disabled by default; when enabled it becomes a budgeted, policy-checked nested model request with no implicit user authority.

The MCP server exports capability-filtered tools, resources and prompts. It never exposes raw SQLite, hidden reasoning, credentials, unrestricted artifacts or broker input. OAuth/credential identity maps to the same durable actor/tenant policy as SDK clients.

## Plugin and extension model

Extensions are signed, content-addressed packages with a manifest declaring:

- type: tool, hook, memory provider, context engine, model/provider, browser/media backend, secret source, connector, dashboard/desktop/TUI UI or distribution;
- entry points and supported protocol/schema ranges;
- tools/events/routes/settings contributed;
- required sandbox, files, network, credentials and resources;
- license, publisher, source, build provenance and update channel;
- configuration schema and migration behavior.

Backend extensions run out of process. TypeScript extensions use generated `@automonique/sdk/extension`; Rust/WASI extensions use equivalent versioned protocols. UI extensions cannot gain backend authority from rendering; their server API and storage are namespaced. Install/update is previewed, verified and canaried. Revocation quarantines new loads while preserving evidence and rollback.

## Hook system

Typed hooks cover daemon/generation, intake/routing, session/turn, provider/model, tool, approval, subagent/work-graph, artifact/publication, connector and automation lifecycle.

Hook classes are explicit:

- observer: asynchronous, cannot change behavior;
- filter: may reject a bounded action with a typed reason;
- transformer: may return schema-validated bounded output;
- context provider: may add labelled untrusted context within a budget;
- workflow trigger: creates a new durable input/action, never executes inline privilege.

Ordering, timeout, failure policy and causation are deterministic. A hook cannot silently approve, widen a sandbox, rewrite historical messages or block reload indefinitely. Shell hooks are an optional compatibility adapter: scripts live under a registered immutable directory, require allowlisting and run in an extension sandbox.

## Secrets and configuration providers

Secret-source adapters support systemd credentials, encrypted local storage, 1Password, Bitwarden, command helpers and future vaults. A command helper is a pinned executable with a closed argument schema and empty environment, not an arbitrary shell command. Returned values remain sealed descriptors.

## Developer experience

Ship scaffolding, schema generation, conformance suites, fake hosts, fixture redaction, hot-reload only in development, and compatibility diagnostics for every extension type. Catalog browsing never installs code. Production startup never downloads or runs package lifecycle scripts.

## Exit gate

The native tool/MCP/extension/hook contracts are complete in Rust schemas and TypeScript SDK; deferred tool search preserves authorization; workflow RPC cannot escape its call budget; all extension types pass sandbox and reload tests; and disabling/quarantining an extension leaves the daemon, active evidence and supported sessions recoverable.
