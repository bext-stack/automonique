# Public agent protocols

**Status:** accepted expansion architecture

## Principle

Automonique exposes one durable domain through several compatibility protocols. ACP, MCP, OpenAI and A2A adapters terminate external wire formats; they do not create alternate session stores, approval systems, tool registries or authorization policy.

## ACP agent server

`automonique acp` and the daemon ACP endpoint let VS Code, Zed, JetBrains and compatible hosts use Automonique as the agent. This is separate from Automonique consuming Jcode/opencode ACP as a provider.

The server maps ACP sessions to durable Automonique sessions and exposes chat, streaming messages/thought summaries where allowed, tool activity, file diffs, terminal events, model selection and approval prompts. Working directory is resolved through the workspace registry. Host `allow once`, durable allow rules and deny map to typed provider/tool approvals; a host cannot enable global bypass mode.

Disconnect/restart resumes from durable session and event cursors. Host capabilities are negotiated, and unsupported rich events degrade to bounded text without losing authoritative records.

### Implemented stable-v1 profile

The production Rust adapter is exposed by `automonique acp` and uses the
official ACP SDK. It implements initialization, durable new/load/list session
mapping, 64 KiB baseline prompts, ordered message/thought/tool projection,
allow-once/deny approval requests, exact run cancellation, and restart-safe
provider-session continuation. Capability negotiation is fail-closed: media,
client MCP servers, additional directories, and configuration/model controls
are not advertised until their effects exist in the canonical Platform
domain. ShellDeck consumes this same profile as an ACP client; it does not own
an alternate provider runtime.

## OpenAI-compatible HTTP API

Provide authenticated, versioned endpoints for:

- `/v1/models` and Automonique capabilities;
- `/v1/chat/completions` with streaming;
- `/v1/responses`, stored response IDs and `previous_response_id`;
- `/v1/runs`, event polling/stream, stop and exact approval responses;
- sessions, jobs/automations, skills and toolset discovery;
- health/readiness and scoped usage.

OpenAI compatibility is honest: Automonique-specific tool progress uses namespaced SSE events/extensions, and unsupported fields return typed errors. Request-selected provider/model/tools/profile remain constrained by actor policy. Idempotency keys and durable receipts cover run creation and mutations. Stored responses have tenant-aware retention and deletion.

The API supports Open WebUI, LibreChat, LobeChat and ordinary SDK clients without exposing internal credentials. Browser CORS is allowlisted, CSRF/session rules remain distinct from bearer API clients, and public binds require TLS plus strong identity.

## Automonique-native Runs API

The TypeScript SDK's native API remains the complete surface for cursor-based events, exact revisions, attachments, artifacts, work graphs, sandboxes and reload. OpenAI/ACP clients can discover a native resource link when they need semantics their protocol cannot represent.

## MCP server

The scoped MCP server described in [Tools, MCP, extensions and hooks](tools-extensions-and-hooks.md) exposes selected tools/resources/prompts and supports Streamable HTTP plus local stdio. External MCP identity resolves to an Automonique service account; sampling and elicitation create ordinary budgeted model/approval events.

## A2A and relay

An optional Agent-to-Agent adapter publishes agent cards/capabilities and accepts authenticated tasks mapped to durable work. A relay protocol supports independently hosted clients/connectors over mutually authenticated WebSocket/HTTPS with reconnect cursors, media artifacts and command manifests. Neither protocol trusts remote agent claims as user approval.

## Local model/OAuth proxy

An optional loopback-only OpenAI-compatible proxy lets Codex, Aider, Cline and scripts use an authorized provider/OAuth credential through Automonique. It issues short-lived scoped local tokens, enforces provider/model/budget policy, separates billing identities and records usage. It is not a way to export subscription credentials or bypass provider terms.

## API versioning and SDK generation

Rust schemas generate OpenAPI, JSON Schema and event manifests plus TypeScript clients. Protocol adapters have independent conformance suites and capability tables. Adjacent releases coexist during daemon reload; unsupported mutations fail closed and external clients can remain read-only when safe.

## Exit gate

ACP editor sessions survive daemon reload; OpenAI clients pass streaming/multi-turn/idempotency tests; MCP/A2A/relay identities remain tenant-scoped; approvals retain exact targets; and no compatibility adapter creates an effect unavailable through the canonical domain services.
