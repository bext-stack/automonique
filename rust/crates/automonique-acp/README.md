# Automonique ACP adapter

`automonique acp` is Automonique's stable Agent Client Protocol v1 stdio
server. It uses the official Rust SDK pinned at `2.0.0` and projects the
canonical Platform v1 domain; it is not a second executor or session authority.

Supported stable surface:

- `initialize` with honest capability negotiation;
- `session/new`, `session/load`, and cursor-based `session/list`;
- baseline text and resource-link prompts up to 64 KiB;
- ordered assistant messages, thought summaries, tool lifecycle updates, and
  allow-once/deny approval prompts;
- `session/cancel`, mapped to the exact current canonical run revision;
- durable opaque ACP-to-provider-session coordinates across adapter restarts.

The adapter intentionally does not advertise client-provided MCP servers,
additional workspace roots, image/audio/embedded prompt content, session
configuration, or provider/model selection until the canonical Platform can
honor those effects. Unsupported inputs fail with typed JSON-RPC errors.

Run the Automonique daemon normally, then configure an ACP client to launch:

```text
automonique acp
```

The command reads the same daemon configuration environment as
`automonique daemon --foreground`. The state directory must be private and the
Platform and progress Unix sockets must belong to that daemon instance.

The ACP mapping database contains compatibility coordinates only. Provider
sessions, runs, events, approval records, receipts, and cancellation remain
authoritative in Automonique's canonical stores.
