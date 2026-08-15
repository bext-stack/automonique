# Monique memory operations

Monique's canonical memory is the private `agent-memory.sqlite3` database in the daemon state directory. SQLite—not prompts, Obsidian, Git, Slack, Telegram, or a model provider—is authoritative.

The store retains four distinct things:

- immutable Slack and Telegram external-identity bindings;
- bounded conversation messages, expired after 90 days;
- revisioned long-term memories with provenance, confidence, sensitivity, visibility, review dates, and tombstones;
- a full audit trail for proposals, approvals, denials, supersession, and forgetting.

FTS5 is the initial retrieval projection. It requires no resident embedding model and keeps idle memory use low. A semantic adapter should only be added after an evaluation corpus demonstrates a material recall improvement that justifies its RAM, latency, and operational cost.

## The tenant

Every durable key carries a tenant, so the daemon and the operator commands must agree on one. It is configured in `<state>/memory/memory.conf`, owned by the daemon user, mode `0600`:

```text
schema=automonique.memory/v1
tenant=<tenant>
end=automonique.memory/v1
```

`<tenant>` is lowercase letters, digits and hyphens, at most 64 bytes. An absent file means `primary`. A present file that is world-readable, malformed, or names no valid tenant refuses daemon startup rather than being ignored.

**Set `tenant=` before upgrading a deployment whose rows were written under another tenant.** Starting under the default loses nothing, but it addresses a different, empty tenant and looks exactly like data loss. The same applies to the operator commands below: `<tenant>` in each of them is this value, and a command run under the wrong one reads an empty set rather than failing.

## Telegram

Admitted messages and successfully delivered assistant replies are captured automatically. High-signal personal/team statements such as “I prefer …” and “we use …” create proposals; they do not become active context until approved. Explicit `remember …` statements and `/remember <fact>` are actor-authorized active memories.

Commands:

- `/memory` — counts and recent active memories
- `/memory search <query>` — FTS search with stable `M-…` citations
- `/memory proposals` — pending automatic or Obsidian edits
- `/memory show <M-ref>` and `/memory sources <M-ref>` — content and provenance
- `/memory approve <M-ref>` or `/memory deny <M-ref>` — exact-revision review
- `/forget <M-ref>` — remove from active recall while retaining an audit tombstone
- `/new` — start a fresh short-term conversation while preserving long-term memory

Credential-shaped tokens are redacted before message persistence. Raw conversations are never exported to Obsidian.

Existing admitted Telegram messages can be imported once from the daemon's main store. The command reads only the selected immutable actor, skips slash commands, and only reads rows inside the same 90-day retention window; reruns are idempotent:

```sh
automonique-memory backfill-telegram /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' /private/state/automonique.sqlite3 <bot-id>
```

## Slack

Socket Mode captures configured Slack administrators' messages in configured channels before acknowledging the Slack envelope. Display names and email addresses never merge identities. Pair an externally verified Slack coordinate with an existing actor explicitly:

```sh
automonique-memory link-identity /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' slack automonique-slack '<immutable-team-id>' '<immutable-user-id>'
```

The Slack capture and context paths resolve this binding before writing or retrieving memory, so reviewed memories follow the actor across both transports. A conflicting binding fails closed.

The legacy bot's recent chat store can be imported selectively after that identity check. Only the exact Telegram identity, legacy Slack scopes ending in the exact Slack user ID, and Slack threads whose durable event author matches that ID are admitted. Slash commands, unrelated actors, and rows older than 90 days are skipped; reruns are idempotent:

```sh
automonique-memory backfill-legacy /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' /private/legacy-chat.db '<telegram-user-id>' '<slack-user-id>'
```

## Obsidian and private Git

Build the operator tool with:

```sh
cargo build -p automonique-store --bin automonique-memory
```

Export only reviewed active memories into an Obsidian-compatible vault:

```sh
automonique-memory export-obsidian /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' /private/monique-memory
```

After editing a generated `Memories/M-….md` note, import the edit as a proposal:

```sh
automonique-memory propose-obsidian /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' /private/monique-memory/Memories/M-….md
```

The import never edits or activates the source memory. It creates a new `candidate` with Obsidian provenance, visible through `/memory proposals`. Approval remains explicit. A private Git repository may version the exported vault, but it is a portable reviewed projection—not a database backup and never an authorization source.

## Retention and recovery

The live surface runs indexed expiry maintenance at most once per day when an actor uses memory. Run the operator hygiene command after a migration or backfill to delete expired rows and remove slash commands already preserved by the authoritative transport inbox:

```sh
automonique-memory hygiene /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>'
```

An owner-reviewed preference may be seeded operationally without creating an unreviewed proposal:

```sh
automonique-memory remember-active /private/state/agent-memory.sqlite3 <tenant> 'telegram:<immutable-user-id>' 'Reviewed preference text'
```

Back up the SQLite database with a WAL-aware SQLite backup while the service is running, or with the daemon stopped. Copying only the main file while WAL is active is not a valid backup. Obsidian exports cannot reconstruct identities, raw conversation history, review state, or the audit ledger.
