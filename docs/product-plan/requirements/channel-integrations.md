# Teams and Discord channel integrations

## Purpose and naming

Automonique must be available where organizations already work without turning each chat platform into a separate product implementation. Microsoft Teams and Discord are first-class channel connectors over the same durable intake, identity, approval, artifact, action-receipt and event contracts as Slack and Telegram.

They are the first implementations of the generic connector contract. Email/SMS, WhatsApp, Signal, Matrix, iMessage bridges, enterprise chat, device/notification, A2A/relay and media/meeting families are specified in the [Connector catalog](connector-catalog.md) and graduate independently through the same identity, receipt, artifact and revocation rules.

`Automonique` is the target product name. Existing `legacy`, `legacy.*` and `@legacy/*` identifiers remain compatibility names. Connectors negotiate protocol/capabilities and never depend on display names.

## Architecture decision

Implement Teams and Discord as separately deployable TypeScript connector services using the generated SDK, not as provider adapters and not as direct `/api/chat` proxies.

```text
Microsoft Teams                         Discord
  Teams SDK HTTPS app                    HTTP Interactions endpoint
  optional Graph/RSC                     optional Gateway worker
          │                                     │
          └──── automonique connector contract ─┘
                              │
                 HTTPS/events or local socket
                              │
                    Automonique operator API
                              │
       durable inbox → route → approval → work → outbox
```

Target source layout:

```text
connectors/typescript/
├─ core/       shared connector runtime, codecs, receipts and conformance
├─ teams/      Microsoft Teams SDK app, manifest and Adaptive Cards
└─ discord/    Discord Interactions app, optional Gateway and manifests
```

The connectors terminate platform protocols and translate them into typed Automonique requests/events. They do not:

- call model/provider APIs directly;
- reconstruct conversation context locally;
- decide approvals, routing, tenancy or tool policy;
- hold Slack, Telegram, provider, workspace or root-broker credentials;
- retry an ambiguous Automonique mutation without querying its action receipt.

Notification-only integrations remain smaller alternatives: Teams Workflows and Discord incoming webhooks consume reviewed outbox deliveries but cannot create work or approvals.

Copilot Studio remains a supported deployment choice for customers who want a Microsoft-managed low-code agent, but it is not Automonique's canonical connector: it cannot define the self-hosted control-plane, provider and tool contracts in this plan. For notification-only Teams destinations, use the [Teams Workflows webhook path](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) rather than treating a workflow URL as a conversational agent.

## Common connector contract

Each connector implements the same bounded contract:

1. Verify the platform request/session before parsing unbounded content.
2. Resolve one configured installation to an Automonique tenant.
3. Map the external user identity to a durable actor or an explicit unlinked state.
4. Build a stable source key and submit the input before acknowledging business acceptance.
5. Preserve platform, installation, conversation, thread/reply, message/interaction, locale and mention coordinates.
6. Materialize attachments only through the artifact ingestion API.
7. Render progress, clarification, approval and terminal records from durable Automonique events.
8. Bind every button/card/modal interaction to an opaque action token, exact target revision and eligible actor.
9. Record outbound platform message IDs and reconciliation evidence in the Automonique outbox/action receipt.
10. Resume subscriptions and pending actions after connector restart without replaying an external effect.

### Delivery and acknowledgement

Platform acknowledgement deadlines are not Automonique business completion deadlines. A connector may send an immediate typing/deferred/accepted response, but it reports “accepted” only after the Automonique inbox returns a durable input ID. Longer work updates the original response when the platform permits and otherwise posts a correlated follow-up.

Each platform adapter declares whether an acknowledgement, edit, delete or follow-up is idempotent. When the remote API lacks an idempotency key, the outbox stores lookup coordinates and reconciles before resend.

### Conversation semantics

- A personal chat/DM maps to a transport conversation scope, not automatically to one permanent provider session.
- Group/channel messages require an explicit mention or command by default.
- Replies bind to the durable Automonique request/session recorded for that exact platform message; proximity never implies follow-up context.
- Edited messages create a revision event. They do not rewrite an already approved action.
- Deleted source messages create a tombstone/presentation event and do not erase the audit record.
- Platform-native threads map to a stable conversation/thread key when available.

### Installations and tenancy

Every app installation is a durable record with platform application ID, external tenant/guild, allowed scopes, Automonique tenant, credential descriptor, manifest/config digest, lifecycle state and installing actor/evidence. There is no global fallback tenant.

An unrecognized tenant, guild, team, chat or user fails closed with an installation/linking response. Display names, email addresses, usernames and mutable handles never serve as authorization IDs.

## Microsoft Teams

### Platform surface

Use the current [Microsoft Teams SDK](https://learn.microsoft.com/en-us/microsoftteams/platform/teams-sdk/) TypeScript app surface (`@microsoft/teams.apps`) for the conversational connector. The generated app receives activities through a public HTTPS endpoint and uses Teams-native sends, typing, Adaptive Cards and dialogs. The connector talks to Automonique through the generated TypeScript SDK.

The connector supports independently capability-gated modes:

- personal chat;
- group chat;
- team/channel mention;
- Adaptive Card actions and dialogs;
- proactive notification to a previously authorized target;
- optional Graph-backed user/file/calendar/SharePoint tools;
- optional all-message context through Resource-Specific Consent (RSC).

Mention-only operation is the safe default. Receiving all chat/channel messages requires separately reviewed RSC permissions such as `ChannelMessage.Read.Group` or `ChatMessage.Read.Chat`; those permissions are declared in the app manifest and recorded per installation. See Microsoft's [all-message/RSC guidance](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/channel-messages-for-bots-and-agents) and [permissions model](https://learn.microsoft.com/en-us/microsoftteams/app-permissions).

### Identity and authorization

The external identity key includes Microsoft 365 tenant ID, Teams application/bot identity and stable Entra/Teams user ID. Personal, group-chat and team/channel scopes are distinct. UPN, email and display name are informational projections only.

Graph access is a separate typed capability. The Teams SDK can expose application- or user-scoped Graph clients, but every Automonique Graph tool declares:

- delegated versus application identity;
- required Entra and/or RSC permissions;
- resource/tenant boundary;
- read/write effect class;
- consent evidence and expiry/revocation behavior.

No generic “Graph request” tool is exposed. Prefer RSC over organization-wide permissions where the required operation is representable.

### Cards, approvals and actions

Adaptive Cards render request summaries, clarifications, approval previews, provider permission requests, progress and terminal results. Card payloads contain only an opaque short-lived action token and presentation data—never credentials, raw policy, arbitrary commands or trusted actor fields.

On invoke/submit the connector re-authenticates the actor and asks Automonique to resolve the token. The server verifies installation, tenant, actor role, action revision, expiry and current state. Updating or replacing a card never widens the action it represents.

### Files and artifacts

Teams file behavior varies by conversation type and may require Graph/SharePoint access. The connector records attachment metadata first, then downloads through a permission-scoped client into the artifact ingestion pipeline with size, type, archive and malware policy. It never sends a Microsoft URL or bearer token to an execution host.

Outbound files use short-lived reviewed artifact grants and the least-capable supported Teams/Graph upload path. The resulting drive/item/message IDs become publication evidence.

### Installation and operation

Ship reproducible Teams app packages/manifests for development, single-tenant staging and production. Custom app upload/admin approval, Entra registration, bot endpoint, RSC/Graph permissions and allowed deployment rings are configuration—not manual tribal knowledge.

The production endpoint is a stable HTTPS URL such as `https://teams.automonique.example/api/messages`; local tunnels are development-only. App secrets/certificates are versioned credential descriptors with overlap rotation. Manifest, Entra application, bot identity and connector release digests appear in health/doctor output.

## Discord

### Interaction-first surface

Use Discord HTTP Interactions as the default mode for slash/message commands, buttons, selects and modals. Discord supports HTTP or Gateway interaction delivery, but not both for one application; the selected mode is durable installation configuration. HTTP requests must pass Discord signature verification and the initial PING check before parsing content. See Discord's [Interactions overview](https://docs.discord.com/developers/interactions/overview) and [receiving/responding contract](https://docs.discord.com/developers/interactions/receiving-and-responding).

Default commands include a canonical `/automonique` entrypoint plus generated safe presets from the command registry. Command schemas are registered from a reviewed manifest digest; the connector does not invent regex routing.

Discord interactions have short acknowledgement deadlines and finite follow-up tokens. The connector defers promptly, durably submits the input, then edits the original or posts bounded follow-ups. It persists interaction/application/message coordinates but never stores continuation tokens in ordinary events or logs.

### Optional Gateway mode

Enable the Gateway only for capabilities that HTTP Interactions cannot provide, such as mention/DM message intake or selected lifecycle events. Persist Gateway session ID, resume URL and sequence as transport state, but still deduplicate business input by Discord event/message/interaction IDs.

Request only required Gateway intents. `MESSAGE_CONTENT` remains disabled by default; Discord documents exceptions for DMs, messages mentioning the app and app-authored messages. Enabling privileged intents requires an explicit privacy/capacity review and a connector capability change. See the [Gateway and intents documentation](https://docs.discord.com/developers/events/gateway).

### Identity, installation and permissions

Support Discord guild installations first. The identity namespace includes application ID, installation type/owner, guild ID when present and immutable Discord user ID. Guild roles and channel permissions may inform a policy mapping but never replace Automonique actor/role authorization.

Installation uses minimal OAuth2 scopes (`bot` only when a bot user is required and `applications.commands` for commands) and minimal Discord permissions. User-installed applications are a separate later capability because their contexts, follow-up limits and tenant semantics differ. See Discord's [OAuth2 scope reference](https://docs.discord.com/developers/topics/oauth2).

### Components, modals and approvals

Buttons, selects and modals use the same opaque revision-bound action-token contract as Teams cards. Sensitive approval previews default to ephemeral interaction responses where supported. Public completion messages contain bounded summaries and links/IDs, never hidden approval evidence or private artifacts.

Set `allowed_mentions` explicitly on every response to prevent content from triggering unintended users/roles. User/model text never controls arbitrary component custom IDs, webhook targets or embed URLs.

### Rate limits, attachments and notifications

Discord REST scheduling follows returned rate-limit buckets and `Retry-After`; limits are never hard-coded. The connector exposes bucket/global throttling to Automonique admission and outbox health. See Discord's [rate-limit guidance](https://docs.discord.com/developers/topics/rate-limits).

Inbound attachment URLs are treated as temporary untrusted download capabilities and ingested into the artifact service under platform size/permission limits. Outbound files use reviewed artifact grants and verify the app's current channel permissions.

For notification-only destinations, use scoped incoming webhooks with credential descriptors, channel/guild binding, outbox receipts and rotation. Discord describes webhooks as a low-effort posting surface that does not require a bot user; webhook possession is therefore a write credential and never appears in client state. See the [Discord webhook reference](https://docs.discord.com/developers/resources/webhook).

## Durable state additions

Add or extend these projections:

- `connector_installations` — platform, app identity, external tenant/guild, Automonique tenant, modes/scopes, manifest digest, credential version and state;
- `external_identities` — namespaced Teams/Entra or Discord user mapping to actor and tenant;
- `transport_conversations` — installation, personal/group/team/guild/channel/thread scope, service URL/target reference and retention;
- `transport_messages` — source key, request/work linkage, current platform revision, reply coordinates and deletion/tombstone state;
- `transport_interactions` — card/component/modal action token hash, target revision, actor constraints, acknowledgement and terminal receipt;
- `proactive_targets` — explicit reviewed destination capability, audience, expiry and last validation;
- `transport_subscriptions` — RSC, Graph, Gateway intents/event subscriptions and consent evidence;
- `transport_rate_limits` — observed Discord buckets and other provider throttling state;
- `connector_cursors` — Gateway/resume/event cursors where the platform exposes them.

Tokens, webhook URLs, Teams service URLs containing secrets and Discord interaction tokens are credential-store values or short-retention encrypted records, never ordinary JSON projections.

## TypeScript SDK connector surface

Add `@automonique/sdk/connector` as the target package name, with a temporary `@legacy/sdk/connector` compatibility export if required. It provides:

- connector registration and capability negotiation;
- installation/tenant/actor resolution;
- durable input submission and source-key helpers;
- snapshot/event subscriptions with cursor recovery;
- action-token resolve/execute and receipt reconciliation;
- outbound render intents rather than platform-specific model strings;
- artifact upload/download grant helpers;
- redaction, bounded logging, health and conformance harnesses;
- fake Teams and Discord fixtures without real tenant/guild credentials.

Platform packages own Teams Activity/Adaptive Card and Discord Interaction/Component types. Those types do not leak into the core Automonique protocol.

## Sovereignty and data boundary

Self-hosting Automonique keeps models, RAG, workspaces, tools, durable policy and operational logs on the organization's infrastructure. It does not make Teams or Discord content local-only: messages, identities, attachments and connector responses traverse and may be retained by Microsoft or Discord under the organization's platform agreement.

Every installation therefore exposes a data-boundary statement and configurable policy for:

- content/metadata sent to the platform;
- content copied into Automonique and its retention class;
- Graph/RSC/Gateway scopes;
- attachment ingestion/publication;
- proactive notifications;
- regions/tenant and connector endpoint;
- deletion/export/reconciliation limitations.

Air-gapped mode cannot support cloud Teams or Discord. A deployment claiming air-gapped operation must disable both connectors and their notification webhooks.

## Reload, failure and reconciliation

Connector processes are independently supervised clients. An `automoniqued` generation reload causes an SDK reconnect from the last durable domain cursor; it does not reinstall an app, reconnect a Teams client manually or repeat an interaction response.

If Automonique is unavailable, connectors acknowledge only what the platform requires and return a bounded temporary-unavailable response. They never buffer unbounded hidden work in process memory. Reconciliation compares Automonique input/outbox/action receipts with platform message coordinates, installation state and active consent/permissions.

Credential revocation, removed app installation, lost RSC/Graph scope, Discord invalid session, expired interaction token and rate-limit quarantine are distinct observable states with runbooks.

## Rollout order

1. Fake-platform conformance and manifest validation with no external credentials.
2. Notification-only Teams Workflow and Discord webhook destinations.
3. Read-only single-tenant/guild health and identity canaries.
4. Personal/DM slash-command intake with no tools and no attachments.
5. Mention-only channel/group intake and durable threaded replies.
6. Clarification and read-only Adaptive Card/component actions.
7. Exact-revision work and provider approvals.
8. Artifact ingestion/publication.
9. Proactive notifications.
10. Optional Graph/RSC or Discord Gateway capabilities, one permission/intent family at a time.

Teams and Discord graduate independently. No rollout flag enables both or grants a new permission implicitly.

These are optional expansion tracks. Their SDK contract may be built alongside the core operator platform, but neither connector's production canary blocks the Rust daemon or Automonique identity cutover when that connector is disabled. Once enabled, its installation enters the deployment's compatibility, reconciliation and rollback gates.

## Explicit non-goals

- Pasting model/API keys into the Teams or Discord client.
- Running model/tool logic in the connector.
- Reading every team, chat, guild or channel by default.
- Treating Teams/Discord roles as global Automonique administrator roles.
- Using cards/components as unsigned authorization records.
- Claiming Teams or Discord traffic is air-gapped or outside the platform operator's cloud.
- Supporting voice, meetings, Discord Activities or broad Microsoft 365 automation in the first connector release; these remain separately planned catalog capabilities rather than being omitted.

## Connector exit gate

Each connector is production-ready only when installation/tenant identity is unambiguous, duplicate delivery produces one Automonique input, mention/command and follow-up semantics pass fixtures, approvals remain exact-revision and actor-bound, attachments cross the artifact boundary, unknown mutations reconcile without resend, credential/permission revocation fails closed, rate limits/backpressure are observed, daemon/connector reload loses no accepted input, and the data-boundary statement matches measured traffic.
