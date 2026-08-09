# Connector catalog

**Status:** accepted expansion catalog

## Common contract

Every connector is an out-of-process application over `@automonique/sdk/connector`, except the legacy in-process Slack/Telegram adapters during migration. It must implement installation identity, actor/tenant mapping, stable source keys, durable acknowledgement, reply/thread semantics, edits/deletes, attachment grants, commands/components, rate limits, credential/consent lifecycle, outbox reconciliation, data-boundary disclosure and independent disable/rollback.

A connector only receives the capabilities required by its graduated modes: notification, personal/DM intake, group/channel mention, commands, components/approvals, files/media, proactive delivery or broader subscriptions. “Full tool access” is never a transport default.

## Planned catalog

| Family | Connectors and adaptation |
|---|---|
| Existing core | Slack and Telegram retain current behavior, then migrate to the connector contract without changing durable IDs. |
| Microsoft | Teams chat/channels/Adaptive Cards plus optional Graph/RSC; Teams meetings/transcript pipeline is separate; Microsoft Graph webhooks are signed inbound routes. |
| Discord | HTTP Interactions first, optional Gateway/voice later, components/modals and scoped webhooks. |
| Meta | WhatsApp Business Cloud is preferred; QR/device libraries are isolated compatibility adapters with explicit account-risk disclosure. |
| Apple | iMessage through a reviewed bridge such as BlueBubbles/Photon on a separately trusted host; no claim of native server-side Apple support. |
| Secure messaging | Signal bridge and SimpleX adapter, each with local identity/key custody and delivery limitations documented. |
| Federated/team chat | Matrix, Mattermost, IRC, Google Chat and Rocket/compatible webhook adapters where protocol identity is stable. |
| Asian enterprise/social | LINE, DingTalk, Feishu/Lark, WeCom, Weixin, QQ and Yuanbao through official APIs where available; unofficial automation remains quarantined/experimental. |
| Email/SMS | Inbound/outbound email with thread/message identity, attachment and sender-domain policy; SMS through a typed provider adapter with opt-out/compliance state. |
| Devices/notifications | Home Assistant, ntfy and generic signed notification/webhook destinations. |
| Agent/UI relays | API Server/Open WebUI, ACP hosts, A2A, Buzz/relay-style WebSocket clients and separately authenticated remote desktop/PWA clients. |

## Voice, meetings, reactions and media

Connectors declare support for voice notes, transcription, TTS replies, stickers/reactions, live voice or meeting streams independently. Media always crosses the artifact pipeline. Teams meeting automation and Discord voice use dedicated media workers with consent/recording indicators, participant/tenant checks, bounded retention and no implicit meeting-wide authority.

## Channel directory and continuity

A normalized, authorization-filtered channel directory lets users select delivery targets without copying opaque IDs. Cross-platform continuity binds an Automonique session only through explicit user/profile policy; messages from two apps are not merged because display names match. `/sethome`-style defaults are revisioned per actor/profile and never global routing shortcuts.

## Pairing and access

Direct-message pairing uses expiring out-of-band codes or administrator-reviewed identity links. Group/channel access requires installation and scope policy. Unknown senders receive no tenant information. Platform admins/roles may inform mappings but do not automatically become Automonique administrators.

## Plugin-generated connectors

The connector SDK includes a manifest generator, command registry integration, media helpers, fake platform, conformance suite and deployment templates. Platform-specific types remain inside the connector package. Connector packages are signed and can be quarantined without stopping core work.

## Rollout

Each connector graduates in this order: notification-only; read-only health; personal/DM no-tools; mention/command intake; contextual follow-ups; attachments; components/approvals; proactive messages; broad subscriptions/media. Every step is tenant-specific and independently reversible.

## Exit gate

No catalog entry is called supported until duplicate/retry/edit/delete behavior, identity, permissions, attachments/media, rate limits, credential revocation, reload/reconnect, data boundary and uninstall/reinstall pass fixtures against its real platform sandbox or an authoritative protocol harness.
