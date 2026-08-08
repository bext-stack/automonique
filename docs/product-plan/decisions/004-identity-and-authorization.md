# ADR 004 — identity, tenancy and authorization

**Status:** accepted for implementation planning

## Context

Automonique accepts Slack, Telegram, Manage, Support, browser, local Unix-socket and remote SDK actors. “Authenticated” or “role-scoped” is insufficient without a canonical actor model, tenant/resource boundaries, credential lifecycle and explainable authorization decisions.

## Decision

Every input and mutation resolves to a durable actor, authentication context and authorization decision before business handling.

## Identity model

Model separately:

- actor: human, service account, transport bot, worker capability or system reconciler;
- external identity: Slack user/team, Telegram user/chat, Teams application/tenant/user, Discord application/installation/guild/user, Manage account/tenant, Support portal user, local UID or SDK credential subject;
- tenant/workspace membership;
- role assignments and resource predicates;
- authentication session/credential with issuance, expiry, rotation and revocation;
- delegation/impersonation chain when explicitly supported.

Identity mappings are unique within their issuer/tenant and changes are audited. Display names are never authorization keys.

## Initial roles

- `viewer` — read authorized status/history;
- `requester` — submit/follow up within allowed scopes;
- `operator` — pause, cancel, retry delivery and control sessions as allowed;
- `approver` — decide exact eligible work/provider approvals;
- `admin` — configure non-secret policy, identities and releases;
- `deployer` — approve eligible privileged deployment/restart proposals;
- `integration` — narrowly scoped machine actions/events.

Roles grant capabilities subject to tenant, channel, workspace, action risk and exact resource predicates. They are not global booleans. High-risk actions may require a distinct role, step-up authentication or multiple independent approvers.

## Transport authentication

- Slack identities bind team/channel/user and verified Slack event/action context.
- Telegram identities bind bot/chat/user and configured allowlists.
- Teams identities bind application, Microsoft tenant, installation/conversation scope and stable Entra/Teams user ID; Discord identities bind application, installation owner/guild and stable user ID.
- Manage and Support identities preserve tenant/client fencing through every linked work item and artifact.
- Local Unix clients use peer UID/PID plus configured local role mapping; same UID does not automatically mean deploy authority.
- Remote SDK clients use hashed, scoped, expiring credentials or an approved interactive session over TLS.
- Browser state uses secure cookies/session tokens, CSRF protection, origin checks and no secrets in URLs.
- Worker capabilities are short-lived, audience/scope/resource-bound and cannot call operator APIs.

## Authorization decision

Every decision records:

- actor/authentication ID and delegation chain;
- requested capability and resource coordinates;
- target/action revision and risk;
- matched policy version and rule IDs;
- allow/deny plus bounded explanation;
- timestamp, generation and correlation ID.

The same server-side policy evaluator serves Slack, Telegram, SDK, dashboard, TUI and CLI. Clients may hide unavailable actions for UX but cannot enforce authority themselves.

## Approval rules

- Approval eligibility is evaluated at decision time and bound to the exact revision/item.
- The requester cannot self-approve where separation-of-duty policy forbids it.
- Expiry, revocation, supersession and quorum are explicit states.
- A scope/capability/workspace/base-revision change invalidates prior approval.
- Provider approvals cannot inherit authority absent from the outer reviewed work.

## Break-glass

Break-glass is disabled by default, time-bounded, locally configured, separately authenticated and emits prominent immutable audit/notification events. It never becomes a hidden SDK flag or provider permission mode.

## Verification

Use a generated role/capability/resource matrix across every transport. Test cross-tenant ID collisions, stale membership, revoked credentials, CSRF, replay, self-approval restrictions, delegation, reload, clock changes and local peer PID reuse. A denied caller must not learn whether an unauthorized resource exists.
