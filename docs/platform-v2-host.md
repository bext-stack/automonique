<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Platform v2 local host

Platform v2 is opt-in at the daemon boundary. Platform v1 remains available
with its existing wire and store when v2 is absent or refused.

The enabling file is `platform-v2-policy.json` in the Automonique state
directory. The daemon opens it with `O_NOFOLLOW`, then checks that descriptor
with `fstat`: it must be a regular file owned by the daemon uid with exact mode
`0600` (including no special bits), no larger than 256 KiB. The current Unix socket admits only the
daemon's effective uid, so the policy must contain exactly one matching
principal. A malformed, insecure, unmapped, or unusable policy disables v2 and
causes v2-only negotiation and requests to receive a correlated typed refusal.

The daemon retains the startup policy descriptor identity, metadata, length,
and SHA-256 digest. It securely reopens and compares that complete generation
before every negotiation and every v2 request. Deletion, replacement, mode or
owner changes, and even an in-place same-principal grant change therefore
refuse with `platform_v2_policy_changed` (or the applicable insecure-policy
category) until the daemon restarts and loads the new generation.

The file has this bounded shape:

```json
{
  "version": 1,
  "principals": [{
    "uid": 1000,
    "tenant": "tenant-example",
    "actor": "operator-example",
    "serving_authority": "automonique",
    "projects": ["project-example"],
    "workspaces": [
      {
        "project": "project-example", "kind": "project", "id": "project-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "host_setup", "id": "host-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "checkout", "id": "checkout-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "user_workspace", "id": "workspace-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "attempt_workspace", "id": "attempt-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "session", "id": "session-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      },
      {
        "project": "project-example", "kind": "pane", "id": "pane-example",
        "inherited_authority": {
          "filesystem": ["workspace-read"], "credentials": [], "network": [],
          "tools": [], "providers": [], "models": []
        }
      }
    ],
    "authority": {
      "filesystem": ["workspace-read"],
      "credentials": [],
      "network": [],
      "tools": [],
      "providers": [],
      "models": []
    },
    "review_authorities": {
      "git": "git-example",
      "review": "review-example"
    }
  }]
}
```

Grant arrays must be strictly sorted and contain only protocol-safe opaque
tokens. Workspace entries bind an exact identity to one visible project and
carry an independently configured inherited authority ceiling. Every ceiling
must be a subset of the actor ceiling and its project/record parent ceiling;
the daemon never substitutes the actor ceiling for a parent ceiling.
Every listed project must have its own `project` identity entry. At startup and
before every read or action, identities must exist in the authoritative work
context store, project identities must equal their declared project, and child
ownership must agree with the durable owner projection. The complete direct
inheritance chain must be visible in policy (`project` → `host_setup` →
`checkout` → `user_workspace` → `attempt_workspace` → `session` → `pane`, as
present);
omitting an intermediate parent refuses v2 rather than falling back to the
project or actor ceiling.
Review authority keys use the six review axes (`filesystem`, `git`, `ci`,
`pull_request`, `review`, and `delivery`). Neither the v2 request envelope nor
its domain documents can replace the actor, tenant, project bindings, six
lifecycle grant axes, authentication kind, or review authority selected here.

When enabled, startup opens three private sibling SQLite stores for work
contexts/lifecycle custody, lineage, and review custody. Inventory decodes only
the bounded visible identity set, cursor state is actor-scoped and bounded,
and opaque lineage intent IDs use one indexed lookup followed by a stored
workspace visibility check. Lifecycle preview and decision records are durable
and idempotent; approval expiry is capped to its preview expiry. Receipt reads
are bound to the authenticated actor, tenant, intent targets, and project.
Create-project receipt lookup is refused because the current lookup wire cannot
soundly bind its newly issued project.
Old previews and receipts are reauthorized after restart from their immutable
actor, intent, project, and exact target coordinates. The current target's
exact inherited ceiling must still equal the preview ceiling; narrowing or
revoking a child makes decision and receipt reads opaque/refused.
For `create_checkout`, the server adds only the intent's exact external
repository coordinate to that preview's authorized targets. The authoritative
store must also prove the coordinate and revision are a repository relation of
the selected project; an unrelated repository is refused even when its
external snapshot exists.

Lifecycle submission is wired through the exact retained preview, current
policy, preview digest, durable approval and server-issued receipt identity.
Supported purely logical changes, including a `UserWorkspace` over an already
authorized checkout and lifecycle archives, commit atomically and return
`completed`. Host-setup and checkout creation refuse before preview custody
until a typed private selector registry can bind the selector to the exact
project, host, repository, kind, and canonical root. Attempt creation and
attempt/session resume return `accepted` only when the configured adapter
explicitly supports that effect kind and the durable outbox reservation
succeeds; no process or filesystem result is fabricated.

The host exposes a typed lifecycle-effect adapter. An enabled adapter receives
only the closed mutation intent, server-issued resulting identity and bound
idempotency key. The host claims work under a bounded durable lease and records
completion only after the adapter reports success and a freshly sampled
trusted time remains inside the lease. A lost, over-lease, or uncertain claim
becomes ambiguous after expiry. Claim and recovery reauthorize the retained
preview against current server policy in the same transaction, so revoked
work is skipped without changing custody or blocking unrelated reads. An
ambiguous effect is never replayed until the same adapter
reconciles the original idempotency key as verified not-started; exact completed
evidence closes it without replay, and unknown evidence remains unavailable.
The production default adapter supports no effects, so unsupported submissions
return `unavailable` before receipt or outbox custody.

Workspace resume intents prove the task's server-stored workspace against the
requested project's bounded policy set and recheck the active workspace and
exact revision, then refuse before custody until a workspace executor and
reconciliation path are configured. Workspace create remains unavailable: its
base and branch selectors
are deliberately separate domains and this release has no typed private
selector-to-canonical-root/repository/base registry. Treating the existing
opaque selector bytes as paths, refs, or commands would be an unsafe authority
guess. Git-worktree execution is blocked for the same reason. Review actions
still validate the server-selected role and current review revision, then
refuse before custody because git/CI/pull-request workers are not configured.
Cancellations of already-existing durable lineage intents remain immediate,
final store operations.

## Offline production bootstrap

An empty work-context store is provisioned with the operator-only
`platform-v2-bootstrap` command. Stop the daemon first. The command acquires
the same `daemon.lock` process fence as the foreground daemon and refuses if a
generation is running. Its destination is always the product state directory
resolved from `XDG_STATE_HOME`; neither the manifest nor a command-line flag
can select a database, checkout path, executable, selector binding, or shell
command.

Write the policy above first, then write a separate manifest owned by the
daemon uid with exact mode `0600`. The manifest is opened with `O_NOFOLLOW`,
must be a regular file, and is bounded to 256 KiB. Unknown fields are refused.
It contains only the initial active project → host setup → checkout → user
workspace graph and GitHub repository coordinates:

```json
{
  "version": 1,
  "tenant": "tenant-example",
  "projects": [{
    "id": "wc2_project_00000000000000000000000000000001",
    "label": "Example project",
    "repositories": [{"authority": "github", "id": "owner/repository"}],
    "host_setups": [{
      "id": "wc2_host_setup_00000000000000000000000000000002",
      "label": "Production host",
      "kind": "local",
      "checkouts": [{
        "id": "wc2_checkout_00000000000000000000000000000003",
        "label": "Main checkout",
        "kind": "git_worktree",
        "repository": {"authority": "github", "id": "owner/repository"},
        "workspaces": [{
          "id": "wc2_user_workspace_00000000000000000000000000000004",
          "label": "Operator workspace"
        }]
      }]
    }]
  }]
}
```

All local identities must use the canonical `wc2_<kind>_<32 lowercase hex
digits>` server-issued shape. Every checkout repository must be declared by
its own project. The bootstrap fixes all initial revisions to 1 and lifecycle
to `active`, derives attributes from the closed `kind` values, and derives all
relations and project ownership from nesting. External repositories are
seeded as revision-1 available GitHub coordinates owned by that exact project.
Selectors are deliberately absent: this bootstrap never translates a
selector into a private path, and runtime creation remains unavailable until a
typed server adapter owns that translation.

The policy must contain exactly one principal for the effective uid, the same
tenant and project set, and exactly the local identities in the manifest. Its
existing authority and inherited-authority checks still apply. Bootstrap does
not copy, infer, or widen grants.

Use the graph-non-mutating plan first, apply while the daemon is stopped, and
verify the durable graph against both the manifest and policy before restart:

```text
automonique platform-v2-bootstrap plan --manifest /operator/private/bootstrap.json
automonique platform-v2-bootstrap apply --manifest /operator/private/bootstrap.json --dry-run
automonique platform-v2-bootstrap apply --manifest /operator/private/bootstrap.json
automonique platform-v2-bootstrap verify --manifest /operator/private/bootstrap.json
```

`plan` and `apply --dry-run` do not create the work-context database. Every
mode opens an existing database read-only first, requires the exact current
schema, and inspects its complete state without migrations. Apply then reopens
that same current-schema database read-write without migration and repeats the
comparison in one immediate SQLite transaction. An older or newer schema is
therefore refused byte-for-byte unchanged.

Apply uses that transaction for the complete external and local graph. It
seeds only a tenant with no authoritative work-context state. Immediately
before commit, while the transaction still owns its write lock, it securely
reopens and validates the policy and requires the exact generation admitted by
preflight. A changed or invalid policy fails the guard and rolls back every
graph row. A retry succeeds only when every record and external projection is
identical; partial state, changed labels/attributes/relations/ownership, and a
durable revision newer than the manifest are distinct refusals and leave the
graph unchanged.

The successful policy guard plus SQLite commit is the bootstrap operation's
linearization boundary. The policy file and SQLite database are separate
filesystem objects, so this is not a cross-filesystem atomic transaction and
does not prevent an external operator from replacing the policy in the narrow
interval after its guarded read. Operators must serialize policy replacement
with bootstrap and run `verify` before daemon restart. On a first Apply,
database schema creation necessarily precedes the guarded graph transaction;
a failed guard may therefore leave an empty current-schema database container,
but no external or local graph rows. The JSON report includes only counts,
tenant, and SHA-256 digests of the securely read manifest and policy. This
command adds no Platform request or response shape and does not change
Platform v1.

## Authenticated web bridge

`automonique-web-entry` exposes Platform v2 only at the additive
`POST /api/platform/v2` route. `POST /api/platform` remains the Platform v1
route with its existing media type, body limit, mobile filtering, and wire
behavior.

The v2 route accepts exactly one of these matching request/response lanes:

- `application/vnd.automonique.platform.negotiation.v1+json`
- `application/vnd.automonique.platform.v2+json`

`Content-Type` and `Accept` must both name the same lane. Negotiation requests
are bounded by the negotiation canonical limit; v2 requests are bounded by the
v2 canonical limit. Local responses are length-prefixed and bounded before
allocation by the corresponding response limit, then decoded against the
original typed request to enforce correlation and response shape.

The bridge remains single-principal at the daemon socket. It accepts either
the dashboard's one configured HTTP Basic credential or an `ma_` mobile access
token with a live, separately persisted Platform v2 delegation. Dashboard
session cookies, Manage service bearers, ungranted mobile credentials, and
other bearer credentials cannot enter this route. An `ma_` token never falls
back to Basic, a session cookie, or Manage authority. Before every local exchange, web-entry
opens the private policy with the same descriptor checks as the daemon and
requires that its server-owned integration tenant and actor exactly equal the
sole principal mapped to its Unix uid. The HTTP authorization header is never
forwarded to the daemon. A missing, changed, multi-principal, or mismatched
policy produces a correlated typed refusal without opening the admin socket.

Mobile Platform v2 authorization is additive to the unchanged
`automonique.mobile-auth/v1` wire. An operator first issues or pairs a normal
v1 mobile credential, then posts the exact credential ID, bounded Platform v2
action set, and at most 32 canonical project IDs to
`POST /api/mobile/platform-v2/grants` using
`application/vnd.automonique.mobile-platform-v2-authorization.v1+json` and
the dashboard Basic credential. This is the bootstrap source of truth:
project roots must already exist in the daemon's server-owned principal policy.
The request never accepts filesystem paths, repository paths, tenant IDs,
actor IDs, expiry, revisions, or authority grants from the mobile client.

The mobile client reads its exact delegation at
`GET /api/mobile/platform-v2/authorization` with the same media type and its
mobile bearer. The response binds the origin identity, credential and
authorization revisions, delegation ID, principal generation, tenant, actor,
access-token issuance/expiry, sorted project roots, and sorted per-operation
grants. Refresh rotation advances both the credential revision and principal
generation; regrant changes the delegation ID and generation; credential
revocation revokes the delegation in the same transaction. Old generations
cannot reuse cached mutation previews. Every request is action-checked and
resolved to one admitted project before the local socket is opened. Targeted
lineage and review reads additionally require the named workspace to belong to
that declared project in the server policy; possession of both project roots
does not permit a cross-project workspace coordinate. The daemon then
independently applies its current policy fence and ownership checks.

A v2 grant is issued only when the v1 credential's persisted actor exactly
matches the web entry's configured actor; changing that configuration cannot
rebind an older credential to the new actor. Before a mobile mutation submit is
sent to the daemon, web entry durably binds its project and idempotency key to
the exact credential, delegation, and principal generation. Mobile receipt
polling accepts only that idempotency coordinate and checks the binding before
opening the socket; receipt-ID lookup is refused because no mobile-owned
receipt-ID binding exists before an ambiguous response. The private SQLite
custody is capped at 128 live entries per credential, survives process restart
and same-delegation access-token rotation, and is deleted on delegation
regrant or credential revocation. Thus another same-project credential and a
new delegation cannot read an older mutation receipt.

The final credential, delegation, generation, and receipt-custody check runs
inside a SQLite `IMMEDIATE` transaction held through the mobile daemon socket
exchange, whose read and write operations are capped at two seconds. Refresh,
regrant, and revocation through another web-entry process therefore cannot
commit between authorization and dispatch. Receipt custody is read or written
inside that same transaction, eliminating a separate pre-transaction
reauthorization window. A fence commit failure is returned as a correlated
typed refusal rather than forwarding a response under uncertain custody.

The current local protocol cannot safely represent multiple daemon principals
behind one web-entry uid. Such a configuration stays blocked; adding more
Basic users must first add a daemon-authenticated delegated-principal protocol
instead of mapping them all to the process uid. Operators must restart the
daemon and web entry together after changing the principal policy so their
in-memory policy generations cannot diverge.
