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
