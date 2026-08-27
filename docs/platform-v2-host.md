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
        "project": "project-example", "kind": "user_workspace", "id": "workspace-example",
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
ownership must agree with the durable owner projection.
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

The lifecycle filesystem adapter, workspace-create/resume adapter, and
git/CI/pull-request workers are intentionally not wired in this slice.
Lifecycle submit and workspace create return typed pending/unavailable
refusals. Resume first checks that the authoritative user workspace exists, is
active, belongs to the requested project, and has the exact expected lifecycle
revision, then refuses before lineage admission. Review actions validate the
server-selected role and current review revision, then likewise refuse before
creating any preview or receipt. This prevents permanent unclaimable custody.
Cancellations of already-existing durable lineage intents remain immediate,
final store operations. A future worker must
use the stores' typed reservation, write-admission, ambiguity, and
reconciliation APIs. It must not replay a write after an ambiguous result and
must never substitute a shell command for an adapter.
