<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Platform v2 local host

Platform v2 is opt-in at the daemon boundary. Platform v1 remains available
with its existing wire and store when v2 is absent or refused.

The enabling file is `platform-v2-policy.json` in the Automonique state
directory. It must be a regular, non-symlink file owned by the daemon uid with
mode `0600`, no larger than 256 KiB. The current Unix socket admits only the
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
      {"project": "project-example", "kind": "project", "id": "project-example"},
      {"project": "project-example", "kind": "user_workspace", "id": "workspace-example"}
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
tokens. Workspace entries bind an exact identity to one visible project.
Review authority keys use the six review axes (`filesystem`, `git`, `ci`,
`pull_request`, `review`, and `delivery`). Neither the v2 request envelope nor
its domain documents can replace the actor, tenant, project bindings, six
lifecycle grant axes, authentication kind, or review authority selected here.

When enabled, startup opens three private sibling SQLite stores for work
contexts/lifecycle custody, lineage, and review custody. Reads are served only
through exact policy scope. Lifecycle preview and decision records are durable
and idempotent. Lineage resume requests are durably accepted for later
reconciliation, and cancellations are durably recorded. Review actions are
durably prepared with approval required. These states do not claim an external
effect completed.

The lifecycle filesystem adapter, workspace-create adapter, and git/CI/pull
request workers are intentionally not wired in this slice. Lifecycle submit
and workspace create therefore return typed pending/unavailable refusals;
review action receipts remain `accepted`/`poll_receipt`. A future worker must
use the stores' typed reservation, write-admission, ambiguity, and
reconciliation APIs. It must not replay a write after an ambiguous result and
must never substitute a shell command for an adapter.
