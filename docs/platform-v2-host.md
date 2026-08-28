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
Purely logical changes, including a `UserWorkspace` over an already authorized
checkout and lifecycle archives, commit atomically and return `completed`.
When the private lifecycle registry described below is installed, local host
setup and checkout creation use the same durable external-effect outbox.
Attempt creation and attempt/session resume return `accepted` only when a
separate execution adapter explicitly supports that effect kind; the local
filesystem adapter does not claim provider/session integration and these three
operations remain unavailable in the production composition.

The host exposes a typed lifecycle-effect adapter. An enabled adapter receives
only the closed mutation intent, server-issued resulting identity and bound
idempotency key. The host claims work under a bounded durable lease and records
completion only after the adapter reports success, policy and selector-registry
generations are rechecked, and a freshly sampled trusted time remains inside
the lease. A lost, over-lease, revoked, or uncertain claim
becomes ambiguous after expiry. Claim and recovery reauthorize the retained
preview against current server policy in the same transaction, so revoked
work is skipped without changing custody or blocking unrelated reads. An
ambiguous effect is never replayed until the same adapter
reconciles the original idempotency key as verified not-started; exact completed
evidence closes it without replay, and unknown evidence remains unavailable.
With no lifecycle registry installed, the production composition supports no
filesystem effects, preserving the previous fail-closed behavior. An installed
registry enables only `create_host_setup` and `create_checkout`; SSH and remote
runtime setup kinds remain typed, explicit refusals.

Workspace resume intents prove the task's server-stored workspace against the
requested project's bounded policy set and recheck the active workspace and
exact revision, then refuse before custody because this adapter cannot perform
a truthful workspace lifecycle transition. Task create likewise remains
unavailable. Cancellations of already-existing durable pending intents remain
immediate and final. Polling an older non-final receipt for which no compatible
adapter is installed returns a typed recovery refusal instead of repeating an
`accepted` receipt indefinitely.

The current lineage schema binds an orchestration task to an existing
`UserWorkspace` before it can accept a workspace intent. Treating validation of
that existing directory as a successful `create` would fabricate a lifecycle
effect, so this release does not do so. Issuing a genuinely new task workspace
requires a future lineage schema that can hold an unbound task without
weakening its foreign-key authority.
Review actions validate the server-selected role, exact authority identity,
current snapshot revision, target revision, lifecycle, and freshness. Anchored
`add_comment` and `approve_review` effects are store-owned: the next canonical
snapshot, immutable write admission, actor-attributed request, and completed
receipt commit in one SQLite `IMMEDIATE` transaction. A crash therefore cannot
expose an accepted local write, and an exact idempotency replay returns the
same terminal receipt without advancing the snapshot again. The policy file is
fenced immediately before and after this transaction.

Agent comment delivery, stage/unstage/commit/conflict resolution, CI reruns,
and pull-request open/update/merge remain unavailable. After full authority and
target validation they refuse before custody as
`platform_v2_review_agent_adapter_unavailable`,
`platform_v2_review_git_adapter_unavailable`,
`platform_v2_review_ci_adapter_unavailable`, or
`platform_v2_review_pull_request_adapter_unavailable`. No request text becomes
a path, command, provider payload, or credential. The private target registry
below establishes the missing identity boundary, but deliberately does not
turn a binding into an executable capability. Git still lacks a server-owned
snapshot-to-blob/index/HEAD provenance document; retained sessions lack a
typed idempotent delivery endpoint; and CI/pull-request providers lack typed
credential consumers plus read-after-write reconciliation. Until those exact
boundaries exist there is no external effect, hence no prepared custody or
ambiguous write to recover.
Cancellations of already-existing durable lineage intents remain immediate,
final store operations.

## Private review target registry

The optional `platform-v2-review-registry.json` sibling is operator-owned,
opened with `O_NOFOLLOW`, restricted to the daemon uid, exact mode `0600`, one
hard link, and a 512 KiB limit. Its descriptor identity, timestamps, length,
and SHA-256 digest are rechecked before every external review action. Removing
or changing an installed generation requires a restart and actions fail closed
as `platform_v2_review_registry_changed`; an installed malformed or insecure
file disables Platform v2 instead of silently falling back.

The bounded version-1 document maps an exact project, workspace kind/id, and
authority kind/id to one closed target variant:

- `local_repository` contains only a canonical uid-owned repository root;
- `retained_session` contains an opaque provider and retained-session id;
- `ci` contains an opaque provider target and credential reference;
- `pull_request` contains an opaque provider repository and credential
  reference.

Credential references are names, never secret material. Target variants must
match their authority family, duplicate bindings and overlapping repository
roots are refused, repository and `.git` metadata cannot be symlinked or
group/world writable, and unknown JSON fields are rejected. The registry is
private composition state: it is never returned by Platform v2 and clients
cannot supply paths, commands, provider targets, or credential references.

## Private lifecycle selector registry

The optional `platform-v2-lifecycle-registry.json` sibling is operator-owned,
opened with `O_NOFOLLOW`, restricted to the daemon uid, exact mode `0600` and
one hard link, and bounded to 512 KiB. The daemon retains and rechecks the descriptor identity,
timestamps, length and SHA-256 digest before every preflight, execution and
reconciliation. A changed generation requires a restart; a previous generation
with a prepared ambiguous effect refuses restart until it can be reconciled
against the exact old binding.

The bounded version-1 document maps opaque selectors to exact project, host,
repository, checkout kind and canonical local roots. Git-worktree entries also
carry a full commit object id and a validated `refs/heads/...` branch. Request
bytes are never interpreted as paths, refs or command options. Local roots and
their parent are uid-owned and not group/world writable; symlinks, path aliases,
overlapping repository/worktree roots, moving bases, existing branches and
non-canonical roots fail closed. `git` is invoked with a fixed executable and
fixed argument layout after validation, never through a shell. Each child runs
in a killable process group with a deadline and one aggregate bounded output
budget; timeout or overflow kills and reaps the group. Tree entry/byte limits,
free-disk headroom and refusal of symlink/submodule entries bound checkout
materialization. System/global Git configuration, interactive prompting,
repository hooks, repository-local clean/smudge/process filters and
file-protocol transport are disabled. An existing worktree must also prove an
uid-owned, non-group/world-writable, single-linked regular `.git` file whose
canonical target and reported common directory are exactly under the configured repository's
`.git/worktrees`; matching commit/ref values from an independent repository do
not suffice. The configured repository's canonical `.git` directory is likewise
required to be uid-owned and non-group/world-writable.

```json
{
  "version": 1,
  "generation": "operator-generation-1",
  "host_setups": [{
    "selector": "local-build-host",
    "host_setup": "wc2_host_setup_00000000000000000000000000000002",
    "project": "project-example",
    "setup_kind": "local", "canonical_root": "/srv/automonique"
  }],
  "checkouts": [{
    "selector": "checkout-main",
    "checkout": "wc2_checkout_00000000000000000000000000000003",
    "project": "project-example",
    "host_setup": "wc2_host_setup_00000000000000000000000000000002",
    "repository_authority": "github", "repository": "owner/repository",
    "checkout_kind": "git_worktree",
    "canonical_root": "/srv/automonique/worktrees/issue-166",
    "repository_root": "/srv/automonique/repositories/product",
    "base_commit": "0123456789abcdef0123456789abcdef01234567",
    "branch_ref": "refs/heads/work/issue-166"
  }],
  "workspaces": [{
    "workspace": "wc2_user_workspace_00000000000000000000000000000004",
    "project": "project-example",
    "checkout": "wc2_checkout_00000000000000000000000000000003",
    "canonical_root": "/srv/automonique/worktrees/issue-166"
  }],
  "task_selectors": []
}
```

For `ssh` or `remote_runtime`, `canonical_root` must be omitted. These entries
remain useful typed policy declarations but are refused by this local adapter.
An authorized-folder checkout omits `repository_root`, `base_commit` and
`branch_ref`; its canonical root must already exist. `host_setup` or `checkout`
may be omitted only on the selector entry that creates that node. Once the
server-issued identity exists, add it in a new registry generation before any
dependent checkout or workspace binding can use it; selectors and durable
identities are never treated as interchangeable.

The sibling `platform-v2-lifecycle-effects.json` is a daemon-owned, atomic,
fsynced, mode-`0600`, single-linked and bounded journal. Its loaded full file
generation is checked immediately before each overwrite. If rename installs a
new generation but the following directory fsync fails, memory retains the
installed generation rather than restoring stale state. A prepared record is durable before an external
effect. Restart reconciliation proves an exact completed worktree, proves it
was not started, or leaves it ambiguous; it never guesses and replays a partial
effect. A prepared validation-only local-host or authorized-folder operation
whose binding becomes invalid is durably tombstoned as not started, releasing
its selector custody. Completed host/checkout mappings retain only opaque identities and path
digests. Logical archive changes do not delete operator files or git
worktrees.

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
inside a SQLite `IMMEDIATE` transaction that also records a request-digest-bound
ten-second dispatch lease. The transaction commits before the daemon socket is
opened, so ambiguous or completed mutation dispatch can never precede durable
mobile receipt custody. Submit custody also retains the exact canonical request
digest: the same coordinate may be retried only by the identical request, while
legacy custody without a digest remains readable but cannot admit a new submit.
Refresh, regrant, and both revocation paths check the same lease table in their
own write transactions and refuse while a dispatch lease is live; they
therefore cannot commit between authorization and dispatch. Socket read and
write operations are capped at two seconds, the lease is released after the
correlated response is validated, and a crashed process leaves only a bounded
lease that expires while its receipt custody remains recoverable. Receipt
custody is read or written in the same transaction that installs the lease,
eliminating a separate reauthorization window.

The current local protocol cannot safely represent multiple daemon principals
behind one web-entry uid. Such a configuration stays blocked; adding more
Basic users must first add a daemon-authenticated delegated-principal protocol
instead of mapping them all to the process uid. Operators must restart the
daemon and web entry together after changing the principal policy so their
in-memory policy generations cannot diverge.
