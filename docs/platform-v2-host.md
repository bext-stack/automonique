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

When `task_selectors` is non-empty, the production adapter supports the narrow
task-workspace lifecycle that the current lineage model can represent without
inventing a filesystem or provider effect. A create intent adopts one exact,
already operator-authorized local checkout as the task's daemon-custodied
`UserWorkspace`. The registry entry must match the project, workspace,
checkout, task, external-work coordinate, and both opaque base and branch
selectors. The lineage index independently proves that the task and external
item are already bound to that same workspace. The authoritative WorkContext
record must also be active and relate that workspace to exactly the same
checkout identity; another checkout or root in the same project is refused.
Create validates a Git worktree at the configured immutable base commit and
exact branch. Resume requires the requested live workspace revision and the
prior adoption, but permits the exact branch HEAD to advance normally when the
configured base remains an ancestor. It still proves the canonical repository
common directory, registered worktree, worktree root, symbolic branch and
branch-to-HEAD identity. Neither operation creates a directory, changes a ref,
starts a provider, or creates an attempt/session.

Workspace effects use a prepared/completed/unknown journal record bound to the
full registry file generation and a digest of the full policy file generation. The
workspace adoption, its live revision, the intent digest and completed state
install in one atomic journal rewrite. On open, every completed create must
have exactly one matching adopted workspace with the same intent and digest;
a completed-only or mismatched row fails closed.
After restart a prepared record is therefore provably not completed and may be
completed only after the exact bindings revalidate; a completed record is an
idempotent receipt. Unknown create custody becomes completed only when the
same intent's adoption mapping is present. Otherwise it is durably reconciled
as not started and a later poll may submit it again; it is never replayed in
the reconciliation call. A changed policy or registry generation cannot
complete an older accepted effect. Cancellation removes only prepared or
verified-not-started unknown custody and refuses once completed adoption is
visible. An accepted intent for which the adapter has no prepared custody is
provably cancellable even if its mutable selector or root has since
disappeared; cancellation still consults the installed journal adapter to
fence a concurrent or ambiguous completion. Exact final lineage receipts are
authorized from their stored workspace scope and replay before mutable adapter
preflight, so later selector or root drift cannot erase a truthful final
outcome. Polling a non-final receipt without a compatible adapter returns a
typed recovery refusal.

The current lineage schema still cannot create a previously unknown workspace:
an orchestration task is authority-bound to an existing logical
`UserWorkspace` before intent admission. `created` therefore means that the
exact pre-authorized logical workspace was newly adopted into runtime custody,
not that Automonique synthesized a path or repository. Creating an unbound
identity remains future schema work.

Review actions validate the server-selected role, exact authority identity,
current snapshot revision, target revision, lifecycle, and freshness. Anchored
`add_comment` and `approve_review` effects are store-owned: the next canonical
snapshot, immutable write admission, actor-attributed request, and completed
receipt commit in one SQLite `IMMEDIATE` transaction. A crash therefore cannot
expose an accepted local write, and an exact idempotency replay returns the
same terminal receipt without advancing the snapshot again. The policy file is
fenced immediately before and after this transaction.

Stage/unstage/commit/conflict resolution, CI reruns, and pull-request
open/update/merge remain unavailable. After full authority and target
validation they refuse before custody as `platform_v2_review_git_adapter_unavailable`,
`platform_v2_review_ci_adapter_unavailable`, or
`platform_v2_review_pull_request_adapter_unavailable`. No request text becomes
a path, command, provider payload, or credential. Git still lacks a
server-owned snapshot-to-blob/index/HEAD provenance document, while CI and
pull-request providers lack typed credential consumers plus read-after-write
reconciliation.

Single and batch comment delivery is available only for an exact `jcode`
`retained_session` binding. The host proves the work-session -> attempt ->
user-workspace ancestry and its exact Platform-v1 provider-session relation,
then reads the selected comments from the authoritative review snapshot. It
persists the registry generation, both session revisions, sorted comment
coordinates and bodies, SHA-256 payload digest, and derived scheduler key in
the same transaction as the accepted review receipt. The same transaction
reserves every exact comment revision, so a second key cannot admit a duplicate
delivery. Only then may the write admission be recorded.

Recovery reconciles the complete persisted transport, key, provider-session
scope, execution fence, and payload bytes; a key match alone is never evidence
for this effect. An absent delivery is submitted to the dedicated
`platform_v2.retained_review` lane. Immediately before provider custody that
lane reopens the private registry and work-context stores and requires the
persisted registry generation, work-session lineage/revision, and managed
provider-session revision. It does not create or finalize a Platform-v1
receipt. A proven completion marks the exact comments `sent` atomically with
the final receipt, rebasing over unrelated review changes when the targets are
still byte-for-byte exact. A proven pre-custody refusal marks them `refused`;
an outcome that may have crossed provider custody remains ambiguous and is
never blindly replayed. `GetReviewReceipt` drives the same reconciliation after
restart. A changed fence before provider custody fails closed rather than
retargeting it.
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
- `retained_session` contains the closed provider (`jcode`), opaque provider
  session id, and exact Platform v2 `work_session_id` whose authoritative
  relations must lead to the bound review workspace and provider session;
- `ci` keeps its backward-compatible provider target and credential reference;
  a GitHub rerun capability additionally requires an exact bounded `checks`
  entry containing `check_id`, numeric `run_id`, 40/64-hex `head_sha`, positive
  `observed_attempt`, and positive `observed_check_revision`;
- `pull_request` contains an opaque provider repository and credential
  reference.

Credential references are names, never secret material in this registry. A
GitHub rerun is enabled only when the separate private sibling
`platform-v2-review-github-credentials.json` contains the same reference and
repository, a header-safe token, and the explicit boolean
`"actions_write": true`. That file has the same owner, mode, link, size,
unknown-field, and generation-fence checks as the review registry. Its token
is moved immediately out of the scrubbed serde/file buffer into a non-Debug,
zeroizing installed container. Only a short-lived typed-client copy is made at
the HTTP boundary; both copies scrub on drop. It is never rendered or sourced
from `gh`, the process environment, or ambient host authentication.

Target variants must
match their authority family, duplicate bindings and overlapping repository
roots are refused, repository and `.git` metadata cannot be symlinked or
group/world writable, and unknown JSON fields are rejected. The registry is
private composition state: its coordinates are never returned by Platform v2
and clients cannot supply paths, commands, provider targets, or credential
references. `GetReviewCapabilities` returns only the exact project/workspace,
snapshot revision, check id/revision, CI authority, and opaque confirmation
digest for currently runnable checks. Advertisement performs a fresh typed
GitHub workflow-run GET and emits
the capability only when run ID, head SHA, observed attempt, and completed
status still match; missing, stale, unavailable, or incoherent provider or
registry/credential state produces no advertised rerun capability. This read
never performs a provider mutation.

`ExecuteReviewAction(rerun_check)` persists the immutable run/repository/head/
attempt plan and custody in the review SQLite store before the one allowed
POST. Only a brand-new write admission in the same process may issue that POST.
The store atomically and durably reserves the ASCII-case-normalized repository,
run ID, and observed attempt across every actor and workspace, so aliases or
concurrent confirmations cannot create two POST opportunities. Attempts and
snapshot/check revisions whose next value cannot be represented are refused
before reservation or custody.
After a restart, `custody_started`, accepted, or ambiguous state is reconciled
with the exact workflow-run GET and is never submitted again. GitHub does not
return a rerun correlation token, so an exact next attempt completes the
receipt only when this process durably retained GitHub's 201 response for the
exact POST. A crash-before-POST or transport-ambiguous mutation remains
ambiguous even if another actor creates the next attempt; the old attempt, a
skipped attempt, or changed head likewise never triggers a second mutation.

Each advertised rerun capability also carries an opaque confirmation digest
over the authenticated actor, project/workspace, snapshot/check revisions,
provider target, and exact registry and credential generations. Cockpit first
renders that capability as an inert confirmation preview. Only an explicit
confirm returns the digest with the action; the daemon recomputes it before
persisting an approval and before provider custody. A changed or substituted
preview fails closed.

## Private attention source registry

The optional `platform-v2-attention-registry.json` sibling is the private
bootstrap source for attention tuples outside the runtime-owned review,
orchestration, and retained-session conventions. With no file, an unknown
source refuses as `platform_v2_attention_registry_unavailable`; it never
projects an empty board or assigns a request-time revision or timestamp. The
file is opened with `O_NOFOLLOW`, must be owned by the daemon uid with exact
mode `0600` and one hard link, and is bounded to 2 MiB. Its descriptor identity,
timestamps, length, and digest are rechecked before every read. A changed or
removed file refuses until restart as `platform_v2_attention_registry_changed`.

The version-1 registry has this closed shape:

```json
{
  "version": 1,
  "generation": "operator-generation-1",
  "snapshots": [
    {"schema": "automonique.platform/attention/v1", "semantics": "atomic_replace"}
  ]
}
```

Each `snapshots` entry is the complete canonical attention document described
in [Platform v2 authoritative attention
navigation](product-plan/platform-v2-attention-navigation.md); the abbreviated
entry above only identifies the nested schema and is not itself installable.
Operators must supply all required fields exactly as demonstrated by the
[installable canonical fixture](../rust/crates/automonique-protocol/fixtures/platform-v2-attention-v1.json).
Unknown outer or nested fields,
duplicate source/project/workspace tuples, malformed coordinates, and
non-monotone replacements are refused.

On startup, the complete validated registry generation is imported in one
transaction into the tenant-bound `platform-v2-attention.sqlite3` store. The
store accepts only an exact idempotent replay or a contract-validated
successor, integrity-binds the canonical bytes, durably retains every issued
item identity across every project and `UserWorkspace` tuple owned by that
source so a removed or moved ID cannot be reused, and revalidates duplicated
scope/revision/time fields on every read. If any tuple conflicts, no tuple from
that registry generation is committed. Request authorization remains bound to
the exact tuple and is not inferred from this source-lifetime identity custody.
The host first authorizes the exact
project and `UserWorkspace` through the current policy/work-context mapping,
then requires the registry tuple and persisted document to remain
byte-identical. Stale rows left by a removed registry entry are therefore
unreachable.

The live daemon additionally derives bounded runtime sources from its durable
review store, lineage index, and retained work-context/session graph. Review
and orchestration source ids equal the authorized `UserWorkspace` id;
provider-session source ids equal the retained `WorkSession` id advertised by
the same bounded work-context inventory. The host revalidates exact policy and
lineage before every read, persists each complete replacement through the
attention store, and never creates client-local pane or layout coordinates.
Review unread state remains exactly `event.unread() > 0`. Orchestration marks
`Blocked` and `Done` unread, marks `Working` read, and omits `Waiting`.
Provider sessions mark `Failed` and `Completed` unread; mark `Active`,
`Preparing`, `Running`, `Archived`, `Cancelled`, and `Closed` read; and omit
`Hibernated`. This bit is authoritative notification eligibility rather than
personal read custody. Consumers retain acknowledgements locally by exact
`(source, item, item_revision)`, suppress notification on exact replay, and
must treat a post-removal opaque item incarnation as new.
Terminal retained sessions remain readable through a dedicated read-only
lineage check so `Completed`, `Failed`, and `Cancelled` attention does not widen
the active-session mutation or delivery gate. The private registry rejects an
authorized tuple claimed by these runtime conventions before importing any
snapshot; the same collision remains rejected after restart. The hosted
cockpit probes durable review existence and requests that attention source only
when the review exists, while still consuming orchestration and retained-session
sources for workspaces without review state. `monique.1clic.pro` consumes these
snapshots directly. Registry hot reload, desktop/mobile consumers, and
cross-client acceptance remain outstanding.

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
  "task_selectors": [{
    "base_selector": "base-issue-166",
    "branch_selector": "branch-issue-166",
    "project": "project-example",
    "workspace": "wc2_user_workspace_00000000000000000000000000000004",
    "checkout": "wc2_checkout_00000000000000000000000000000003",
    "task": "task-issue-166",
    "external_provider": "github",
    "external_authority": "installation-example",
    "external_scope": "owner/repository",
    "external_key": "issue-166"
  }]
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
digests. Task-workspace entries additionally retain the adopting intent and
opaque workspace/checkout relation; their effect entries retain the exact
registry-generation record and policy-generation digest. Logical archive
changes do not delete operator files or git worktrees.

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
custody binds an operation family as well as the project and idempotency key;
review custody additionally binds the exact workspace kind and ID. Mutation
custody cannot admit a review lookup, and custody for one review workspace
cannot admit another. Legacy custody rows without this complete coordinate fail
closed after migration. Typed review-action submission, review-capability
reads, check reruns, and review-receipt lookup require independent
`execute_review_action`, `get_review_capabilities`, `rerun_check`, and
`get_review_receipt` mobile grants. The historical execute grant remains
limited to local `add_comment` and `approve_review`; it never grants a rerun. A
rerun grant accepts only the typed `rerun_check` action, and the web cockpit
shows it only when the exact live-preflighted check/revision capability matches
its fresh review snapshot. Provider-session, Git/filesystem, and pull-request
action families remain refused before the daemon socket. Custody is capped at
128 live entries per credential, survives process
restart and same-delegation access-token rotation, and is deleted on delegation
regrant or credential revocation. Thus another same-project credential and a
new delegation cannot read an older mutation receipt.

The final credential, delegation, generation, and receipt-custody check runs
inside a SQLite `IMMEDIATE` transaction that also records a request-digest-bound
ten-second dispatch lease. The transaction commits before the daemon socket is
opened, so ambiguous or completed mutation dispatch can never precede durable
mobile receipt custody. Submit custody also retains the exact canonical request
digest: the same coordinate may be retried only by the identical request.
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
