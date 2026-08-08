# ADR 003 — workspace registry and isolation

**Status:** accepted for implementation planning

## Context

Automonique may run several agents concurrently against the Bext monorepo and individual sites. Thread/issue/session serialization does not prevent two unrelated jobs from editing the same checkout or files. A validated `cwd` protects path scope but not concurrent correctness, dirty-tree contamination or reproducible delivery.

## Decision

Introduce a durable workspace registry and make writable work execute in an isolated attempt workspace by default.

```text
canonical source checkout (read-only to workers)
  └─ immutable base revision
       ├─ worktree/snapshot for attempt A
       └─ worktree/snapshot for attempt B
```

Read-only queries may use a verified canonical source snapshot. Writable attempts receive a dedicated Git worktree or immutable copied snapshot under an Automonique-owned workspace root. The primary checkout is never a shared writable agent workspace.

## Registry

Each workspace record contains:

- stable workspace/site ID and tenant/scope;
- canonical repository path and remote identity;
- allowed root/subpaths and default branch;
- source revision and cleanliness evidence;
- target site/server mapping with provenance and revision;
- risk/sandbox/tool/network policy;
- retention and cleanup policy.

Learned domain-to-server targets become revisioned registry data with actor/provenance, not an untracked JSON side channel.

## Locking and concurrency

- Work item serialization remains by thread/issue/provider session.
- Workspace integration locks protect branch publication, merge, deployment and other shared effects.
- Optional path/site intent locks warn or serialize attempts expected to modify overlapping areas.
- Isolated attempts may run concurrently when their base revision and policies are compatible.
- A lock lease is fenced by epoch and never released solely because a daemon generation exits.
- Conflict detection occurs before publication; Automonique never auto-overwrites another attempt or user change.

## Attempt lifecycle

1. Resolve registry entry and exact base revision.
2. Validate canonical checkout ownership, remote, cleanliness and object availability.
3. Create an exclusive attempt worktree/snapshot without following unsafe links.
4. Record base revision, workspace ID, paths and sandbox grants in `RunSpec`.
5. Run tools only inside the attempt workspace plus explicit read-only dependencies.
6. Capture patch, commits, changed paths, tests, screenshots and build outputs as artifacts.
7. Review/integrate through a typed workflow under an integration lock.
8. Retain or remove the attempt workspace according to terminal state and artifact policy.

When a provider uses an external/shared daemon, the daemon—not merely the local bridge—must enforce the recorded workspace root and deny resume into another workspace/tenant context. If that cannot be proven by conformance tests and process evidence, use a dedicated daemon scoped to the registered workspace security context.

## Dirty and non-Git sources

A dirty canonical checkout cannot seed writable work unless an explicit immutable snapshot is created and reviewed. Non-Git sources require a content manifest/hash and equivalent copy-on-write isolation. Symlinks, submodules and nested repositories receive explicit policy rather than implicit traversal.

## Delivery and deployment

The privileged broker consumes only an approved exact revision plus verified artifacts from the workspace/artifact system. Deployment never builds from a mutable attempt directory after approval. Merge conflicts or base drift create a new review revision.

## Verification

Test simultaneous edits to the same/different paths, dirty checkout, branch movement, submodules, symlink races, cleanup crashes, disk pressure, merge conflict, user edits during a run, and deployment of exactly the approved content. No two attempts may share a writable filesystem tree.
