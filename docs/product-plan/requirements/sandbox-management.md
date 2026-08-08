# Sandbox management

**Status:** accepted implementation plan

## Purpose

Automonique treats sandboxing as a versioned, attestable runtime contract compiled from the reviewed work plan. It is not a provider flag, a shared container, or a promise that every Linux host offers the same isolation.

The sandbox must contain model-directed code, tools, extensions and provider subprocesses while preserving the minimum connectivity needed for the trusted provider adapter. It must also survive daemon reload without changing the authority of an active execution host.

## Threat model

Assume that prompts, repository contents, generated code, archives, MCP responses and tool output can be hostile. Protect against:

- reading host credentials, unrelated repositories, user home data, runtime sockets or another tenant's workspace;
- writing outside the exact attempt workspace or mutating the canonical source checkout;
- arbitrary Internet, metadata-service, private-network, loopback or Unix-socket access;
- fork bombs, memory/CPU/I/O exhaustion and unbounded spool/artifact growth;
- path, symlink, hard-link, mount, `/proc`, descriptor and executable-replacement races;
- provider or extension processes silently widening tool/network policy;
- session resume through a different tenant, account, workspace or weaker sandbox;
- escape through a root Docker socket, general sudo rule or overly broad privileged helper.

The first release does not claim a different-kernel security boundary. Rootless namespaces, Landlock and seccomp remain same-kernel controls. Work requiring hostile-kernel isolation is ineligible until an approved microVM/remote isolated executor profile is available.

## Policy compilation

The deterministic execution plan compiles into an immutable `SandboxSpec` referenced by `RunSpec`. It contains:

- profile ID/version and complete policy digest;
- tenant, actor, provider account and workspace security-context hash;
- immutable base revision plus readable and writable path grants;
- executable, interpreter, tool, MCP and companion allowlists;
- provider-control and tool-workload network policies kept distinct;
- credential descriptors and the exact process class allowed to receive each one;
- cgroup, rlimit, timeout, temporary-storage, spool and artifact budgets;
- required kernel/systemd features and accepted enforcement implementation digests;
- nested tool-execution, extension and optional stronger-isolation requirements;
- approval/policy revision and prohibited-capability set.

The host records an `EnforcementAttestation` containing the resolved real paths, namespaces, cgroup/unit IDs, kernel/boot identity, effective systemd properties, Landlock ABI/ruleset digest, seccomp digest, egress-policy digest, credential delivery mode and any verified external-daemon context.

Missing required enforcement fails before provider input is delivered. There is no silent fallback from a stronger profile to a weaker one.

## Standard profiles

Profiles are minimum contracts. A deployment may make them stricter, but a capability cannot be added without a new plan revision.

| Profile | Filesystem | Tool/workload network | Intended use |
|---|---|---|---|
| `observe` | registered immutable snapshot, no writes | denied | deterministic inspection and safe status/query work |
| `workspace-offline` | one isolated writable attempt workspace | denied | code edits, tests and builds that need no external fetch |
| `workspace-egress` | isolated writable workspace | named destinations through the egress broker | dependency/API work with reviewed outbound needs |
| `extension-isolated` | minimal materialized inputs and output grants | denied or brokered per extension | third-party provider/MCP/companion process |
| `shell-isolated` | explicit workspace and artifact grants | denied by default | separately authorized compatibility shell |
| `strong-isolation` | disposable encrypted volume/snapshot | explicit broker only | future microVM or remote isolated executor for higher-risk work |

Classification/chat lanes use a no-tools variant and receive no workspace-write or tool credentials. Privileged deployment, service, DNS and production mutations are never profile capabilities; they remain typed post-sandbox broker actions against reviewed artifacts/revisions.

## Process and resource boundary

Each attempt- or session-scoped execution host runs in a dedicated systemd unit/cgroup. Apply and attest, as supported by the selected implementation:

- `NoNewPrivileges`, capability bounding, restrictive umask and private temporary/runtime directories;
- cgroup v2 `MemoryHigh`/`MemoryMax`, CPU quota/weight, `TasksMax`, I/O weight/limits and bounded runtime;
- rlimits for descriptors, processes, core dumps and file sizes;
- bounded tmpfs/scratch plus workspace, spool and artifact quotas;
- complete descendant accounting and cancellation even after process-group/session changes;
- no root Docker/Podman socket, host D-Bus, SSH agent, arbitrary Unix socket or inherited ambient descriptor.

Admission reserves resource and disk budgets before launch. A limit event is terminal or explicitly retryable; it is never disguised as provider completion.

## Filesystem boundary

Use layered controls:

1. The workspace registry resolves canonical sources and provisions one immutable-base worktree/snapshot per mutating attempt.
2. A mount namespace exposes only the provider/runtime files, selected read-only dependencies, materialized artifacts and the attempt workspace. Home, production state, sibling workspaces and host runtime sockets are absent.
3. Landlock restricts filesystem access inside that view as defense in depth.
4. A minimal `/proc` and `/dev` view prevents unrelated process/environment discovery and unsafe device access.
5. Path operations use pre-opened descriptors and fd-relative checks where possible; links, mount crossings and replacement races are rejected.

The Phase 0/2 spike chooses the supported rootless implementation—direct namespaces, systemd sandbox properties, or a pinned no-install-script helper such as bubblewrap. If the user service cannot create the required namespaces safely, a separate minimal root-owned sandbox launcher may create only the prevalidated boundary; it is not the deployment broker and never accepts a command string.

## Network boundary

Seccomp can deny socket operations or restrict address families, but it cannot securely enforce domain/destination policy. Destination-aware egress therefore uses a network namespace plus a narrow egress broker/proxy:

- `observe` and `workspace-offline` tool processes receive loopback-only or no network namespace access;
- reviewed destinations are stable policy objects, not arbitrary URLs supplied in prompts;
- the broker performs DNS resolution, rejects private/link-local/metadata/loopback ranges unless explicitly authorized, pins the resolved request, bounds redirects and records destination/bytes/outcome;
- proxy credentials and destination policy never enter the tool process;
- inbound listeners are denied unless a profile declares a loopback-only provider service with a random credential;
- Unix-domain sockets are explicit filesystem/capability grants, not an escape around IP policy;
- nftables/system routing is configured only through a narrow host capability when rootless enforcement is insufficient.

Provider control-plane egress and model-directed tool egress are separate. The trusted adapter/provider may reach pinned model/auth endpoints, while tool commands use a nested no-network or brokered boundary. A provider version is ineligible for a restricted profile if its tool execution cannot be intercepted, separately sandboxed and proved not to reuse provider-control connectivity for model-directed arbitrary requests.

Built-in web search, URL fetch, MCP and browser tools remain explicit capabilities with their own egress policy; allowing the provider API does not allow these tools automatically.

## Credentials and process classes

- Prefer sealed inherited descriptors, systemd credentials or an equivalent one-time protected mechanism over ordinary environment variables.
- A credential is delivered only to the adapter/provider or exact tool/MCP process class named by the spec.
- Nested tool processes start from an empty allowlisted environment and do not inherit provider, Slack, GitHub, connector, fleet or root-broker credentials.
- Credential version/audience is checked immediately before use; rotation or revocation blocks new turns and may quarantine an active host according to policy.
- Secret scanning/redaction is defense in depth, not the isolation mechanism.

## Provider, MCP and extension containment

- Claude, Codex and opencode native servers remain in the execution-host boundary and use only tested sandbox-compatible modes.
- Jcode's external daemon must attest equivalent tenant/account/workspace/tool/network enforcement; otherwise Automonique provisions a daemon per security context or rejects the profile.
- Each third-party TypeScript provider, MCP server or companion runs in its own child unit/sandbox with a declared digest, capabilities, credentials, paths, egress and resource budget.
- Extension installation never runs lifecycle scripts on a production host unless separately reviewed into the immutable release.
- A provider approval request cannot widen `SandboxSpec`; added authority produces a new reviewed plan and normally a new host.

Workflow runtimes, hooks, learned skills and UI extensions follow the same rule. Declarative workflows are preferred; WASI components, JavaScript workers and Python workers each run in a pinned child boundary with only declared host calls. Pre/post hooks receive typed bounded envelopes, not ambient process state. UI extensions cannot load native code into the daemon or desktop shell and reach mutations only through the authenticated SDK.

Browser and computer-use workers run in disposable profiles with an origin allowlist, isolated cookie/credential jars, bounded screenshots/recordings, clipboard denial by default and no access to the operator's display session. Media decoders and document parsers are treated as hostile-input workers. Remote, batch, cluster, microVM and hosted executors must enforce the portable `RunSpec`, prove workload identity and return fenced lifecycle/attestation evidence; a remote vendor's “sandbox” label is never accepted as proof by itself.

## Session reuse and reload

An active host is pinned to its sandbox policy and attestation. A follow-up may reuse it only when tenant, provider account, workspace context, credentials and policy are identical or demonstrably narrower. Any widening creates a new revision/host and re-enters approval.

Daemon generation handoff adopts the existing host and revalidates its attestation digest, cgroup/unit and namespace identity. Reload never rebuilds the sandbox around a live provider. A missing/mismatched enforcement object quarantines the host and permits only bounded observation, reconciliation or cancellation.

## Self-hosting candidate boundary

Development self-hosting adds a stable/candidate boundary above ordinary worker isolation:

- candidate services use digest-named systemd units, UID/runtime paths, sockets, network namespace, database, artifact store and credential audience;
- production transport, Support/fleet, protected-branch, release-signing and deployment credentials are absent rather than merely hidden by prompt policy;
- source, dependency and toolchain acquisition uses the reviewed bootstrap manifest and egress allowlist;
- build workers receive immutable caches or brokered writes plus CPU/memory/PID/I/O/disk quotas;
- candidate database migrations operate only on synthetic or cloned state and cannot mutate the stable development database;
- candidate messages/files/effects terminate in fake, shadow or explicitly allowlisted canary targets;
- stable verifies candidate artifacts through digests and descriptors rather than trusting paths or candidate-reported success;
- independent rebuild workers have a different workload identity and provenance authority from both stable and candidate.

The stable bootstrap verifier/launcher never loads candidate libraries or executes candidate hooks in-process. Candidate escape, credential discovery, stable-socket binding, evidence tampering and provenance forgery are explicit negative-test families.

## Privileged and stronger-isolation paths

The deployment broker remains a separate root-owned executable accepting only typed, revision-bound operations over reviewed artifacts. If namespace/network setup requires privilege, use a different sandbox launcher with a closed schema containing policy digest, UID, prepared file descriptors and resource values—never arbitrary argv, paths or shell text.

For work that cannot be trusted under a shared kernel, add a `strong-isolation` provider backed by a disposable microVM or independently isolated remote executor. It must implement the same event, artifact, credential, cancellation and attestation contracts. Until that profile exists and passes conformance, such work is rejected rather than run in a normal container with a stronger label.

## Management and observability

The SDK, dashboard, TUI and CLI expose read-only sandbox evidence and authorized policy selection:

- requested/effective profile and policy/attestation digests;
- filesystem, egress, tool, credential and resource summaries without secret values;
- kernel feature health and enforcement implementation version;
- resource usage/pressure, quota exhaustion and violation events;
- external-daemon/extension containment status and downgrade/refusal reason;
- why a job was admitted, rejected, quarantined or required new approval.

Emit durable `SandboxPrepared`, `SandboxAttested`, `SandboxViolation`, `SandboxLimitReached`, `SandboxQuarantined` and `SandboxReleased` events. Alert on enforcement drift, repeated denials, orphan namespaces/cgroups, broker policy failures, unexpected egress and cleanup backlog.

Runbooks cover kernel capability loss after upgrade, stuck namespace/cgroup, egress broker outage, disk quota, denied dependency fetch, credential revocation, external-daemon mismatch, sandbox-launcher failure and emergency provider quarantine.

## Verification and exit gate

The implementation is not production-ready until tests prove:

- required profiles fail closed on every missing kernel/systemd feature;
- filesystem escapes through links, mounts, `/proc`, descriptors and race replacement fail;
- Internet, private/metadata/loopback and Unix-socket access is denied unless exactly granted;
- DNS rebinding, redirect and proxy-confusion cases cannot escape the reviewed destination set;
- provider-control connectivity cannot be repurposed as tool egress;
- CPU, memory, PID, I/O, runtime, tmp, workspace, spool and artifact limits terminate/reconcile correctly;
- nested tools/extensions receive only their named paths, credentials and network policy;
- cancellation kills all descendants and cleanup leaves no reusable namespace, mount, socket or credential;
- current and previous daemon generations adopt the same attested host without policy drift;
- Jcode and every other external daemon reject cross-context resume;
- the privileged sandbox launcher/broker parsers pass fuzzing and independent review;
- production-kernel smoke tests and a controlled escape-oriented review pass for every enabled profile.

Core cutover requires `observe`, `workspace-offline` and the provider-control separation needed by enabled providers. `workspace-egress`, third-party extensions, the optional shell and `strong-isolation` graduate independently behind capability flags.
