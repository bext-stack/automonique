# Initial development launcher

## Purpose

The first Automonique code cannot depend on the finished `automonique-bootstrap` or `automonique-lab`. A temporary stage-minus-one launcher provides one safe command that an operator can run after the private `bext-stack/automonique` repository and reviewed source baseline exist:

```bash
./scripts/automonique-dev start --provider auto --workers 1 --budget-eur 25
```

The launcher performs preflight, renders a reviewable plan, asks for an exact interactive confirmation, starts a persistent but bounded seed-development unit and attaches the operator. Its only goal is to build and verify the minimal Rust bootstrap/lab, import the durable development program and then retire itself. It is not a second permanent scheduler.

The script never creates the GitHub repository, changes repository visibility/rules, pushes, merges, publishes, signs a release, deploys production or reads production credentials. Those remain explicit external actions in the repository and self-hosting plans.

## Canonical files

```text
scripts/automonique-dev                  small Bash entry point
tools/bootstrap-seed/
├─ index.ts                              temporary Bun coordinator
├─ adapters/                             bounded Claude/Codex/opencode/Jcode launch adapters
├─ protocol.ts                           seed event/status schema
└─ test/                                 fake providers and failure fixtures

.automonique/dev/
├─ seed-program.yaml                     reviewed finite stage-minus-one DAG
├─ program.yaml                          full generated implementation DAG
├─ policies/seed.yaml                    paths, commands, budgets and stop rules
├─ guides/                               porting/state/security/naming/test guides
└─ scenarios/seed/                       bootstrap/lab acceptance scenarios

rust/crates/automonique-bootstrap/       permanent handoff target
tools/automonique-lab/                   permanent Rust development control plane
```

The Bash file handles only argument parsing, preflight discovery, locking, plan confirmation and `exec`/systemd launch. Durable orchestration and provider-specific parsing live in the typed seed coordinator. Once the Rust lab passes its handoff gate, the seed coordinator becomes a compatibility/recovery tool and is eventually removed by an explicit retirement ticket.

## Prerequisites

The source-build path requires:

- Linux initially, with `bash`, `git`, `flock`, `sha256sum`, `mktemp` and user systemd available;
- Bun at the version pinned by the bootstrap manifest for the temporary coordinator;
- `rustup`, `cargo` and `rustc` matching the checked bootstrap manifest, or a verified prebuilt bootstrap binary;
- at least one authenticated supported provider CLI selected through an adapter capability probe;
- a clean or explicitly snapshotted canonical Automonique checkout;
- enough declared disk, memory, process and provider budget;
- no running launcher for the same repository fingerprint.

Missing dependencies produce exact install/documentation guidance and exit without mutation. The script does not install system packages, run a remote shell installer or request sudo. `--offline` refuses every network-dependent step and requires all source/toolchain/provider inputs to be present and verified.

## Command surface

```text
./scripts/automonique-dev inspect [options]
./scripts/automonique-dev plan [options] --out <file>
./scripts/automonique-dev start [options]
./scripts/automonique-dev apply --plan <file> --digest <sha256>
./scripts/automonique-dev resume [run-id]
./scripts/automonique-dev status [run-id] [--json]
./scripts/automonique-dev logs [run-id] [--follow]
./scripts/automonique-dev attach [run-id]
./scripts/automonique-dev stop <run-id> --reason <text>
./scripts/automonique-dev doctor
./scripts/automonique-dev handoff-status
./scripts/automonique-dev cleanup --plan
```

`start` is the ergonomic interactive command: it runs `inspect`, creates the plan, prints its digest/summary and requires `apply <digest>` on a TTY. Non-interactive use must call `plan` followed by `apply` with the exact digest. `CI=1`, no TTY or redirected stdin never implies consent.

Useful options:

```text
--repo <absolute-path>                 default: discovered repository root
--provider auto|claude|codex|opencode|jcode
--model <provider-model-id>            optional, capability checked
--workers <1..seed-policy-max>         default: 1
--budget-eur <decimal>                 required unless policy supplies a lower cap
--max-wall-time <duration>             default from seed policy
--state-dir <absolute-path>            default: XDG state keyed by repository ID
--offline
--foreground                           no transient user unit; intended for tests
--no-tui                               print status command instead
--resume <run-id>
```

All paths are canonicalized and checked against forbidden roots. Environment-variable aliases are limited to non-secret defaults; command-line secret values are rejected. Provider authentication remains owned by the selected CLI/credential descriptor.

## First-run experience

The intended terminal flow is:

```text
$ ./scripts/automonique-dev start --provider auto --workers 1 --budget-eur 25

Automonique development bootstrap
Repository:  bext-stack/automonique @ <revision>
Source:      clean tree <digest>
Seed plan:   8 work units, max 1 worker
Provider:    <selected provider and probed mode>
Budget:      EUR 25 / 4h / declared token cap
Effects:     local worktree, XDG state, user transient unit
Forbidden:   push, merge, release, deploy, production credentials
Plan digest: sha256:<digest>

Type: apply <digest>
> apply <digest>

Started: seedrun_<id>
Status:  ./scripts/automonique-dev status seedrun_<id>
Attach:  ./scripts/automonique-dev attach seedrun_<id>
Stop:    ./scripts/automonique-dev stop seedrun_<id> --reason "..."
```

After the Rust lab passes handoff:

```text
SH0 seed verified: <artifact digest>
Development program imported: <program revision>
Stable lab unit: automonique-lab@<repo-id>.service
Attach: automoniquectl self-host status
TUI: automonique-tui --development
Seed coordinator: retired (recovery manifest retained)
```

## Preflight and plan contents

`inspect` is read-only and records:

- repository remote/ID, current branch/revision/tree/dirty patch and nested repository state;
- license/provenance/bootstrap/seed-program/policy file presence and digests;
- required tool versions and executable digests;
- provider versions, authentication health and supported non-TTY/stream/resume mode without exposing credentials;
- filesystem type, free disk/inodes, XDG paths, user systemd/cgroup/namespace/Landlock capabilities;
- existing seed/lab units, locks, runs, worktrees and recoverable state;
- network/offline requirements and approved dependency sources;
- calculated CPU/memory/PID/I/O/disk/token/cost/wall-time ceilings;
- exact files/directories/units that `apply` may create and cleanup behavior.

The resulting versioned plan contains immutable inputs, commands as program/argv, expected outputs, action order, rollback for each action, stop conditions and plan expiry. Any repository/toolchain/policy/provider change invalidates it.

## Stage-minus-one seed program

`seed-program.yaml` is intentionally finite and manually reviewed. It cannot add work to itself. It contains only the minimum path to permanent tooling:

1. Validate source, guides, work IDs and existing TypeScript parity fixtures.
2. Create the canonical Cargo workspace and generated bounded development protocol.
3. Implement minimal SQLite work-DAG/attempt/lease/event storage for `automonique-lab`.
4. Implement one sandboxed provider adapter path plus fake provider; additional providers follow after the lab owns conformance.
5. Implement file/worktree leases and typed Git/build brokers with no push/merge authority.
6. Implement `automonique-bootstrap inspect|plan|apply|verify|resume` and the bootstrap manifest reader.
7. Run the three harness trials, clean-host SH0 scenario, restart recovery and secret scan.
8. Build immutable SH0, start it, import the full `program.yaml`, reconcile seed evidence and stop the coordinator.

Each unit is mapped to existing R0/R1 tickets, allowed paths, objective, tests, provider budget, reviewer roles and a human checkpoint. The seed path uses one implementer at a time by default and at least two fresh-context reviews before a unit becomes handoff evidence.

## Seed coordinator behavior

The temporary Bun coordinator reuses only reviewed bounded primitives from the legacy implementation or implements a small isolated equivalent:

- length-prefixed/NDJSON provider event handling with stdout/stderr separation;
- per-run persistent status/events under XDG state;
- provider session ID capture and bounded resume;
- one worktree and one write lease per seed unit;
- explicit argv/stdin prompt delivery, never a generated shell command line;
- background build/test processes in a transient user systemd scope/cgroup;
- stop/timeout/cancellation of complete descendant cgroups;
- independent implementer/reviewer/fixer prompts and frozen candidate diffs;
- commit-metrics evidence without automatic Git commit/push;
- restart/resume from completed durable boundaries.

It does not import production legacy databases, tokens, conversations, Slack/Telegram state or provider credentials from `.env`. Synthetic fixtures are copied by digest. Provider CLIs receive the minimal environment produced by the seed policy.

## Provider selection

`--provider auto` probes all installed adapters and selects the first policy-preferred compatible non-interactive mode with healthy existing authentication. The plan prints the selected provider, binary/version/digest, model, capabilities, expected credential source and fallback policy before confirmation.

A fallback is never silent. Provider loss pauses the affected unit; changing provider/model creates a revised plan/attempt with separate metrics. Resume uses only a provider-tagged session ID with matching repository/worktree/security context.

The seed coordinator initially needs one reliable provider. Claude, Codex, opencode and Jcode adapters become mandatory before the permanent lab harness exit gate, not before the first local source file can be created.

## Filesystem and runtime layout

```text
$XDG_STATE_HOME/automonique-dev/<repo-id>/seed/
├─ runs/<run-id>/
│  ├─ plan.json
│  ├─ status.json
│  ├─ events.ndjson
│  ├─ stderr
│  ├─ evidence/
│  └─ handoff.json
├─ locks/
├─ worktrees/<unit-id>/
└─ recovery/

$XDG_RUNTIME_DIR/automonique-dev/<repo-id>/
├─ seed.lock
├─ seed.sock
└─ lab.sock
```

Modes are 0700 directories and 0600 files/sockets. Repository-local generated state is limited to ignored build output; durable local state never dirties the source tree. A repository ID derives from canonical remote plus local registration, not only its directory name.

## systemd ownership

Default `start` launches a transient user service such as `automonique-seed@<repo-id>-<run-id>.service` with explicit working directory, runtime/state paths, resource limits, environment allowlist and kill mode. The terminal may detach without stopping development. `foreground` exists for CI and debugging only.

The seed process cannot install persistent units itself. During handoff, the reviewed bootstrap action installs/enables the user-level stable lab unit, verifies readiness, transfers only development-program ownership, writes the handoff receipt and terminates the transient seed unit. A failed handoff leaves the coordinator recoverable and the candidate lab non-owning.

## Git policy

- The script refuses `main`/default-branch writes and creates or selects a bot-owned bootstrap branch/worktree through exact commands.
- Agent processes cannot run Git mutation commands; they request stage/commit through the seed Git broker after path, base and diff checks.
- Seed mode defaults to preparing uncommitted reviewed units. `--allow-local-commits` may enable scoped commits with metrics trailers, but never push.
- No stash, reset, checkout of arbitrary refs, force operation, tag, remote edit, push, PR, merge or submodule URL change is exposed.
- Existing dirty state is refused unless `--snapshot-dirty` creates a reviewed immutable patch artifact; it is never silently included.

## Failure and recovery

Failure behavior is explicit:

| Failure | Result |
|---|---|
| Preflight/plan invalid | no mutation |
| Operator declines/expires | no mutation |
| Provider unavailable | unit paused with resumable evidence |
| Coordinator killed/reboot | transient unit stops; `resume` reconciles worktree/process/session evidence |
| Build/test exceeds resources | cgroup stopped; unit failed/reviewable; host remains healthy |
| Source changes | current result superseded; new plan required |
| Review blocker | candidate frozen; fixer or human disposition required |
| Rust lab fails readiness | seed retains ownership; lab stopped/quarantined |
| Handoff unknown | query durable handoff receipt and unit/socket ownership; never repeat blindly |
| Disk pressure | stop new work, preserve minimal state/evidence and print cleanup plan |

Cleanup is preview-first, targets only registered seed worktrees/units/state and preserves evidence/recovery by default. The script never recursively removes a workspace root, home or unresolved variable path.

## Testing

Before anyone relies on the launcher, CI and a disposable host prove:

- ShellCheck plus Bats tests for argument parsing, quoting, paths, plan confirmation and every refusal;
- fake executable/provider fixtures for success, malformed events, missing auth, timeout, resume and fallback;
- repositories with clean/dirty/detached/wrong-remote/nested/worktree/source-change states;
- no secret in argv, environment projection, plan, logs, systemd properties or evidence;
- exact descendant cancellation and resource limits;
- interrupted plan/apply/start/build/review/handoff/recovery at every durable boundary;
- no push/merge/release/deploy or production credential access, including adversarial prompts;
- reproducible seed plan and deterministic program import;
- successful handoff to the Rust lab and a second run that immediately delegates rather than restarting seed orchestration;
- idempotent stop/cleanup and preservation of unrelated worktree/user state.

## Retirement

After `automonique-bootstrap` and `automonique-lab` are stable:

- `scripts/automonique-dev start` becomes a thin compatibility entry that executes `automonique-bootstrap` or connects to the stable lab;
- the Bun coordinator remains only for a declared recovery window with no new capabilities;
- clean-host tests ensure a source bootstrap no longer needs the coordinator;
- removal requires archived seed protocol/fixtures, recovery evidence and a migration message for any persisted seed run.

The permanent user experience remains the same command even though ownership moves from stage-minus-one Bash/Bun to the Rust bootstrap/lab.

## Exit gate

The launcher is ready when an operator can run the single `start` command in a clean private upstream clone, review and confirm an exact plan, detach, observe bounded agent/review/build progress, survive coordinator termination/reboot, and receive a verified SH0 lab that imports the full program. No production data/credential, destructive Git action, remote publication or unexplained mutation occurs, and a repeated command detects the lab and attaches instead of creating a second control plane.
