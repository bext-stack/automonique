# Automonique

Automonique is a durable, local-first agent control plane that accepts work,
executes it through multiple model and tool providers, preserves state across
failures and upgrades, and exposes the same authority through every client.

Linux-first and built primarily in Rust, it aims to make every state change and
external effect typed, revision-checked, journaled, and reconcilable.

## Repository status

Automonique performs real external effects. A configured daemon holds durable
SQLite state under one fenced process generation, answers a peer-authenticated
local admin socket, and — for each surface an operator has explicitly enabled —
talks to Telegram, Slack, GitHub, and a support backend, and executes real
provider processes inside the enforced sandbox with brokered network egress.

Every one of those surfaces is off until an operator writes its configuration
file by hand into the daemon's private state directory. Absent the file, the
daemon builds no client for that surface and says so; present but malformed, it
refuses to start rather than degrading quietly.

| Surface | Enabled by | What it does when enabled |
| --- | --- | --- |
| Telegram | `telegram/bot.conf` | Long-polls, publishes a command menu, answers operator commands, and replies. Without an `allow=` line the token is dropped and no client is built. |
| Slack | `slack/slack.conf` | A Socket Mode worker that reads channels, posts messages, opens modals, and publishes an App Home view. |
| GitHub | `github/github.conf` | Creates issues, comments, edits checklists, and runs typed work-management mutations — each one separately enabled by an `action=` line, each carrying an idempotency marker checked before a create and re-checked after an ambiguous failure. |
| Support intake | `support/fleet.conf` | Polls the ticket board into a durable store and drafts replies. Intake itself sends nothing; an email or a dispatched job happens only on an explicit operator intent. |
| Provider execution | `provider` | Composes a bounded launch document and runs a real provider process through the full sandbox boundary, returning its answer. |
| Brokered egress | `egress-destinations` | Starts one loopback CONNECT broker per run on a kernel-assigned ephemeral port, allowing exactly the host/port pairs the file names and denying everything else. Absent, every brokered document is refused. |
| Self-improvement | `improvement-lab.json` | Runs a pinned agent in a worktree, pushes a tested candidate, opens and merges pull requests, repoints a release symlink, and restarts a systemd user unit. Gated behind two separate administrator approvals bound by an HMAC challenge. |
| Durable memory | `memory/memory.conf` | The one gate whose absent state is a default rather than an off switch: memory runs under a neutral default tenant. It never migrates rows written under another tenant. |

What the daemon still does not do, and says so at the sites that would have to
change:

- **No scheduler, no executor, no acting on anyone's behalf.** The automation
  store, approval ledger, and batch registry record decisions durably and
  truthfully, and nothing reads them to decide anything. Registering an
  automation starts nothing, a recorded approval permits nothing, and a batch's
  concurrency ceiling throttles nothing.
- **No release trust.** A provider binary is admitted by pinned digest and by
  the daemon's own workspace registry, never by a verified signature. The
  signature seam is structurally unconstructible, not merely unimplemented.
- **No generation handoff.** Approved code upgrades drain accepted work and
  restart the process through an atomic release link; there are no `reload`,
  `rollback`, or `generations` verbs and intake does not overlap between the
  two generations. Skill-only releases hot-reload without a process restart.
- **No metrics exporter, no tracing, no logger.** Bounded metrics are derived
  from one SQLite snapshot and served over the local status command only.
- **Named surface gaps.** Telegram `/cancel` and `/deny` answer
  `cancel_verb_absent` and `approval_wiring_absent` rather than faking an
  effect; callback queries cannot be acknowledged; support intake pages nothing
  and holds no cursor or lease.

Large historical planning and development-harness surfaces remain in the tree,
but they are no longer prerequisites for product development.

Status reconciled against `d10cfa5`, 2026-08-15. A pull request that adds or
enables an external surface updates this section in the same pull request; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

```text
docs/product-plan/       product goals, requirements, architecture, migration
rust/crates/             Rust product crates and tests
sdk/                     Apache-2.0 client SDKs
plan/                    archived executable-plan experiment
tools/                   development and diagnostic tools

AGENTS.md                direct development and safety policy
GOVERNANCE.md            authority boundaries
LICENSE-POLICY.md        Elastic-2.0 / Apache-2.0 directory boundary
PROVENANCE.md            clean-room provenance
```

## Start developing

Read [`AGENTS.md`](AGENTS.md), inspect the relevant requirement, code, and
tests, then make the requested change directly. Run checks that fit the change;
commit normally and non-force-push when requested. The old material under
`plan/` is historical and is not part of this workflow.

Useful checks include:

```sh
python3 tools/check_licenses.py
python3 tools/scrub/scan.py
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo test --manifest-path rust/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --locked -- -D warnings
```

The runner's containment proofs need a delegated cgroup v2 subtree, which an
interactive login session does not have. Outside one they assert the fail-closed
refusal instead. To actually exercise the boundary, run them in a delegated
scope and require enforcement, so a host that cannot prove it fails loudly
rather than reporting a green but vacuous run:

```sh
systemd-run --user --scope -p Delegate=yes \
  --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
  cargo test --manifest-path rust/Cargo.toml -p automonique-runner --test containment
```

Choose checks relevant to the changed area. Product CI remains authoritative
for actual failures; the archived plan's self-consistency is not a product
gate.

## Run the local daemon

The current executable requires explicit private XDG runtime and state roots;
it does not fall back to a home directory. On a normal Linux user session these
variables are often already set. To launch it:

```sh
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:?set a private runtime directory}"
export XDG_STATE_HOME="${XDG_STATE_HOME:?set a private state directory}"
cargo run --manifest-path rust/Cargo.toml -p automonique -- daemon --foreground
```

From another terminal with the same environment:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- status
cargo run --manifest-path rust/Cargo.toml -p automonique -- status --json
printf '%s' 'local fixture' | cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  submit workspace:test fixture:1
cargo run --manifest-path rust/Cargo.toml -p automonique -- shutdown
```

If a prior daemon died after claiming synthetic work but before committing its
outcome, the successor stays online in `failed` state with intake closed. The
operator can inspect the durable record and submit an exact fail-only decision:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- reconcile inspect <run-id>
cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  reconcile fail <run-id> <generation-id> <epoch> <revision> <decision-key>
```

The decision never requeues ambiguous work. It atomically records a failed run,
failed inbox item, and fake reconciliation receipt; an exact retry replays the
same receipt.

Expired, outcome-ambiguous outbox effects can likewise be inspected without
revealing their payload or lease token. The CLI fetches and validates the exact
token over the authenticated local socket; only the receipt/reason is read as a
bounded line on stdin, keeping both values out of argv and process listings:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- outbox inspect <outbox-id>
printf '%s\n' '<receipt-or-reason>' | \
  cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  outbox reconcile <delivered|dead-letter> <outbox-id> <generation-id> \
  <epoch> <attempt> <revision>
```

The daemon creates only `automonique/` children under those roots and refuses
permissive or foreign-owned paths. Its only listening socket is the local Unix
admin socket; the one network listener it ever binds is the per-run egress
broker, on a kernel-assigned loopback port that is never shared or reused
between runs.

The `submit` command above is the synthetic lane, and it is still exactly what
it was: bounded local synthetic work, read from stdin, serialized by scope, and
recorded as one deterministic terminal plus one pending `fake.receipt`. That
command executes no process, calls no provider, drains no outbox, and sends no
external effect, and `accepting_intake=true` refers only to it. Starting real
work is a different, separately authenticated request, so holding a document
and running it stay two decisions rather than one.

The runner now installs real, exercised kernel boundaries rather than only
observing that kernel interfaces exist. A run cgroup provides descendant-complete
containment on cgroup v2: placement is race-free because a self-migrating entry
helper confirms its own membership before it `execv`s the workload, ceilings are
applied before the cgroup can hold a process, `cgroup.kill` terminates the whole
subtree atomically, and disposal leaves no kernel residue. A test proves that a
`setsid` grandchild — which defeats process-group termination — is still reaped.
On top of that, the runner has verified descriptor closure (close everything
outside an explicit allowlist, then re-read `/proc/self/fd` to confirm), a
Landlock filesystem allowlist with distinct read / read-write / read-execute
grant intents that refuses partially enforced rulesets, and a Landlock ABI-4
TCP policy that denies `bind`/`connect` by default. The TCP policy is
deliberately not called network denial: UDP, raw sockets, `AF_UNIX`, and
already-connected inherited sockets remain outside Landlock's reach, the tests
record those gaps as executable fact, and closing them requires descriptor
closure (done) plus a future seccomp socket filter. A read-only capability
probe reports which of these mechanisms the host can actually enforce and a
mode selector refuses or degrades loudly, never silently.

A seccomp socket-family filter now closes the socket-creation side of that
gap: by default a sandboxed workload cannot create any socket at all, and a
plan may grant only a closed vocabulary of shapes (AF_UNIX stream/datagram,
AF_UNIX seqpacket, IPv4/IPv6 TCP streams). The filter masks the type flags so
`SOCK_CLOEXEC`/`SOCK_NONBLOCK` cannot slip past it, applies the same domain
discipline to `socketpair(2)`, denies the io_uring syscalls and the x32
syscall ABI, and refuses non-x86_64 builds rather than guessing. Its tests
record what remains honestly out of reach: descriptors inherited before
enforcement and `SCM_RIGHTS` passing over a granted unix socket.

A composed launch path ties the mechanisms together: a supervisor encodes a
bounded, typed `LaunchPlan` (program, argv, filesystem grants, TCP exceptions,
socket-shape grants — delivered over stdin, never argv), and a trusted entry
helper joins the run cgroup, confirms membership from the kernel, replaces
stdin with `/dev/null`, closes and verifies descriptors, installs both
Landlock domains and the socket filter, and only then `execve`s the workload
with an empty environment. A plan whose layers contradict each other — a TCP
port exception without the TCP socket grant — is refused rather than resolved
silently. An end-to-end test launches a real workload under all five
boundaries at once and reads the workload's own observations to prove each
held simultaneously, with the TCP probe denied by Landlock at `connect`
(EACCES) while the UDP probe dies earlier at `socket` (EPERM) — two distinct
errnos proving two distinct layers; a truncated plan refuses before anything
runs.

On top of the launch path sits the first execution backend: a supervised
direct-process run that records started/terminal lifecycle events in the
attempt's hash-chained spool, maps helper refusals distinctly from workload
failures, kills the whole tree on cancellation or deadline through the cgroup,
and never returns with the spool non-terminal or the cgroup left behind. A
runner control socket exposes each attempt over a private, versioned Unix
endpoint that authenticates kernel peer credentials before reading a single
request byte: bounded `inspect`, cursor-paged byte-exact `subscribe`,
read-only `heartbeat`, and durably idempotent `cancel` whose replay says
`already_delivered` and whose reuse across attempts conflicts. The store
crate gains a provider session journal persisting process, session, turn,
request, cursor, capability/schema, and approval bindings with revision-checked
transitions, transactional multi-row commits, and reads that surface
hand-written corruption as typed errors instead of trusting rows.

The launch frame now also carries an explicit environment allowlist and an
optional prompt: variables are validated by grammar and bounds and passed to
`execve` exactly as named (nothing inherited, nothing synthesized), and prompt
bytes are delivered as the workload's stdin through a sealed anonymous memfd —
no path ever names them, they cannot appear in argv, and without a prompt the
workload's stdin is still `/dev/null`. A supervised attempt now composes the
backend with the runner control socket: a peer can inspect and heartbeat a
live run over the authenticated endpoint and cancel it for real, with the
kill proven against a `setsid`-escaped descendant. The store crate adds a
durable host-wide cancellation ledger whose delivered/already-delivered/
conflict answers survive restart, ready to replace the control socket's
documented in-memory ledger when the daemon composition wires the two
together. Provider execution now happens for real: the agents crate builds
exact sandboxed launch plans for a digest-pinned provider executable and parses
provider event streams incrementally, and the daemon's execution lane drives
those plans through the launch helper with one worker thread per attempt. The
daemon's status reports a measured `execution_state`
(`sandbox_unavailable_no_lane` / `sandbox_enforceable_no_lane`): what the host
could enforce for a launcher. Both spellings still say `no_lane`, which the
lane's own wiring has outgrown — the measurement is honest about the host and
stale about the lane, and correcting the vocabulary is a protocol change. The
admin status read surface and the doctor report schema are now generated
into the Apache-2.0 TypeScript SDK by a maintained generator with a drift
gate that fails when the checked-in files no longer match, a typecheck
against the package's strict tsconfig, and a test comparing the Rust
encoder's own field sets against the generated ones. A strict Slack Socket
Mode envelope parser with typed plan-then-ack acknowledgement discipline
joins the Telegram parser as the second network-free connector core; a
configured daemon now drives that parser from a live Socket Mode worker.

Enforcement needs a delegated cgroup v2 subtree, which is what the daemon gets
as a systemd user service with `Delegate=yes`; where no delegated domain
exists every API refuses fail-closed and never reports partial enforcement.
The daemon calls this backend on a configured host, but launch authority is
still not established by signature: a provider binary is admitted by pinned
digest and by the daemon's own workspace registry, and the release-manifest
trust chain remains unbuilt.

The Telegram poller has a concrete synchronous HTTPS
client with WebPKI certificate verification, redirects and environment proxies
disabled, bounded response headers/body, and a request deadline inside the
lease margin. Telegram's required token-bearing URL exists only during that
request and is absent from public errors and Debug output; the dependency graph
statically disables Trace logging because the HTTP library exposes request
paths at that level. The concrete store adapter persists dispositions and the
offset atomically. The daemon now loads an explicit operator-written bot
configuration from a private `telegram/bot.conf` under its state directory —
header/terminator-framed, owner-only permissions required, the token validated
against its `bot_id` — and, when one is present, acquires, renews, and cleanly
releases the durable per-bot poller lease beneath its generation fence. An
absent configuration stays honestly `disabled_no_client`; a present-but-invalid
or insecure one refuses startup instead of degrading silently, and a live
predecessor's bot lease is fenced out by expiry, never seized. Whether that
lease is *used* is a second, explicit decision: without an `allow=` line naming
who may command the bot, the token is dropped, no client is constructed, and
the daemon reports `lease_owned_no_client` with the lease epoch. With one, the
token is retained in memory, one worker thread long-polls beneath the same
lease, and the status reports `polling_live` — a daemon holding a client never
reports a no-client state. That poller answers `/help`, `/status` and `/runs`
from the daemon's own read surfaces on its own store connections and refuses a
sender outside the allowlist without reading their message. `/run`, `/work`,
`/research`, the Slack and GitHub verbs, the memory verbs and `/approve` now
run for real; `/cancel` and `/deny` still reply that the surface behind them
does not exist rather than faking an effect. The observability crate derives bounded metrics from one timestamped
SQLite snapshot and serves them over the local authenticated status command,
but it has no metrics exporter. A release-manifest candidate can bind the
descriptor helper, boundary installer, fixture, workspace, and runner digests
for review, but cannot mint launch authority; an independently authenticated
release trust root is still missing, so nothing a release manifest asserts is
verified before a run.

## Clean-room and licensing

The prior implementation source is forbidden input. The checked-in
specification, authorized structural references, public standards, and
provenanced black-box fixtures are permitted; see `AGENTS.md` and
[`PROVENANCE.md`](PROVENANCE.md).

Product code is under Elastic-2.0, and `sdk/` is the only Apache-2.0 root. The
provider connectors are Elastic-2.0 crates under `rust/crates/`: they are
daemon-internal libraries, each locked to one backend, and nothing outside the
daemon consumes them. See [`LICENSE-POLICY.md`](LICENSE-POLICY.md).
