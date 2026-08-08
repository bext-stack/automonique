# ADR 008: ShellDeck is the native desktop client

- **Status:** accepted
- **Decision date:** 2026-08-06

## Context

ShellDeck (`github.com/benfavre/shelldeck`, MIT, owner-controlled) is an
existing native Rust/GPUI desktop SSH/terminal client that already
implements, against the legacy assistant and the legacy Manage console,
working versions of several planned capabilities:

- account login plus a browser device-authorization flow (localhost
  callback, explicit human authorize step, account-bound scoped tokens with
  role binding, whoami/logout);
- User/Support/Dev application modes with capability gating;
- a control surface for agent work: run state, approval/confirmation strip,
  history, dispatch and per-ticket hand-off;
- a device fleet runtime: register/heartbeat/claim/execute loop with
  execution disabled by default, an explicit autonomy gate and per-job
  confirmation, covered by fake-executor tests;
- cloud-synced connection profiles (upsert-by-source merge that never
  touches locally-owned entries), TOML configuration, tag-driven signed
  releases and an update channel;
- an ACP-ready Jcode executor fallback, converging on the same provider set
  the plans name (Jcode/Claude/Codex/opencode).

The transferred planning corpus predates this and assumed a new-build
desktop application; none was ever built. Rather than plan a parallel
codebase to regain dashboard component reuse and an easier Windows target,
the owner chose to build the desktop surface on ShellDeck.

## Decision

- ShellDeck is the native desktop client. No separate desktop application
  is built.
- ShellDeck remains a separate MIT repository. It integrates as the first
  external consumer of the typed admin/SDK protocols and must pass the same
  semantic conformance suite as every other surface before presenting
  itself as the Automonique desktop. Nothing is imported into this
  repository without the owner-authorized provenance process.
- The Rust protocol layers specified for the TUI — protocol client and
  reconnect state machine, multiplexed attachment registry, snapshot/event
  reducers, typed action preview/confirmation — are built as a shared
  client crate consumed by both `automonique-tui` and ShellDeck. The
  TypeScript SDK serves the dashboard, IDE and future mobile clients.
- ShellDeck's fleet runtime becomes the first workstation-class execution
  host: its register/heartbeat/claim/execute loop is remapped onto ADR 001
  attempt/host/session lifetimes and the durable claim protocol, retiring
  its legacy ring-buffer contract. Its safety posture — execution off by
  default, explicit autonomy gate, per-job confirmation — is adopted as a
  requirement for any non-server execution host.
- Desktop UI extensions follow the same constrained declarative/WASI widget
  model as the TUI. One extension model spans both Rust clients.
- Windows: GPUI's Windows support is behind Linux/macOS. Until a ShellDeck
  Windows build passes the conformance suite, Windows users are served by
  the dashboard/PWA, presented per existing policy as a clearly weaker
  named profile, never as an equivalent desktop claim.

The requirement documents (client experience, target architecture,
TypeScript SDK, external capability ledger) state this architecture
directly; their `provenance.toml` entries carry the amendment with the
as-transferred hashes retained. Historical documents under `reference/`
still describe the earlier assumption and remain non-authoritative.

## Consequences

The desktop surface ships as ShellDeck releases, not Automonique releases;
the conformance suite and protocol capability negotiation are the
compatibility gate between them. The shared Rust client crate gets a second
consumer from day one, hardening the TUI's protocol layers. Dashboard
component reuse on desktop is given up, and the Windows native client
depends on GPUI's Windows maturity. MIT licensing keeps code movement clean
in both directions, with attribution via `NOTICE` if code ever transfers.
The legacy fleet protocol remains dormant in this repository; ShellDeck's
current compatibility with it is ShellDeck's concern until the durable
claim protocol replaces it.
