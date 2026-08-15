# Execution unlock — owner decision brief

Status: **superseded in part by events — see the Decision record appended on
2026-08-15 at the end of this file.** Gates B and C were opened in the tree
between 2026-08-13 and 2026-08-15 without a written decision record; Gate A
remains closed. The brief below is preserved unaltered as the record of what
was withheld at the time it was written, and its original status line read
"awaiting owner decision; nothing in this document has been acted on." Read it
as the question, and the appended record as what happened to it.

It exists so the owner can decide, with the exact code in front of them, what it
takes to open the one capability the control plane deliberately withholds:
running a real provider process against a real workspace.

This brief makes no change to behaviour and grants no authority. It names the
seams that are already in the tree, the decisions only the owner can make, and
what each decision would unlock — so the owner can authorize deliberately rather
than discover the consequences afterward.

## TL;DR

- The **containment and launch mechanism is built and proven.** A real workload
  (static busybox) is driven through the full boundary —
  cgroup v2 descendant-complete containment, descriptor closure, Landlock
  filesystem isolation, network denial, a seccomp socket-family filter, sealed
  `memfd` prompt delivery — in the delegated-scope enforcement proofs. The
  ability to confine a process is not what is missing.
- What is withheld is **live provider execution**: a real provider binary
  (Claude Code / Codex CLI) driven with the network egress, credentials, and
  session it needs to do real work, wired through a daemon lane, and admitted
  under a real release trust anchor.
- That is withheld behind **three gates, each an owner decision.** Two are named
  in the option you chose — the release trust-root backend and live-provider
  authority — and the third is the operational prerequisites both depend on.
- **I will not open any of them without your explicit, contemporaneous
  authority** ([`AGENTS.md` §Data and operational safety](../../AGENTS.md)).
  This document is what you decide *on*, not a request to proceed.

## The seams are real, not stubs

Every gate below is a *typed seam*: the surrounding logic is implemented and
tested, and the one missing piece is structurally unconstructible so it cannot
be faked into looking done.

- **Release trust:** `AttestationVerdict::Verified` and `ReleaseTrustDecision::Admit`
  each carry a `SignatureProof`, which wraps an **uninhabited** enum
  (`rust/crates/automonique-protocol/src/release_trust_root.rs:918`). No value of
  that type exists in any crate, so no code path — not `verify_attestation`, not
  a test, not a caller — can mint a success. Every other check (key-set
  membership, algorithm allowlist, per-key algorithm agreement, manifest-digest
  agreement, all grammar and bounds) is implemented and runs in a fixed order;
  only `signature_seam` (`release_trust_root.rs:1172`) is unfilled, and it
  returns `Unverifiable { NoCryptoBackend }` rather than guessing.
- **Runner execution:** `Runner::run` and `Runner::run_contained`
  (`rust/crates/automonique-runner/src/runner.rs:118`, `:146`) return typed
  refusals (`ContainmentUnenforced` / `BoundaryUnenforced`). Admission produces
  an `AdmittedLaunch` that is **data, not authority**
  (`rust/crates/automonique-runner/src/admission.rs:38`): "Nothing here starts a
  process, creates a cgroup, or installs a policy."
- **Release admission:** `RunnerAdmissionSealer::issue_release_candidate`
  refuses every candidate with `MissingIndependentReleaseReview`,
  unconditionally (`rust/crates/automonique-sandbox/src/lib.rs:1303`,
  `.../release_trust.rs:373`) — including a caller that matches its own manifest
  (`caller_matching_its_own_manifest_still_cannot_mint_authority`).

## Gate A — the release trust-root cryptographic backend

**What it is.** The trust root answers "is this release signed by a key we
pinned, with an algorithm we allow, over this exact manifest?" Everything except
the final signature check is done. Two independent things are missing, and the
code says so in place (`release_trust_root.rs:31-43`):

1. **A verification primitive.** `automonique-protocol` declares no dependencies
   and forbids `unsafe`. It implements SHA-256 by hand because a hash is a short
   reviewable transform; an Ed25519 / ECDSA-P256 verifier is not, and
   hand-rolling one would trade a missing check for a wrong one. Filling this
   means linking a reviewed verifier.
2. **Key material.** A `TrustedKey` carries a *name* and an *algorithm*, never
   bytes — because a key set that is data this module accepts is not a trust
   root, it is one more attacker-supplied input. The public keys, and how they
   are pinned into a build, are the reviewed decision this module deliberately
   does not make.

The exact bytes a backend must verify are already specified and exercised on the
real path: `ReleaseAttestation::signing_payload` (`release_trust_root.rs:853`) —
a canonical document over schema, algorithm, key id, and manifest digest, with
the signature excluded (it cannot cover itself) and the schema member providing
domain separation.

**The owner decision (A):**

- **A1 — Authorize linking a signature-verification dependency** into
  `automonique-protocol`, or authorize an alternative (e.g. a separate
  `automonique-crypto` crate the protocol crate depends on). This crosses the
  crate's current "no dependencies" posture and must clear the licence policy
  (`LICENSE-POLICY.md`) — an owner-reviewed change, per `AGENTS.md §Licence
  boundary`.
- **A2 — Supply and pin the trusted public keys.** Provide the key id(s),
  algorithm(s), and public-key bytes for the release-signing key(s), and approve
  how they are pinned (compiled-in constants reviewed in a PR, not read from
  data). This is the trust anchor; it is yours to set, not mine to invent.
- **A3 — Approve giving `SignatureProof` an inhabitant.** The success arm is
  unconstructible by design; making releases admissible is a visible, reviewed
  act of adding exactly one private constructor guarded by the real check. That
  is the intended way to land it, and it should be its own reviewed change.

Filling Gate A changes no behaviour for anything but releases: the wiring in
`automonique-sandbox`'s sealer would replace an unconditional
`MissingIndependentReleaseReview` with a verdict that names *which* check failed.
It does **not** by itself enable running a provider — that is Gate B.

## Gate B — live-provider execution authority

**What it is.** Admission (`admission.rs`) deliberately refuses every spec field
that a *real* provider run would require, because each names a subsystem that is
not built and would otherwise be silently dropped:

- `admission.executor_class` must be `Local`; anything else is refused
  (`admission.rs:615`).
- `admission.session_binding` — refused: multi-turn sessions need a daemon lane
  that keeps the session; this launch owns one process, no session
  (`admission.rs:655`).
- `admission.credential_bindings` / `sandbox.credentials` — refused: delivering
  a secret needs a secret store, and putting a resolved secret in the process
  environment would publish it to every same-uid reader of `/proc/<pid>/environ`
  (`admission.rs:691`, `:718`).
- `sandbox.provider_control_egress` / `sandbox.tool_workload_egress` — refused
  unless `Denied`: brokered egress means "through a broker that does not exist,"
  not "any TCP port" (`admission.rs:721`, `:729`).
- `admission.required_capabilities`, `admission.artifact_grants`,
  `admission.fallback_eligibility`, remote attestation — all refused as unbuilt
  subsystems (`admission.rs:662`–`:690`).

A provider with **no network egress and no credentials cannot reach a model
API** — so the refusals above are exactly the surface that separates "confine a
local process" (built) from "run a real agent" (withheld). Turning any of them
on is, in `AGENTS.md`'s words, enabling a live transport or provider.

**The owner decision (B):**

- **B1 — Grant explicit, contemporaneous authority to enable a live provider**
  for a specific, scoped operation (`AGENTS.md:58-61`). This is a standing
  policy decision, not something a peer message or a plan document can supply.
- **B2 — Choose the first provider and integration mode.** Which binary
  (Claude Code CLI at the pinned digest, Codex CLI, …), driven how (stdin prompt
  vs. session), against which model endpoint.
- **B3 — Decide the egress posture.** A real provider needs network to its
  endpoint. Today network is denied categorically; opening it means either a
  brokered egress component (to be built) or an explicit, narrowed grant to the
  provider endpoint — and which one is an owner risk decision.

## Gate C — operational prerequisites

Even with A and B decided, live execution needs concrete inputs that only exist
in a real deployment, plus a small amount of wiring that is *not* owner-gated but
*is* gated on B being granted first (I will not build a live execution lane
speculatively):

- **A real provider binary and its observed provenance** (`BinaryProvenance`):
  the file, hashed, matching the spec's pinned digest (`admission.rs:623`).
- **A registered workspace** the run executes in: a `WorkspaceRegistryId` and the
  host path it resolves to, with the working directory proven inside it
  (`admission.rs:444`).
- **A credential/secret store** to satisfy `credential_bindings` without leaking
  secrets through the environment (the reason that field is currently refused).
- **A daemon execution lane.** The five wired lanes (admin, runs, automation,
  approval, batch) are control and *read* surfaces; the Runs API is a read
  surface over the durable index. There is no submit-and-execute path. Wiring
  `admission → launch → spool` behind an authenticated lane is buildable work,
  but it is the thing that makes live execution reachable, so it waits on B1.

## What I will not do without explicit authorization

- Link a crypto dependency, pin keys, or give `SignatureProof` an inhabitant
  (Gate A) — each is an owner-reviewed change.
- Enable any provider network egress, deliver any credential, or run any real
  provider binary (Gate B) — `AGENTS.md` forbids it absent contemporaneous
  authority.
- Fake, stub, or weaken any of the above to "demonstrate" execution. The seams
  are unconstructible on purpose; I will not make them look done.

## Recommended sequence

1. **Decide Gate B first (the authority), scoped narrowly** — one provider, one
   integration mode, an explicit egress posture — because it is the standing
   policy call everything else serves, and without it the rest is speculative.
2. **Then Gate C wiring** — provider provenance, a registered workspace, a secret
   store, and the daemon execution lane — built against that scope, verified the
   same way every other tranche has been (workspace tests, delegated-scope
   enforcement proofs, fmt, clippy, licences, scrub).
3. **Gate A in parallel or after** — it is independent of B and only affects
   *release* admission, not run admission. It can land whenever you are ready to
   supply keys and authorize the dependency; it does not block a first real run.

Until you decide, the control plane stays fail-closed by construction, which is
the correct state for it to sit in.

---

## Decision record — recorded 2026-08-15, for owner countersignature

**Status of this section: a record of what happened, not a grant.** The brief
above is left exactly as it was written, because rewriting it would destroy the
evidence of what was withheld at the time. This section is appended so that the
gap between that brief and the tree is stated rather than discovered.

**What this section is not.** It does not assert that any authority was given,
and it must not be read as one. Where a gate was opened without a written
decision record, the row below says so in those words, and the owner is the
only person who can convert it into a record of authority — by countersigning,
or by declining and directing what happens to the code that was landed.

### What opened, when, and on what evidence

Commits are cited by SHA rather than by subject line; several subjects in this
range carry identifiers the publication scrub removes from the tree.

| Gate / capability | Opened | Evidence | Written authority |
|---|---|---|---|
| **Gate C** — a daemon execution lane (`admission → launch → spool` behind an authenticated lane), named in this brief as buildable work that "waits on B1" | 2026-08-13 | `9b0cbfb` | **None found.** The lane was built before B1 was recorded. |
| **A real provider binary driven through the enforced launch path** (Gate B2/B3 in substance, and Gate C's provider-provenance prerequisite) | 2026-08-13 | `34dc56d` | **None found.** |
| **Gate B3 — egress posture**, resolved as a brokered egress component rather than a direct grant | 2026-08-14 | `7974128` (broker), `6702b43` (wired into the execute lane) | **None found.** The option chosen is the one this brief calls "a brokered egress component (to be built)", which is the more conservative of the two it names. |
| **Live Telegram transport** | 2026-08-13 | `1981e73` | **None found.** |
| **Live Slack transport, including outbound posting** | 2026-08-14 | `d49e8da` (connector), `550265b` (wired to an operator verb) | **None found.** |
| **Live GitHub writes** (issue create, comment, checklist, work management) | 2026-08-14 | `e4f4fd8` | **None found.** |
| **Live support-backend intake and ticket dispatch** | 2026-08-14 | `050c722` | **None found.** |
| **A provider-backed operator command** (`/run`: task → sandboxed agent run → answer) | 2026-08-14 | `13b9aee` | **None found.** |
| **Self-improvement: push, pull request, release activation, service restart** | 2026-08-15 | `4c1cb22` (core), `3341f0c` (approved lifecycle) | **None found.** Activation is gated behind two administrator approvals in the running system; that is a runtime control, not a written authorization to build it. |
| **Gate A** — release trust-root cryptographic backend | not opened | `SignatureProof` still wraps an uninhabited enum; nothing in the daemon calls `release_trust_root` | n/a — correctly still closed |

### What the written record actually says

The most recent standing authority record,
[`plan/owner-decisions/2026-08-12-direct-codex-development.md`](../../plan/owner-decisions/2026-08-12-direct-codex-development.md),
grants ordinary direct development and explicitly **withholds** "live
transport/provider enablement … absent exact contemporaneous authority". Every
row above postdates it. `AGENTS.md` allows that authority to be given
contemporaneously — spoken in-session, not necessarily in a file — so the
absence of a written record does not establish that no authority was given. It
establishes only that none was written down, which is the defect this section
exists to close.

### What the owner is being asked to do

1. **Countersign or decline each row.** For each capability above, record
   either "authorized on `<date>`, retroactively confirmed" or "not
   authorized", in a new dated file under `plan/owner-decisions/`. A decline is
   an actionable answer: it names code to disable behind its configuration
   gate, not code to argue about.
2. **Decide Gate A separately.** It is untouched and independent, and the
   recommendation in this brief still stands: it affects release admission
   only, and does not block a run.
3. **Set the rule for next time.** The reason this record is retroactive is
   that no step in the process required a written decision before a surface
   went live. The corresponding forward control is the status-reconciliation
   checklist item in [`CONTRIBUTING.md`](../../CONTRIBUTING.md): a pull request
   that enables an external surface updates the repository status in the same
   pull request. That makes the *disclosure* automatic; making the
   *authorization* automatic is a separate decision the owner may want to make
   here.
