# Blocking gates

A blocking gate is a condition the repository must satisfy before its named
class of work may start. This file also records advisory hardening gates that
block only the corresponding capability claim. `AGENTS.md` requires refusing
work explicitly blocked by an unresolved gate, and `plan/check.py` refuses a
graph that closes a gate not defined here.

A gate closes when its **closing evidence** exists and receives the review or
explicit owner acceptance configured for that gate. A gate is never closed by
an unsupported assertion.

| Gate | Closed by | Blocks |
|---|---|---|
| [`GATE-BASELINE`](#gate-baseline) | `BOOT-001` | ~~all work~~ **closed** |
| [`GATE-IDENTITY`](#gate-identity) | `BOOT-002` | advisory identity-hardening claim only |
| [`GATE-SCRUB`](#gate-scrub) | `BOOT-003` | making the repository public |
| [`GATE-ORACLE`](#gate-oracle) | `BOOT-004` | differential parity, fixture capture |
| [`GATE-LICENCE`](#gate-licence) | first distribution contract | advisory release-readiness claim only |

---

### GATE-BASELINE

**State: closed 2026-08-09 by `BOOT-001`.**

The executable plan must be checked in, internally consistent, and verified by
CI before any work item can claim an immutable base.

Blocks: everything. No item is selectable while this gate is open.

Closing evidence:

- `plan/work-graph.toml` is checked in and regenerable from
  `docs/product-plan/reference/work-breakdown.md`;
- `python3 plan/check.py --verify` exits zero in CI on every push;
- drift in either direction fails the build, demonstrated by a deliberately
  broken commit that CI rejects.

---

### GATE-IDENTITY

**State: advisory/open.** Current commits are unsigned and dedicated workload
identities have not been configured.

`GOVERNANCE.md` defines logical implementer, reviewer, fixer, builder and
integration roles, but permits them to coincide when the owner chooses. This
gate records optional identity separation; it does not require it.

Blocks: only a claim that dedicated workload-identity separation is active.
It does **not** block implementation, harness work, review, local commits or
owner-configured protected integration.

Closing evidence:

- every identity claimed as distinct has separate credentials;
- signatures, when enabled, verify against a published trust root;
- a test proves non-integration credentials cannot write the protected branch;
- `PROVENANCE.md` § Repository identity is updated to describe the achieved
  state rather than the gap.

---

### GATE-SCRUB

**State: open.** Two manual sanitization passes have run
(`docs/product-plan/README.md` § Plan transfer). Nothing prevents a third
identifier from being reintroduced.

Blocks: making the repository public. It does not block private development.

Closing evidence:

- an automated scan runs in CI over every tracked file;
- protected scan rules derived from both sanitization passes are configured
  without committing or logging private values and fail on reintroduction;
- the scan covers commit messages and file contents, not file contents alone;
- a deliberately reintroduced identifier is rejected in a test commit.

Retained by decision, and therefore not scan failures:

| Retained | Reason |
|---|---|
| `Monique` | first-party mascot; product identity |
| `bext-stack` | real repository organization, required by `SECURITY.md` |
| `legacy*` | dormant compatibility identifiers, neutral by construction |
| legacy source filenames | structural references permitted by `AGENTS.md` |
| legacy environment and command names | same permission; `reference/legacy-inventory.md` documents the mandatory `JEAN_DB` override, and an operator who cannot see the real variable name cannot apply the safety instruction |

The last entry is the one to watch. It is permitted because removing it would
make a live safety instruction unusable, not because environment names are
generally safe to publish. A future entry justified the same way needs the same
test: does redacting it destroy the reader's ability to act correctly?

**Location rule.** `reference/legacy-inventory.md` is the single sanctioned
place for exhaustive legacy names — table, environment, command, route and
companion identifiers — because `R0-13` requires classifying every one of them
and a redacted inventory cannot be classified. Everywhere else, prose uses the
neutral description. A legacy identifier appearing outside that file is a scan
failure even when the same identifier is permitted inside it.

Client, customer and third-party product names are **never** permitted, in that
file or anywhere else. The distinction is ownership: first-party legacy
identifiers are migration data, other people's names are not ours to publish.

---

### GATE-ORACLE

**State: open.** The boundary is specified in `PROVENANCE.md`; nothing
implements it.

`PROVENANCE.md` permits a parity oracle to execute privately against synthetic
inputs while exposing "only bounded behavior results." The AI harness
(`docs/product-plan/requirements/ai-implementation-harness.md` § Differential
parity and shadow oracle) depends on that comparison. No process today
separates the oracle's output from the legacy source it runs against, so
running one would contaminate the clean room it is meant to protect.

Blocks: `R0-02` and `R0-07` fixture capture, and all differential parity work.

Closing evidence:

- a documented process boundary naming what holds legacy source, what strips
  oracle output, and who owns each side;
- the stripping mechanism is tested against a deliberate leak attempt covering
  source text, credentials, private identifiers and stack traces;
- oracle output is content-scanned before it reaches any agent context;
- the configured review record or explicit owner acceptance is bound to the
  exact boundary candidate.

---

### GATE-LICENCE

**State: advisory/open.**

`LICENSE-POLICY.md` states a precise boundary — product `Elastic-2.0`, `sdk/`
`integrations/`, and `connectors/` `Apache-2.0`. The intentionally lightweight
development check validates source SPDX headers against those roots.

Blocks: only a claim that an artifact is ready for distribution. It does not
block product, SDK, connector, or release-tooling implementation.

Evidence required by the first distribution contract, as applicable:

- package metadata and source headers declare the intended licence;
- shipped dependencies and required notices are inventoried;
- code moved across the product/Apache boundary has explicit owner review;
- an SBOM is generated when the artifact or distribution channel requires it.
