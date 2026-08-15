<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — what GATE-ORACLE blocks

**Status: DECIDED 2026-08-15. Path B — re-scope the gate's blocking claim.**
The owner delegated this decision to the implementer with the two paths below
stated in advance; this memo records which was taken and on what evidence. It
changes what the gate *claims to block*. It does not change the boundary, the
gate's state, or any of its four closing conditions.

| Field | Value |
|---|---|
| Question | GATE-ORACLE declares it blocks "all differential parity work". Does that include M2's live-traffic shadow comparison, or only comparison against the private legacy archive? |
| Declared in | [`plan/gates.md`](../gates.md#gate-oracle) § GATE-ORACLE, "Blocks:" line; restated in [`PROVENANCE.md`](../../PROVENANCE.md) |
| Decided | **Path B.** Archive-differential work stays blocked. Live-traffic shadow comparison is not, and never was, what this gate protects against |
| Gate state after this decision | **still open**, unchanged |
| Boundary state after this decision | **unchanged**, byte for byte |

## What the gate actually protects

GATE-ORACLE exists because of one sentence in
[`PROVENANCE.md`](../../PROVENANCE.md): agents implementing the clean product
must not receive legacy implementation source, and a parity oracle that runs
against the prior implementation "must expose only bounded behavior results and
must not emit source, private data, credentials, proprietary identifiers, or
implementation text."

The hazard is therefore specific and physical. It is *reading the private
archive* — the prior implementation's source, data and credentials, which
[`tools/oracle/README.md`](../../tools/oracle/README.md) § The two sides places
on the custody host, owned by the repository owner as archive custodian, and
which no agent role in this repository is authorized to read. The oracle
boundary is the pipe that lets a comparison run *on that host* and return
selectors from a closed vocabulary instead of bytes.

## Why live-traffic shadow comparison is on the other side of that line

M2's harness (issues #10, #11, #14) compares two things:

1. envelopes this daemon produces for events it already receives, and
2. messages the legacy bot **publishes into shared channels this daemon is
   already a member of**.

Neither is archive material. The second is the load-bearing one, and the
distinction is not a matter of degree: those messages are the legacy system's
*public output*, delivered by the provider to every member of the channel,
identical to what any human in the workspace sees. Observing them requires no
access to the custody host, no credential belonging to the archive, and no
cooperation from the custodian. Nothing in that path can emit source, private
data, credentials or implementation text, because nothing in that path ever
holds any.

Reading the gate to cover this produces an incoherent result: the daemon is
permitted to *receive* those messages (it already does, in production) and
permitted to *act* on them, but forbidden to *record and compare* them. A gate
that blocks measuring what you are already allowed to do blocks the evidence,
not the hazard.

## What stays blocked, unchanged

- `R0-02` sanitized fixture corpus and `R0-07` provider transcript corpus. Both
  capture from the private archive; both are named in the gate and remain
  `blocked_by_gates = ["GATE-ORACLE"]` in `plan/work-graph.toml`.
- Any archive-differential comparison: replaying legacy inputs against the
  prior implementation on the custody host, or any output derived from doing
  so. This is the work the boundary was built for, and it stays behind the one
  unmet closing condition.
- `BOOT-004` itself, which remains `status = "blocked"`. The gate closes only
  when an owner accepts an exact revision of the boundary or a configured
  review runs against it — `plan/baseline.py` derives closure from that item's
  status, so no edit to `gates.md` or to this memo can close it.

## The test to apply

For any proposed comparison, one question decides it:

> Does producing this evidence require reading, executing, or receiving output
> derived from the private legacy archive on the custody host?

**Yes** — blocked by GATE-ORACLE; it needs the boundary, and the boundary needs
the owner acceptance that is still outstanding. **No** — not blocked; the
material is either this repository's own output or the legacy system's public
output, and GATE-ORACLE never governed it.

A case that is genuinely unclear is blocked, and comes back here as an
amendment to this memo rather than being argued in a pull request.

## What this decision explicitly does not do

- It does **not** weaken the oracle boundary. `release.py`, `scan.py`,
  `vocabulary.py` and `fields.json` are untouched, and
  [`tools/oracle/test_boundary.py`](../../tools/oracle/test_boundary.py)'s 74
  adversarial tests pass unmodified. Widening that vocabulary is a protected
  policy change requiring an external exact-revision decision, and this is not
  one.
- It does **not** close GATE-ORACLE or mark any closing condition met. The
  fourth condition — a review record or owner acceptance bound to the exact
  boundary candidate — is still not met, and the gate's own text still says so.
- It does **not** permit any agent to read the private archive, under any
  reading, for any purpose.

## Why now, and what would change it

The M2 harness reuses the oracle's own closed diff vocabulary
(`tools/oracle/vocabulary.py`, `tools/oracle/fields.json`), so a live-traffic
verdict and a future archive-differential verdict come out in the same shape.
That is deliberate: taking Path B now costs nothing in rework if the owner later
wants archive-differential fixtures, which is Path A.

**Path A — staff the gate** — remains available and unchanged: name reviewers,
run the configured review against an exact committed revision of the boundary,
complete `BOOT-004`. Take it when archive fixtures are actually wanted. It adds
custody-host review time ahead of any work that needs `R0-02` or `R0-07`.

If a future scope wants comparison against archive material *inside* M2, this
decision does not cover it: that converts the question back to Path A and must
be recorded as a new decision here.
