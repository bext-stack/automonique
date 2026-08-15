<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — the Apache-2.0 connector boundary

**Status: DECIDED 2026-08-15 — option 2, keep Elastic-2.0 and re-document.**
The owner delegated this decision to the implementer with the three options
below stated in advance. The options are kept in full: the point of the record
is which was chosen and why, which is not readable from the outcome alone.

| Field | Value |
|---|---|
| Question | `integrations/` and `connectors/` are declared Apache-2.0 roots. Neither directory exists. What is the boundary actually supposed to be? |
| Declared in | `LICENSE-POLICY.md`, `README.md` (directory map and the licensing section), `AGENTS.md` § Licence boundary, `plan/gates.md` GATE-LICENCE, `tools/check_licenses.py` `APACHE_ROOTS` |
| What shipped instead | three Elastic-2.0 crates under `rust/crates/`: `automonique-github-connector`, `automonique-slack-connector`, `automonique-support-connector` |
| Decided | **Option 2.** `sdk/` is the only Apache-2.0 root; the connectors stay Elastic-2.0 and are documented as daemon-internal libraries |
| Relicensing performed | **none.** Option 2 is the only one of the three that relicenses nothing |

## What was decided, and what changed

`APACHE_ROOTS` is `{"sdk"}`. The `PENDING_ROOT_DECISION` shim is gone, so a
phantom Apache root is now a plain failure with no exemption to route it
through — the guard that was added while this was pending is now load-bearing
rather than advisory. Every surface that quoted the old boundary was rewritten
to say what is true: `README.md` (directory map and licensing section),
`LICENSE-POLICY.md`, `AGENTS.md` § Licence boundary, and GATE-LICENCE in
`plan/gates.md`. `tools/test_check_licenses.py` asserts the live state — every
declared root exists, and a connector crate carrying an `Apache-2.0` header is
refused — so the documents and the checker cannot drift apart again silently.

`COMMERCIAL.md` and `NOTICE` were swept for the same phrase and carry neither.

## What the roots were reserved for, and why that does not change the answer

The two roots were not arbitrary. The archived executable plan reserves them for
27 blocked items across two epics — `R8F` ("Connector SDK package") and `R13`
("Generic connector generator/conformance") — whose `allowed_paths` are
`connectors/typescript/…`, declared `Apache-2.0`. Those would be genuine neutral
client libraries, and an Apache root would be the right home for them.

That is a different thing from what shipped under the same word. The Rust
connectors are daemon-internal and target-locked; the planned TypeScript
connectors are consumer-facing and generated. Naming both "connectors" is what
let a root reserved for the second read as a promise about the first.

So the boundary now describes the tree as it is, and `plan/check.py`'s
archived-graph licence rule is deliberately **not** changed: it still admits
`connectors/` and `integrations/` for those 27 items, because it governs planned
work rather than files on disk. If `R8F` or `R13` is ever taken up, creating an
Apache root for it is a decision to record then — with real code behind it, on
the day it exists, which is the whole point of this one.

## What was true before

The three connectors were, and remain, Elastic-2.0 Rust crates. The two
documented Apache roots did not exist, so the part of the licence checker that
would have enforced them enforced nothing: every file was judged against
`Elastic-2.0` because no path can begin with a directory that is not there. The
defect was never a mislicensed file; it was four documents promising a boundary
that no code sat behind, which a reader could have acted on in good faith.

## The options

### Option 1 — move the connector crates under `connectors/` and relicense them Apache-2.0

Makes the documents true by making the tree match them.

Against it: `LICENSE-POLICY.md` says in as many words that moving code below an
Apache root does not relicense it and that such a move requires owner review
before distribution. So this is not a reorganization that happens to change a
header — it is a deliberate relicensing of already-shipped Elastic-2.0 code,
and it should be decided as one. It also costs workspace-member path churn and
an SPDX rewrite across three crates.

### Option 2 — keep Elastic-2.0 and re-document (**chosen**)

Remove the two phantom roots everywhere and make every surface agree that
`sdk/` is the only Apache root.

For it, on the evidence:

- **The connectors are not neutral client libraries.** The support connector is
  deliberately target-locked to one backend's wire protocol: the base admits an
  origin and nothing after it, the request path is a private constant, and the
  action string renders only from a private enum
  (`rust/crates/automonique-support-connector/src/lib.rs:26-33`). The Slack and
  GitHub connectors are locked the same way to `slack.com` and
  `api.github.com`. A library nobody outside this product can point anywhere
  else is not the thing an Apache root exists to enable.
- **Nothing outside the daemon consumes them.** All three appear as path
  dependencies of `automonique-daemon` and of nothing else
  (`rust/crates/automonique-daemon/Cargo.toml:15,24,29`).
- **The repository's licence authority is Elastic-2.0 throughout.** Option 2
  removes an exception that was never exercised rather than creating one.

The `sdk/` root stays exactly as it is: it holds a real generated TypeScript
package with a drift gate, which is the case the Apache boundary was written
for.

### Option 3 — split: thin Apache-2.0 client libraries plus Elastic-2.0 daemon wiring

The architecturally purest answer and by far the most work: it means separating
each connector's transport and decoding from its product-specific policy, and
maintaining the seam afterwards. There is no consumer today that would benefit.

Revisit this if an external SDK consumer ever materializes; option 2 does not
foreclose it, because moving code out to a new Apache root would be the same
owner-reviewed act then that option 1 is now.

## Exactly what each option needs

**Option 2 (done 2026-08-15)** — five edits and one deletion, all small:

1. `LICENSE-POLICY.md` — delete the `integrations/` and `connectors/` bullets,
   keep `sdk/`. **Done**, with the reason recorded in place.
2. `README.md` directory map — delete the two lines. **Done.**
3. `README.md` licensing section — `sdk/` is the only Apache root. **Done.**
4. `AGENTS.md` § Licence boundary — same sentence, same edit. **Done.**
5. `plan/gates.md` GATE-LICENCE — the quoted boundary becomes product
   `Elastic-2.0`, `sdk/` `Apache-2.0`. **Done**, as a dated amendment.
6. `tools/check_licenses.py` — `APACHE_ROOTS = {"sdk"}`, and remove
   `PENDING_ROOT_DECISION` entirely rather than emptying it: a pending set with
   nothing pending is a permission that protects nothing. **Done**, and
   `tools/test_check_licenses.py` now asserts every declared root exists and
   that a connector carrying an `Apache-2.0` header is refused.

`COMMERCIAL.md` and `NOTICE` were swept for the same phrase; neither carried it.

**Option 1** (not taken) — everything above except step 6, inverted: create `connectors/`,
`git mv` the three crates into it, update `rust/Cargo.toml` workspace members
and the daemon's three path dependencies, rewrite every SPDX header in those
crates to `Apache-2.0`, add the Apache licence text and package metadata each
independently distributed package must carry, and record the relicensing itself
as a reviewed decision in a separate file under `plan/owner-decisions/`.
`integrations/` still has to be resolved separately — nothing is planned for
it, so it is a phantom root under this option too.

**Option 3** (not taken) — option 1's mechanics applied to newly-extracted crates, plus the
extraction: per connector, split the HTTP/decode core from the target lock and
the product policy, decide which half each existing test belongs to, and
re-establish the fixture-and-loopback-fake discipline on both sides of the new
seam. Size this as architecture work, not as a licence change.

## Why this was worth deciding rather than leaving

Nothing was breaking, and that was the problem. The checker kept passing, the
documents kept describing a boundary that was not enforced anywhere, and the
next person to read `LICENSE-POLICY.md` would have believed the connectors were
Apache-2.0 — which, acted on, is a licensing error made in good faith on the
repository's own documentation. Option 2 removes the possibility rather than
the symptom: there is no longer a documented root without code behind it, and
the checker now fails outright if one reappears.

Option 3 stays available. It is foreclosed by nothing here, and moving a
connector out to a new Apache root would be the same owner-reviewed relicensing
act then that option 1 was now.
