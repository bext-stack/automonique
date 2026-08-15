<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — the Apache-2.0 connector boundary

**Status: PENDING. This memo decides nothing. Crossing the licence boundary
requires explicit owner review by the repository's own policy, so an
implementer records the options and stops.**

| Field | Value |
|---|---|
| Question | `integrations/` and `connectors/` are declared Apache-2.0 roots. Neither directory exists. What is the boundary actually supposed to be? |
| Declared in | `LICENSE-POLICY.md:25-26`, `README.md:65-66` and `:317-318`, `AGENTS.md:81-82`, `plan/gates.md:287` (GATE-LICENCE), `tools/check_licenses.py` `APACHE_ROOTS` |
| What shipped instead | three Elastic-2.0 crates under `rust/crates/`: `automonique-github-connector`, `automonique-slack-connector`, `automonique-support-connector` |
| Decided by | the owner alone — `LICENSE-POLICY.md` reserves boundary crossings for owner review |
| Recommendation | **Option 2 — keep Elastic-2.0 and re-document** |

## What is true today

The three connectors are Elastic-2.0 Rust crates. The two documented Apache
roots do not exist, so the part of the licence checker that would enforce them
enforces nothing: every file is judged against `Elastic-2.0` because no path
can begin with a directory that is not there.

This milestone added the guard that makes that visible instead of silent.
`tools/check_licenses.py` now asserts that every declared Apache root is a
directory in the tree, and reports one line per root that is not. The two known
ones are listed in `PENDING_ROOT_DECISION` pointing at this file, so they print
on every run as `pending:` without failing a check nobody without owner
authority can fix. **Any other phantom root fails outright.** Emptying that set
is the last step of whichever option is chosen below, and
`tools/test_check_licenses.py` asserts the live state, so the set cannot drift
away from the tree unnoticed.

## The options

### Option 1 — move the connector crates under `connectors/` and relicense them Apache-2.0

Makes the documents true by making the tree match them.

Against it: `LICENSE-POLICY.md` says in as many words that moving code below an
Apache root does not relicense it and that such a move requires owner review
before distribution. So this is not a reorganization that happens to change a
header — it is a deliberate relicensing of already-shipped Elastic-2.0 code,
and it should be decided as one. It also costs workspace-member path churn and
an SPDX rewrite across three crates.

### Option 2 — keep Elastic-2.0 and re-document (recommended)

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

**Option 2 (recommended)** — five edits and one deletion, all small:

1. `LICENSE-POLICY.md:25-26` — delete the `integrations/` and `connectors/`
   bullets, keep `sdk/`.
2. `README.md:65-66` — delete the two lines from the directory map.
3. `README.md:317-318` — "Code under `sdk/` is under Apache-2.0."
4. `AGENTS.md:81-82` — same sentence, same edit.
5. `plan/gates.md:287` (GATE-LICENCE) — the quoted boundary becomes product
   `Elastic-2.0`, `sdk/` `Apache-2.0`.
6. `tools/check_licenses.py` — `APACHE_ROOTS = {"sdk"}`, and empty
   `PENDING_ROOT_DECISION`. `tools/test_check_licenses.py`'s live-state test
   then passes with zero notices.

Also sweep `COMMERCIAL.md` and `NOTICE` for the same phrase; neither carries it
today, but they are the two root documents most likely to acquire it.

**Option 1** — everything above except step 6, inverted: create `connectors/`,
`git mv` the three crates into it, update `rust/Cargo.toml` workspace members
and the daemon's three path dependencies, rewrite every SPDX header in those
crates to `Apache-2.0`, add the Apache licence text and package metadata each
independently distributed package must carry, and record the relicensing itself
as a reviewed decision in a separate file under `plan/owner-decisions/`.
`integrations/` still has to be resolved separately — nothing is planned for
it, so it is a phantom root under this option too.

**Option 3** — option 1's mechanics applied to newly-extracted crates, plus the
extraction: per connector, split the HTTP/decode core from the target lock and
the product policy, decide which half each existing test belongs to, and
re-establish the fixture-and-loopback-fake discipline on both sides of the new
seam. Size this as architecture work, not as a licence change.

## What happens if this is not decided

Nothing breaks, and that is the problem. The checker keeps passing, the
documents keep describing a boundary that is not enforced anywhere, and the
next person to read `LICENSE-POLICY.md` will believe the connectors are
Apache-2.0 — which, if they act on it, is a licensing error made in good faith
on the repository's own documentation.
