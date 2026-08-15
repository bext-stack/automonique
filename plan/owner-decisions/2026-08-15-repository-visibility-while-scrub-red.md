<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — repository visibility while the publication scrub is red

**Status: PENDING. This memo decides nothing. It is written by an implementer
who does not hold the authority to change repository visibility or to upload a
secret, and it exists so the owner can decide with the measurements in front of
them.**

| Field | Value |
|---|---|
| Question | Does the repository stay public while the publication scrub cannot pass? |
| Blocked on | owner-only actions: repository administration, and provisioning two environment secrets |
| Gate | `plan/gates.md#gate-scrub` — recorded open, and explicitly "Blocks: making the repository public" |
| Decided by | the owner alone |
| Recommendation | **Option A — private until the protected bundle is provisioned and the full-history scan is green or its residue is accepted in writing** |

## What is true today

The tracked tree is scrubbed. `plan/check.py --verify` reports zero
identifier-location failures, and the values that were in source, docs and UI
strings moved into operator configuration and sanctioned homes.

Three things are nevertheless still true, and they are why this is a decision
rather than a formality:

1. **History is untouched.** Every prior revision of the affected files is
   still a reachable blob, and nine commit messages on `main` still carry an
   identifier — two in a subject, seven in a body. A clone gets all of it. No
   forward-only change can alter this; only a history rewrite or an accepted
   -findings mechanism can, and the rewrite is its own owner decision.
2. **Nothing detects the client and agency names automatically.** The public
   fingerprint mechanisms cover the first-party legacy name only. Detection of
   third-party values lives entirely in the protected HMAC bundle, and **zero
   protected rules are installed**, because provisioning them is an owner
   action. Until then every scrub job in this repository can only find the four
   public synthetic values, and says so on every run.
3. **The engineering that consumes the bundle is now in place.** This milestone
   added a `protected-push-scrub` job that runs on every push and pull request,
   gated on secret availability: with the secrets it scans in protected mode,
   without them it runs development mode and emits a loud warning. Provisioning
   is therefore the only remaining step — no further code change is needed for
   CI to harden.

## The options

**A. Make the repository private until the scrub is green.** Reversible in one
click, costs nothing but visibility, and it is the only mitigation that works
*today* rather than after a decision chain. It does not fix history; it stops
the audience for it.

**B. Stay public and accept the exposure window.** Defensible only if the owner
judges the residual values as low-harm — they are a former client's product and
tenant names, hostnames, an agency org, and a bot name, not credentials. The
window then lasts until the history decision is made and executed, which is not
a short interval.

**C. Stay public and expedite a history rewrite.** Combines B's exposure with
the most disruptive fix. A nine-commit rewrite spanning the connector series
invalidates every fork, open pull request and local clone. Doing it under time
pressure is how a rewrite goes wrong.

## Recommendation and why

**Option A.** The asymmetry is the argument: going private costs a day of
public visibility on a repository with no external contributors, and it is
undone by a single setting the moment the scrub is green. Staying public spends
an irreversible resource — every hour of exposure is an hour in which the
history can be cloned by anyone, and a clone taken today is not affected by any
later rewrite. A is also the only option that does not require the owner to
decide the *history* question first; it buys the time to decide that one
properly.

Option A is compatible with everything else in flight. Development continues
unchanged, CI runs unchanged, and the push-time scrub keeps working. Nothing in
this repository depends on being publicly readable today.

## Exactly what happens once the owner decides

**If A (recommended):**

1. Owner sets the repository to private (Settings → General → Danger Zone).
   Record the date here.
2. Owner writes a private values file **outside the repository** — the tool
   refuses one inside it — one `family: value` per line, covering all four
   families: the legacy bot name, the client product/tenant, the two client
   hostnames, the profile-app id, the client agency org, and the internal
   product / environment names.
   - The legacy bot name is *retained by decision* in its sanctioned inventory
     and in the protocol name registry. It must therefore carry `@home`
     annotations naming those exact files, or the scan is unfixably red:
     `legacy-name: <the name> @home docs/product-plan/reference/legacy-inventory.md @home rust/crates/automonique-protocol/src/compat.rs`
     — add `@home rust/crates/automonique-protocol/src/compat/generated.rs` if
     the generated spelling carries it too. The `homes` grammar and the
     scanner's matching suppression landed with this milestone.
   - Never annotate a client or third-party value with a home. Those are
     permitted nowhere, and a home would make that unenforceable.
3. `python3 tools/scrub/provision.py --values <file> --dry-run` — prints rule
   IDs, families, byte lengths, and how many sanctioned files each rule
   retains. It prints no value. It refuses if a value is still present outside
   its declared homes, and refuses if a declared home is not a tracked file.
4. `python3 tools/scrub/provision.py --values <file> --upload` — writes the two
   secrets to the `scrub-publication` environment.
5. Push anything. `protected-push-scrub` switches to protected mode with no
   further edit, and its warning disappears. That is the proof the bundle is
   live.
6. Run `publication-scrub` once by `workflow_dispatch`. **Expect it to be red**,
   on the nine historical commit messages and on every prior revision of the
   affected files. That redness is the honest measurement of the history
   question and is the input to the rewrite decision — it is not a defect in
   the provisioning.
7. Decide the history question. Only then does making the repository public
   again have a green scrub behind it.

**If B or C:** record which, and why, in this file, and amend
`plan/gates.md#gate-scrub` so the gate text stops asserting a blocking
condition the repository is knowingly operating against. A gate that everyone
knows is being ignored teaches readers that gates are decorative, which costs
more than this one decision.

## Two hazards to hold on to

- **The `scrub-publication` environment must not gain a required-reviewer or
  wait-timer protection rule.** `protected-push-scrub` names that environment
  to read its secrets, so a protection rule would make every push queue behind
  a human. If publication ever needs such a rule, mirror the two secrets at
  repository level and drop the `environment:` key from the push job instead.
  The workflow carries this warning inline.
- **A push-scoped scan cannot answer the publication question.** The push job
  reads the tracked tree and the pushed commit range; on this repository that
  is about 31 seconds against about 99 seconds for the full-history scan, and
  the saving is exactly the part that would have looked at history. A green
  push tick is never evidence that a rewrite is unnecessary. That is why
  `publication-scrub` remains, and why its scope note is printed on every
  tree-scope run.
