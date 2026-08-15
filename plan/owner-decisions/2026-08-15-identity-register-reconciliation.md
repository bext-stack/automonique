<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — reconciling the identity register

**Status: PENDING. This memo decides nothing and registers nobody. Writing an
identity into `.github/identity/register.toml` means writing a real name and
email address into a source file in a public repository, and reassigning
governance roles. Both are the owner's to do, so an implementer records what
Git already says and stops.**

| Field | Value |
|---|---|
| Question | Who does this repository claim its commit identities are, now that three commits were made by identities the register does not list? |
| Measured | `python3 .github/identity/check_identity.py` exits 1 with **7 unsupported claims** |
| Blocked on | writing a real name and email into a tracked file; reassigning `GOVERNANCE.md` roles |
| Decided by | the owner alone |
| Recommendation | register both identities; resolve the email question by naming `register.toml` as the single sanctioned home for commit-identity metadata |

## What the checker refuses, and why

Three merge commits were created through the GitHub web interface:
`c2f8b167`, `d0fafcfe`, `da6633b2`. Git records three facts about them that
the register does not support.

| # | Refusals | Fact |
|---|---|---|
| 1–3 | "authored by an identity `register.toml` does not list", once per merge | the author is the owner's own Git identity, which the register has never listed |
| 4–6 | "committed by an identity `register.toml` does not list", once per merge | the committer is GitHub's web-flow identity, which merges through the UI always uses |
| 7 | "3 commit(s) carry a signature while every identity declares `signing = \"none\"` — the register understates the achieved state" | GitHub signs web-flow merges with its own key; `%G?` reports `E` locally because that key is absent from the local keyring |

Refusal 7 is worth reading carefully: it is the checker catching the register
*under*-claiming. The repository is doing better than it says, and that is
still drift, because the register's job is to be the record of the achieved
state.

**`historical_exception` cannot cover any of this.** An exception must be an
ancestor of `rule_effective_commit` (`register.toml:19-21`), and all three
merges postdate it. That constraint is deliberate: it is what stops a new
non-conforming commit being excused without also moving the rule line, which
is a far louder edit. Do not work around it.

## What has to be registered

Three edits to `register.toml`, all of which need real values only the owner
should write:

1. **The owner's commit identity** — the `name` and `email` exactly as they
   appear in the author header of the three merges. `separation = "shared"`,
   `commits = true`.
2. **GitHub's web-flow committer identity** — `GitHub <noreply@github.com>`,
   which is not personal data and is the same for every repository on the
   platform. `signing = "gpg"` with GitHub's web-flow key fingerprint, since
   that identity is what actually signs.
3. **`signing_effective_commit`** — the full SHA of `da6633b`, the first signed
   merge. The checker refuses a signing identity with no
   `signing_effective_commit`, and refuses one that is not an ancestor of
   `HEAD`.

### The role redistribution this forces

`check_roles` (`check_identity.py:276-290`) refuses a role held by two
identities **and** a role held by none, and `check_identity_entry` requires
every identity to hold at least one. `candidate` currently holds all five
(`register.toml:44`), so adding two identities is **not** an additive edit —
the five roles have to be redistributed. A truthful split:

| Identity | Roles | Why it is true |
|---|---|---|
| `candidate` | `implementer`, `reviewer`, `fixer` | it writes, reviews and repairs the changes |
| the owner | `merger` | the owner is who pressed merge on all three |
| web-flow | `builder` | GitHub Actions runs every build and test check |

`separation_claimed` stays `false`. This memo does not make the repository's
identity separation real: the external half of that claim — branch protection
and a rejected-push transcript (`plan/gates.md:105-114`) — is untouched, and
claiming separation without it would be the same under-verified assertion the
checker exists to prevent.

## The email question, and the recommended resolution

Registering the owner's identity puts a real email address into a tracked
source file. `AGENTS.md` § Data and operational safety forbids personal email
addresses in source files, and the register itself already honours that: one
existing `historical_exception` deliberately does not reproduce the identity it
excuses, recording instead that "the commit object remains the authoritative
record" (`register.toml`, third exception).

So there is a genuine conflict, and three ways out.

1. **Name `register.toml` as the single sanctioned home for registered
   commit-identity metadata** — one clarifying line in `AGENTS.md`, the same
   one-sanctioned-home pattern the legacy inventory already uses and that
   `plan/check.py`'s `LEGACY_IDENTIFIER_HOMES` enforces. The address is
   already in the author header of every commit the repository publishes, so
   this conceals nothing that is currently concealed; it makes the existing
   disclosure deliberate and bounded. **Recommended.**
2. **Match on a SHA-256 digest of the email instead of the plaintext.** More
   code in the checker, and no real concealment — the address is public in the
   commit headers, so the digest is trivially confirmable by anyone who
   already has it. It buys the appearance of privacy, not privacy.
3. **Use a `noreply` address for future merges and leave the three as
   exceptions.** Not available: exceptions cannot reach past
   `rule_effective_commit`, so this fixes only the future while the seven
   refusals stand.

Whichever is chosen, record it here and, if it is option 1, make the `AGENTS.md`
edit in the same change as the `register.toml` edit — a sanctioned home that is
sanctioned only in a memo is not a rule.

## What landed now, and what it does until the owner acts

`.github/workflows/identity.yml` exists (`name: identity`, on push, pull
request and manual dispatch). It runs the checker's own test suite and then the
checker, over a full-depth checkout — `read_commits` walks all of `git log
HEAD`, so a shallow clone would make the check measure a handful of commits and
pass for the wrong reason. It imports no GPG key, deliberately: `check_signing`
selects the commits that must verify by **author**, and the merges are only
*committed* by web-flow, so `git verify-commit` is never invoked. Registering
the owner with `signing = "none"` keeps it that way. A check that passes only
because CI fetched a public key at runtime is a weak link worth not building.

**The workflow is green today, and it is not pretending.** It carries
`EXPECTED_UNSUPPORTED: '7'` — the exact count above — and:

- **fails if the count goes up**, so a new unregistered identity or a new
  attribution trailer is refused from today;
- **fails if the count goes down** without the number being lowered in the same
  change, so the baseline cannot rot into a mute;
- emits a warning and a run-summary line on every run saying the register is
  pending and that this job is not evidence that it is truthful.

That is the same shape as `PENDING_ROOT_DECISION` in `tools/check_licenses.py`:
a known-pending state recorded as data, enforcing in both directions, retiring
itself when the decision lands. The alternative — letting the workflow be red
from the day it merges, on every push, fixable by nobody but the owner — would
have taught everyone to ignore a red identity check, which costs more than the
check is worth.

## Exactly what the owner does

1. Choose the email resolution above (recommendation: option 1) and record it
   in this file.
2. Edit `register.toml`: add the two identities, redistribute the five roles as
   tabled, set `signing_effective_commit` to the full SHA of `da6633b`.
3. If option 1: add the one-line sanctioned-home clarification to `AGENTS.md`,
   in the same change.
4. Run `python3 .github/identity/check_identity.py`. It must exit 0.
5. Set `EXPECTED_UNSUPPORTED` to `'0'` in `.github/workflows/identity.yml`, in
   the same change. The workflow will refuse the change otherwise, which is the
   point.
6. `plan/gates.md` § GATE-IDENTITY's workflow citation is true from the moment
   `identity.yml` merged; step 3 of its owner checklist (`plan/gates.md:109`)
   needs `plan`, `rust`, `scrub` **and `identity`** nameable as required status
   checks, and `identity` now is.

**One standing consequence to accept knowingly:** future merges stay covered
only while the owner merges through the GitHub UI. A local unsigned merge
authored by the owner's identity after `signing_effective_commit` would make
the checker red. If the owner ever wants to merge locally, the register has to
say so first.
