# BOOT-003 — Pre-publication scrub gate

| | |
|---|---|
| Epic | `BOOT` — repository readiness gates |
| Track | core |
| Depends on | `BOOT-001` |
| Closes | [`GATE-SCRUB`](../gates.md#gate-scrub) |
| Licence class | `Elastic-2.0` |
| Allowed paths | `plan/`, `.github/workflows/`, `tools/scrub/` |
| Hill-climbability | 80 — deterministic scan with a fixture corpus |

## Objective

Prevent private identifiers from re-entering a repository intended to be public.

The measurable objective is: a commit reintroducing any configured scrub rule
fails CI, naming a non-sensitive rule ID plus file and line, with zero false
positives on the current tree. Private identifier values never enter the
repository or CI logs.

## Background

Two manual sanitization passes have run; their scope is recorded in
`docs/product-plan/README.md` § Plan transfer. Manual passes do not stay done.
The first pass claimed to have removed all private identifiers and had not —
four families survived it and were found by inspection months later.

## Scope

In scope:

- a scanner over every tracked file **and** every commit message;
- a repository-safe synthetic rule corpus plus a protected CI rule source for
  fingerprints derived from the sanitization passes;
- an explicit allow list for retained identifiers, each with a recorded reason;
- CI wiring that fails the build on a match.

Out of scope:

- scrubbing anything new. If the scanner finds a live identifier, open a
  separate item; do not silently rewrite documents inside this unit;
- secret detection. Credentials are a different class with a different response
  (rotation, not renaming) and belong in the R9 security work.

## Allow list — retained by decision

| Identifier | Reason |
|---|---|
| `Monique` | first-party mascot; product identity |
| `bext-stack` | real repository organization, required by `SECURITY.md` |
| `legacy*` | dormant compatibility identifiers, neutral by construction |
| legacy source filenames | permitted structural references under `AGENTS.md` |

Any addition to this table requires a recorded owner decision. The allow list
is the part of this gate most likely to be widened under pressure; treat a
proposed addition as a policy change, not a scanner tweak.

## Verification contract

| Check | Expected |
|---|---|
| Clean tree | scanner reports zero findings on `main` |
| File content | reintroduced identifier in any tracked file → fail |
| Commit message | reintroduced identifier in a commit message → fail |
| Allow list | each retained identifier present → no finding |
| Message quality | failure names a non-sensitive rule ID, file and line without echoing the matched value |
| Missing protected rules | publication job refuses with a clear configuration error; private development remains available |

## Forbidden shortcuts

- adding a found identifier to the allow list instead of removing it;
- scanning only file contents;
- scanning only changed files, so a reintroduction on a branch that is later
  merged goes unseen;
- excluding `docs/` because it is "only documentation" — every identifier found
  so far has been in documentation.

## Completion evidence

- scanner output on the clean tree;
- four synthetic deliberate-reintroduction runs, one per scrubbed rule family,
  each showing the expected failure without a private value;
- the allow-list table with a reason recorded per entry.

## Integration and rollback

Additive CI job. Rollback is removing the workflow, which reopens
`GATE-SCRUB` and re-blocks publication.
