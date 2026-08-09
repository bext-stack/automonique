# BOOT-005 — Lightweight licence hygiene

| | |
|---|---|
| Epic | `BOOT` — repository readiness |
| Track | core |
| Depends on | `BOOT-001` |
| Closes | none; `GATE-LICENCE` remains advisory until distribution |
| Licence class | `Elastic-2.0` |
| Allowed paths | `LICENSE-POLICY.md`, `README.md`, `AGENTS.md`, `xtask/`, `.github/workflows/`, `plan/` |
| Hill-climbability | 95 — two deterministic rules and two negative fixtures |

## Objective

Keep licence hygiene cheap during development. The existing plan check verifies
that commentable source files have an SPDX identifier and that it matches the
repository path: product paths are `Elastic-2.0`; `sdk/`, `integrations/`, and
`connectors/` are `Apache-2.0`.

## Scope

In scope:

- a standard-library Python check inside `plan/check.py`;
- negative fixtures for a missing identifier and a wrong path-derived licence;
- removing the custom Rust licence tool and its separate workflow;
- making release-grade licence review advisory until distribution.

Out of scope until a distribution contract exists:

- SBOM and notice generation;
- dependency or third-party manifest enforcement;
- Git-history or content-similarity analysis;
- automatic approval of code moved across the product/Apache boundary.

The clean-room prohibition remains mandatory and separate from this check.

## Verification contract

| Check | Expected |
|---|---|
| Header presence | a commentable source file without SPDX fails with its path |
| Path mapping | an Elastic-2.0 source below `sdk/` fails expecting Apache-2.0 |
| Regression fixtures | all plan self-tests pass without modifying the working tree |

## Forbidden shortcuts

- an exemption list for first-party source;
- skipping an Apache root to make a new package pass;
- treating a passing path/header check as distribution approval;
- weakening the clean-room or third-party licence policy.

## Completion evidence

- `python3 plan/check.py --verify` passes over the repository;
- `python3 plan/selftest.py` rejects both licence fixtures;
- the custom `xtask` licence implementation and separate workflow are absent.

## Integration and rollback

The check runs inside the existing plan workflow and adds no dependency.
Rollback restores the previous policy text but must not restore a blocking
development gate without a new owner decision.
