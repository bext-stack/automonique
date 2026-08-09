# BOOT-002 — Optional integration identity hardening

| | |
|---|---|
| Epic | `BOOT` — repository readiness gates |
| Track | core |
| Depends on | `BOOT-001` |
| Closes | [`GATE-IDENTITY`](../gates.md#gate-identity) |
| Licence class | `Elastic-2.0` |
| Allowed paths | `.github/`, `plan/`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `PROVENANCE.md` |
| Hill-climbability | 60 — optional external administrative hardening, not a build prerequisite |

## Objective

Provide verifiable identity separation for installations whose owner chooses
that hardening.

The measurable objective is: when identity separation is enabled, a reviewer
with only repository access can confirm which identity authored and integrated
a commit and verify any configured signatures against a published trust root.
This item does not block development or owner-configured integration.

## Current state

Every current commit is unsigned. `GOVERNANCE.md` and `CONTRIBUTING.md` permit
truthful human or automation identities and describe optional workload-identity
hardening. `PROVENANCE.md` § Repository identity records the state.

This is an optional defense-in-depth improvement. Exact-tree checks and
external protected-branch authority remain required even when roles share an
identity.

## Scope

In scope:

- if selected by the owner, create distinct workload identities for the roles
  the installation chooses to separate, with no shared key material;
- publish the trust root and enable signature verification;
- configure branch protection so only the owner-configured integration
  credential can write to `main`;
- update `PROVENANCE.md` § Repository identity to describe the achieved state.

Out of scope:

- migrating existing history to the new identities. The root commit's
  authorship is a fact; record it accurately rather than rewriting it;
- granting any identity release-signing or production-deploy authority. Those
  are separate authorities under `GOVERNANCE.md` and stay separate.

## Verification contract

| Check | Expected |
|---|---|
| Protected write boundary | a non-integration credential cannot write to `main` |
| Signature verifies | when signing is enabled, `git verify-commit` succeeds against the published root |
| Declared separation | identities claimed as separate have distinct fingerprints |
| Truthful evidence | shared identities and zero-reviewer outcomes are recorded without an independence claim |

## Forbidden shortcuts

- claiming two labels are separate identities when they share one credential;
- closing this gate on the basis of configuration that has not been tested by
  an actual rejected push;
- treating optional identity hardening as a prerequisite for ordinary build work.

## Completion evidence

- transcript of a rejected non-integration write to `main`;
- `git verify-commit` output for identities configured to sign;
- fingerprint listing for identities claimed as distinct;
- the updated `PROVENANCE.md` section.

## Integration and rollback

This changes repository administration, not the tree. Rollback means restoring
the previous branch protection; it does not require reverting a commit. A
rollback removes the identity-separation claim but does not block development
or owner-configured integration.

## Owner note

Repository administration is an external action under `GOVERNANCE.md` and
cannot be performed by an implementing agent. This item is written to be
executed by the owner, with an agent preparing configuration and tests only.
