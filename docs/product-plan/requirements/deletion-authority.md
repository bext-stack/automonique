# Deletion authority

**Status.** Drafted 2026-08-15 as part of M2 #13. Authored in this repository —
not transferred planning material, and not derived from legacy source. The
precise semantics below are **owner-confirmable**, though less of this one is
open than the other three: unlike them, this property has an **observable
reference behaviour** to specify against rather than a decision to invent.

## The property

Deletion is a **distinct approval class**, exercised under a **separately held
credential**. The ordinary credential's delete verb **refuses**.

Three separate claims, and each is load-bearing:

1. **A separate credential.** The authority that deletes is not the authority
   that posts and edits, and is not held by the same principal.
2. **A distinct approval class.** An approval of ordinary work does not
   authorize a deletion. A deletion needs an approval that says "deletion", and
   that names the exact resource.
3. **The ordinary path refuses.** Asking the ordinary credential to delete is
   not an authorization failure to be fixed with a better approval; it is a verb
   that credential does not have.

## Why two credentials rather than one policy check

`reference/legacy-inventory.md` § Configuration surface records that the prior
system already enforced this with two distinct credentials rather than one
in-process rule, and `reference/feature-parity.md:101` records the split as the
thing to preserve. That makes this the one safety property with an existing
answer rather than an invented one — what is being re-specified is the
*contract*, not the decision.

The reason the split is worth keeping: a policy check is a branch in code, and a
branch can be taken. A credential the process does not hold is a capability the
process does not have — no branch, no bug, no reachable path. When the ordinary
worker is compromised, or a caller reaches for a general-purpose API, or a
refactor moves a check, the credential split is still there.

## Failure-mode semantics, exactly

| Attempt | Refusal | Effect |
|---|---|---|
| ordinary credential, delete verb | `delete_verb_unavailable` | none; the attempt is recorded |
| deletion credential, ordinary-class approval | `approval_class_mismatch` | none; the attempt is recorded |
| deletion credential, approval naming another resource | `approval_subject_mismatch` | none; the attempt is recorded |
| deletion credential, approval already used | `approval_already_consumed` | none; the attempt is recorded |
| a credential the surface does not recognise | `unknown_credential` | none; the attempt is recorded |
| deletion credential, deletion-class approval, exact subject, unused | performed | one deletion, with a receipt citing the approval |

Four bindings this table is making explicit:

1. **The ordinary delete verb refuses unconditionally.** It refuses even when
   presented with a perfect deletion-class approval for the exact resource. The
   answer does not depend on how good the approval is, and specifying it any
   other way invites an implementation that checks the approval first and finds
   a reason to proceed.
2. **Every attempt is recorded, refused ones included.** A refusal nobody can
   find afterwards is indistinguishable from an attempt that never happened,
   and the refused attempts are the interesting half of the audit trail.
3. **An approval names one resource and authorizes one effect.** "Approved
   deleting that message" does not extend to the next message, and does not
   extend to a second deletion of the same one.
4. **Never bundled with ordinary cleanup.** A deletion is its own act with its
   own approval; it is not a step inside a broader operation that was approved
   as a whole. `feature-parity.md:101` states this directly, and the type shape
   enforces it: the delete path takes no verb parameter, because deleting is the
   only thing that credential is for.

### Separately held, structurally

A deletion credential is minted from a grant, and minting refuses when the grant
names the ordinary credential's holder (`credential_not_separately_held`). One
principal holding both is one compromise away from holding neither separately —
which is the arrangement the property exists to prevent, so it is refused at
construction rather than discouraged in prose.

The credential rotation, custody and storage rules are *owner-confirmable* and
belong with the credential-management contract in
`operations-and-governance.md`, not here. What this document fixes is that the
two are distinct and separately held; where they live is an operations decision.

## Conformance

The suite is `automonique_protocol::safety_conformance::deletion_authority`
(`rust/crates/automonique-protocol/src/safety_conformance/deletion_authority.rs`),
generic over one trait, `DeletionAuthority`. The trait's shape carries part of
the property: `perform_ordinary` takes an ordinary credential and a verb and
refuses the delete verb; `delete` takes a deletion credential and no verb at all.

| Case | What it pins |
|---|---|
| `the_two_credentials_are_separately_held` | different holders, checked even though the type already guarantees it |
| `the_ordinary_credential_refuses_the_delete_verb` | with the strongest approval a caller could present |
| `the_ordinary_credential_still_posts_and_updates` | narrowing the surface, not shutting it down |
| `a_deletion_requires_a_deletion_class_approval` | and the same deletion, correctly approved, proceeds |
| `an_approval_authorizes_only_its_exact_subject` | one approval, one resource |
| `an_approval_authorizes_exactly_one_effect` | no replay |
| `every_performed_deletion_cites_a_deletion_class_approval` | the whole run, and exactly one deletion happened |

`rust/crates/automonique-protocol/tests/safety_conformance.rs` also runs the
suite against four **mutants**: an authority whose ordinary credential deletes,
one that accepts any approval, one that ignores the approved subject, and one
that replays approvals. Each must fail at the case that names what was broken.
The separately-held precondition is checked directly instead, because the type
has one constructor and that constructor refuses a shared holder — no subject
can violate it.

## What this does not prove

Nothing in the daemon implements `DeletionAuthority` yet. The binding is the
launch roadmap's Increment 4, which lists the separately-authorized delete among
the things it builds;
`automonique_protocol::safety_conformance::PENDING_BINDINGS` carries the gap as
checkable data.

One question this contract does not answer, deliberately: **who** may approve a
deletion. That is an authority question for the approval lane, and answering it
here would put a second, weaker copy of that policy in a document about
credentials.

## Provenance

`reference/feature-parity.md:101` records the deletion row as **Replace** with no
fixture, and its evidence column records that the split is "enforced today by a
separate delete credential — preserve that split".
`reference/legacy-inventory.md` records the same split in the configuration
surface. This document specifies the contract those two rows call for; it
imports no legacy source, which the clean-room boundary in `PROVENANCE.md` keeps
out of scope.
