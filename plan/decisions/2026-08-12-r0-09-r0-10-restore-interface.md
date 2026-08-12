# R0-09/R0-10 restore-interface clarification candidate

| | |
|---|---|
| Candidate base | `124b3f3bba2da1f407e09b9bbd95378fdd99f5f3` |
| Effective | only after exact-tree integration, for descendant R0-10 attempts |
| Paths | `plan/contracts/R0-09.md`, `plan/contracts/R0-10.md`, this report |
| Objective | prospectively pin the restore-inventory interface and define the baseline recovery measurement boundary without changing product behavior |
| Budget | one candidate iteration; 30 minutes; stop rather than expand scope |
| Licence | `Elastic-2.0` |

## Dependency evidence

`BOOT-001` and `R0-09` are done at the candidate base. R0-09 already generates
`plan/inventory/surface/restore-dependencies.json`, schema
`automonique.restore-dependencies/v1`, with `work_item: R0-09` and
`consumer: R0-10`. The prior R0-10 consumer instead expected an unspecified
alternate interface. The integrated owner decision
`plan/owner-decisions/2026-08-11-r1-12-contract-amendments.md` records this exact
cross-item defect and directs the resolver to select one interface and write it
into both contracts.

Two independent read-only reviews agreed that the existing product requirements
permit a synthetic cadence and a same-kernel clean-host boundary, provided the
boundary is disclosed honestly and cannot see source, repository, credentials,
sockets or host network authority. They also found three ambiguities that must
be closed prospectively: RTO endpoints, the scope of “new” in the dependency
rule, and the required disposition of R0-09's heterogeneous ordered positions.

## Clarification

- R0-09's existing generated export is canonical; an R0-10 consumer must
  independently re-derive it rather than trusting mutable self-description.
- A fresh same-kernel boundary is sufficient for this synthetic baseline only;
  it is not evidence of VM, physical-host, hostile-kernel or production
  recovery.
- Cadence and loss placement are fixed before the run. RTO includes creation of
  the disposable boundary and ends after applicable verification and actual
  disconnected-recovery startup.
- Reusing an isolation executable already declared at the admitted base does
  not add a repository prerequisite when no install/fetch occurs and absence
  refuses without fallback. Incidental machine presence alone is insufficient.
- Every R0-09 position receives one closed disposition. Required unexercised
  work blocks completion; enablement gates pass only by remaining closed.

## Checks

Run from the repository root:

```text
git diff --check -- plan/contracts/R0-09.md plan/contracts/R0-10.md plan/decisions/2026-08-12-r0-09-r0-10-restore-interface.md
python3 plan/check.py --verify
python3 tools/program.py --verify
python3 tools/guides.py --verify
python3 tools/surface_inventory/verify.py
python3 tools/harness_loop.py check
```

## Review and non-retroactivity

Reviewers: 2 read-only contract/route reviewers. Blocking findings for this
three-file clarification: 0. A separate immutable-base `plan/selftest.py`
failure in legacy-identifier checks is outside these paths and is not waived or
claimed fixed here; the admission checks named above remain required.

This is a partial contract candidate, not R0-10 completion. It changes no prior
evidence, status, graph, baseline, gate, authority, product code or metric. The
attempt admitted at the candidate base remains judged by the old wording. No
old null or failed row becomes a pass. Only a later R0-10 attempt descended from
the integrated clarification may rely on it.

Stop on any product implementation, retroactive evidence/status change,
objective weakening, production credential or system access, authority/gate
change, generated-plan drift, licence-boundary violation, failed required
check, or path outside the three-file scope.
