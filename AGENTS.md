# Automonique agent contract

This is a clean-room implementation repository. Prior implementation
source and Git history are outside the allowed context and must not be copied,
mounted, searched, summarized, or used to generate code.

The bot-authored specifications under `docs/product-plan/` are permitted
implementation inputs. Their provenance and transfer classification are
recorded there. Agents may use those checked-in files but must not access the
private archive from which some implementation-independent requirements were
transferred.

## Before implementation

- Select a ready work ID from `docs/product-plan/work-dag.toml`.
- Record dependency evidence, allowed paths, expected base, objective, budget,
  tests, licence class, and stop conditions.
- Refuse work blocked by an unresolved legal, provenance, baseline, or policy
  gate.

## Hard rules

- Never commit credentials, private/customer data, logs, sessions, real
  infrastructure identifiers, personal email addresses, or absolute home paths.
- Never generate a shell command string from model output. Use explicit argv or
  typed APIs.
- Never edit outside the work unit's lease or change the metric, baseline,
  licence, policy, or budget judging your own work.
- Never delete, skip, ignore, or weaken a test; add a stub; bulk-refresh a
  golden; or widen unsafe/lint allowances to pass a gate.
- Never approve your own work.
- Never claim an unmeasured metric. Missing evidence is `null` with a reason.
- Product files use `Elastic-2.0`; `sdk/` and `integrations/` use
  `Apache-2.0`. Moving code across that boundary requires policy review.

## Git authority

Workers use typed stage/commit operations for leased paths at an expected base.
They cannot push, merge, force, rewrite history, edit remotes, or administer the
repository. A separate merger identity may perform the bounded integration
defined in `GOVERNANCE.md` only after exact-tree gates pass.

## Verification

Report actual checks, counts, failure paths, restart behavior, compatibility,
licence classification, and provenance. Compilation alone is not completion.
