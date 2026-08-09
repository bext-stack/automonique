<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — runtime topology contract

| Field | Decision |
|---|---|
| Status | approved for `R0-05` and one publication |
| Expected base | `6f6255cdc4689d079545995825f8ed52dc6a050f` |
| Work ID | `R0-05` — runtime topology decision |
| Dependency evidence | `R0-03` is done; `plan/evidence/R0-03.json` has SHA-256 `9d28baa7ae4978f0577693fb1a48957cc238b625cee5e82fc745cb8d53f1e191`; `R0-05` is selectable and has no blocking gate |
| Objective | pin the direct foreground lifecycle as the portable core, separate optional supervisor capabilities, define failure ownership, and make the adapter recommendation threshold executable |
| Allowed paths | `plan/`, `tools/`, derived `.automonique/dev/program.yaml` |
| Intended snapshot | decision JSON and Markdown, a standard-library verifier, verifier regression tests in the existing CI test module, R0-05 evidence and generated plan/DAG state |
| Licence class | `Elastic-2.0` |
| Budget | one decision document and one dependency-free verifier; no product runtime, service/supervisor adapter, network call, credential, privileged operation, host mutation, or persistent process |
| Tests | source-evidence digest binding, decision semantics and negative mutations, plan integrity/self-tests, DAG reproducibility, Python compilation, diff and secret/path hygiene |
| Review | zero independent reviewers; explicit owner-supervised continuation |

## Publication authorization

After the exact candidate passes, create one ordinary commit on `main` and push
it normally to `origin/main` only if the remote still equals the expected base.
Do not force, rewrite, tag, release, publish a package, change repository
settings, or modify another ref.

The recovery reference is the expected base. A failed push or CI run leaves the
commit available locally for inspection; it does not authorize a force push or
history rewrite.

## Stop conditions

Stop if the R0-03 digest or measured environment cannot be reproduced, if an
adapter becomes a core dependency, if the decision claims an unmeasured
capability, if any failure mode lacks a single-owner outcome, if a dependency
is required, if a required check fails, or if `origin/main` moves from the
expected base.
