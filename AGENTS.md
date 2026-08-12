# Automonique development policy

Codex may work directly in this repository: inspect files, edit code and
documentation, run tests, use bounded parallel agents, and create ordinary
commits and non-force pushes for owner-requested repository work.

The material under `plan/`, `.automonique/dev/`, and the harness-related tools
is retained as planning history and optional tooling. Claims, packets, leases,
readiness gates, per-item contracts, evidence records, mandatory reviews, and
exact-tree completion transactions are not prerequisites for development.

## Clean-room boundary

This is a clean-room implementation repository. Prior implementation source —
including code, tests, build scripts, configuration, and Git history — must not
be read, mounted, cloned, searched, copied, paraphrased, reconstructed from
memory, or used to generate code.

Permitted inputs are:

- files checked into this repository;
- structural references authorized by the owner, such as prior file and module
  names, directory shape, table and column names, command and environment names,
  and the porting map in
  `docs/product-plan/reference/migration-plan.md`;
- black-box input/output fixtures with recorded provenance; and
- public standards and dependencies permitted by the repository's licence
  policy.

A structural reference identifies where behavior lived, not how it was
implemented. Stop and ask if an input may cross this boundary.

## Working directly

- Start from the owner's requested outcome. Read the relevant product-plan
  documents and current code, then implement the smallest coherent change.
- Use parallel agents when useful. Give concurrent writers disjoint files and
  reconcile their results before committing.
- Preserve unrelated working-tree changes. Do not sweep another task's files
  into a commit.
- Run the tests, formatters, linters, generators, and security checks relevant
  to the changed area. Report the commands and actual results.
- Generated files must be regenerated from their documented source and
  committed with it. Do not hand-edit a generated artifact.
- Do not delete, skip, weaken, stub, or broadly suppress a test merely to make
  a change pass.

The roadmap, contracts, and gates under `plan/` remain useful design inputs,
but they do not decide whether work may start or land. Product reality and
relevant tests take precedence over plan bookkeeping.

## Data and operational safety

Never commit credentials, secret values, private or customer data, logs,
sessions, real infrastructure identifiers, personal email addresses in source
files, or absolute home-directory paths.

Do not access or mutate production infrastructure, deploy to production,
publish a release or package, rotate credentials, administer the repository,
or enable live transports or providers without explicit contemporaneous owner
authority for that operation.

Never generate a shell command string from model output. Use explicit argument
vectors or typed APIs for commands influenced by untrusted/model-produced data.

## Git safety and provenance

Ordinary commits and non-force pushes for requested repository work are
permitted. Codex-authored commits use the configured automation identity
`Automonique Candidate <candidate@automonique.invalid>`; human-authored commits
use the human's truthful configured identity. Do not add assistant attribution
or co-author trailers.

Do not discard work, rewrite history, force-push, delete refs, change remotes,
or use destructive commands such as `git reset --hard` unless the owner
explicitly authorizes the exact operation and recovery path. Stop on conflicts,
ambiguous remote state, or non-fast-forward rejection.

## Licence boundary

Product code uses `Elastic-2.0`. Code under `sdk/`, `integrations/`, and
`connectors/` uses `Apache-2.0`.

Do not move or duplicate code across that boundary without recording the
licence consequence and obtaining owner review before distribution. Release
and distribution work must also perform the dependency, notices, and SBOM
checks required by `LICENSE-POLICY.md`.
