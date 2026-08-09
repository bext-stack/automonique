<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — lightweight development licensing

| Field | Decision |
|---|---|
| Status | approved |
| Repository base | `b87724b298a585385301347a79c91bb8c605bf88` |
| Requested | 2026-08-09 through the owner-controlled repository workspace |
| Objective | replace premature release-compliance automation with a small path-aware SPDX check that does not block product development |
| Allowed paths | `LICENSE-POLICY.md`, `README.md`, `.github/workflows/`, `plan/`, `xtask/` |
| Licence class | `Elastic-2.0`; existing Apache roots are normalized as `sdk/`, `integrations/`, and `connectors/` |
| Budget | standard-library Python only; no separate workflow, build dependency, SBOM generator, Git-history comparison, third-party manifest parser, or development-blocking licence gate |
| Verification | plan integrity and self-tests, generated-graph equality, Python compilation, lightweight licence negative fixtures, diff hygiene, and GitHub Actions |

## Decision

Development keeps two mechanical rules: commentable source files carry an SPDX
identifier, and the identifier matches the file's repository root. Product
paths use `Elastic-2.0`; `sdk/`, `integrations/`, and `connectors/` use
`Apache-2.0`. The existing plan workflow runs this check.

Release-grade work is deferred until the first distributable artifact exists.
At that point the owner may require dependency notices, third-party licence
review, boundary-move review, an SBOM, and package metadata as appropriate to
the artifact. `GATE-LICENCE` is advisory until then and cannot block SDK,
connector, release-tooling, or other implementation work.

The custom Rust licence tool, its build files, its evidence claims, and its
separate GitHub workflow are removed. This does not alter the clean-room rule
or authorize copying product code into an Apache-licensed package.

## Publication authorization

The owner previously requested that the repository start from one root commit.
After this simplification passes locally, replace `origin/main` once more using
`--force-with-lease=refs/heads/main:b87724b298a585385301347a79c91bb8c605bf88`
and a new parentless commit containing the complete verified snapshot. Only
`origin/main` is in scope; no other ref or repository setting may change.

## Stop conditions

Stop if the lightweight check cannot reject a missing or path-incompatible
SPDX identifier, if any plan check fails, if a credential or private value is
present, or if the remote tip differs from the expected lease.
