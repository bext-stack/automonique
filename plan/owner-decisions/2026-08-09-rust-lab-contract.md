<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — make the R0-19 Rust target explicit

| Field | Decision |
|---|---|
| Status | pending external owner acceptance of the exact control candidate commit and tree |
| Expected base | `ef898976776b02a15987359789f3789bedde8b78` on local and remote `main` |
| Dependencies | published R0-06, R0-17 and R0-18 evidence remains unchanged; this proposal changes only the R0-19 Rust requirement and lease |
| Objective | make the Rust `automonique-lab` target, committed lockfile and required verification explicit before Rust implementation begins |
| Allowed paths | `.automonique/dev/objectives.json`, `.automonique/dev/program.yaml`, `plan/contracts/R0-19.md`, `plan/generate.py`, `plan/owner-decisions/2026-08-09-rust-lab-contract.md`, `plan/work-graph.toml` |
| Budget | one six-file control proposal and its deterministic verification; no product implementation, completion evidence, history/status change, authority change or integration before exact owner acceptance |
| Checks | generated work graph byte comparison; plan integrity and 12-case self-test; program and guides verification; targeted plan/program/guide/harness tests; scrub tests and repository scan; exact Git parent/tree/path/trailer assertions; full completion gate must refuse missing Rust evidence |
| Licence class | `Elastic-2.0` |
| Stop conditions | any extra path, generated-artifact drift, failed deterministic check, scrub finding, changed base, missing Rust-evidence refusal, candidate/tree mismatch, or absent exact-revision owner acceptance |

The repository owner directed the active Codex session to build Monique in
Rust and to use agent orchestration to do the complete migration. This decision
corrects the R0-19 bootstrap contract before any Rust implementation is judged.

## Exact scope

- R0-19 must produce the locked `rust/crates/automonique-lab` Cargo workspace
  member described by the product plan.
- `rust/Cargo.lock` is added to the R0-19 path lease so a reproducible Rust
  workspace can be committed.
- The verification contract gains a required `Rust workspace` result.
- Existing Python lab code is classified as the supervised bootstrap adapter,
  not as completion of the Rust implementation.

## Non-retroactivity

This control change does not certify itself and does not retroactively satisfy
R0-19. The existing completion evidence is not rewritten by this proposal; the
new required Rust-workspace result is therefore absent and completion must fail
closed until measured Rust evidence is added by a later implementation
candidate. The protected-control candidate requires external owner acceptance
bound to its exact commit and tree before integration. Rust implementation
begins only from a base containing that accepted correction. All generic force,
history-rewrite, remote-edit, release, package-publication and deployment
authority remains unavailable.
