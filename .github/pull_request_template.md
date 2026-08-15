## What this changes

<!-- One or two sentences. Link the issue: "Closes #NN". -->

## Affected-area checklist

- [ ] **Licence boundary** — if a file's directory/licence changed, `python3 tools/check_licenses.py` passes and the boundary docs match (`LICENSE-POLICY.md`, `README.md`).
- [ ] **Scrub** — no legacy/client/personal identifier introduced; `python3 tools/scrub/scan.py` and `python3 plan/check.py --verify` pass. (Deployment values belong in the daemon's private config, never in tracked source.)
- [ ] **Status truth** — if this adds or enables an external surface, the `README.md` "Repository status" section and the daemon's crate doc are updated in the same PR.
- [ ] **Tests/gates** — `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, and the tools suite pass. New durable state ships a STRICT table with a migration-replay test.
- [ ] **No attribution trailer** — no `Co-Authored-By`/vendor trailer on any commit (repo policy; the identity checker refuses them).

## Notes for the reviewer

<!-- Judgment calls, deviations, or anything an owner must decide. -->
