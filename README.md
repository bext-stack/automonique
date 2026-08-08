# Automonique

Automonique is beginning from a clean, independently governed genesis. This
repository deliberately imports neither implementation source nor Git history
from any pre-genesis system.

## Genesis status

This local tree is the verified clean-room genesis for the public Automonique
repository. The current product specification, architecture, autonomous
development contract and checked work DAG are under `docs/product-plan/`.
Implementation begins with the approved `BOOT-001` bootstrap baseline.

The intended public repository is:

<https://github.com/bext-stack/automonique>

## Operating

```bash
scripts/develop              # one bounded autonomous pass, then exit
scripts/develop --loop 300   # keep running passes; Ctrl-C stops
```

One command converges everything it needs: it builds the release binary when
stale, commissions the checked-out candidate when HEAD is not yet the
commissioned revision (all builder gates plus two independent Claude reviews
over a frozen worktree, assembled into a signed receipt), archives and
re-bootstraps the durable store when it belongs to a prior lineage, and then
runs development. Nothing persists between passes and nothing starts at boot;
the tool works only when explicitly run. A persistent supervisor service
remains available by bootstrapping with `--unattended`.

Each pass leases the first dependency-ready item from the checked work DAG;
authors, two fresh independent reviewers, fixers, builders and the merger
operate through separate durable role records inside isolated transient units
with bounded runtime, memory and tasks. Supported worker providers are Codex,
Claude Code and jcode, each behind the same fail-closed contract: pinned CLI
version, schema-validated structured results, measured token usage and a
canonical session identity on every receipt. Provider-side hard spend/token
ceilings and local pre-dispatch reservations enforce the cumulative budget.

`./automonique status` and `./automonique doctor` are read-only operator
views. Process crashes, host restarts, ambiguous remote effects and unhealthy
candidate generations are reconciled automatically; a failing generation is
rolled back to the last known-good digest. Candidate health is proved before
protected `main` can move.

## Licensing

- Product code is made available under the Elastic License 2.0.
- Official SDKs and integration libraries are licensed under Apache-2.0.
- Commercial, hosting, OEM, and partner rights are available only through a
  separate written agreement.
- Automonique names, logos, mascots, and brand assets are governed separately
  by the trademark policy.

See [LICENSE-POLICY.md](LICENSE-POLICY.md) for the exact directory boundary.
