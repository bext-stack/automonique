# Planning archive and optional tools

This directory preserves Automonique's detailed roadmap, contracts, dependency
graph, gates, evidence, and earlier autonomous-development experiments. It is a
useful source of requirements and history, not an admission controller for
ordinary development.

You do not need a ready ID, contract, claim, packet, lease, evidence JSON,
baseline movement, gate preflight, or status transition to change product code.
Start from the owner's requested outcome, the product plan, the current code,
and the relevant tests.

## Contents

```text
work-graph.toml    historical generated dependency graph
ready.md           historical generated selection view
gates.md           capability/release conditions and historical gates
contracts/         detailed work-item specifications
evidence/          evidence recorded by the former workflow
history.jsonl      former integration ledger
authority.toml     configuration for archived harness tools
check.py           optional graph/licence/history verifier
gate.py            optional legacy evidence/scope preflight
```

These files may still be consulted or updated when doing roadmap work. If a
change intentionally edits a generator source or graph, regenerate its derived
artifacts using the commands documented by that generator. Product changes do
not need parallel bookkeeping edits here.

## Optional historical workflow

The former workflow is still available for experiments:

```sh
python3 plan/check.py --verify
python3 tools/program.py --verify
python3 tools/harness_loop.py status
```

It may refuse because its archived contracts, host capabilities, or generated
state are incomplete. Such a refusal is about that optional workflow, not
permission to develop, test, commit, or push the product.

The small mandatory licence-path check has been separated from this stack:

```sh
python3 tools/check_licenses.py
```
