# Archived development-harness artifacts

The files in this directory are generated views used by Automonique's earlier
self-hosting and work-admission experiments. They are preserved for research,
debugging, and historical traceability.

They are not inputs to the normal Codex development workflow. Product work does
not require regenerating `program.yaml`, `objectives.json`, guides, loop state,
claims, packets, or completion evidence.

The historical tools remain available on an opt-in basis:

```sh
python3 tools/program.py --verify
python3 tools/guides.py --verify
python3 tools/harness_loop.py status
```

A refusal from those tools does not block direct repository editing, relevant
tests, ordinary commits, or non-force pushes.
