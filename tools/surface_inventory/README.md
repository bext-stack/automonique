<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Surface inventory checker (`R0-09`)

The identity, data and operations surface the rewrite must carry, recorded as
classes, owners and shapes.

| File | Role |
|---|---|
| `plan/inventory/surface/inventory.json` | source of truth, hand-authored |
| `plan/inventory/surface/README.md` | generated human view |
| `plan/inventory/surface/restore-dependencies.json` | generated machine view for `R0-10` |
| `tools/surface_inventory/model.py` | vocabulary, structure and provenance rules |
| `tools/surface_inventory/hygiene.py` | private-identifier and secret-shape refusals |
| `tools/surface_inventory/render.py` | the two derived views |
| `tools/surface_inventory/verify.py` | the checker and the regenerator |

Run it:

```sh
python3 tools/surface_inventory/verify.py             # verify; writes nothing
python3 tools/surface_inventory/verify.py --write     # regenerate the two views
python3 -m unittest discover -s tools/surface_inventory -p 'test_*.py'
```

Verification is offline: it reads the inventory, the files it cites and the two
derived views. No network, no secret, no dependency outside the standard
library. Exit status is 0 for a valid, current inventory, 1 for any finding and
2 when the document cannot be read.

## What makes a bad entry impossible rather than discouraged

- Every classifying field is a closed vocabulary; an unknown member is a parse
  refusal, not a warning.
- A credential entry's key set is exact and contains **no field a value could
  go in** — not even an example. Adding one means editing `model.py`, which is
  the reviewable act.
- A withheld fact is two enums, a shape and a reason, and nothing else. That is
  what stops "record the shape, not the value" from becoming a place to write
  the value down.
- A number is accepted only beside a citation whose exact words are found in
  the checked-in file it names **and** which contains that number beside its
  unit. Requiring merely *a* citation was not enough — any citation would have
  done, so a recalled figure could be parked next to an unrelated quote. A quote
  that stops being true in its source file also fails the check.
- An example must sit in a reserved, non-routable namespace and say so:
  `synthetic-*` for a placeholder, `.invalid` / `.example` / `.test` for a
  reserved value.
- Runbook triggers and steps are scanned for shell prompts, command words and
  SQL. A production-touching runbook records no mutating step. The trigger is
  scanned on the same terms as a step, because a rule about steps alone would
  be satisfied by writing the command one field to the left.

## The judgement this item actually carries

Deciding which operational facts are recordable *without* exposing a private
identifier is the hard part, and the rule used here is: record the class, the
owner and the shape; withhold the value and say which shape was withheld and
why. A tenant identifier, an external platform ID, a host name, a workspace
path and a credential value are all withheld — but the fact that each exists,
who owns it and what governs it is recorded, which is what `R1-13` and `R0-10`
need.

`null` with a reason is a measurement here, not an omission:

- `unassigned-in-corpus` — the governing policy requires the field and no
  checked-in document assigns it. Most owner fields are this, and that is the
  finding: policy demands an owner per retention class, per credential and per
  runbook, and the corpus assigns none.
- `not-reachable-from-repository` — the value lives in a running deployment
  this clean-room repository cannot reach.
- `would-expose-private-identifier` — recording the real value would put a
  private identifier in a repository intended to be public.
- `policy-configurable-no-default` — the policy declares the value configurable
  and states no default number.

## Follow-up for the integrator

This checker is standalone by design: several items were in flight and
`plan/check.py` is a collision point, so nothing was wired into it here. The
follow-up is one call from `plan/check.py` (or a step in the `plan` workflow) to
`tools.surface_inventory.verify.main()`, which already returns a process exit
status. Until that happens the inventory is checked only when the command above
is run.
