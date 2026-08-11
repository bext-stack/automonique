# Identifier inventory (`R0-13`)

`identifiers.json` is generated. Edit
[`tools/identifiers/inventory.py`](../../tools/identifiers/inventory.py), not
this directory.

```sh
python3 tools/identifiers/inventory.py generate   # rewrite identifiers.json
python3 tools/identifiers/inventory.py verify     # check it, write nothing
python3 tools/identifiers/test_inventory.py       # 40 tests, incl. negative controls
```

`verify` exits non-zero on any divergence between the checked-in file and what
the permitted `docs/product-plan/` corpus derives, in either direction. Wiring
it into `plan/check.py` is a follow-up for the integrator; the module is
self-contained and has its own `main()` returning an exit code so that wiring is
one call.

## What it says

Every entry carries a `name`, one `kind` from a closed set of seven, one `class`
from a closed set of three, a `spelling_form`, and a `source` naming the region
that derived it, the permitted files it occurs in and the evidence literal that
must still occur in each of them.

| Field | Meaning |
|---|---|
| `entries` | classified names: `durable`, `compatibility-only` or `presentation-only` |
| `unclassified` | names that fit no class, listed with the reason rather than absorbed |
| `out_of_scope` | names the corpus spells that fit none of the seven kinds |
| `withheld` | names accounted for by fingerprint because they may not be written here |
| `families` | one declared pattern per absorbed group, with everything it absorbed listed |
| `regions` | the ten deterministic parses the entries are derived from, with counts |
| `gaps` | what this inventory does not reach, named rather than implied |

Every `compatibility-only` entry names the durable identifier it forwards to,
the reason the compatibility surface exists, and the permitted source that binds
the two. A forward with no durable counterpart is refused at generation, so a
dangling forward cannot be checked in.

## What consumes it

`R1-17` and `R1-19` are named in the `consumers` object of the generated file,
which states the exact comparison each should run. In short:

- **`R1-17`** — `durable_names` is the sorted set of durable names;
  `compatibility_forwards` maps each compatibility-only name to
  `{"forwards_to": …, "also": […]}`. Every `CanonicalName` spelling in
  `rust/crates/automonique-protocol/src/compat/generated.rs` must be in
  `durable_names`, and every `LegacyName` spelling must appear in
  `compatibility_forwards` with its canonical spelling equal to `forwards_to` or
  present in `also`. `ConsumerContract` in `tools/identifiers/test_inventory.py`
  already runs exactly that comparison against the checked-in registry.
- **`R1-19`** — `legacy_exceptions` is the namespace gate's exception set: one
  row per compatibility-only entry whose first segment is the compatibility
  namespace root, with its kind, its forwarding target and the permitted source
  that authorized it.

The inventory derives its names from `docs/product-plan/` and never reads the
Rust registry, so the comparison is between two independently sourced lists
rather than a fixture restating the thing it checks.

## What it is not

It renames nothing, generates no compatibility codec, and closes no gate. It
records names and their classes, and says plainly where the corpus does not let
it decide.
