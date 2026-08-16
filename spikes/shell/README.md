<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Shell decision fixture

This historical spike explored how interactive shell access and file transfer
could be measured before choosing an isolated compatibility boundary or
retirement. The old plan called it `R0-11`; that contract is not a current
development prerequisite.

**The measurement does not exist and is not simulated here.** Nothing in this
repository can reach a running instance of the predecessor system, and
`AGENTS.md` puts the private archive out of context, so there is no honest way
to produce the counts from this tree. This directory therefore delivers the
three things that *can* be delivered without a host:

1. **the fixture format and its parser** (`fixture.py`) — the shape a real
   capture must arrive in, with the dishonest variants refused at parse rather
   than discouraged in prose;
2. **the offline replay harness** (`replay.py`) — derives decision inputs from
   recorded observations, with no host access, deterministically;
3. **a decision memo** — `plan/decisions/R0-11-shell-boundary.md` and its
   machine-readable twin, which states the options per class and the evidence
   each option would need. Every class is recorded `unresolved`, and no
   measurement exists to inform a product choice.

`observations/2026-08-11-synthetic-example.json` is a worked example over
**synthetic** data. It is labelled synthetic in three independent ways — corpus
`kind`, every observation's `capture_method`, and every sample's `synthetic`
flag — and the parser refuses to let it be relabelled as capture. The replay
harness will not let a synthetic count resolve a class.

## Files

| Path | What it is |
|---|---|
| `fixture.py` | closed-vocabulary parser, sanitizer and typed refusals |
| `replay.py` | offline replay: corpora → `generated/decision-inputs.json` |
| `check_shell_decision.py` | standalone checker: corpora, staleness, decision record |
| `observations/2026-08-11-no-live-system.json` | the real corpus: six classes, all `null` with a reason |
| `observations/2026-08-11-synthetic-example.json` | worked example, synthetic throughout |
| `generated/decision-inputs.json` | generated; regenerate with `replay.py --write` |

## Commands

```sh
python3 spikes/shell/fixture.py --format                 # the closed vocabulary
python3 spikes/shell/fixture.py --validate observations/<file>.json
python3 spikes/shell/replay.py --check                   # fails when the artifact is stale
python3 spikes/shell/replay.py --write                   # regenerate it (atomic rename)
python3 spikes/shell/check_shell_decision.py             # everything above plus the decision record
python3 spikes/shell/test_shell_fixture.py               # positive and negative controls
```

The vocabulary is printed from the enums rather than restated here, because a
second copy of a closed set is a copy that drifts.

## What the format makes impossible

The point of the format is that the failures the contract's stop conditions
name cannot be spelled, not that they are asked for politely.

- **A captured command string has nowhere to go.** A sample carries a `shape`
  from a closed enum plus `placeholders` from a closed enum, and must set
  `synthetic: true`. There is no free-text command field anywhere in the
  document, so a credential, customer name or private host cannot be recorded
  by accident. A regex sanitizer over every string in the document is the
  second belt, not the first.
- **Recall has no capture method.** Only log-derived methods
  (`audit_log_query`, `session_table_count`, `artifact_service_log`,
  `process_accounting`, `reverse_proxy_access_log`) may carry a number. There
  is deliberately no `operator_interview`, because an interviewed frequency is
  recall presented as data.
- **An `unmeasured` corpus may not contain a number**, and a `measured` corpus
  may not use `synthetic_authored`. Promoting the worked example into evidence
  takes more than editing one word, and every route through is refused.
- **A class cannot go missing.** All six usage classes must appear in every
  corpus and in the decision record. Silence is the way a class defaults.
- **A boundary must say what it isolates, permits and refuses**, each as a
  statement of at least twelve characters that is not merely a reassuring
  adjective. `"sandboxed"` is refused by name.
- **A retirement without a replacement and a user path raises
  `ReplacementlessRetirement`** — the contract calls that case a finding, so it
  is an exception, not a warning.
- **An outcome other than `unresolved` requires a measured count for that
  class** in the decision inputs. With today's corpora nothing is resolvable,
  which is why the memo records six `unresolved` classes rather than six
  agreeable-sounding boundaries.

## Dropping in a real capture

When usage data exists, the capture side is the only new work:

1. produce one JSON file under `observations/` with `kind: "measured"`,
   `capture_host_access: "live-system"`, one entry per usage class, and a
   log-derived `capture_method` and window for each counted class. Sanitize at
   capture: emit shapes and placeholders, never command text;
2. `python3 spikes/shell/fixture.py --validate observations/<new>.json`;
3. `python3 spikes/shell/replay.py --write` and commit the regenerated inputs;
4. re-derive the decision: classes with measured counts become resolvable, and
   an owner may then record a `boundary` or a `retirement` for each. The
   parser will refuse an outcome whose cited count does not match the inputs.

Replay never touches the host again. That is what "the fixture replays offline
from recorded observations" buys: the decision can be re-derived and audited on
a machine that has never seen the system.

## Boundaries of this spike

It implements no shell, opens no session, opens no socket, starts no process
and grants no execution authority. It is input to the sandbox and shell
contracts and satisfies neither.

The checker is not yet wired into `plan/check.py` or a CI workflow — both are
outside this item's ownership. `check_shell_decision.py` is self-contained,
importable, and returns an exit code from `main()` so the integrator can wire
it in one line.
