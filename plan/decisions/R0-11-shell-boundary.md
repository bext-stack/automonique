<!-- SPDX-License-Identifier: Elastic-2.0 -->

# R0-11 shell and file-transfer decision memo

Status: **unresolved for all six usage classes.** No class is accepted as an
isolated compatibility boundary and no class is retired. This memo states the
options and the evidence each one needs; the choice is the owner's.

Machine-readable twin: [`R0-11-shell-boundary.json`](R0-11-shell-boundary.json),
validated by `spikes/shell/check_shell_decision.py` against
`spikes/shell/generated/decision-inputs.json` (SHA-256
`051b6a12bc5fee226ad09e54cad9708cbf86928e271338c6caae6906829fc033`).

## What was measured

Nothing. That is the finding, not an omission.

`plan/contracts/R0-11.md` asks for observed use "by class and frequency with a
cited capture method". The counts live on a running instance of the predecessor
system. This repository cannot reach one, and `AGENTS.md` puts the private
archive out of context, so there is no capture method available here that would
produce a number. Every class is therefore recorded `null` with its reason in
`spikes/shell/observations/2026-08-11-no-live-system.json`, and the fixture
refuses to hold a number in a corpus declared unmeasured.

`spikes/shell/observations/2026-08-11-synthetic-example.json` is a **synthetic**
worked example, present only to prove the format and the replay path work
end to end. It is labelled synthetic three independent ways and the replay
harness refuses to let a synthetic count resolve any class.

## Usage classes

Six, each named by a checked-in planning document, none invented here.

| Class | What it covers | Recorded outcome |
|---|---|---|
| `interactive_shell_create` | creating an interactive shell session | unresolved |
| `interactive_shell_attach` | attaching as observer or controller | unresolved |
| `interactive_shell_command` | commands run inside a session, by shape | unresolved |
| `file_upload` | bytes into a workspace | unresolved |
| `file_download` | bytes out of a workspace | unresolved |
| `inline_path_bridge` | the arbitrary host-path transfer bridge | unresolved |

## The standing plan disposition is context, not this decision

`docs/product-plan/reference/feature-parity.md` already records a plan-level
disposition for the surface as a whole: *isolate and preserve during migration;
retire only by explicit later decision*. It is cited in the JSON record with
`binds_this_record: false`, and the validator refuses any other value.

Two reasons it cannot close this item. It is one disposition for the whole
surface where `R0-11` asks for one per class — `inline_path_bridge` is on a
different trajectory from `interactive_shell_attach` and the plan says so.
And it was written from the migration's point of view rather than from observed
use, which is precisely the assumption this item exists to replace.

## The two options, and what each would cost

For every class the open options are the same. The differences are in the
evidence, which is enumerated per class in the JSON.

**Accept an isolated compatibility boundary.** Needs a measured corpus, an
`isolates` / `permits` / `refuses` triple specific enough that each refusal is
something a test can attempt and observe denied, and a named owner. Five of the
six classes carry a **draft** triple in the JSON record, marked
`accepted: false`; the validator refuses a draft that claims acceptance and
refuses a triple made of reassuring adjectives. They exist so the owner has
concrete text to accept, amend or reject rather than a blank page.

**Retire the class explicitly.** Needs a measured corpus, a replacement outcome
named as a surface that exists rather than a plan item, the steps a current user
takes to reach it, and a named owner. A retirement missing the replacement or
the user path raises `ReplacementlessRetirement` — the contract calls that case
a finding, so the fixture makes it an exception rather than a warning.

One caution that applies to every retirement here: **a low or zero count does
not by itself justify retirement.** A break-glass path is rare and still
load-bearing. The evidence lists therefore ask what breaks when the class is
gone, separately from how often it is used.

## What would change this memo

1. A `kind: "measured"` corpus lands under `spikes/shell/observations/`, with a
   log-derived capture method and window per class.
2. `python3 spikes/shell/replay.py --write` regenerates the decision inputs;
   classes with a measured count become resolvable.
3. The owner records `boundary` or `retirement` per class in the JSON twin. The
   validator refuses an outcome whose cited count does not match the inputs, so
   the decision stays bound to the measurement it was taken from.

Until then, unresolved is the honest state, and it is recorded as unresolved
rather than defaulted to either outcome.

## Scope

This memo and its fixture implement no shell, open no session and grant no
execution authority. They are input to the sandbox and shell contracts and
satisfy neither.
