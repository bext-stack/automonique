# SPDX-License-Identifier: Elastic-2.0

"""Standalone checker for the R0-11 shell decision fixture.

One command answers every mechanical question the contract asks:

* does every observation corpus parse under the closed vocabulary, with its
  sanitizer clean and every usage class present?
* is the checked-in `generated/decision-inputs.json` exactly what replaying
  those corpora produces, or is it stale?
* does the decision record cover every usage class with exactly one outcome,
  cite the decision inputs it was actually derived from, and keep every
  resolved class backed by a measured count?

    python3 spikes/shell/check_shell_decision.py            # exit 0 or 1

It is importable (`main()` returns the exit code) and depends on nothing
outside the standard library and this directory. Wiring it into `plan/check.py`
is the follow-up for the integrator; `plan/check.py` is shared by several items
and is deliberately not edited here.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import fixture  # noqa: E402
import replay  # noqa: E402

DECISION = fixture.ROOT / "plan/decisions/R0-11-shell-boundary.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--observations", type=pathlib.Path, default=replay.OBSERVATIONS)
    parser.add_argument("--generated", type=pathlib.Path, default=replay.GENERATED)
    parser.add_argument("--decision", type=pathlib.Path, default=DECISION)
    args = parser.parse_args(argv)

    failures: list[str] = []
    lines: list[str] = []

    paths = replay.corpus_paths(args.observations)
    if not paths:
        print(f"REFUSE: no observation corpus under {args.observations}", file=sys.stderr)
        return 1

    corpora = []
    for path in paths:
        try:
            corpus = fixture.load_corpus(path)
        except fixture.FixtureError as exc:
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        corpora.append(corpus)
        counted = sum(1 for entry in corpus["observations"] if entry["count"] is not None)
        lines.append(
            f"corpus   {corpus['corpus_id']:32} kind={corpus['kind']:10} "
            f"classes={len(corpus['observations'])} counted={counted} "
            f"null_with_reason={len(corpus['observations']) - counted}"
        )
    if failures:
        for failure in failures:
            print(f"REFUSE:  {failure}", file=sys.stderr)
        return 1

    try:
        expected = replay.render(replay.build(paths))
    except (fixture.FixtureError, replay.ReplayError) as exc:
        print(f"REFUSE:  replay: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if not args.generated.exists():
        print(f"REFUSE:  {args.generated} does not exist; run replay.py --write", file=sys.stderr)
        return 1
    if args.generated.read_text() != expected:
        print(
            f"REFUSE:  {args.generated} is stale — it does not match a replay of "
            f"{len(paths)} corpus file(s); run 'python3 spikes/shell/replay.py --write'",
            file=sys.stderr,
        )
        return 1
    lines.append(f"replay   {args.generated.name} matches a replay of {len(paths)} corpus file(s)")

    inputs = replay.load_decision_inputs(args.generated)
    try:
        decision = fixture.load_decision(args.decision, inputs)
    except fixture.FixtureError as exc:
        print(f"REFUSE:  {args.decision.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    tally: dict[str, int] = {outcome: 0 for outcome in fixture.OUTCOMES}
    for name in sorted(decision["classes"]):
        entry = decision["classes"][name]
        tally[entry["outcome"]] += 1
        resolvable = inputs["classes"][name]["resolvable"]
        lines.append(
            f"class    {name:28} outcome={entry['outcome']:11} "
            f"resolvable={str(resolvable).lower():5} "
            f"({inputs['classes'][name]['resolvable_reason']})"
        )

    lines.append(
        "outcomes " + ", ".join(f"{outcome}={count}" for outcome, count in tally.items())
    )
    for line in lines:
        print(line)
    print(
        f"ok — {len(fixture.USAGE_CLASSES)} usage class(es), "
        f"{inputs['totals']['resolvable_classes']} resolvable, "
        f"{tally['unresolved']} explicitly unresolved"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
