# SPDX-License-Identifier: Elastic-2.0

"""Offline replay of the shell usage corpora into decision inputs.

Replay reads only files under `spikes/shell/observations/`. It opens no socket,
starts no process and reads no host state, so the decision inputs can be
re-derived on a machine that has never seen the system the observations came
from — which is the whole point of recording observations instead of opinions.

    python3 spikes/shell/replay.py --check    # regenerate and compare, exit 1 if stale
    python3 spikes/shell/replay.py --write    # rewrite the checked-in artifact

The generated artifact is deterministic: sorted keys, two-space indent, one
trailing newline, and frequencies rounded to three decimals. `--write` stages to
a sibling temporary file and renames it into place, so a concurrent reader sees
either the old bytes or the new ones and never a half-written file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import fixture  # noqa: E402

ROOT = fixture.ROOT
HERE = pathlib.Path(__file__).resolve().parent
OBSERVATIONS = HERE / "observations"
GENERATED = HERE / "generated" / "decision-inputs.json"


class ReplayError(Exception):
    """Replay cannot produce an unambiguous set of decision inputs."""


def corpus_paths(directory: pathlib.Path = OBSERVATIONS) -> list[pathlib.Path]:
    return sorted(directory.glob("*.json"))


def _window_days(window: dict[str, str]) -> int:
    start = dt.date.fromisoformat(window["start"])
    end = dt.date.fromisoformat(window["end"])
    return (end - start).days + 1


def _empty_slot() -> dict[str, Any]:
    return {
        "corpus_id": None,
        "count": None,
        "per_day": None,
        "capture_method": None,
        "capture_citation": None,
        "window": None,
    }


def _slot(corpus: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    window = observation["window"]
    days = _window_days(window) if window else None
    return {
        "corpus_id": corpus["corpus_id"],
        "count": observation["count"],
        "per_day": round(observation["count"] / days, 3) if days else None,
        "capture_method": observation["capture_method"],
        "capture_citation": observation["capture_citation"],
        "window": dict(window) if window else None,
    }


def build(paths: list[pathlib.Path]) -> dict[str, Any]:
    """Derive decision inputs from the observation corpora."""
    corpora = [fixture.load_corpus(path) for path in paths]

    classes: dict[str, Any] = {
        name: {
            "summary": meta["summary"],
            "source": meta["source"],
            "measured": _empty_slot(),
            "synthetic": _empty_slot(),
            "unmeasured": [],
            "sample_shapes": [],
            "resolvable": False,
            "resolvable_reason": "",
        }
        for name, meta in fixture.USAGE_CLASSES.items()
    }

    for corpus in corpora:
        for observation in corpus["observations"]:
            entry = classes[observation["class"]]
            shapes = {sample["shape"] for sample in observation["samples"]}
            entry["sample_shapes"] = sorted(set(entry["sample_shapes"]) | shapes)
            if observation["count"] is None:
                entry["unmeasured"].append(
                    {"corpus_id": corpus["corpus_id"], "kind": corpus["kind"],
                     "reason": observation["reason"]}
                )
                continue
            slot = "synthetic" if corpus["kind"] == "synthetic" else "measured"
            if entry[slot]["corpus_id"] is not None:
                raise ReplayError(
                    f"class {observation['class']} is counted by two {slot} corpora "
                    f"({entry[slot]['corpus_id']} and {corpus['corpus_id']}); merge them "
                    f"upstream rather than letting replay choose"
                )
            entry[slot] = _slot(corpus, observation)

    for name, entry in classes.items():
        entry["unmeasured"] = sorted(entry["unmeasured"], key=lambda row: row["corpus_id"])
        if entry["measured"]["count"] is not None:
            entry["resolvable"] = True
            entry["resolvable_reason"] = (
                f"measured count {entry['measured']['count']} from "
                f"{entry['measured']['corpus_id']} by {entry['measured']['capture_method']}"
            )
        else:
            synthetic = entry["synthetic"]["count"] is not None
            entry["resolvable_reason"] = (
                "no measured count for this class"
                + (
                    "; the only count is synthetic and cannot resolve anything"
                    if synthetic
                    else ""
                )
            )

    return {
        "schema": fixture.DECISION_INPUTS_SCHEMA,
        "generator": "spikes/shell/replay.py",
        "replayed_from": [
            {
                "corpus_id": corpus["corpus_id"],
                "kind": corpus["kind"],
                "path": corpus["path"],
                "sha256": corpus["sha256"],
                "captured_on": corpus["captured_on"],
                "capture_host_access": corpus["capture_host_access"],
                "counted_classes": sum(
                    1 for entry in corpus["observations"] if entry["count"] is not None
                ),
                "null_with_reason_classes": sum(
                    1 for entry in corpus["observations"] if entry["count"] is None
                ),
            }
            for corpus in sorted(corpora, key=lambda item: item["corpus_id"])
        ],
        "classes": classes,
        "totals": {
            "usage_classes": len(fixture.USAGE_CLASSES),
            "resolvable_classes": sum(1 for entry in classes.values() if entry["resolvable"]),
            "corpora": len(corpora),
        },
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_atomic(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(path.name + ".staging")
    staging.write_text(text, encoding="utf-8")
    os.replace(staging, path)


def load_decision_inputs(path: pathlib.Path = GENERATED) -> dict[str, Any]:
    """The checked-in decision inputs, with their own path and digest attached."""
    document = json.loads(path.read_text())
    if document.get("schema") != fixture.DECISION_INPUTS_SCHEMA:
        raise ReplayError(f"{path} is not {fixture.DECISION_INPUTS_SCHEMA}")
    document["path"] = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name
    document["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if the checked-in copy is stale")
    mode.add_argument("--write", action="store_true", help="regenerate the checked-in copy")
    parser.add_argument("--observations", type=pathlib.Path, default=OBSERVATIONS)
    parser.add_argument("--generated", type=pathlib.Path, default=GENERATED)
    args = parser.parse_args(argv)

    paths = corpus_paths(args.observations)
    if not paths:
        print(f"REFUSE: no observation corpus under {args.observations}", file=sys.stderr)
        return 1
    try:
        expected = render(build(paths))
    except (fixture.FixtureError, ReplayError) as exc:
        print(f"REFUSE: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.write:
        write_atomic(args.generated, expected)
        print(f"wrote {args.generated} from {len(paths)} corpus file(s)")
        return 0

    if not args.generated.exists():
        print(f"STALE: {args.generated} does not exist; run --write", file=sys.stderr)
        return 1
    actual = args.generated.read_text()
    if actual != expected:
        print(
            f"STALE: {args.generated} does not match a replay of "
            f"{len(paths)} corpus file(s); run --write and commit the result",
            file=sys.stderr,
        )
        return 1
    print(f"ok — {args.generated} matches a replay of {len(paths)} corpus file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
