#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Record cross-client attention parity against the shared succession corpus.

`automonique.platform/attention/v1` is `atomic_replace`, so no single snapshot
decides what a client must conclude after a sequence of reads. The shared corpus
fixes that sequence; this harness runs each surface's replay of it and emits one
signed-off report naming the exact revision of every repository it ran against.

It is deterministic and offline. It never performs the authorized live GUI
acceptance flow, and it says so in the report rather than implying coverage it
does not have.

The report is the only thing written to stdout; every child's output goes to
stderr, so `run_attention_parity_acceptance.py ... > report.json` produces a
file that parses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SCHEMA = "automonique.attention-parity-acceptance-report/v1"
CORPUS_RELATIVE = (
    "rust/crates/automonique-protocol/fixtures/platform-v2-attention-conformance-v1.json"
)
SHELLDECK_CORPUS_RELATIVE = (
    "crates/shelldeck-core/tests/fixtures/platform-v2-attention-conformance-v1.json"
)


@dataclass(frozen=True)
class Check:
    name: str
    root: Path
    command: tuple[str, ...]
    marker_path: str
    marker: str
    environment: tuple[tuple[str, str], ...] = ()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip()


def repository(root: Path) -> dict[str, object]:
    return {
        "path": str(root),
        "revision": git(root, "rev-parse", "HEAD"),
        "dirty": bool(git(root, "status", "--porcelain")),
    }


def digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def has_marker(check: Check) -> bool:
    path = check.root / check.marker_path
    try:
        return check.marker in path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False


def run(check: Check) -> dict[str, object]:
    command = list(check.command)
    result: dict[str, object] = {
        "name": check.name,
        "command": command,
        "cwd": str(check.root),
    }
    if not has_marker(check):
        result.update(
            {
                "state": "blocked",
                "reason": f"required fixture marker absent: {check.marker_path}",
            }
        )
        return result
    environment = os.environ.copy()
    environment.update(dict(check.environment))
    # The report is the only thing on stdout, so `> report.json` yields a file a
    # reader can parse. Child output still streams live, on stderr.
    completed = subprocess.run(
        command,
        cwd=check.root,
        env=environment,
        check=False,
        stdout=sys.stderr,
    )
    result.update(
        {
            "state": "passed" if completed.returncode == 0 else "failed",
            "exit_code": completed.returncode,
        }
    )
    return result


def parse_args() -> argparse.Namespace:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Run the deterministic cross-client attention succession parity checks. "
            "This never performs the authorized live GUI acceptance flow."
        )
    )
    parser.add_argument("--automonique-root", type=Path, default=script_root)
    parser.add_argument("--hosted-root", type=Path, required=True)
    parser.add_argument("--shelldeck-root", type=Path, required=True)
    parser.add_argument("--mobile-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = {
        "automonique": args.automonique_root.resolve(),
        "hosted": args.hosted_root.resolve(),
        "shelldeck": args.shelldeck_root.resolve(),
        "mobile": args.mobile_root.resolve(),
    }
    try:
        sources = {name: repository(root) for name, root in roots.items()}
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"acceptance preflight failed: {error}", file=sys.stderr)
        return 2

    # A replay only proves parity while every surface reads the same bytes.
    canonical = digest(roots["automonique"] / CORPUS_RELATIVE)
    vendored = {
        "shelldeck": digest(roots["shelldeck"] / SHELLDECK_CORPUS_RELATIVE),
    }
    corpus = {
        "path": CORPUS_RELATIVE,
        "sha256": canonical,
        "vendored": vendored,
        "identical": canonical is not None
        and all(value == canonical for value in vendored.values()),
        # Mobile has no checked-in copy: it reads the corpus through the
        # vendored SDK archive. `sdk_exports_the_same_corpus` is what holds that
        # export to this file, so the mobile replay is anchored to the same
        # bytes without a second copy to keep in step.
        "mobile_source": "vendored @automonique/sdk testing export",
    }

    checks = [
        Check(
            name="contract_owns_both_replacement_lanes",
            root=roots["automonique"] / "rust",
            command=(
                "cargo",
                "test",
                "-p",
                "automonique-protocol",
                "--test",
                "attention_conformance",
            ),
            marker_path="crates/automonique-protocol/tests/attention_conformance.rs",
            marker="the_baseline_lane_admits_a_bridged_gap_a_successor_lane_refuses",
        ),
        Check(
            name="sdk_exports_the_same_corpus",
            root=roots["automonique"] / "sdk/typescript/packages/sdk",
            command=("npm", "test", "--", "test/attention-conformance.test.ts"),
            marker_path="src/attention-conformance.ts",
            marker="createAttentionConformanceCorpus",
        ),
        Check(
            name="hosted_projection_refuses_partial_aggregation",
            root=roots["hosted"] / "rust",
            command=(
                "cargo",
                "test",
                "-p",
                "automonique-web-entry",
                "retention_gap_or_source_refusal_discards_partial_attention_aggregation",
            ),
            marker_path="crates/automonique-web-entry/src/platform_cockpit.rs",
            marker="retention_gap_or_source_refusal_discards_partial_attention_aggregation",
        ),
        Check(
            name="shelldeck_replays_the_corpus",
            root=roots["shelldeck"],
            command=(
                "cargo",
                "test",
                "-p",
                "shelldeck-core",
                "config::platform_attention::tests::sdtest_1842_shared_attention_corpus_replays_to_the_recorded_outcomes",
            ),
            marker_path="crates/shelldeck-core/src/config/platform_attention.rs",
            marker="sdtest_1842_shared_attention_corpus_replays_to_the_recorded_outcomes",
            environment=(("PKG_CONFIG_PATH", "/usr/lib/x86_64-linux-gnu/pkgconfig"),),
        ),
        Check(
            name="mobile_replays_the_corpus",
            root=roots["mobile"],
            command=(
                "npm",
                "test",
                "--",
                "--runTestsByPath",
                "src/core/attention-source-corpus.test.ts",
            ),
            marker_path="src/core/attention-source-corpus.test.ts",
            marker="replays %s to the recorded outcome",
        ),
    ]

    results = [run(check) for check in checks]
    clean = all(not bool(source["dirty"]) for source in sources.values())
    passed = (
        clean
        and bool(corpus["identical"])
        and all(result["state"] == "passed" for result in results)
    )
    report = {
        "schema": SCHEMA,
        "mode": "deterministic_fixture_only",
        "passed": passed,
        "sources": sources,
        "corpus": corpus,
        "checks": results,
        "known_asymmetry": {
            "hosted": (
                "monique.1clic.pro reads attention snapshots fresh per request and "
                "retains nothing across them, so the corpus's retention-gap and "
                "availability-restoration cases cannot apply to it. Its parity is over "
                "the projection, not the succession, and it is checked as such."
            )
        },
        "live_verification": {
            "state": "required_not_run",
            "reason": (
                "Closing the epic requires the authorized cross-client live acceptance "
                "flow on deployed ShellDeck, monique.1clic.pro, and Automonique Mobile "
                "builds. This harness only proves the deterministic corpus parity."
            ),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
