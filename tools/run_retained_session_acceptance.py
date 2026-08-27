#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Run the deterministic, non-live preparation checks for issue #169."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SCHEMA = "automonique.retained-session-acceptance-report/v1"


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
    completed = subprocess.run(command, cwd=check.root, env=environment, check=False)
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
            "Run deterministic cross-client retained-session preparation. "
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

    checks = [
        Check(
            name="authority_three_scoped_clients",
            root=roots["automonique"] / "rust",
            command=(
                "cargo",
                "test",
                "-p",
                "automonique-daemon",
                "--test",
                "retained_session_acceptance",
            ),
            marker_path="crates/automonique-daemon/tests/retained_session_acceptance.rs",
            marker="one_retained_session_survives_three_scoped_clients_ambiguity_and_reconnect",
        ),
        Check(
            name="hosted_retained_session_cockpit",
            root=roots["hosted"] / "rust",
            command=(
                "cargo",
                "test",
                "-p",
                "automonique-web-entry",
                "retained_session_cockpit_preserves_fences_resync_and_ambiguous_receipts",
            ),
            marker_path="crates/automonique-web-entry/src/lib.rs",
            marker="retained_session_cockpit_preserves_fences_resync_and_ambiguous_receipts",
        ),
        Check(
            name="mobile_server_allowlist",
            root=roots["hosted"] / "rust",
            command=(
                "cargo",
                "test",
                "-p",
                "automonique-web-entry",
                "mobile_auth::tests::platform_policy_is_per_action_per_session_and_fail_closed",
            ),
            marker_path="crates/automonique-web-entry/src/mobile_auth.rs",
            marker="platform_policy_is_per_action_per_session_and_fail_closed",
        ),
        Check(
            name="shelldeck_retained_session_contract",
            root=roots["shelldeck"],
            command=(
                "cargo",
                "test",
                "-p",
                "shelldeck-core",
                "config::platform::tests",
            ),
            marker_path="crates/shelldeck-core/src/config/platform.rs",
            marker="sdtest_1728_ambiguous_follow_up_reconciles_without_replaying_text",
            environment=(("PKG_CONFIG_PATH", "/usr/lib/x86_64-linux-gnu/pkgconfig"),),
        ),
        Check(
            name="mobile_retained_session_contract",
            root=roots["mobile"],
            command=(
                "npm",
                "test",
                "--",
                "--runTestsByPath",
                "src/core/sdk-gateway.test.ts",
                "src/core/reconciliation.test.ts",
                "src/core/projection.test.ts",
                "src/core/vertical-slice.test.ts",
                "src/providers/mobile-provider.test.tsx",
            ),
            marker_path="src/core/sdk-gateway.test.ts",
            marker="retention expiry becomes a typed resync with no partial page",
        ),
    ]
    results = [run(check) for check in checks]
    clean = all(not bool(source["dirty"]) for source in sources.values())
    passed = clean and all(result["state"] == "passed" for result in results)
    report = {
        "schema": SCHEMA,
        "mode": "deterministic_fixture_only",
        "passed": passed,
        "sources": sources,
        "checks": results,
        "live_verification": {
            "state": "required_not_run",
            "reason": (
                "Issue #169 requires an authorized non-production session and visual GUI "
                "verification on ShellDeck, monique.1clic.pro, and Automonique Mobile."
            ),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
