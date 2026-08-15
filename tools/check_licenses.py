#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Check the repository's path-to-SPDX licence boundary.

This is intentionally independent from the archived executable-plan checker so
ordinary product development does not need to validate roadmap state.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from collections.abc import Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_NAMES = {"Dockerfile", "Justfile", "Makefile"}
SOURCE_SUFFIXES = {
    ".bash", ".c", ".cc", ".cpp", ".css", ".go", ".graphql", ".h",
    ".hpp", ".htm", ".html", ".java", ".js", ".jsx", ".kt", ".kts",
    ".nix", ".pl", ".proto", ".ps1", ".py", ".rb", ".rego", ".rs",
    ".scala", ".sh", ".sql", ".svelte", ".svg", ".swift", ".toml",
    ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml", ".zsh",
}
SKIP_PARTS = {
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv",
    "__pycache__", "node_modules", "target", "third_party",
}
SPDX = re.compile(r"SPDX-License-Identifier:\s*([^\s*<>]+)")
APACHE_ROOTS = {"sdk", "integrations", "connectors"}
# Declared roots the owner has not yet decided the fate of. A root here is
# reported on every run and does not fail the check; a declared root that is
# *not* here and does not exist on disk does fail. Removing a name from this
# set is the one-line act that converts its notice into a failure, and is the
# last step of whichever option the memo below records.
PENDING_ROOT_DECISION = {"integrations", "connectors"}
PENDING_DECISION_MEMO = "plan/owner-decisions/2026-08-15-connector-licence-boundary.md"


def repository_paths(root: pathlib.Path = ROOT) -> list[pathlib.Path]:
    """Return tracked and unignored new files, falling back to a filesystem walk."""
    try:
        result = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "-z", "--cached",
                "--others", "--exclude-standard",
            ],
            check=True,
            capture_output=True,
        )
        candidates = [
            root / item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        ]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        candidates = sorted(root.rglob("*"))
    return [
        path
        for path in candidates
        if path.is_file()
        and not any(part in SKIP_PARTS for part in path.relative_to(root).parts)
    ]


def expected_identifier(relative: pathlib.Path) -> str:
    return "Apache-2.0" if relative.parts[0] in APACHE_ROOTS else "Elastic-2.0"


def check_declared_roots(root: pathlib.Path) -> tuple[list[str], list[str]]:
    """Every declared Apache root must be a directory that exists.

    A root that does not exist gates nothing, and a checker that silently gates
    nothing is worse than no checker: it reads as a green boundary while the
    boundary is a sentence in a document. The failure has to be about the
    declaration, because there is no file to hang it on — the whole defect is
    the absence of files.

    Returns `(problems, notices)`. A root the owner has not yet ruled on is a
    notice: it is printed on every run so it cannot be forgotten, and it does
    not fail a check nobody without owner authority can fix. Any other phantom
    root is a problem.
    """
    problems: list[str] = []
    notices: list[str] = []
    for name in sorted(APACHE_ROOTS):
        if (root / name).is_dir():
            continue
        if name in PENDING_ROOT_DECISION:
            notices.append(
                f"{name}/: declared an Apache-2.0 root but absent from the tree, so "
                f"it gates nothing. Pending an owner decision — see "
                f"{PENDING_DECISION_MEMO}"
            )
            continue
        problems.append(
            f"{name}/: declared an Apache-2.0 root but is not a directory in this "
            f"tree, so the declaration gates nothing. Create it, remove it from "
            f"APACHE_ROOTS and from the documents that quote the boundary, or "
            f"record it in PENDING_ROOT_DECISION with a decision memo."
        )
    return problems, notices


def check_paths(root: pathlib.Path, paths: Iterable[pathlib.Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        relative = path.relative_to(root)
        if path.name not in SOURCE_NAMES and path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        expected = expected_identifier(relative)
        try:
            head = "\n".join(path.read_text(errors="replace").splitlines()[:8])
        except OSError as exc:
            problems.append(f"{relative.as_posix()}: cannot read source: {exc}")
            continue
        identifiers = SPDX.findall(head)
        if not identifiers:
            problems.append(
                f"{relative.as_posix()}: missing SPDX-License-Identifier: {expected}"
            )
        elif identifiers != [expected]:
            actual = ", ".join(identifiers)
            problems.append(
                f"{relative.as_posix()}: SPDX identifier {actual}; expected {expected}"
            )
    return problems


def main() -> int:
    root_problems, notices = check_declared_roots(ROOT)
    problems = root_problems + check_paths(ROOT, repository_paths(ROOT))
    for notice in notices:
        print(f"pending: {notice}", file=sys.stderr)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(
        "ok — repository source licence boundary"
        + (f" ({len(notices)} declared root(s) pending a decision)" if notices else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
