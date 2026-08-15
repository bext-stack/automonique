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
# `sdk/` is the only Apache-2.0 root, decided 2026-08-15 — see
# plan/owner-decisions/2026-08-15-connector-licence-boundary.md. This also
# declared `integrations/` and `connectors/`, neither of which ever existed on
# disk, so those two gated nothing; the connectors shipped as Elastic-2.0
# daemon-internal crates under rust/crates/ and stay there.
APACHE_ROOTS = {"sdk"}


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


def check_declared_roots(root: pathlib.Path) -> list[str]:
    """Every declared Apache root must be a directory that exists.

    A root that does not exist gates nothing, and a checker that silently gates
    nothing is worse than no checker: it reads as a green boundary while the
    boundary is a sentence in a document. The failure has to be about the
    declaration, because there is no file to hang it on — the whole defect is
    the absence of files.
    """
    return [
        f"{name}/: declared an Apache-2.0 root but is not a directory in this "
        f"tree, so the declaration gates nothing. Create it, or remove it from "
        f"APACHE_ROOTS and from the documents that quote the boundary."
        for name in sorted(APACHE_ROOTS)
        if not (root / name).is_dir()
    ]


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
    problems = check_declared_roots(ROOT) + check_paths(ROOT, repository_paths(ROOT))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(
        f"ok — repository source licence boundary "
        f"({len(APACHE_ROOTS)} Apache-2.0 root(s), all present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
