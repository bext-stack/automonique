#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Check the R0-09 surface inventory and its derived views.

    python3 tools/surface_inventory/verify.py            # verify, write nothing
    python3 tools/surface_inventory/verify.py --write    # regenerate the views

Verification runs offline: it reads the inventory, the files it cites and the
two derived views, and touches nothing else. No network, no secret, no runtime
dependency outside the standard library.

Exit status is 0 when the inventory is valid and its derived views are current,
1 when anything is wrong, and 2 when the document cannot be read at all — so
CI, and later `plan/check.py`, can branch on it directly.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.surface_inventory import hygiene, model, render  # noqa: E402

SURFACE = ROOT / "plan/inventory/surface"
README = SURFACE / "README.md"
RESTORE = SURFACE / "restore-dependencies.json"


def write_atomic(path: pathlib.Path, payload: bytes) -> None:
    """Stage beside the target, then rename.

    A plain write is visible to a reader half-finished; a parallel run of this
    repository's checks has already been reddened once by exactly that.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", suffix=".staging", delete=False)
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        pathlib.Path(handle.name).unlink(missing_ok=True)
        raise


def derived(document: dict, source_bytes: bytes,
            surface: pathlib.Path) -> dict[pathlib.Path, bytes]:
    return {
        surface / README.name: render.render_readme(document),
        surface / RESTORE.name: render.render_restore(document, source_bytes),
    }


def label(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check(inventory: pathlib.Path, *, root: pathlib.Path,
          write: bool) -> tuple[int, list[str], list[str]]:
    """Return (exit status, findings, report lines)."""
    try:
        source_bytes = inventory.read_bytes()
        document = model.load(inventory)
    except model.InventoryError as exc:
        return 2, [str(exc)], []

    findings = model.errors(document, root)
    findings += hygiene.scan_strings(model.strings(document))
    if findings:
        return 1, findings, []

    try:
        views = derived(document, source_bytes, inventory.parent)
    except render.RenderError as exc:
        return 1, [f"derived view cannot be rendered: {exc}"], []

    for path, payload in views.items():
        findings += hygiene.scan_text(payload.decode(), label(path, root))
    if findings:
        return 1, findings, []

    stale: list[str] = []
    for path, payload in views.items():
        relative = label(path, root)
        if write:
            if not path.exists() or path.read_bytes() != payload:
                write_atomic(path, payload)
                stale.append(f"rewrote {relative}")
            continue
        if not path.exists():
            findings.append(
                f"{relative} is missing — run "
                f"`python3 tools/surface_inventory/verify.py --write`")
        elif path.read_bytes() != payload:
            findings.append(
                f"{relative} is stale: the checked-in copy differs from what the "
                f"inventory renders — run "
                f"`python3 tools/surface_inventory/verify.py --write`")

    measured = model.counts(document)
    report = [
        f"{name}: {row['entries']} entries, {row['gaps']} gaps, "
        f"{row['owner_null']} owner(s) null with a reason, "
        f"{row['withheld']} withheld fact(s), "
        f"{row['synthetic']} synthetic example(s)"
        for name, row in measured.items()
    ] + stale
    if findings:
        return 1, findings, report
    return 0, [], report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=pathlib.Path, default=model.INVENTORY)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--write", action="store_true",
                        help="regenerate the derived views atomically")
    args = parser.parse_args(argv)

    status, findings, report = check(args.inventory, root=args.root,
                                     write=args.write)
    for line in report:
        print(f"  {line}")
    for finding in findings:
        print(f"FAIL: {finding}", file=sys.stderr)
    if status:
        print(f"\nsurface inventory: FAIL ({len(findings)} finding(s))",
              file=sys.stderr)
        return status

    totals = model.counts(model.load(args.inventory))
    entries = sum(row["entries"] for row in totals.values())
    gaps = sum(row["gaps"] for row in totals.values())
    unassigned = sum(row["owner_null"] for row in totals.values())
    withheld = sum(row["withheld"] for row in totals.values())
    print(
        f"ok — {len(model.SECTION_ORDER)} sections, {entries} entries, "
        f"{gaps} recorded gaps, {unassigned} owner(s) null with a reason, "
        f"{withheld} withheld fact(s); derived views current"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
