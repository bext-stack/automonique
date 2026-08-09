#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Measure specification debt — the number this repository drives to zero.

A gate that only says "the plan is internally consistent" cannot tell progress
from motion. This computes counters that are deterministic, derivable from the
tree alone, and monotonic in the direction of a finished specification.

`plan/gate.py` refuses to land work that increases any counter, which is the
important half: it is trivial to close one ledger row by opening two.

    python3 plan/baseline.py            # print counters, write plan/baseline.json
    python3 plan/baseline.py --json     # print the snapshot, write nothing
    python3 plan/baseline.py --explain  # list what each counter is counting
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
GRAPH = ROOT / "plan/work-graph.toml"
GATES = ROOT / "plan/gates.md"
CONTRACTS = ROOT / "plan/contracts"
BASELINE = ROOT / "plan/baseline.json"
BREAKDOWN = ROOT / "docs/product-plan/reference/work-breakdown.md"

CAPABILITY_LEDGER = ROOT / "docs/product-plan/requirements/external-capability-ledger.md"
PARITY_LEDGER = ROOT / "docs/product-plan/reference/feature-parity.md"

# R0-16 keys the capability ledger to these; R0-08 keys the parity ledger.
CAPABILITY_KEYS = ["capability", "adaptation", "track", "owner", "ticket", "fixture"]
PARITY_KEYS = ["capability", "owner", "decision", "fixture", "evidence"]

LINK = re.compile(r"\[[^\]]*\]\(([^)#]+?)(?:#[^)]*)?\)")
DEFINED_ID = re.compile(r"^- \*\*([A-Z]+[0-9]+[A-Z]?-[0-9]+)\s", re.M)
USED_ID = re.compile(r"\b(R[0-9]+[A-Z]?-[0-9]{2})\b")
GATE_ID = re.compile(r"^### (GATE-[A-Z-]+)", re.M)
ADVISORY_GATE = re.compile(
    r"^### (GATE-[A-Z-]+)\s+\*\*State: advisory(?:/open)?\.\*\*", re.M)


def md_files() -> list[pathlib.Path]:
    return [p for p in ROOT.rglob("*.md")
            if ".git" not in p.parts and p.parts[len(ROOT.parts):][:1] != ("LICENSES",)]


def parse_tables(path: pathlib.Path) -> list[tuple[list[str], list[list[str]]]]:
    """Return (header_cells, data_rows) for each pipe table in the file."""
    tables, header, rows, in_table = [], None, [], False
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s.startswith("|"):
            if in_table and header:
                tables.append((header, rows))
            header, rows, in_table = None, [], False
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):      # separator row
            in_table = True
            continue
        if header is None:
            header = [c.lower() for c in cells]
        else:
            rows.append(cells)
    if in_table and header:
        tables.append((header, rows))
    return tables


def ledger_debt(path: pathlib.Path, keys: list[str]) -> tuple[int, list[str]]:
    """Missing required fields across every row of every table in a ledger.

    A key absent from the header counts against every row in that table — that
    is the honest reading, since the field exists for no row. A key present but
    blank counts against its own row only.
    """
    total, detail = 0, []
    for header, rows in parse_tables(path):
        if not rows:
            continue
        present = {k: i for k in keys
                   for i, h in enumerate(header) if k in h}
        absent = [k for k in keys if k not in present]
        for row in rows:
            missing = list(absent)
            for k, i in present.items():
                if i >= len(row) or not row[i].strip():
                    missing.append(k)
            total += len(missing)
        if absent:
            detail.append(f"{path.name}: table missing column(s) "
                          f"{', '.join(absent)} across {len(rows)} row(s)")
    return total, detail


def load_items() -> list[dict]:
    with GRAPH.open("rb") as fh:
        return tomllib.load(fh)["item"]


def contracts_missing(items: list[dict]) -> tuple[int, list[str]]:
    """Items reachable in one wave that have no contract file.

    "One wave away" means every unmet dependency is itself ready now — not
    merely that one dependency is unmet. Because epics chain, almost every
    item in the graph has exactly one unmet dependency, so the looser reading
    counts the whole backlog and measures nothing.
    """
    done = {i["id"] for i in items if i.get("status") == "done"}
    ready = {i["id"] for i in items
             if i["id"] not in done
             and all(d in done for d in i["depends_on"])}
    near = ready | {i["id"] for i in items
                    if i["id"] not in done and i["id"] not in ready
                    and all(d in done or d in ready for d in i["depends_on"])}
    missing = [i for i in sorted(near) if not (CONTRACTS / f"{i}.md").exists()]
    return len(missing), [f"no contract: {i}" for i in missing[:8]]


def gates_open(items: list[dict]) -> tuple[int, list[str]]:
    text = GATES.read_text()
    known = set(GATE_ID.findall(text))
    advisory = set(ADVISORY_GATE.findall(text))
    closed = {i["closes_gate"] for i in items
              if i.get("closes_gate") and i.get("status") == "done"}
    still = sorted(known - advisory - closed)
    return len(still), [f"open: {g}" for g in still]


def links_broken() -> tuple[int, list[str]]:
    bad = []
    for p in md_files():
        for m in LINK.finditer(p.read_text()):
            t = m.group(1)
            if t.startswith(("http", "mailto:")):
                continue
            if not (p.parent / t).exists():
                bad.append(f"{p.relative_to(ROOT)} -> {t}")
    return len(bad), bad[:8]


def refs_undefined() -> tuple[int, list[str]]:
    defined = set(DEFINED_ID.findall(BREAKDOWN.read_text()))
    used: set[str] = set()
    for p in md_files():
        used |= set(USED_ID.findall(p.read_text()))
    dangling = sorted(used - defined)
    return len(dangling), [f"undefined: {d}" for d in dangling[:8]]


def evidence_missing(items: list[dict]) -> tuple[int, list[str]]:
    """An item marked done with no evidence file is a false completion claim."""
    bad = [i["id"] for i in items if i.get("status") == "done"
           and not (ROOT / "plan/evidence" / f"{i['id']}.json").exists()]
    return len(bad), [f"done without evidence: {i}" for i in bad[:8]]


def snapshot() -> dict:
    items = load_items()
    counters, detail = {}, {}

    for name, (count, why) in {
        "capability_ledger_fields_missing": ledger_debt(CAPABILITY_LEDGER, CAPABILITY_KEYS),
        "parity_ledger_fields_missing": ledger_debt(PARITY_LEDGER, PARITY_KEYS),
        "contracts_missing": contracts_missing(items),
        "gates_open": gates_open(items),
        "links_broken": links_broken(),
        "refs_undefined": refs_undefined(),
        "evidence_missing": evidence_missing(items),
    }.items():
        counters[name] = count
        if why:
            detail[name] = why

    done = sum(1 for i in items if i.get("status") == "done")
    return {
        "schema": "automonique.spec-debt/v1",
        "counters": counters,
        "total": sum(counters.values()),
        # Context, never a reward. See ai-implementation-harness.md § Baselines.
        "context": {"items": len(items), "items_done": done},
        "detail": detail,
    }


def digest(snap: dict) -> str:
    payload = json.dumps({"counters": snap["counters"]}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="print snapshot, write nothing")
    ap.add_argument("--explain", action="store_true", help="show what is being counted")
    args = ap.parse_args()

    snap = snapshot()
    snap["digest"] = digest(snap)

    if args.json:
        print(json.dumps(snap, indent=2))
        return 0

    width = max(len(k) for k in snap["counters"])
    print("specification debt")
    for k, v in snap["counters"].items():
        flag = "" if v == 0 else "  <-"
        print(f"  {k:<{width}}  {v:>5}{flag}")
    print(f"  {'TOTAL':<{width}}  {snap['total']:>5}")
    print(f"\n  items {snap['context']['items_done']}/{snap['context']['items']} done"
          f"   digest {snap['digest']}")

    if args.explain:
        print()
        for name, lines in snap["detail"].items():
            print(f"{name}:")
            for line in lines:
                print(f"  {line}")

    BASELINE.write_text(json.dumps(snap, indent=2) + "\n")
    print(f"\nwrote {BASELINE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
