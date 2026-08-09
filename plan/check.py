#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Verify plan integrity and regenerate the ready set.

This is the drift gate demanded by R0-17: a plan ticket cannot disappear from
the executable graph, and an executable node cannot exist without a plan entry.
It also refuses a graph with dangling dependencies, cycles, unknown gates, a
licence-boundary violation, or an item marked done without gate evidence.

    python3 plan/check.py            # verify, rewrite plan/ready.md
    python3 plan/check.py --verify   # verify only, write nothing (CI mode)

Exit code is non-zero on any failure, so CI can gate on it directly.
"""

from __future__ import annotations

import argparse
import pathlib
import json
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
GRAPH = ROOT / "plan/work-graph.toml"
BREAKDOWN = ROOT / "docs/product-plan/reference/work-breakdown.md"
GATES = ROOT / "plan/gates.md"
CONTRACTS = ROOT / "plan/contracts"
EVIDENCE = ROOT / "plan/evidence"
HISTORY = ROOT / "plan/history.jsonl"
READY = ROOT / "plan/ready.md"
AUTHORITY = ROOT / "plan/authority.toml"

SOURCE_NAMES = {"Dockerfile", "Justfile", "Makefile"}
SOURCE_SUFFIXES = {
    ".bash", ".c", ".cc", ".cpp", ".css", ".go", ".graphql", ".h",
    ".hpp", ".htm", ".html", ".java", ".js", ".jsx", ".kt", ".kts",
    ".nix", ".pl", ".proto", ".ps1", ".py", ".rb", ".rego", ".rs",
    ".scala", ".sh", ".sql", ".svelte", ".svg", ".swift", ".toml",
    ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml", ".zsh",
}
SKIP_SOURCE_PARTS = {
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv",
    "__pycache__", "node_modules", "target", "third_party",
}
SPDX = re.compile(r"SPDX-License-Identifier:\s*([^\s*<>]+)")

BREAKDOWN_ID = re.compile(r"^- \*\*([A-Z]+[0-9]+[A-Z]?-[0-9]+)\s", re.M)
GATE_ID = re.compile(r"^### (GATE-[A-Z-]+)", re.M)
ADVISORY_GATE = re.compile(
    r"^### (GATE-[A-Z-]+)\s+\*\*State: advisory(?:/open)?\.\*\*", re.M)

errors: list[str] = []
warnings: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def load() -> dict:
    with GRAPH.open("rb") as fh:
        return tomllib.load(fh)


def check_authority() -> None:
    """Keep bootstrap convenience from becoming protected authority."""
    if not AUTHORITY.exists():
        fail("plan/authority.toml is missing")
        return
    try:
        with AUTHORITY.open("rb") as fh:
            authority = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"plan/authority.toml cannot be read: {exc}")
        return

    if authority.get("schema") != "automonique.authority/v1":
        fail("plan/authority.toml has an unsupported schema")
    if authority.get("mode") not in {
        "owner-supervised-bootstrap", "autonomous-protected-integration"
    }:
        fail("plan/authority.toml has an unknown authority mode")

    base = authority.get("decision_base", "")
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        fail("authority decision_base must be a full lowercase Git object ID")
    decision = authority.get("decision", "")
    if not isinstance(decision, str) or not decision.startswith("plan/owner-decisions/"):
        fail("authority decision must be below plan/owner-decisions/")
    else:
        decision_path = ROOT / decision
        if not decision_path.is_file():
            fail(f"authority decision does not exist: {decision}")
        elif base and base not in decision_path.read_text():
            fail(f"authority decision {decision} does not name decision_base {base}")

    protected = [
        "push", "merge_protected_branch", "administer_repository",
        "sign_release", "publish_package", "deploy_production",
    ]
    enabled = [name for name in protected if authority.get(name) is not False]
    if enabled:
        fail("worker authority must explicitly deny: " + ", ".join(enabled))
    if authority.get("review_policy") != "owner-configurable":
        fail("review_policy must remain owner-configurable")


def check_source_licences() -> None:
    """Apply the small development-time path/SPDX invariant."""
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_SOURCE_PARTS for part in relative.parts):
            continue
        if path.name not in SOURCE_NAMES and path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        expected = (
            "Apache-2.0"
            if relative.parts[0] in {"sdk", "integrations", "connectors"}
            else "Elastic-2.0"
        )
        head = "\n".join(path.read_text(errors="replace").splitlines()[:8])
        identifiers = SPDX.findall(head)
        label = relative.as_posix()
        if not identifiers:
            fail(f"{label} is missing SPDX-License-Identifier: {expected}")
        elif identifiers != [expected]:
            actual = ", ".join(identifiers)
            fail(f"{label} has SPDX identifier {actual}; expected {expected} from its path")


def check_bidirectional(items: list[dict]) -> None:
    """R0-17: neither direction may drift."""
    graph_ids = {i["id"] for i in items if i["epic"] != "BOOT"}
    plan_ids = set(BREAKDOWN_ID.findall(BREAKDOWN.read_text()))

    for missing in sorted(plan_ids - graph_ids):
        fail(f"ticket {missing} is in the work breakdown but not in the graph")
    for invented in sorted(graph_ids - plan_ids):
        fail(f"node {invented} is in the graph but not in the work breakdown")


def check_deps(items: list[dict]) -> None:
    ids = {i["id"] for i in items}
    for it in items:
        for d in it["depends_on"]:
            if d not in ids:
                fail(f"{it['id']} depends on unknown item {d}")
            if d == it["id"]:
                fail(f"{it['id']} depends on itself")


def check_cycles(items: list[dict]) -> None:
    deps = {i["id"]: list(i["depends_on"]) for i in items}
    WHITE, GREY, BLACK = 0, 1, 2
    colour = dict.fromkeys(deps, WHITE)

    def visit(node: str, trail: list[str]) -> None:
        colour[node] = GREY
        for nxt in deps.get(node, []):
            if nxt not in colour:
                continue
            if colour[nxt] == GREY:
                cyc = " -> ".join(trail[trail.index(nxt):] + [nxt]) if nxt in trail \
                      else f"{node} -> {nxt}"
                fail(f"dependency cycle: {cyc}")
            elif colour[nxt] == WHITE:
                visit(nxt, trail + [nxt])
        colour[node] = BLACK

    sys.setrecursionlimit(10000)
    for node in deps:
        if colour[node] == WHITE:
            visit(node, [node])


def check_gates(items: list[dict]) -> set[str]:
    if not GATES.exists():
        fail("plan/gates.md is missing")
        return set()
    gate_text = GATES.read_text()
    known = set(GATE_ID.findall(gate_text))
    advisory = set(ADVISORY_GATE.findall(gate_text))
    for it in items:
        g = it.get("closes_gate")
        if g and g not in known:
            fail(f"{it['id']} closes unknown gate {g}")
        for b in it.get("blocked_by_gates", []):
            if b not in known:
                fail(f"{it['id']} is blocked by unknown gate {b}")
            if b in advisory:
                fail(f"{it['id']} is blocked by advisory {b}")
            if b == g:
                fail(f"{it['id']} closes the same gate that blocks it: {b}")
    closed = {it["closes_gate"] for it in items
              if it.get("closes_gate") and it.get("status") == "done"}
    for g in sorted(known - advisory - {i.get("closes_gate") for i in items}):
        warnings.append(f"gate {g} has no item that closes it")
    return closed


def check_licence(items: list[dict]) -> None:
    """LICENSE-POLICY.md: Apache-2.0 only below sdk/ and integrations/."""
    for it in items:
        apache = it["licence"] == "Apache-2.0"
        paths = it["allowed_paths"]
        if apache and paths and not all(
            p.startswith(("sdk/", "integrations/", "connectors/")) for p in paths
        ):
            fail(f"{it['id']} is Apache-2.0 but writes outside the SDK boundary: {paths}")
        if not apache and paths and all(p.startswith("sdk/") for p in paths):
            warnings.append(f"{it['id']} is Elastic-2.0 but only writes under sdk/")


def compute_ready(items: list[dict], closed_gates: set[str]) -> list[dict]:
    """Ready = dependencies done, blocking gates closed, and a contract written.

    The contract requirement is part of readiness rather than an integrity
    error. An item whose dependencies are satisfied but which nobody has
    specified is not workable: an agent handed it would invent the objective,
    the lease and the checks. Treating that as "ready but broken" would make
    the graph fail the moment any epic unblocks, which is backwards — the
    contract backlog is normal, and `contracts_missing` measures it.

    GATE-BASELINE is implicit on every item: while it is open, only the item
    that closes it is selectable.
    """
    done = {i["id"] for i in items if i.get("status") == "done"}
    baseline_open = "GATE-BASELINE" not in closed_gates
    ready = []
    for it in items:
        if it.get("status") == "done":
            continue
        if not all(d in done for d in it["depends_on"]):
            continue
        if any(g not in closed_gates for g in it.get("blocked_by_gates", [])):
            continue
        if baseline_open and it.get("closes_gate") != "GATE-BASELINE":
            continue
        if not (CONTRACTS / f"{it['id']}.md").exists():
            continue
        ready.append(it)
    return ready


def unblocked_without_contract(items: list[dict], closed_gates: set[str]) -> list[str]:
    """Dependency- and gate-clear, but unspecified. The contract-writing queue."""
    done = {i["id"] for i in items if i.get("status") == "done"}
    baseline_open = "GATE-BASELINE" not in closed_gates
    out = []
    for it in items:
        if it.get("status") == "done":
            continue
        if not all(d in done for d in it["depends_on"]):
            continue
        if any(g not in closed_gates for g in it.get("blocked_by_gates", [])):
            continue
        if baseline_open and it.get("closes_gate") != "GATE-BASELINE":
            continue
        if not (CONTRACTS / f"{it['id']}.md").exists():
            out.append(it["id"])
    return out


def check_evidence(items: list[dict]) -> None:
    """`done` is a gate verdict, not an edit.

    Marking an item done unblocks everything behind it, so a done item with no
    gate-recorded evidence is treated as an integrity failure rather than a
    missing nicety. plan/gate.py writes the evidence; nothing else should.
    """
    for it in items:
        if it.get("status") != "done":
            continue
        ev = EVIDENCE / f"{it['id']}.json"
        if not ev.exists():
            fail(f"{it['id']} is marked done but has no evidence at "
                 f"plan/evidence/{it['id']}.json — only plan/gate.py may "
                 f"authorize a completion")
    if HISTORY.exists():
        landed = {json.loads(l)["item"] for l in HISTORY.read_text().splitlines() if l.strip()}
        done = {i["id"] for i in items if i.get("status") == "done"}
        for orphan in sorted(done - landed):
            warnings.append(f"{orphan} is done but never passed through the gate")


def write_ready(items: list[dict], ready: list[dict],
                unspecified: list[str]) -> None:
    done = sum(1 for i in items if i.get("status") == "done")
    lines = [
        "# Ready set",
        "",
        "GENERATED by `plan/check.py` — do not edit by hand.",
        "",
        "An item is ready when every dependency is `done`. Selecting work means "
        "taking a ready ID, reading its contract, and refusing it if any gate it "
        "depends on is still open.",
        "",
        f"- items total: **{len(items)}**",
        f"- done: **{done}**",
        f"- ready now: **{len(ready)}**",
        f"- blocked: **{len(items) - done - len(ready)}**",
        "",
        "## Selectable now",
        "",
        "| ID | Epic | Title | Licence | Contract |",
        "|---|---|---|---|---|",
    ]
    for it in sorted(ready, key=lambda i: i["id"]):
        c = f"[contract](contracts/{it['id']}.md)" \
            if (CONTRACTS / f"{it['id']}.md").exists() else "— missing —"
        lines.append(
            f"| `{it['id']}` | {it['epic']} | {it['title']} | {it['licence']} | {c} |"
        )
    lines += [
        "",
        "## Next to unblock",
        "",
        "The first blocked items behind the current ready set:",
        "",
    ]
    done_ids = {i["id"] for i in items if i.get("status") == "done"}
    ready_ids = {i["id"] for i in ready}
    nxt = [i for i in items if i["id"] not in ready_ids and i["id"] not in done_ids]
    for it in sorted(nxt, key=lambda i: i["id"])[:10]:
        blockers = [f"`{d}`" for d in it["depends_on"] if d not in done_ids]
        blockers += [f"gate `{g}`" for g in it.get("blocked_by_gates", [])]
        if not blockers and not (CONTRACTS / f"{it['id']}.md").exists():
            blockers.append("contract")
        lines.append(f"- `{it['id']}` {it['title']} — waits on "
                     + ", ".join(blockers[:4])
                     + (" …" if len(blockers) > 4 else ""))

    if unspecified:
        lines += ["", "## Unblocked but unspecified", "",
                  "Dependency- and gate-clear, but no contract exists, so they are "
                  "not selectable. Writing one of these contracts is itself useful "
                  "work and lowers `contracts_missing`.", "",
                  "  " + ", ".join(f"`{i}`" for i in unspecified[:24])
                  + (f" …and {len(unspecified) - 24} more" if len(unspecified) > 24 else "")]

    gated = [i for i in items if i.get("blocked_by_gates")]
    if gated:
        lines += ["", "## Gate-blocked work", "",
                  "Items that a gate holds back independently of their "
                  "dependencies:", "",
                  "| Gate | Items |", "|---|---|"]
        by_gate: dict[str, list[str]] = {}
        for it in gated:
            for g in it["blocked_by_gates"]:
                by_gate.setdefault(g, []).append(it["id"])
        for g in sorted(by_gate):
            ids = sorted(by_gate[g])
            shown = ", ".join(f"`{i}`" for i in ids[:6])
            more = f" …and {len(ids) - 6} more" if len(ids) > 6 else ""
            lines.append(f"| [`{g}`](gates.md#{g.lower()}) | {shown}{more} |")

    READY.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="verify only; do not rewrite ready.md")
    args = ap.parse_args()

    if not GRAPH.exists():
        print("plan/work-graph.toml is missing — run plan/generate.py", file=sys.stderr)
        return 2

    data = load()
    items = data["item"]

    check_authority()
    check_source_licences()

    if data.get("item_count") != len(items):
        fail(f"item_count says {data.get('item_count')} but the file has {len(items)}")

    check_bidirectional(items)
    check_deps(items)
    check_cycles(items)
    closed = check_gates(items)
    check_licence(items)
    ready = compute_ready(items, closed)
    unspecified = unblocked_without_contract(items, closed)
    check_evidence(items)

    for w in warnings:
        print(f"warn: {w}")
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)

    if errors:
        print(f"\n{len(errors)} integrity failure(s)", file=sys.stderr)
        return 1

    if not args.verify:
        write_ready(items, ready, unspecified)
        print(f"ok — {len(items)} items, {len(ready)} ready, "
              f"{len(unspecified)} unblocked-but-unspecified; wrote plan/ready.md")
    else:
        print(f"ok — {len(items)} items, {len(ready)} ready, "
              f"{len(unspecified)} unblocked-but-unspecified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
