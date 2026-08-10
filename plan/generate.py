#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Generate plan/work-graph.toml from the checked work breakdown.

The work breakdown in docs/product-plan/reference/work-breakdown.md is the
human source of truth for *what* the work is. This script derives the machine
source of truth for *order, gates, authority and licence class*.

Run `plan/check.py` after regenerating: it proves bidirectional completeness
(R0-17). A ticket cannot disappear from the graph, and a graph node cannot
exist without a breakdown entry.

    python3 plan/generate.py          # rewrite plan/work-graph.toml
    python3 plan/generate.py --stdout # print without writing
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BREAKDOWN = ROOT / "docs/product-plan/reference/work-breakdown.md"
OUT = ROOT / "plan/work-graph.toml"

# --------------------------------------------------------------------------
# Bootstrap epic. These items are defined here rather than in the breakdown
# because they concern the repository itself, not the product. Some close a
# gate in plan/gates.md; lightweight hygiene items need not.
# --------------------------------------------------------------------------
BOOT = [
    dict(
        id="BOOT-001",
        title="Executable plan integrity",
        summary=(
            "Check in the generated work graph, wire plan/check.py into CI, and "
            "fail the build on drift in either direction between the breakdown "
            "and the graph."
        ),
        depends_on=[],
        closes="GATE-BASELINE",
        allowed_paths=["plan/", ".github/workflows/"],
        status="done",
    ),
    dict(
        id="BOOT-002",
        title="Optional integration identity hardening",
        summary=(
            "Optionally create dedicated workload identities and signing for "
            "installations that choose identity-separated integration; this "
            "hardening does not block supervised or owner-configured work."
        ),
        depends_on=["BOOT-001"],
        closes="GATE-IDENTITY",
        allowed_paths=[
            ".github/", "plan/", "GOVERNANCE.md", "CONTRIBUTING.md",
            "PROVENANCE.md",
        ],
    ),
    dict(
        id="BOOT-003",
        title="Pre-publication scrub gate",
        summary=(
            "Automate the identifier scan that keeps private names out of the "
            "public tree; load protected rules without committing private "
            "values and fail CI on any reintroduction."
        ),
        depends_on=["BOOT-001"],
        closes="GATE-SCRUB",
        allowed_paths=["plan/", ".github/workflows/", "tools/scrub/"],
    ),
    dict(
        id="BOOT-004",
        title="Parity-oracle boundary",
        summary=(
            "Design and implement the process boundary that lets a private "
            "parity oracle emit bounded behavior results without emitting "
            "source, credentials or implementation text. Blocks fixture capture."
        ),
        depends_on=["BOOT-001"],
        closes="GATE-ORACLE",
        allowed_paths=["tools/oracle/", "plan/"],
    ),
    dict(
        id="BOOT-005",
        title="Lightweight licence hygiene",
        summary=(
            "Run a path-aware SPDX header check in the existing plan CI and "
            "defer dependency notices, SBOMs and boundary-move review until "
            "the first distribution contract."
        ),
        depends_on=["BOOT-001"],
        closes=None,
        allowed_paths=[
            "LICENSE-POLICY.md", "README.md", "AGENTS.md", "xtask/",
            ".github/workflows/", "plan/",
        ],
        status="done",
    ),
]

BOOT_IDS = [b["id"] for b in BOOT]

# --------------------------------------------------------------------------
# Epic-level dependency spine, transcribed from work-breakdown.md.
# Item-level dependencies are additive on top of these.
# --------------------------------------------------------------------------
EPIC_DEPS = {
    "R0": ["BOOT-001"],
    # Product work starts once the supervised development contract is proven.
    # Later R0 self-host hardening remains required only for changing its own
    # bootstrap, security and promotion boundaries.
    "R1": ["R0-18"],
    "R2": ["R1"],
    "R3": ["R2"],
    "R4": ["R3"],
    "R5": ["R4"],
    "R6": ["R4"],
    "R7": ["R5", "R6"],
    "R8A": ["R7"],
    "R8B": ["R8A"],
    "R8C": ["R8B"],
    "R8D": ["R8B"],
    "R8E": ["R8C", "R8D"],
    "R8F": ["R8B"],
    "R8G": ["R8F"],
    "R9": ["R0", "R1"],
    "R10": ["R8A", "R9"],
    "R11": ["R8B", "R10"],
    "R12": ["R11"],
    "R13": ["R8B"],
    "R14": ["R2", "R7"],
    "R15": ["R4", "R8B"],
}

# core blocks cutover; expansion and research graduate independently
TRACK = {
    **{e: "core" for e in ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                           "R8A", "R8B", "R8C", "R8D", "R8E", "R9", "R10"]},
    **{e: "expansion" for e in ["R8F", "R8G", "R11", "R12", "R13", "R14"]},
    "R15": "research",
}

# Apache-2.0 applies below sdk/ and integrations/ only (LICENSE-POLICY.md)
APACHE_EPICS = {"R8B", "R8F", "R13"}
APACHE_ITEMS = {"R11-08", "R11-09"}

ALLOWED_PATHS = {
    "R0":  ["plan/", "spikes/", ".automonique/dev/", "tools/"],
    "R1":  ["rust/crates/automonique-protocol/", "rust/crates/automonique-policy/",
            "rust/Cargo.toml", "sdk/typescript/packages/protocol/", "xtask/"],
    "R2":  ["rust/crates/automonique-runner/", "rust/crates/automonique-sandbox/",
            "rust/crates/automonique-agents/", "rust/crates/automonique-workspaces/",
            "rust/crates/automonique-artifacts/"],
    "R3":  ["rust/crates/automonique-daemon/"],
    "R4":  ["rust/crates/automonique-store/"],
    "R5":  ["rust/crates/automonique-core/", "rust/crates/automonique-fleet/",
            "rust/crates/automonique-automation/"],
    "R6":  ["rust/crates/automonique-transports/"],
    "R7":  ["rust/crates/automonique-core/", "rust/crates/automonique-context/",
            "rust/crates/automonique-memory/", "rust/crates/automonique-skills/",
            "rust/crates/automonique-tools/", "rust/crates/automonique-extensions/",
            "rust/crates/automonique-models/"],
    "R8A": ["rust/crates/automonique-daemon/", "rust/crates/automonique-web/"],
    "R8B": ["sdk/typescript/"],
    "R8C": ["apps/dashboard/"],
    "R8D": ["rust/crates/automonique-tui/", "rust/crates/automonique-cli/",
            "rust/crates/automonique/"],
    "R8E": ["tests/canary/"],
    "R8F": ["connectors/typescript/teams/", "connectors/typescript/discord/",
            "connectors/typescript/core/", "sdk/typescript/packages/connector/"],
    "R8G": ["tests/canary/"],
    "R9":  ["rust/crates/automonique-deploy-broker/", "rust/crates/automonique-sandbox/",
            "rust/crates/automonique-shell/"],
    "R10": ["xtask/", "release/", "tests/"],
    "R11": ["rust/crates/automonique-compat-api/", "sdk/typescript/packages/"],
    "R12": ["apps/", "sdk/typescript/packages/ui/", "rust/crates/automonique-tui/"],
    "R13": ["connectors/typescript/"],
    "R14": ["rust/crates/automonique-models/", "rust/crates/automonique-media/",
            "rust/crates/automonique-executors/"],
    "R15": ["rust/crates/automonique-artifacts/", "tools/eval/"],
}

# Per-item overrides where the epic default is wrong. An Apache-2.0 item may
# not carry write access to a product path; plan/check.py enforces this.
ITEM_PATHS = {
    # R0-08 and R0-16 fill in the ledgers that `plan/baseline.py` counts. The
    # epic default lease excludes docs/, so each needs write access to the one
    # ledger file its own objective is measured against — and to no other
    # document.
    "R0-08": [
        "plan/", "spikes/", ".automonique/dev/", "tools/",
        "docs/product-plan/reference/feature-parity.md",
    ],
    "R0-16": [
        "plan/", "spikes/", ".automonique/dev/", "tools/",
        "docs/product-plan/requirements/external-capability-ledger.md",
    ],
    "R0-03": [
        "spikes/foreground-lifecycle/", "plan/", ".github/workflows/plan.yml",
        ".automonique/dev/program.yaml",
    ],
    "R0-04": [
        "spikes/execution-host/", "plan/", ".automonique/dev/program.yaml",
        ".automonique/dev/objectives.json",
    ],
    "R0-17": [
        "plan/", "spikes/", ".automonique/dev/", "tools/",
        ".github/workflows/plan.yml",
    ],
    "R0-19": [
        "plan/", ".automonique/dev/", "tools/", "rust/Cargo.toml",
        "rust/Cargo.lock",
        "rust/crates/automonique-lab/", "sdk/typescript/packages/lab/",
    ],
    "R1-01": [
        "rust/crates/automonique-protocol/", "rust/crates/automonique-policy/",
        "rust/Cargo.toml", "rust/Cargo.lock", "sdk/typescript/packages/protocol/",
        "xtask/", ".github/workflows/rust.yml",
    ],
    "R1-07": [
        "rust/crates/automonique/", "rust/crates/automonique-cli/",
        "rust/crates/automonique-protocol/", "rust/crates/automonique-policy/",
        "rust/Cargo.toml", "rust/Cargo.lock",
    ],
    "R11-08": ["sdk/typescript/packages/extension/"],
    "R11-09": ["sdk/typescript/packages/ui/"],
}

# Dependencies that are architectural rather than explicitly written as a
# single "Depends on" phrase in the prose breakdown.
ITEM_DEPS = {
    "R0-05": ["R0-03"],
    "R0-18": ["R0-17"],
    "R0-19": ["R0-06", "R0-17", "R0-18"],
    "R0-21": ["R0-19"],
    "R0-20": ["R0-21"],
    "R0-22": ["R0-20", "R0-21"],
    "R1-07": ["R1-01"],
}

# Completion is written here so regeneration cannot silently reopen landed
# work. Every done item must have evidence and a gate history record.
ITEM_STATUS = {
    "R0-03": "done",
    "R0-04": "done",
    "R0-05": "done",
    "R0-06": "done",
    "R0-17": "done",
    "R0-18": "done",
    "R1-01": "done",
    "R1-02": "done",
    "R0-16": "done",
}

# Gates block a *class* of work, not the whole graph. A gate listed here must be
# closed before the item may start; plan/check.py refuses an unknown gate name.
# GATE-BASELINE is implicit on everything and is not repeated per item.
EPIC_GATES = {
    "R10": ["GATE-SCRUB"],   # publishing remains blocked until scrubbed
}
ITEM_GATES = {
    "R0-02": ["GATE-ORACLE"],         # fixture capture touches legacy behavior
    "R0-07": ["GATE-ORACLE"],
}

ITEM_RE = re.compile(r"^- \*\*(?P<id>[A-Z]+[0-9]+[A-Z]?-[0-9]+)\s+(?P<rest>.*)$")
EPIC_RE = re.compile(r"^## Epic (?P<epic>[A-Z]+[0-9]+[A-Z]?) — (?P<name>.+)$")
DEP_RE = re.compile(r"Depends on ([A-Z]+[0-9]+[A-Z]?-[0-9]+)")


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def parse_breakdown() -> tuple[list[dict], dict[str, str]]:
    items, epics, epic = [], {}, None
    for line in BREAKDOWN.read_text().splitlines():
        if m := EPIC_RE.match(line):
            epic = m.group("epic")
            epics[epic] = m.group("name")
            continue
        if m := ITEM_RE.match(line):
            rest = m.group("rest")
            # "Title:** summary"  or  "Title.**"
            if ":**" in rest:
                title, summary = rest.split(":**", 1)
            else:
                title, summary = rest.rstrip("*").rstrip("."), ""
            title = title.strip().rstrip(":")
            summary = summary.strip()
            summary = re.sub(r"\s*Depends on [A-Z0-9-]+\.\s*", " ", summary).strip()
            items.append(dict(
                id=m.group("id"),
                epic=epic,
                title=title,
                summary=summary,
                item_deps=DEP_RE.findall(rest),
            ))
    return items, epics


def build() -> str:
    items, epics = parse_breakdown()
    item_ids = {item["id"] for item in items}
    by_epic: dict[str, list[str]] = {}
    for it in items:
        by_epic.setdefault(it["epic"], []).append(it["id"])

    out: list[str] = []
    out.append("# SPDX-License-Identifier: Elastic-2.0")
    out.append("")
    out.append("# Automonique executable work graph")
    out.append("#")
    out.append("# GENERATED by plan/generate.py — do not edit by hand.")
    out.append("# Human source of truth: docs/product-plan/reference/work-breakdown.md")
    out.append("# Integrity check:        python3 plan/check.py")
    out.append("")
    out.append('schema = "automonique.work-graph/v1"')
    out.append(f"item_count = {len(BOOT) + len(items)}")
    out.append("")
    out.append("# Epics, in dependency-spine order.")
    out.append("[epics]")
    out.append('BOOT = "repository readiness gates"')
    for e in EPIC_DEPS:
        if e in epics:
            out.append(f'{e} = "{esc(epics[e])}"')
    out.append("")

    for b in BOOT:
        out.append("[[item]]")
        out.append(f'id = "{b["id"]}"')
        out.append('epic = "BOOT"')
        out.append('track = "core"')
        out.append(f'title = "{esc(b["title"])}"')
        out.append(f'summary = "{esc(b["summary"])}"')
        out.append(f"depends_on = {b['depends_on']!r}".replace("'", '"'))
        out.append('licence = "Elastic-2.0"')
        out.append(f"allowed_paths = {b['allowed_paths']!r}".replace("'", '"'))
        if b["closes"]:
            out.append(f'closes_gate = "{b["closes"]}"')
        out.append(f'status = "{b.get("status", "ready" if not b["depends_on"] else "blocked")}"')
        out.append("")

    for it in items:
        epic = it["epic"]
        deps = list(it["item_deps"]) + ITEM_DEPS.get(it["id"], [])
        # depend on the last item of each predecessor epic; item-level deps refine
        for pred in EPIC_DEPS.get(epic, []):
            if pred in by_epic and by_epic[pred]:
                deps.append(by_epic[pred][-1])
            elif pred in BOOT_IDS:
                deps.append(pred)
            elif pred in item_ids:
                deps.append(pred)
        deps = sorted(set(deps))
        licence = ("Apache-2.0" if epic in APACHE_EPICS or it["id"] in APACHE_ITEMS
                   else "Elastic-2.0")
        out.append("[[item]]")
        out.append(f'id = "{it["id"]}"')
        out.append(f'epic = "{epic}"')
        out.append(f'track = "{TRACK.get(epic, "core")}"')
        out.append(f'title = "{esc(it["title"])}"')
        if it["summary"]:
            out.append(f'summary = "{esc(it["summary"])}"')
        out.append(f"depends_on = {deps!r}".replace("'", '"'))
        out.append(f'licence = "{licence}"')
        gates = ITEM_GATES.get(it["id"], EPIC_GATES.get(epic, []))
        if gates:
            out.append(f"blocked_by_gates = {gates!r}".replace("\'", '"'))
        paths = ITEM_PATHS.get(it["id"], ALLOWED_PATHS.get(epic, []))
        out.append(f"allowed_paths = {paths!r}".replace("'", '"'))
        out.append(f'status = "{ITEM_STATUS.get(it["id"], "blocked")}"')
        out.append("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()
    # Exactly one trailing newline, identical on both paths: BOOT-001 requires
    # `--stdout` to byte-match the checked-in file.
    text = build().rstrip("\n") + "\n"
    if args.stdout:
        sys.stdout.write(text)
    else:
        OUT.write_text(text)
        n = text.count("[[item]]")
        print(f"wrote {OUT.relative_to(ROOT)} — {n} items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
