#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The landing gate. An item is done when this says so, not when an agent does.

Nothing here trusts a claim. The contract names the checks; the evidence file
must answer every one of them; the declared file list must match what actually
changed and stay inside the item's lease; and the specification-debt counters
must not have moved backwards.

    python3 plan/gate.py --item BOOT-001 \
        --summary "wire plan integrity into CI" \
        --files plan/check.py .github/workflows/plan.yml

    ... --commit      also stage exactly those files and commit with attestation
    ... --dry-run     report the verdict, record nothing

Exit code is non-zero when the gate refuses, so a loop can branch on it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import baseline as bl  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
GRAPH = ROOT / "plan/work-graph.toml"
CONTRACTS = ROOT / "plan/contracts"
EVIDENCE = ROOT / "plan/evidence"
BASELINE = ROOT / "plan/baseline.json"
HISTORY = ROOT / "plan/history.jsonl"

VERIFICATION_SECTION = re.compile(
    r"^##+ Verification contract\s*$(.*?)(?=^##+ |\Z)", re.M | re.S)

refusals: list[str] = []
notices: list[str] = []


def refuse(msg: str) -> None:
    refusals.append(msg)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout.strip()


def porcelain() -> list[str]:
    """Raw `git status --porcelain` lines.

    Never strip this: column 1 is the index status and is a space for an
    unstaged change, so stripping shifts every path left by one character.
    """
    return subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()


def _path_of(line: str) -> str:
    p = line[3:]
    if " -> " in p:                # rename: take the destination
        p = p.split(" -> ", 1)[1]
    return p.strip().strip('"')


def dirty_paths() -> list[str]:
    return [_path_of(l) for l in porcelain() if l.strip()]


def staged_deletions() -> set[str]:
    return {_path_of(l) for l in porcelain()
            if l.startswith(("D ", "AD", " D"))}


# --------------------------------------------------------------------------


def load_item(item_id: str) -> dict | None:
    with GRAPH.open("rb") as fh:
        items = tomllib.load(fh)["item"]
    for it in items:
        if it["id"] == item_id:
            it["_all"] = items
            return it
    return None


def contract_checks(item_id: str) -> list[str]:
    """Check names from the contract's Verification contract table, column 1."""
    path = CONTRACTS / f"{item_id}.md"
    if not path.exists():
        refuse(f"no contract at plan/contracts/{item_id}.md")
        return []
    m = VERIFICATION_SECTION.search(path.read_text())
    if not m:
        refuse(f"contract {item_id} has no '## Verification contract' section")
        return []
    names, seen_sep = [], False
    for line in m.group(1).splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            seen_sep = True
            continue
        if not seen_sep:          # header row
            continue
        if cells and cells[0]:
            names.append(cells[0].strip("`"))
    if not names:
        refuse(f"contract {item_id} lists no checks")
    return names


def check_readiness(it: dict) -> None:
    done = {i["id"] for i in it["_all"] if i.get("status") == "done"}
    unmet = [d for d in it["depends_on"] if d not in done]
    if unmet:
        refuse(f"{it['id']} is not ready — unmet dependencies: {', '.join(unmet)}")
    open_gates = [g for g in it.get("blocked_by_gates", [])
                  if g not in {i["closes_gate"] for i in it["_all"]
                               if i.get("status") == "done" and i.get("closes_gate")}]
    if open_gates:
        refuse(f"{it['id']} is blocked by open gate(s): {', '.join(open_gates)}")
    if it.get("status") == "done":
        refuse(f"{it['id']} is already marked done")


def check_evidence(it: dict, required: list[str]) -> dict | None:
    path = EVIDENCE / f"{it['id']}.json"
    if not path.exists():
        refuse(f"no evidence at plan/evidence/{it['id']}.json — "
               f"the contract names {len(required)} check(s) that must be answered")
        return None
    try:
        ev = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        refuse(f"evidence for {it['id']} is not valid JSON: {e}")
        return None

    if ev.get("item") != it["id"]:
        refuse(f"evidence names item {ev.get('item')!r}, expected {it['id']!r}")

    answered = {c.get("name", "").strip("`"): c for c in ev.get("checks", [])}
    for name in required:
        c = answered.get(name)
        if c is None:
            refuse(f"check {name!r} from the contract has no result in evidence")
            continue
        result = c.get("result")
        if result == "fail":
            refuse(f"check {name!r} failed")
        elif result is None:
            if not c.get("reason"):
                refuse(f"check {name!r} has a null result with no reason — "
                       f"missing evidence is null with a reason, never absent")
            else:
                notices.append(f"check {name!r} unmeasured: {c['reason']}")
        elif result != "pass":
            refuse(f"check {name!r} has unrecognized result {result!r}")

    extra = set(answered) - set(required)
    if extra:
        notices.append(f"evidence answers {len(extra)} check(s) not in the "
                       f"contract: {', '.join(sorted(extra))}")
    return ev


def check_lease(it: dict, declared: list[str]) -> list[str]:
    """Declared files must be really changed and inside the item's lease."""
    actually_dirty = set(dirty_paths())
    deletions = staged_deletions()

    unknown = [p for p in declared if p not in actually_dirty and p not in deletions]
    if unknown:
        refuse("--files names paths that are not changed: " + ", ".join(unknown))

    allowed = it.get("allowed_paths", [])
    if allowed:
        outside = [p for p in declared
                   if not any(p == a.rstrip("/") or p.startswith(a) for a in allowed)]
        if outside:
            refuse(f"{it['id']} leased {allowed} but the diff touches: "
                   + ", ".join(outside))

    undeclared = sorted(actually_dirty - set(declared))
    if undeclared:
        notices.append(f"leaving {len(undeclared)} undeclared dirty path(s) alone: "
                       + ", ".join(undeclared[:6])
                       + (" …" if len(undeclared) > 6 else ""))
    return sorted(set(declared))


def check_plan_integrity() -> None:
    r = subprocess.run([sys.executable, "plan/check.py", "--verify"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        refuse("plan integrity check failed:\n    "
               + "\n    ".join((r.stderr or r.stdout).strip().splitlines()[:6]))


def check_metric(allow_flat: str | None) -> tuple[dict, dict]:
    before = json.loads(BASELINE.read_text()) if BASELINE.exists() else None
    after = bl.snapshot()
    after["digest"] = bl.digest(after)
    if before is None:
        notices.append("no stored baseline — recording this run as the first")
        return {}, after

    b, a = before["counters"], after["counters"]
    rose = {k: (b.get(k, 0), v) for k, v in a.items() if v > b.get(k, 0)}
    fell = {k: (b[k], a.get(k, 0)) for k in b if a.get(k, 0) < b[k]}

    for k, (was, now) in rose.items():
        refuse(f"counter {k} increased: {was} -> {now}")
    if not fell and not rose:
        if allow_flat:
            notices.append(f"no counter moved; accepted because: {allow_flat}")
        else:
            refuse("no specification-debt counter decreased. Pass "
                   "--allow-no-metric-change '<reason>' if that is honest for "
                   "this item, and the reason is recorded in history.")
    return fell, after


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--item", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--allow-no-metric-change", metavar="REASON")
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    it = load_item(args.item)
    if it is None:
        print(f"FAIL: {args.item} is not in the work graph", file=sys.stderr)
        return 2

    required = contract_checks(args.item)
    check_readiness(it)
    ev = check_evidence(it, required)
    files = check_lease(it, args.files)
    check_plan_integrity()
    fell, after = check_metric(args.allow_no_metric_change)

    print(f"item     {it['id']}  {it['title']}")
    print(f"licence  {it['licence']}")
    print(f"files    {len(files)}")
    for p in files:
        print(f"           {p}")
    if fell:
        print("progress")
        for k, (was, now) in fell.items():
            print(f"           {k}: {was} -> {now}")
    print(f"debt     {after['total']}  (digest {after['digest']})")

    for n in notices:
        print(f"note:    {n}")
    for r in refusals:
        print(f"REFUSE:  {r}", file=sys.stderr)

    if refusals:
        print(f"\ngate: FAIL ({len(refusals)} refusal(s))", file=sys.stderr)
        return 1
    print("\ngate: PASS")

    if args.dry_run:
        print("(dry run — nothing recorded)")
        return 0

    head = git("rev-parse", "HEAD")
    if args.commit:
        existing = [p for p in files if (ROOT / p).exists()]
        if existing:
            git("add", "--", *existing)
        title = f"{it['epic'].lower()}({it['id']}): {args.summary}"
        # The commit-metrics contract from ai-implementation-harness.md.
        trailers = "\n".join([
            f"Automonique-Work: {it['id']}",
            "Automonique-Checks: pass",
            f"Automonique-Review: {ev.get('review', {}).get('reviewers', 0)}-pass/"
            f"{ev.get('review', {}).get('blocking_findings', 0)}-blocking",
            f"Automonique-Metrics: sha256:{after['digest']}",
        ])
        body = f"{args.summary}\n\nSpecification debt: {after['total']}.\n\n{trailers}"
        git("commit", "-m", title, "-m", body)
        head = git("rev-parse", "HEAD")
        print(f"committed {head[:10]}: {title}")

    BASELINE.write_text(json.dumps(after, indent=2) + "\n")
    with HISTORY.open("a") as fh:
        fh.write(json.dumps({
            "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "item": it["id"],
            "epic": it["epic"],
            "summary": args.summary,
            "files": files,
            "debt_total": after["total"],
            "counters": after["counters"],
            "digest": after["digest"],
            "no_metric_change_reason": args.allow_no_metric_change,
            "head": head,
        }) + "\n")
    print(f"recorded in plan/history.jsonl; baseline rolled forward to "
          f"{after['total']}")
    print(f"\nNow set status = \"done\" for {it['id']} — the gate authorized it, "
          f"nothing else may.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
