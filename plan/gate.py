#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The landing gate. An item is done when this says so, not when an agent does.

Nothing here trusts a claim. The contract names the checks; the evidence file
must answer every one of them; the declared file list must match what actually
changed and stay inside the item's lease; and the specification-debt counters
must not have moved backwards.

    python3 plan/gate.py --item BOOT-001 \
        --summary "wire plan integrity into CI" \
        --files plan/check.py .github/workflows/plan.yml \
        --dry-run

    ... --dry-run     run the complete-contract preflight and record nothing
    ... --partial     run a non-completion preflight and record nothing

A completion is a transaction containing the implementation, evidence, metric
baseline, history record, done status and regenerated plan artifacts in one
tree.  ``--dry-run`` judges exactly that tree: the item's implementation lease
plus the completion artifacts, with the done flip still uncommitted at HEAD.

``--commit`` refuses by design and is not a gap.  This gate verifies; it does
not hold Git authority.  ``python3 tools/harness_loop.py complete`` runs this
preflight and then commits the verified tree through the typed broker.

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

# A completion transaction must carry its own evidence, measured baseline,
# history record, done status and regenerated artifacts. Those paths are part
# of every completion by construction, so leasing them per item would only
# duplicate the same list 375 times. They are permitted *in addition to* the
# item's implementation lease, and only in a completion preflight.
COMPLETION_ARTIFACTS = (
    "plan/generate.py",
    "plan/work-graph.toml",
    "plan/ready.md",
    "plan/baseline.json",
    "plan/history.jsonl",
    ".automonique/dev/program.yaml",
    ".automonique/dev/objectives.json",
)


# The machinery that judges and performs a completion. A candidate must never
# change these in the same transaction that completes it, even when its lease
# happens to cover them: the tree would then be judged by rules it wrote itself.
# Change them first, in their own commit, judged by the policy already in place.
COMPLETION_FORBIDDEN = (
    "plan/gate.py",
    "plan/baseline.py",
    "plan/check.py",
    "plan/selftest.py",
    "plan/authority.toml",
    "tools/harness_loop.py",
    "tools/git_broker.py",
    "tools/local_integration.py",
    "AGENTS.md",
)


def completion_paths(item_id: str) -> tuple[str, ...]:
    """Paths a completion transaction for `item_id` may touch beyond its lease.

    The evidence path is item-scoped on purpose: a completion may write its own
    evidence and no other item's.
    """
    return (f"plan/evidence/{item_id}.json", *COMPLETION_ARTIFACTS)

refusals: list[str] = []
notices: list[str] = []
FULL_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def refuse(msg: str) -> None:
    refusals.append(msg)


def reset_diagnostics() -> None:
    refusals.clear()
    notices.clear()


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


def item_at_head(item_id: str) -> dict | None:
    """The item as the committed graph records it, or None if unreadable."""
    try:
        committed = git("show", "HEAD:plan/work-graph.toml")
    except subprocess.CalledProcessError:
        return None
    try:
        items = tomllib.loads(committed)["item"]
    except (tomllib.TOMLDecodeError, KeyError):
        return None
    for entry in items:
        if entry.get("id") == item_id:
            return entry
    return None


def status_at_head(item_id: str) -> str | None:
    """The item's status in the committed graph, or None if unreadable."""
    entry = item_at_head(item_id)
    return entry.get("status") if entry else None


def lease_at_head(item_id: str) -> list[str] | None:
    """The item's lease as the committed graph records it.

    Read from HEAD, never the working tree: the graph is generated, so a
    candidate that edits `plan/generate.py` could otherwise widen its own lease
    and be judged against the wider one in the same transaction. Widening a
    lease is legitimate work — it just has to land first, judged on its own.
    """
    entry = item_at_head(item_id)
    if entry is None:
        return None
    paths = entry.get("allowed_paths")
    return list(paths) if isinstance(paths, list) else None


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
        # A completion transaction contains its own status flip, so the working
        # tree legitimately reads `done` while the gate judges it. Only a status
        # that was already committed means the item is genuinely finished.
        if status_at_head(it["id"]) == "done":
            refuse(f"{it['id']} is already marked done")
        else:
            notices.append(
                f"{it['id']} is flipped to done by this transaction; "
                f"HEAD still records it unfinished"
            )


def check_evidence(
    it: dict, required: list[str], *, completion: bool = True
) -> dict | None:
    path = EVIDENCE / f"{it['id']}.json"
    if not path.exists():
        message = (
            f"no evidence at plan/evidence/{it['id']}.json — "
            f"the contract names {len(required)} check(s) that must be answered"
        )
        if completion:
            refuse(message)
        else:
            notices.append(message + "; partial preflight cannot authorize completion")
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
            message = f"check {name!r} failed"
            if completion:
                refuse(message)
            else:
                notices.append(message + "; partial preflight only")
        elif result is None:
            reason = c.get("reason")
            if not reason:
                refuse(f"check {name!r} has a null result with no reason — "
                       f"missing evidence is null with a reason, never absent")
            elif completion:
                refuse(
                    f"check {name!r} is unmeasured and cannot authorize completion: "
                    f"{reason}"
                )
            else:
                notices.append(
                    f"check {name!r} unmeasured: {reason}; partial preflight only"
                )
        elif result != "pass":
            message = f"check {name!r} has unrecognized result {result!r}"
            if completion:
                refuse(message)
            else:
                notices.append(message + "; partial preflight only")

    extra = set(answered) - set(required)
    if extra:
        notices.append(f"evidence answers {len(extra)} check(s) not in the "
                       f"contract: {', '.join(sorted(extra))}")

    review = ev.get("review")
    if not isinstance(review, dict):
        refuse("evidence review record is missing or not an object")
    else:
        for field in ("reviewers", "blocking_findings"):
            value = review.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                refuse(f"evidence review {field} must be a non-negative integer")
        blocking = review.get("blocking_findings")
        if isinstance(blocking, int) and not isinstance(blocking, bool) and blocking > 0:
            message = f"evidence has {blocking} unresolved blocking review finding(s)"
            if completion:
                refuse(message)
            else:
                notices.append(message + "; partial preflight only")
    return ev


def attestation_trailers(it: dict, ev: dict, after: dict) -> list[str]:
    """Return completion trailers only for a fully measured preflight."""

    digest = after.get("digest")
    if not isinstance(digest, str) or not FULL_SHA256.fullmatch(digest):
        raise ValueError("metrics digest must be a full 64-hex SHA-256")
    review = ev.get("review")
    if not isinstance(review, dict):
        raise ValueError("completion evidence lacks a review record")
    reviewers = review.get("reviewers")
    blocking = review.get("blocking_findings")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in (reviewers, blocking)
    ):
        raise ValueError("completion review counts must be non-negative integers")
    return [
        f"Automonique-Work: {it['id']}",
        "Automonique-Checks: pass",
        f"Automonique-Review: {reviewers}-pass/{blocking}-blocking",
        f"Automonique-Metrics: sha256:{digest}",
    ]


def check_lease(it: dict, declared: list[str], *, completion: bool = True) -> list[str]:
    """Declared files must be really changed and inside the item's lease."""
    actually_dirty = set(dirty_paths())
    deletions = staged_deletions()

    unknown = [p for p in declared if p not in actually_dirty and p not in deletions]
    if unknown:
        refuse("--files names paths that are not changed: " + ", ".join(unknown))

    committed_lease = lease_at_head(it["id"])
    if committed_lease is None:
        allowed = list(it.get("allowed_paths", []))
        notices.append(
            f"{it['id']} is not in the committed graph; judging against the "
            f"working-tree lease"
        )
    else:
        allowed = committed_lease
        if allowed != list(it.get("allowed_paths", [])):
            refuse(
                f"{it['id']} changes its own lease in this transaction. "
                "Land the lease change first, judged on its own, then do the work."
            )
    if allowed:
        permitted = list(allowed)
        if completion:
            permitted.extend(completion_paths(it["id"]))
        outside = [p for p in declared
                   if not any(p == a.rstrip("/") or p.startswith(a) for a in permitted)]
        if outside:
            refuse(f"{it['id']} leased {allowed} but the diff touches: "
                   + ", ".join(outside))

    if completion:
        machinery = [p for p in declared if p in COMPLETION_FORBIDDEN]
        if machinery:
            refuse(
                "a completion cannot also change the machinery that judges it: "
                + ", ".join(sorted(machinery))
                + " — commit that separately first"
            )

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
    reset_diagnostics()
    ap = argparse.ArgumentParser()
    ap.add_argument("--item", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--allow-no-metric-change", metavar="REASON")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--commit", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument(
        "--partial",
        action="store_true",
        help="read-only partial preflight; never authorizes completion",
    )
    args = ap.parse_args()

    if args.commit:
        print(
            "REFUSE: --commit is disabled until baseline, history, done status "
            "and regenerated plan artifacts can be included and verified in "
            "one exact completion tree",
            file=sys.stderr,
        )
        return 1
    if not args.dry_run and not args.partial:
        print(
            "REFUSE: choose --dry-run for a full completion preflight or "
            "--partial for a truthful non-completion preflight",
            file=sys.stderr,
        )
        return 1

    it = load_item(args.item)
    if it is None:
        print(f"FAIL: {args.item} is not in the work graph", file=sys.stderr)
        return 2

    required = contract_checks(args.item)
    check_readiness(it)
    ev = check_evidence(it, required, completion=not args.partial)
    files = check_lease(it, args.files, completion=not args.partial)
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
    if args.partial:
        print("\npreflight: PARTIAL PASS")
        print("(read-only — does not authorize completion, evidence, metrics or commit)")
        return 0

    assert ev is not None
    print("\ngate: PASS")
    print("attestation")
    for trailer in attestation_trailers(it, ev, after):
        print(f"           {trailer}")
    print("(dry run — complete-contract preflight only; nothing recorded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
