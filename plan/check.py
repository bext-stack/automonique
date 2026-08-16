#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Verify plan integrity and regenerate the ready set.

This is the drift gate demanded by R0-17: a plan ticket cannot disappear from
the executable graph, and an executable node cannot exist without a plan entry.
It also refuses a graph with dangling dependencies, cycles, unknown gates, a
licence-boundary violation, or an item marked done without gate evidence.

    python3 plan/check.py            # verify, rewrite plan/ready.md
    python3 plan/check.py --verify   # verify only; refuses if ready.md is stale (CI mode)

Exit code is non-zero on any failure, so CI can gate on it directly.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import json
import re
import subprocess
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


def repository_files() -> list[pathlib.Path]:
    """Every file that is part of the repository, and nothing that is not.

    Both whole-tree scans below used `ROOT.rglob("*")` against a hand-kept skip
    list. A skip list only knows what someone remembered to add, and what it did
    not know about was `.claude/worktrees/`, where the agent tooling checks the
    repository out again: 154 licence failures, every one of them a nested copy
    whose `sdk/` files land at a path whose first component is no longer `sdk`
    and so are judged against the wrong licence.

    Git already knows the answer, so ask it. `--cached --others
    --exclude-standard` is tracked files plus new ones that are not ignored, so
    a file added but not yet staged is still checked — which matters, since this
    gate runs before the commit — while anything `.gitignore` or
    `.git/info/exclude` rules out is not part of the repository and is not
    scanned. `SKIP_SOURCE_PARTS` stays as the fallback for a non-git checkout
    and as a second line for directories git does track but nothing should scan.
    """
    try:
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z",
             "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        ).stdout
        candidates = [ROOT / name.decode() for name in listed.split(b"\0") if name]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        # Not a git checkout, or git is unavailable. Fall back to the walk; the
        # skip list is weaker than git's answer but better than refusing to run.
        candidates = sorted(ROOT.rglob("*"))
    return [
        path for path in candidates
        if path.is_file()
        and not any(part in SKIP_SOURCE_PARTS
                    for part in path.relative_to(ROOT).parts)
    ]

# --- Legacy identifier location (R1-17, GATE-SCRUB) -------------------------
#
# `plan/gates.md#gate-scrub` and `plan/contracts/R1-17.md` say the same thing
# from two directions: a legacy identifier belongs in the classified inventory
# and in the name registry the compatibility surface is generated from, and
# nowhere else. Everywhere else prose uses the neutral description.
LEGACY_INVENTORY = "docs/product-plan/reference/legacy-inventory.md"
NAME_REGISTRY = "rust/crates/automonique-protocol/src/compat.rs"
GENERATED_REGISTRY = "rust/crates/automonique-protocol/src/compat/generated.rs"

# Every place a legacy identifier may appear, with the authority that permits
# it. Adding a row here widens the rule and is the reviewable act.
LEGACY_IDENTIFIER_HOMES = {
    LEGACY_INVENTORY: "the sanctioned inventory (plan/gates.md#gate-scrub)",
    NAME_REGISTRY: "the name registry (plan/contracts/R1-17.md)",
    GENERATED_REGISTRY: "generated from the name registry (plan/contracts/R1-17.md)",
    "plan/gates.md": "the location rule itself, which names its own example",
}

# Fingerprints rather than spellings, so this file does not itself become a
# place a legacy identifier appears. `length` is carried so that only words of
# that length are hashed, which is what keeps a full-tree scan cheap; it is the
# same shape `tools/scrub/synthetic-rules.json` uses.
LEGACY_TOKEN_FINGERPRINTS = (
    {
        "length": 4,
        "digest": "4ff17bc8ee5f240c792b8a41bfa2c58af726d83b925cf696af0c811627714c85",
        "reason": "the predecessor system's identifier prefix",
    },
)

# The compatibility spelling the product uses for a legacy environment or
# configuration name — `docs/product-plan/requirements/operations-and-governance.md`
# writes it `LEGACY_*`. In shipped Rust source it may only be written by the
# registry and by what the registry generates; anywhere else it is a
# hand-written alias with no authorizing entry. The lowercase command and
# binary spellings (`legacyctl`, `legacy-shell`) are the namespace gate's
# surface, not this one — `automonique_protocol::namespace` refuses any
# identifier segment starting with `legacy` unless an inventory entry names
# the contract that authorized it.
ALIAS_LITERAL = re.compile(r'"(LEGACY_[A-Z0-9_]+)"')
SHIPPED_RUST = re.compile(r"rust/crates/[^/]+/src/")
WORD = re.compile(r"[A-Za-z][A-Za-z0-9]*")

HARNESS_TRACK = "harness"
HARNESS_GATE = "GATE-HARNESS"
# Gates an owner closes by decision rather than by completing a work item. They
# are real blocking gates; they just have no closing ticket to warn about.
OWNER_CLOSED_GATES = {HARNESS_GATE}

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
    for path in repository_files():
        relative = path.relative_to(ROOT)
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


def readable_text(path: pathlib.Path) -> str | None:
    """The file's text, or `None` if it is not text at all."""
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError):
        return None


def check_legacy_identifier_location() -> None:
    """A legacy identifier lives in the inventory and the registry, nowhere else.

    `plan/contracts/R1-17.md` makes this a check row and `plan/gates.md`
    makes it a scan failure: the identifier is permitted inside the two
    sanctioned files precisely so that it can be classified and generated from,
    and permitted nowhere else because every other occurrence is a copy that
    nothing will ever retire.

    Two rules, because a legacy identifier reaches this tree two ways.

    1. The predecessor system's own prefix, matched by fingerprint so that
       enforcing the rule does not violate it. The failure names the file and
       line and never the value.
    2. `LEGACY_*`, the product's compatibility spelling for an environment or
       configuration name, written as a string literal in shipped Rust source.
       That is a hand-written alias unless it is in the registry or in what the
       registry generates, and a hand-written alias has no authorizing entry.

    Both are guarded against being vacuous: rule 1 must still match inside the
    sanctioned inventory, and rule 2 must still have a generated spelling to be
    about. A rule that matches nothing measures nothing.
    """
    lengths = {rule["length"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    reasons = {rule["digest"]: rule["reason"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    sanctioned_occurrences = 0
    generated_spellings = 0

    for path in repository_files():
        relative = path.relative_to(ROOT)
        text = readable_text(path)
        if text is None:
            continue
        label = relative.as_posix()
        permitted = label in LEGACY_IDENTIFIER_HOMES
        shipped_rust = SHIPPED_RUST.match(label) is not None

        for number, line in enumerate(text.splitlines(), start=1):
            for word in WORD.findall(line):
                if len(word) not in lengths:
                    continue
                digest = hashlib.sha256(word.lower().encode()).hexdigest()
                reason = reasons.get(digest)
                if reason is None:
                    continue
                if label == LEGACY_INVENTORY:
                    sanctioned_occurrences += 1
                if not permitted:
                    fail(f"{label}:{number} names a legacy identifier ({reason}); "
                         f"it is permitted only in " + ", ".join(sorted(LEGACY_IDENTIFIER_HOMES))
                         + " — use the neutral description here")
            if not shipped_rust:
                continue
            for alias in ALIAS_LITERAL.findall(line):
                if label == GENERATED_REGISTRY:
                    generated_spellings += 1
                elif not permitted:
                    fail(f"{label}:{number} writes the legacy spelling {alias} by hand; "
                         f"a compatibility spelling is generated from the registry in "
                         f"{NAME_REGISTRY}, and one that is not in it has no authorizing "
                         f"entry")

    if not sanctioned_occurrences:
        fail(f"the legacy-identifier fingerprints match nothing in {LEGACY_INVENTORY}, "
             f"so the rule proves nothing: either the identifier left the inventory "
             f"and the rule should go with it, or the fingerprints have rotted")
    if not generated_spellings:
        fail(f"{GENERATED_REGISTRY} generates no LEGACY_* spelling, so the "
             f"hand-written-alias rule has nothing to be about; regenerate it, or "
             f"drop the rule with the registry entry it guarded")


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
    for g in sorted(known - advisory - OWNER_CLOSED_GATES
                    - {i.get("closes_gate") for i in items}):
        warnings.append(f"gate {g} has no item that closes it")
    return closed


def check_licence(items: list[dict]) -> None:
    """Apache-2.0 items may only write below sdk/, integrations/ or connectors/.

    This governs the archived plan graph, not the tree. `LICENSE-POLICY.md`
    narrowed to `sdk/` alone on 2026-08-15 because the other two roots hold no
    code; the 27 blocked `R8F`/`R13` items that reserve them are planned work,
    and an Apache root for those is a decision to take when they ship. See
    `plan/owner-decisions/2026-08-15-connector-licence-boundary.md`, and
    `tools/check_licenses.py` for the boundary that applies to files on disk.
    """
    for it in items:
        apache = it["licence"] == "Apache-2.0"
        paths = it["allowed_paths"]
        if apache and paths and not all(
            p.startswith(("sdk/", "integrations/", "connectors/")) for p in paths
        ):
            fail(f"{it['id']} is Apache-2.0 but writes outside the SDK boundary: {paths}")
        if not apache and paths and all(p.startswith("sdk/") for p in paths):
            warnings.append(f"{it['id']} is Elastic-2.0 but only writes under sdk/")


def focus_rank(item: dict) -> tuple[int, str]:
    """Product first, then discovery, then harness.

    The contract-writing queue is ordered by this so that the cheapest way to
    make work selectable is always to specify product work. `tools/program.py`
    and the harness selector apply the same ordering to eligible items.
    """
    if item.get("track") == HARNESS_TRACK:
        return (2, item["id"])
    if item.get("epic") in {"BOOT", "R0"}:
        return (1, item["id"])
    return (0, item["id"])


def check_focus(items: list[dict], ready: list[dict]) -> None:
    """GATE-HARNESS: the harness may not outrun the product it exists to build.

    The repository spent its first 375-item plan building its own development
    harness, because the harness was the only work with a contract and the
    selector took the first eligible item in graph order. Classification alone
    would not have stopped that — a track label nothing enforces is a comment.
    This binds the label to the gate that makes it mechanical.
    """
    for it in items:
        harness = it.get("track") == HARNESS_TRACK
        gated = HARNESS_GATE in it.get("blocked_by_gates", [])
        if harness and not gated:
            fail(f"{it['id']} is on the harness track but is not blocked by "
                 f"{HARNESS_GATE} — regenerate with plan/generate.py")
        if gated and not harness:
            fail(f"{it['id']} is blocked by {HARNESS_GATE} but is not on the "
                 f"harness track; the gate freezes harness work only")

    escaped = [it["id"] for it in ready if it.get("track") == HARNESS_TRACK]
    if escaped:
        fail("harness work reached the ready set while " + HARNESS_GATE
             + " is open: " + ", ".join(sorted(escaped)))

    frozen = sorted(it["id"] for it in items
                    if it.get("track") == HARNESS_TRACK
                    and it.get("status") != "done"
                    and (CONTRACTS / f"{it['id']}.md").exists())
    if frozen:
        warnings.append(
            f"{len(frozen)} harness contract(s) are written but frozen by "
            f"{HARNESS_GATE}: " + ", ".join(frozen)
            + " — they are kept as the record of what was specified, not as "
              "selectable work")


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


def render_ready(items: list[dict], ready: list[dict],
                 unspecified: list[str]) -> str:
    done = sum(1 for i in items if i.get("status") == "done")
    return "\n".join([
        "# Archived graph snapshot",
        "",
        "GENERATED by `plan/check.py` — do not edit by hand.",
        "",
        "These are counters from the former executable-plan model. They do not "
        "select, block, or authorize current repository work; see `plan/README.md`.",
        "",
        f"- items: **{len(items)}**",
        f"- recorded done: **{done}**",
        f"- historically ready: **{len(ready)}**",
        f"- historically blocked: **{len(items) - done - len(ready)}**",
        f"- historically unspecified: **{len(unspecified)}**",
        "",
    ])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="verify only; refuse if ready.md is stale, rewrite nothing")
    ap.add_argument("--identifiers", action="store_true",
                    help="run only the legacy-identifier location rule and exit; "
                         "needs no plan graph and no secrets, so CI can gate every "
                         "push on it")
    args = ap.parse_args()

    if args.identifiers:
        # The narrow entry point exists because this one rule is the only part
        # of this file that is about the *published* tree rather than about
        # plan bookkeeping, and it is the only enforcement the first-party
        # legacy name has that needs no protected fingerprint bundle. Running
        # the whole checker to get it would make a push gate depend on the
        # roadmap being self-consistent, which is a different question with a
        # different owner.
        check_legacy_identifier_location()
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        if errors:
            print(f"\n{len(errors)} identifier-location failure(s)", file=sys.stderr)
            return 1
        print("ok — no legacy identifier outside its sanctioned homes")
        return 0

    if not GRAPH.exists():
        print("plan/work-graph.toml is missing — run plan/generate.py", file=sys.stderr)
        return 2

    data = load()
    items = data["item"]

    check_authority()
    check_source_licences()
    check_legacy_identifier_location()

    if data.get("item_count") != len(items):
        fail(f"item_count says {data.get('item_count')} but the file has {len(items)}")

    check_bidirectional(items)
    check_deps(items)
    check_cycles(items)
    closed = check_gates(items)
    check_licence(items)
    ready = compute_ready(items, closed)
    by_id = {i["id"]: i for i in items}
    unspecified = sorted(unblocked_without_contract(items, closed),
                         key=lambda i: focus_rank(by_id[i]))
    check_focus(items, ready)
    check_evidence(items)

    for w in warnings:
        print(f"warn: {w}")
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)

    if errors:
        print(f"\n{len(errors)} integrity failure(s)", file=sys.stderr)
        return 1

    rendered = render_ready(items, ready, unspecified)
    if not args.verify:
        # Atomically, because a reader in a parallel run must never observe a
        # half-written ready set.
        staging = READY.with_suffix(".md.staging")
        staging.write_text(rendered)
        staging.replace(READY)
        print(f"ok — {len(items)} items, {len(ready)} ready, "
              f"{len(unspecified)} unblocked-but-unspecified; wrote plan/ready.md")
        return 0

    # CI mode writes nothing, but silence is not the same as agreement. A commit
    # that moved the graph and ran only --verify used to leave a stale ready.md
    # checked in, and nothing said so: the plan advertised finished work as
    # selectable. Same class of defect as .automonique/dev/program.yaml going
    # stale against the graph, and the same cure — compare, do not assume.
    current = READY.read_text() if READY.exists() else ""
    if current != rendered:
        print("FAIL: plan/ready.md is stale — regenerate it with "
              "`python3 plan/check.py` and commit the result", file=sys.stderr)
        print("\n1 integrity failure(s)", file=sys.stderr)
        return 1
    print(f"ok — {len(items)} items, {len(ready)} ready, "
          f"{len(unspecified)} unblocked-but-unspecified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
