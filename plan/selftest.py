#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Prove that plan/check.py actually detects the drift it claims to detect.

A checker that has never failed is indistinguishable from a checker that cannot
fail. Each case below copies the plan and specification into a scratch
directory, breaks it there in one specific way, and asserts that `check.py`
exits non-zero *and* says why. The working tree is never modified.

    python3 plan/selftest.py           # run every case
    python3 plan/selftest.py -v        # show each checker's output

Exit code is non-zero if any case fails to be detected, so CI gates on it.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def scratch(tmp: pathlib.Path) -> pathlib.Path:
    """A disposable copy of everything check.py reads."""
    work = tmp / "tree"
    work.mkdir()
    shutil.copytree(ROOT / "plan", work / "plan",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (work / "docs/product-plan/reference").mkdir(parents=True)
    shutil.copy(ROOT / "docs/product-plan/reference/work-breakdown.md",
                work / "docs/product-plan/reference/work-breakdown.md")
    return work


def run_check(work: pathlib.Path) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "plan/check.py", "--verify"],
                       cwd=work, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


# -- mutations -------------------------------------------------------------

def drop_ticket(work: pathlib.Path) -> None:
    """A ticket vanishes from the breakdown; its graph node is now orphaned."""
    p = work / "docs/product-plan/reference/work-breakdown.md"
    p.write_text("\n".join(l for l in p.read_text().splitlines()
                          if not l.startswith("- **R5-08 ")))


def invent_node(work: pathlib.Path) -> None:
    """A graph node appears with no ticket behind it."""
    p = work / "plan/work-graph.toml"
    t = p.read_text().replace("item_count = 375", "item_count = 376")
    p.write_text(t + '\n[[item]]\nid = "R99-01"\nepic = "R0"\ntrack = "core"\n'
                     'title = "invented"\ndepends_on = []\nlicence = "Elastic-2.0"\n'
                     'allowed_paths = []\nstatus = "blocked"\n')


def set_deps(p: pathlib.Path, item_id: str, deps: list[str]) -> None:
    t = p.read_text()
    i = t.index(f'id = "{item_id}"')
    j = t.index("depends_on = ", i)
    k = t.index("\n", j)
    rendered = ", ".join(f'"{d}"' for d in deps)
    p.write_text(t[:j] + f"depends_on = [{rendered}]" + t[k:])


def make_cycle(work: pathlib.Path) -> None:
    """Close a two-item loop: R1-02 -> R1-03 -> R1-02."""
    p = work / "plan/work-graph.toml"
    set_deps(p, "R1-02", ["R1-03"])
    set_deps(p, "R1-03", ["R1-02"])


def unknown_gate(work: pathlib.Path) -> None:
    """An item names a gate that gates.md does not define."""
    p = work / "plan/work-graph.toml"
    t = p.read_text()
    i = t.index('id = "R0-01"')
    j = t.index('status = ', i)
    p.write_text(t[:j] + 'blocked_by_gates = ["GATE-INVENTED"]\n' + t[j:])


def widen_apache_lease(work: pathlib.Path) -> None:
    """An Apache-2.0 item is given write access to a product path."""
    p = work / "plan/work-graph.toml"
    t = p.read_text()
    i = t.index('id = "R8B-01"')
    j = t.index("allowed_paths = ", i)
    k = t.index("\n", j)
    p.write_text(t[:j] + 'allowed_paths = ["rust/crates/automonique-core/"]' + t[k:])


def missing_spdx(work: pathlib.Path) -> None:
    """A new product source file omits its development-time licence marker."""
    (work / "plan/missing.py").write_text("print('missing')\n")


def wrong_spdx_root(work: pathlib.Path) -> None:
    """An SDK source file declares the product licence."""
    path = work / "sdk/client.ts"
    path.parent.mkdir(parents=True)
    path.write_text("// SPDX-License-Identifier: Elastic-2.0\nexport {};\n")


def done_without_evidence(work: pathlib.Path) -> None:
    """An item is marked done by hand, with no gate-recorded evidence."""
    p = work / "plan/work-graph.toml"
    t = p.read_text()
    i = t.index('id = "R0-01"')
    j = t.index('status = "blocked"', i)
    p.write_text(t[:j] + 'status = "done"' + t[j + len('status = "blocked"'):])


def escalate_bootstrap_authority(work: pathlib.Path) -> None:
    """Supervised mode attempts to grant itself protected push authority."""
    p = work / "plan/authority.toml"
    p.write_text(p.read_text().replace("push = false", "push = true"))


def mandate_independent_review(work: pathlib.Path) -> None:
    """A policy edit tries to make independent review globally mandatory."""
    p = work / "plan/authority.toml"
    p.write_text(p.read_text().replace(
        'review_policy = "owner-configurable"',
        'review_policy = "mandatory-independent"'))


def block_on_identity_hardening(work: pathlib.Path) -> None:
    """An ordinary work item is incorrectly blocked on advisory identity work."""
    p = work / "plan/work-graph.toml"
    t = p.read_text()
    i = t.index('id = "R0-03"')
    j = t.index('status = ', i)
    p.write_text(t[:j] + 'blocked_by_gates = ["GATE-IDENTITY"]\n' + t[j:])


def block_on_licence_advisory(work: pathlib.Path) -> None:
    """Development is incorrectly blocked on distribution readiness."""
    p = work / "plan/work-graph.toml"
    t = p.read_text()
    i = t.index('id = "R0-03"')
    j = t.index('status = ', i)
    p.write_text(t[:j] + 'blocked_by_gates = ["GATE-LICENCE"]\n' + t[j:])


CASES = [
    ("drift, forward  (ticket removed from breakdown)", drop_ticket,        "R5-08"),
    ("drift, reverse  (node invented in graph)",        invent_node,        "R99-01"),
    ("dependency cycle",                                make_cycle,         "cycle"),
    ("unknown gate reference",                          unknown_gate,       "GATE-INVENTED"),
    ("Apache work lease escapes its roots",              widen_apache_lease, "SDK boundary"),
    ("source file missing SPDX header",                  missing_spdx,       "missing SPDX"),
    ("source file has wrong path licence",               wrong_spdx_root,    "expected Apache-2.0"),
    ("done without gate evidence",                      done_without_evidence, "no evidence"),
    ("bootstrap authority escalation",                  escalate_bootstrap_authority,
     "must explicitly deny: push"),
    ("mandatory independent review",                    mandate_independent_review,
     "review_policy"),
    ("identity hardening used as blocker",              block_on_identity_hardening,
     "blocked by advisory GATE-IDENTITY"),
    ("licence readiness used as development blocker",   block_on_licence_advisory,
     "blocked by advisory GATE-LICENCE"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    before = (ROOT / "plan/work-graph.toml").read_bytes()
    failures = 0

    # the tree must already be clean, or a "detected" result proves nothing
    with tempfile.TemporaryDirectory() as tmp:
        work = scratch(pathlib.Path(tmp))
        code, out = run_check(work)
        if code != 0:
            print("FAIL  baseline: an unmodified copy does not pass\n" + out,
                  file=sys.stderr)
            return 1
        print("ok    baseline: unmodified copy passes")

    for name, mutate, expect in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            work = scratch(pathlib.Path(tmp))
            mutate(work)
            code, out = run_check(work)
            if args.verbose:
                print(f"\n--- {name} ---\n{out.strip()}\n")
            if code == 0:
                print(f"FAIL  {name}: not detected", file=sys.stderr)
                failures += 1
            elif expect.lower() not in out.lower():
                print(f"FAIL  {name}: detected, but the message does not mention "
                      f"{expect!r}", file=sys.stderr)
                failures += 1
            else:
                print(f"ok    {name}")

    after = (ROOT / "plan/work-graph.toml").read_bytes()
    if before != after:
        print("FAIL  the working tree was modified by this self-test",
              file=sys.stderr)
        failures += 1
    else:
        print("ok    working tree unchanged")

    if failures:
        print(f"\n{failures} case(s) not detected", file=sys.stderr)
        return 1
    print(f"\nall {len(CASES)} drift cases detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
