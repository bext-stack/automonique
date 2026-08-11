#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Verify the checked-in contract inventory against the sources it cites.

    python3 tools/contract_inventory/check.py            # verify
    python3 tools/contract_inventory/check.py --summary  # verify and print counts

Exit code is non-zero on any failure, so CI can branch on it directly. This
module is importable and its `main()` returns the exit code, so wiring it into
`plan/check.py` is a one-line follow-up for the integrator; it deliberately
does not edit that file, which several items share.

Two directions of drift are refused, because only checking one of them is how a
generated artifact quietly stops describing anything:

  * a checked-in artifact that a fresh build no longer produces — the sources
    moved and the copy is stale;
  * an artifact whose entries the sources do not evidence — the copy moved and
    the sources never said it.

The second is checked against the checked-in bytes rather than against the
freshly built object, so a hand edit to `inventory.json` is caught by the same
pass that catches a stale one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

_REPO = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.contract_inventory import build, sources as src  # noqa: E402
from tools.contract_inventory.sources import Documents, SourceError, flatten  # noqa: E402

EXPECTED_FILES = (build.INVENTORY, build.COVERAGE)


class Checker:
    def __init__(self, root: pathlib.Path | None = None) -> None:
        self.root = pathlib.Path(root) if root is not None else build.REPO_ROOT
        self.docs = Documents(self.root)
        self.problems: list[str] = []
        self.document: dict | None = None

    def fail(self, message: str) -> None:
        self.problems.append(message)

    # -- drift -------------------------------------------------------------

    def check_drift(self) -> dict | None:
        directory = self.root / build.OUTPUT_DIR
        if not directory.is_dir():
            self.fail(f"{build.OUTPUT_DIR} does not exist; the inventory is not generated")
            return None

        present = sorted(p.relative_to(self.root).as_posix()
                         for p in directory.iterdir() if p.is_file())
        unexpected = [p for p in present if p not in EXPECTED_FILES]
        if unexpected:
            self.fail(f"{build.OUTPUT_DIR} carries file(s) nothing generates: "
                      + ", ".join(unexpected))

        try:
            fresh = build.Builder(self.root).build()
        except (build.InventoryError, SourceError) as error:
            self.fail(f"the inventory no longer builds from its sources: {error}")
            return None

        for relative, text in fresh.items():
            path = self.root / relative
            if not path.exists():
                self.fail(f"{relative} is missing; a fresh build produces it")
                continue
            checked_in = path.read_text()
            if checked_in != text:
                self.fail(
                    f"{relative} is not what its sources generate — regenerate it with "
                    f"tools/contract_inventory/build.py "
                    f"(checked-in sha256 {hashlib.sha256(checked_in.encode()).hexdigest()[:12]}, "
                    f"fresh {hashlib.sha256(text.encode()).hexdigest()[:12]})")

        path = self.root / build.INVENTORY
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError as error:
            self.fail(f"{build.INVENTORY} is not valid JSON: {error}")
            return None

    # -- the checked-in document -------------------------------------------

    def check_vocabulary(self, document: dict) -> None:
        if document.get("schema") != build.SCHEMA:
            self.fail(f"{build.INVENTORY} has schema {document.get('schema')!r}, "
                      f"expected {build.SCHEMA!r}")
        expected = {
            "surface_classes": list(build.SURFACE_CLASSES),
            "granularities": list(build.GRANULARITIES),
            "owner_via": list(build.OWNER_VIA),
            "fixture_classes": list(build.FIXTURE_CLASSES),
            "blockers": list(build.BLOCKERS),
            "gap_kinds": list(build.GAP_KINDS),
            "corpus_status": ["present", "absent"],
        }
        recorded = document.get("vocabulary", {})
        for name, values in expected.items():
            if recorded.get(name) != values:
                self.fail(f"vocabulary {name} in the checked-in inventory is not the closed "
                          f"set the generator enforces: {recorded.get(name)!r}")

    def check_sources(self, document: dict) -> None:
        for entry in document.get("sources", []):
            key = entry.get("key")
            if key not in src.PERMITTED_SOURCES:
                self.fail(f"the inventory cites {key!r}, which is not a permitted source")
                continue
            if entry.get("path") != src.PERMITTED_SOURCES[key]:
                self.fail(f"source {key} records path {entry.get('path')!r}")
                continue
            try:
                actual = self.docs.digest(key)
            except SourceError as error:
                self.fail(str(error))
                continue
            if entry.get("sha256") != actual:
                self.fail(f"source {key} has changed since the inventory recorded its digest")

    def check_citation(self, label: str, citation: dict) -> None:
        key = citation.get("source")
        if key not in src.PERMITTED_SOURCES:
            self.fail(f"{label}: cites {key!r}, which is not a permitted source")
            return
        if citation.get("path") != src.PERMITTED_SOURCES[key]:
            self.fail(f"{label}: citation path {citation.get('path')!r} is not {key}'s")
            return
        try:
            if not self.docs.quotes(key, citation["section"], citation["quote"]):
                self.fail(f"{label}: {src.PERMITTED_SOURCES[key]} "
                          f"{citation['section']!r} does not say "
                          f"{flatten(citation['quote'])!r}")
        except SourceError as error:
            self.fail(f"{label}: {error}")

    def check_entries(self, document: dict) -> None:
        entries = document.get("entries", [])
        vocabulary = document.get("vocabulary", {})
        owners = vocabulary.get("target_owners", [])
        seen: set[str] = set()
        try:
            porting_map = build.Builder(self.root).porting_map()
        except SourceError as error:
            self.fail(str(error))
            porting_map = {}

        for entry in entries:
            label = entry.get("id", "<unnamed>")
            if label in seen:
                self.fail(f"{label}: duplicate entry id")
            seen.add(label)

            if entry.get("surface_class") not in build.SURFACE_CLASSES:
                self.fail(f"{label}: surface class {entry.get('surface_class')!r} is outside "
                          f"the seven")
            if entry.get("granularity") not in build.GRANULARITIES:
                self.fail(f"{label}: granularity {entry.get('granularity')!r} is outside the set")
            if not entry.get("name"):
                self.fail(f"{label}: an entry must name what it is")

            citations = entry.get("citations") or []
            if not citations:
                self.fail(f"{label}: an entry without a citation is invalid")
            for citation in citations:
                self.check_citation(label, citation)

            self.check_owner(label, entry, owners, porting_map)
            self.check_fixture(label, entry)

    def check_owner(self, label: str, entry: dict, owners: list[str],
                    porting_map: dict) -> None:
        owner = entry.get("owner")
        via = entry.get("owner_via")
        if via not in build.OWNER_VIA:
            self.fail(f"{label}: owner_via {via!r} is outside the closed set")
            return
        if owner is None:
            if via != "unresolved":
                self.fail(f"{label}: a null owner must record owner_via 'unresolved'")
            if not entry.get("owner_reason"):
                self.fail(f"{label}: a null owner must carry a reason, never a blank")
            return
        if entry.get("owner_reason"):
            self.fail(f"{label}: an owned entry may not also carry an unowned reason")
        if owner not in owners:
            self.fail(f"{label}: target owner {owner!r} is not a destination any permitted "
                      f"source names — an invented destination")
            return
        if via == "porting-map":
            evidence = entry.get("owner_evidence")
            if not evidence:
                self.fail(f"{label}: an owner resolved through the porting map must cite the row")
                return
            self.check_citation(label, evidence)
            row = porting_map.get(flatten(evidence.get("quote", "")))
            if row is None:
                self.fail(f"{label}: the porting map has no row {evidence.get('quote')!r}")
            elif owner not in row["destinations"]:
                self.fail(f"{label}: the porting map row {evidence.get('quote')!r} does not "
                          f"send its area to {owner}")
            elif len(row["destinations"]) > 1 and not entry.get("owner_note"):
                self.fail(f"{label}: the porting map row names several destinations and the "
                          f"entry records no reason for choosing {owner}")
        elif via == "parity-ledger-target-owner":
            cell = entry.get("ledger_target_owner", "")
            if owner not in cell:
                self.fail(f"{label}: the parity ledger's target-owner cell does not name {owner}")

    def check_fixture(self, label: str, entry: dict) -> None:
        plan = entry.get("fixture_plan")
        if not isinstance(plan, dict):
            self.fail(f"{label}: an entry must carry a parity fixture plan")
            return
        fixture_class = plan.get("class")
        if fixture_class not in build.FIXTURE_CLASSES:
            self.fail(f"{label}: fixture class {fixture_class!r} is outside the closed set")
            return
        for field in ("inputs", "outputs"):
            if not plan.get(field):
                self.fail(f"{label}: the fixture plan must name its observable {field}")
        status = plan.get("corpus_status")
        if status not in ("present", "absent"):
            self.fail(f"{label}: corpus status {status!r} is outside the closed set")
        elif status == "present":
            corpus_path = plan.get("corpus_path")
            if not corpus_path or not (self.root / corpus_path).exists():
                self.fail(f"{label}: the fixture plan claims a sanitized capture at "
                          f"{corpus_path!r}, which does not exist")
        elif plan.get("corpus_path"):
            self.fail(f"{label}: corpus status is absent but a capture path is recorded")

        blockers, detail = build.FIXTURE_BLOCKERS[fixture_class]
        if bool(plan.get("blocked")) != bool(blockers):
            self.fail(f"{label}: fixture class {fixture_class!r} is "
                      f"{'blocked' if blockers else 'not blocked'} by construction, but the "
                      f"plan says otherwise")
        reason = plan.get("blocking_reason")
        if blockers:
            if not isinstance(reason, dict) or reason.get("blockers") != blockers:
                self.fail(f"{label}: a blocked plan must name its blockers "
                          f"({', '.join(blockers)})")
            elif not reason.get("detail"):
                self.fail(f"{label}: a blocked plan must say why it is blocked")
            for blocker in (reason or {}).get("blockers", []):
                if blocker not in build.BLOCKERS:
                    self.fail(f"{label}: blocker {blocker!r} is outside the closed set")
        elif reason is not None:
            self.fail(f"{label}: an unblocked plan may not record a blocking reason")

    def check_findings(self, document: dict) -> None:
        entry_ids = {e.get("id") for e in document.get("entries", [])}
        for finding in document.get("unclassified", []):
            label = finding.get("id", "<unnamed>")
            if label in entry_ids:
                self.fail(f"{label}: an unclassified observation may not also be an entry")
            if not finding.get("why_no_class"):
                self.fail(f"{label}: an unclassified observation must say why no class fits")
            if not finding.get("citations"):
                self.fail(f"{label}: an unclassified observation must cite its source")
            for citation in finding.get("citations", []):
                self.check_citation(label, citation)
        for gap in document.get("gaps", []):
            label = gap.get("id", "<unnamed>")
            if gap.get("kind") not in build.GAP_KINDS:
                self.fail(f"{label}: gap kind {gap.get('kind')!r} is outside the closed set")
            if not gap.get("needed_to_close"):
                self.fail(f"{label}: a gap must say what would close it")
            for citation in gap.get("citations", []):
                self.check_citation(label, citation)

    def check_counts(self, document: dict) -> None:
        entries = document.get("entries", [])
        counts = document.get("counts", {})
        if counts.get("entries") != len(entries):
            self.fail(f"the recorded entry count {counts.get('entries')} is not the "
                      f"{len(entries)} entries present")
        per_class = {c: sum(1 for e in entries if e.get("surface_class") == c)
                     for c in build.SURFACE_CLASSES}
        if counts.get("per_class") != per_class:
            self.fail("the recorded per-class counts are not the entries present")
        empty = [c for c, n in per_class.items() if n == 0]
        if empty:
            self.fail("these surface classes have no entry, so the inventory does not cover "
                      "the seven: " + ", ".join(empty))
        unowned = sorted(e["id"] for e in entries if e.get("owner") is None)
        if document.get("unowned_entries") != unowned:
            self.fail("the recorded unowned subset is not the unowned entries present")
        blocked = sorted(e["id"] for e in entries
                         if (e.get("fixture_plan") or {}).get("blocked"))
        if document.get("blocked_entries") != blocked:
            self.fail("the recorded blocked subset is not the blocked plans present")
        if counts.get("unclassified_findings") != len(document.get("unclassified", [])):
            self.fail("the recorded unclassified count is not the findings present")
        if counts.get("gaps") != len(document.get("gaps", [])):
            self.fail("the recorded gap count is not the gaps present")

    def check_cross_source(self, document: dict) -> None:
        """Two documents count the same rows. Trust neither; compare them."""
        try:
            measured = build.Builder(self.root).cross_source()
        except SourceError as error:
            self.fail(str(error))
            return
        recorded = document.get("counts", {}).get("cross_source")
        if recorded != measured:
            self.fail("the recorded cross-source measurements are not what the sources say")
        if measured["coverage_map_total"] != measured["parity_ledger_rows"]:
            self.fail(
                f"the coverage map accounts for {measured['coverage_map_total']} rows "
                f"({measured['coverage_map_pinned']} pinned, "
                f"{measured['coverage_map_partial']} partial, "
                f"{measured['coverage_map_unpinned']} unpinned) but the parity ledger "
                f"carries {measured['parity_ledger_rows']}; the two documents disagree")

    def check_legacy_tokens(self) -> None:
        for relative in EXPECTED_FILES:
            path = self.root / relative
            if not path.exists():
                continue
            try:
                build.refuse_legacy_tokens(relative, path.read_text())
            except build.InventoryError as error:
                self.fail(str(error))

    # -- entry point -------------------------------------------------------

    def run(self) -> int:
        document = self.check_drift()
        if document is not None:
            self.document = document
            self.check_vocabulary(document)
            self.check_sources(document)
            self.check_entries(document)
            self.check_findings(document)
            self.check_counts(document)
            self.check_cross_source(document)
        self.check_legacy_tokens()
        return 1 if self.problems else 0


def summarise(document: dict) -> str:
    counts = document["counts"]
    lines = [f"entries {counts['entries']}"]
    for name, value in counts["per_class"].items():
        lines.append(f"  {name:<20} {value:>4}")
    lines += [
        f"unowned                {counts['unowned']:>4}",
        f"blocked fixture plans  {counts['blocked_fixture_plans']:>4}",
        f"unclassified findings  {counts['unclassified_findings']:>4}",
        f"gaps                   {counts['gaps']:>4}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="store_true", help="print measured coverage")
    parser.add_argument("--root", default=None, help="repository root to verify")
    args = parser.parse_args(argv)

    checker = Checker(pathlib.Path(args.root) if args.root else None)
    code = checker.run()
    for problem in checker.problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if code:
        print(f"\n{len(checker.problems)} inventory failure(s)", file=sys.stderr)
        return code
    document = checker.document or {}
    if args.summary:
        print(summarise(document))
    else:
        print(f"ok — {document.get('counts', {}).get('entries')} entries verified against "
              f"{len(document.get('sources', []))} permitted source(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
