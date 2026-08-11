#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Generate the behavioural contract inventory from its permitted sources.

    python3 tools/contract_inventory/build.py            # regenerate in place
    python3 tools/contract_inventory/build.py --check    # write nothing

The inventory is derived, never authored: the members of every family, every
count and every target owner come out of `docs/product-plan/`, and
`rules.toml` supplies only the classification judgements. Anything the sources
do not determine is emitted as a `null` owner with a reason, an unclassified
finding, or a gap — never as a plausible value.

The closed vocabularies below are enforced at construction. An entry with a
class outside the seven, a fixture class outside the named set, a blocker
outside the named set, or an owner the porting map does not name cannot be
built at all; `InventoryError` is raised and nothing is written.

Writes are atomic — staged beside the target and renamed — because a reader
running concurrently with a regeneration would otherwise observe a half-written
file, which is how an earlier parallel run in this repository turned a suite red
for reasons that had nothing to do with the change under test.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import tomllib

# Importable as a module and runnable as a script, so the checker can be wired
# into CI either way without a wrapper.
_REPO = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.contract_inventory import sources as src
from tools.contract_inventory.sources import Documents, SourceError, backticked, flatten, slugify

REPO_ROOT = src.REPO_ROOT
RULES = pathlib.Path(__file__).resolve().parent / "rules.toml"
OUTPUT_DIR = "plan/inventory/contracts"
INVENTORY = f"{OUTPUT_DIR}/inventory.json"
COVERAGE = f"{OUTPUT_DIR}/coverage.md"

SCHEMA = "automonique.contract-inventory/v1"

# The seven surface classes. Closed: an observation that fits none of them is
# recorded as an unclassified finding and never pushed into the nearest class.
SURFACE_CLASSES = (
    "input",
    "state transition",
    "timer",
    "side effect",
    "command",
    "backend event",
    "operational script",
)

GRANULARITIES = ("capability", "surface")
OWNER_VIA = ("parity-ledger-target-owner", "porting-map", "unresolved")

# What a parity fixture for an entry would have to be. Closed, and each class
# fixes whether the plan is blocked: a plan cannot name a class that needs a
# live capture and then claim it is unblocked.
FIXTURE_CLASSES = (
    "enumeration-presence",
    "schema-snapshot",
    "legacy-test-conversion",
    "replay-capture",
    "provider-transcript",
    "effect-recording",
    "none-replaced",
)

BLOCKERS = (
    "GATE-ORACLE", "private-archive", "live-network",
    "production-read", "production-write", "secret",
)

FIXTURE_BLOCKERS: dict[str, tuple[list[str], str]] = {
    "enumeration-presence": ([], ""),
    "none-replaced": ([], ""),
    "schema-snapshot": (
        ["GATE-ORACLE", "production-read"],
        "the column-level shape is not in any permitted source; capturing it means reading the live legacy database",
    ),
    "legacy-test-conversion": (
        ["GATE-ORACLE", "private-archive"],
        "converting the named legacy test requires the legacy tree, which the clean-room boundary keeps out of implementation, and capture is blocked until the oracle boundary exists",
    ),
    "replay-capture": (
        ["GATE-ORACLE", "production-read"],
        "a replay fixture needs a sanitized capture of live traffic",
    ),
    "provider-transcript": (
        ["GATE-ORACLE", "live-network", "secret"],
        "a provider transcript needs a live provider binary, its credential and its network",
    ),
    "effect-recording": (
        ["GATE-ORACLE", "live-network", "production-write"],
        "recording an outward effect needs the live endpoint and would write where production writes",
    ),
}

GAP_KINDS = ("count-discrepancy", "unnamed-member", "unreachable-source", "deferred-to-item")

# Loaded from plan/check.py rather than restated: the fingerprint is how that
# file enforces the same rule without naming the value, and a second copy here
# would be a constant this module could drift from.
sys.path.insert(0, str(REPO_ROOT / "plan"))
import check as plan_check  # noqa: E402


class InventoryError(Exception):
    """The inventory cannot be built truthfully."""


def refuse_legacy_tokens(label: str, text: str) -> None:
    """Refuse a legacy identifier reaching a generated file.

    `plan/gates.md` permits the predecessor's identifier prefix in exactly one
    document. A generated artifact is not that document, so a quotation that
    would carry one out of it is refused here rather than discovered by the
    repository-wide scan later. The failure names the position, never the value.
    """
    lengths = {rule["length"] for rule in plan_check.LEGACY_TOKEN_FINGERPRINTS}
    reasons = {rule["digest"]: rule["reason"] for rule in plan_check.LEGACY_TOKEN_FINGERPRINTS}
    import hashlib
    for word in plan_check.WORD.findall(text):
        if len(word) not in lengths:
            continue
        reason = reasons.get(hashlib.sha256(word.lower().encode()).hexdigest())
        if reason is not None:
            raise InventoryError(
                f"{label} would carry a legacy identifier ({reason}) out of the "
                f"sanctioned inventory; cite the neutral description instead"
            )


def load_rules(path: pathlib.Path = RULES) -> dict:
    with path.open("rb") as handle:
        rules = tomllib.load(handle)
    if rules.get("schema") != "automonique.contract-inventory.rules/v1":
        raise InventoryError(f"{path} has an unrecognised rules schema")
    return rules


class Builder:
    def __init__(self, root: pathlib.Path | None = None, rules: dict | None = None) -> None:
        self.docs = Documents(root)
        self.root = self.docs.root
        self.rules = rules if rules is not None else load_rules()
        self.entries: list[dict] = []
        self.unclassified: list[dict] = []
        self.gaps: list[dict] = []
        self.sections_used: dict[str, set[str]] = {}
        self._porting_map: dict[str, dict] | None = None

    # -- source helpers ----------------------------------------------------

    def cite(self, source: str, section: str, quote: str) -> dict:
        """A citation the checker can re-verify, refused now if it is false."""
        if not self.docs.quotes(source, section, quote):
            raise InventoryError(
                f"{src.PERMITTED_SOURCES[source]} {section!r} does not say "
                f"{flatten(quote)!r}; an entry may not cite what its source does not carry"
            )
        self.sections_used.setdefault(source, set()).add(section)
        return {
            "source": source,
            "path": src.PERMITTED_SOURCES[source],
            "section": section,
            "quote": flatten(quote),
        }

    def porting_map(self) -> dict[str, dict]:
        """Area -> {destinations, phase, cell} from the migration plan."""
        if self._porting_map is None:
            body = self.docs.section("migration-plan", "## Porting map")
            tables = self.docs.tables(body)
            if not tables:
                raise SourceError("the porting map has no table")
            rows: dict[str, dict] = {}
            for row in tables[0][1]:
                rows[flatten(row[0])] = {
                    "destinations": sorted(set(re.findall(r"automonique-[a-z]+", row[1]))),
                    "cell": flatten(row[1]),
                    "phase": flatten(row[2]) if len(row) > 2 else "",
                }
            self._porting_map = rows
        return self._porting_map

    def destination_vocabulary(self) -> list[str]:
        """Every Rust destination the permitted sources actually name."""
        vocabulary: set[str] = set()
        for row in self.porting_map().values():
            vocabulary.update(row["destinations"])
        modules = self.docs.section(
            "legacy-inventory", "### Largest modules and their destinations")
        for _, table in self.docs.tables(modules):
            for row in table:
                vocabulary.update(re.findall(r"automonique-[a-z]+", row[-1]))
        return sorted(vocabulary)

    # -- owner resolution --------------------------------------------------

    def resolve_owner(self, rule: dict, label: str, parity_owner_cell: str | None = None) -> dict:
        """Resolve one entry's target owner, or refuse to invent one."""
        via = rule.get("owner_via", "unresolved")
        if via not in OWNER_VIA:
            raise InventoryError(f"{label}: owner_via {via!r} is outside the closed set")
        owner = rule.get("owner")
        vocabulary = self.destination_vocabulary()

        if via == "unresolved":
            if owner:
                raise InventoryError(f"{label}: an unresolved owner may not name a destination")
            reason = rule.get("owner_reason")
            if not reason:
                raise InventoryError(f"{label}: a null owner must carry a reason")
            return {"owner": None, "owner_via": via, "owner_reason": reason,
                    "owner_evidence": None, "owner_note": None}

        if not owner:
            raise InventoryError(f"{label}: owner_via {via!r} names no owner")
        if owner not in vocabulary:
            raise InventoryError(
                f"{label}: {owner!r} is not a destination any permitted source names "
                f"(the sources name {', '.join(vocabulary)}) — an invented destination "
                f"is refused, not recorded"
            )

        if via == "porting-map":
            area = rule.get("porting_map_row")
            row = self.porting_map().get(flatten(area or ""))
            if row is None:
                raise InventoryError(
                    f"{label}: the porting map has no row {area!r}, so the owner "
                    f"resolves through nothing")
            if owner not in row["destinations"]:
                raise InventoryError(
                    f"{label}: the porting map row {area!r} sends its area to "
                    f"{row['destinations'] or 'no automonique- destination'}, not to {owner}")
            evidence = self.cite("migration-plan", "## Porting map", f"{area}")
            note = rule.get("owner_note")
            if len(row["destinations"]) > 1 and not note:
                raise InventoryError(
                    f"{label}: the porting map row names {len(row['destinations'])} "
                    f"destinations; choosing one requires a recorded reason")
            return {"owner": owner, "owner_via": via, "owner_reason": None,
                    "owner_evidence": evidence, "owner_note": note}

        # parity-ledger-target-owner
        if parity_owner_cell is None or owner not in parity_owner_cell:
            raise InventoryError(
                f"{label}: the parity ledger's target-owner cell does not name {owner}")
        return {"owner": owner, "owner_via": via, "owner_reason": None,
                "owner_evidence": None, "owner_note": rule.get("owner_note")}

    # -- fixture plan ------------------------------------------------------

    @staticmethod
    def fixture_plan(rule: dict, name: str, label: str) -> dict:
        fixture_class = rule.get("fixture_class")
        if fixture_class not in FIXTURE_CLASSES:
            raise InventoryError(
                f"{label}: fixture class {fixture_class!r} is outside the closed set")
        blockers, detail = FIXTURE_BLOCKERS[fixture_class]
        for blocker in blockers:
            if blocker not in BLOCKERS:
                raise InventoryError(f"{label}: blocker {blocker!r} is outside the closed set")
        inputs = rule.get("fixture_inputs", "").format(name=name)
        outputs = rule.get("fixture_outputs", "").format(name=name)
        if not inputs or not outputs:
            raise InventoryError(f"{label}: a fixture plan must name its inputs and outputs")
        corpus_path = rule.get("corpus_path")
        return {
            "class": fixture_class,
            "inputs": inputs,
            "outputs": outputs,
            "corpus_status": "present" if corpus_path else "absent",
            "corpus_path": corpus_path,
            "blocked": bool(blockers),
            "blocking_reason": ({"blockers": blockers, "detail": detail} if blockers else None),
        }

    # -- entry construction ------------------------------------------------

    def overrides_for(self, family: str) -> list[dict]:
        return [o for o in self.rules.get("override", []) if o["family"] == family]

    def merged_rule(self, family: str, base: dict, key: str, group: str | None) -> dict:
        rule = dict(base)
        for override in self.overrides_for(family):
            if "when_key" in override and flatten(override["when_key"]) != flatten(key):
                continue
            if "when_group" in override and override["when_group"] != group:
                continue
            if "when_key" not in override and "when_group" not in override:
                raise InventoryError(f"{family}: an override must say what it matches")
            rule.update({k: v for k, v in override.items()
                         if k not in {"family", "when_key", "when_group"}})
            if override.get("owner_via") == "unresolved":
                rule.pop("owner", None)
                rule.pop("owner_note", None)
        return rule

    def add(self, family: str, key: str, name: str, rule: dict, citations: list[dict],
            detail: str | None = None, extra: dict | None = None,
            parity_owner_cell: str | None = None) -> None:
        label = f"{family}:{key}"
        if rule.get("surface_class") == "unclassified":
            why = rule.get("why_no_class")
            if not why:
                raise InventoryError(f"{label}: an unclassified observation must say why")
            self.unclassified.append({
                "id": label,
                "family": family,
                "name": name,
                "why_no_class": why,
                "disposition": rule.get("disposition", ""),
                "citations": citations,
            })
            return
        surface_class = rule.get("surface_class")
        if surface_class not in SURFACE_CLASSES:
            raise InventoryError(
                f"{label}: class {surface_class!r} is outside the seven; an observation "
                f"that fits none is recorded unclassified, never forced into the nearest")
        granularity = rule.get("granularity")
        if granularity not in GRANULARITIES:
            raise InventoryError(f"{label}: granularity {granularity!r} is outside the closed set")
        if not citations:
            raise InventoryError(f"{label}: an entry without a citation is invalid")
        owner = self.resolve_owner(rule, label, parity_owner_cell)
        entry = {
            "id": label,
            "family": family,
            "granularity": granularity,
            "surface_class": surface_class,
            "name": name,
            "detail": detail or "",
            **owner,
            "fixture_plan": self.fixture_plan(rule, name, label),
            "citations": citations,
        }
        if extra:
            entry.update(extra)
        self.entries.append(entry)

    # -- families ----------------------------------------------------------

    def build_family(self, family: str, rule: dict) -> int:
        extraction = rule["extraction"]
        source, section = rule["source"], rule["section"]
        members: list[tuple[str, str, str | None, str, list[dict]]] = []
        # (key, name, group, detail, citations)

        if extraction == "table-cell-backticks":
            tables = self.docs.tables(self.docs.section(source, section))
            for row in tables[0][1]:
                group = flatten(row[rule["group_column"]])
                for token in backticked(row[rule["token_column"]]):
                    members.append((token, token, group,
                                    f"{group} group", [self.cite(source, section, f"`{token}`")]))

        elif extraction == "paragraph-backticks":
            paragraph = self.docs.paragraph_starting(source, section, rule["paragraph_prefix"])
            for token in backticked(paragraph):
                members.append((token, token, None, "",
                                [self.cite(source, section, f"`{token}`")]))

        elif extraction == "table-rows":
            tables = self.docs.tables(self.docs.section(source, section))
            for row in tables[0][1]:
                raw = flatten(row[rule["key_column"]])
                key = raw.strip("`")
                detail = flatten(row[rule["detail_column"]])
                members.append((key, key, None, detail,
                                [self.cite(source, section, raw)]))

        elif extraction == "table-split-cell":
            tables = self.docs.tables(self.docs.section(source, section))
            for row in tables[0][1]:
                detail = flatten(row[rule["detail_column"]])
                for job in [j.strip() for j in row[rule["key_column"]].split(",")]:
                    members.append((job, job, None, f"every {detail}",
                                    [self.cite(source, section, job)]))

        elif extraction == "paragraph-comma-list":
            paragraph = self.docs.paragraph_starting(source, section, rule["paragraph_prefix"])
            body = paragraph.split(":**", 1)[1]
            for piece in body.split(", "):
                item = piece.strip().rstrip(".").strip()
                if item.lower().startswith("and "):
                    item = item[4:]
                members.append((item, item, None, "",
                                [self.cite(source, section, item)]))

        elif extraction == "declared":
            for declared in self.rules.get("declared", []):
                if declared["family"] != family:
                    continue
                key = declared["key"]
                members.append((key, key, None, "",
                                [self.cite(source, section, declared["quote"])]))

        elif extraction == "parity-rows":
            return self.build_parity(family, rule)

        else:
            raise InventoryError(f"{family}: extraction {extraction!r} is not implemented")

        declared_by_key = {d["key"]: d for d in self.rules.get("declared", [])
                           if d["family"] == family}
        covered = 0
        for key, name, group, detail, citations in members:
            merged = self.merged_rule(family, rule, key, group)
            if key in declared_by_key:
                merged.update({k: v for k, v in declared_by_key[key].items()
                               if k not in {"family", "key", "quote", "covers"}})
                if declared_by_key[key].get("owner_via") == "unresolved":
                    merged.pop("owner", None)
                    merged.pop("owner_note", None)
                covered += declared_by_key[key].get("covers", 1)
            else:
                covered += 1
            self.add(family, key, name, merged, citations, detail=detail)
        self.reconcile_count(family, rule, len(members), covered)
        return len(members)

    def build_parity(self, family: str, rule: dict) -> int:
        headings = [h for h in self.docs.sections("feature-parity")
                    if h.startswith("## ") and self.parity_tables(h)]
        rows: list[tuple[str, list[str]]] = []
        for heading in headings:
            for table in self.parity_tables(heading):
                rows.extend((heading, row) for row in table)
        classified = self.rules.get("parity", {})
        seen: set[str] = set()
        for heading, row in rows:
            capability, target_owner, decision, fixture_cell, evidence = (
                flatten(row[0]), flatten(row[1]), flatten(row[2]),
                flatten(row[3]), flatten(row[4]))
            slug = slugify(capability)
            entry_rule = classified.get(slug)
            if entry_rule is None:
                raise InventoryError(
                    f"parity row {capability!r} has no classification in rules.toml; "
                    f"the ledger and the inventory have diverged")
            if flatten(entry_rule["row"]) != capability:
                raise InventoryError(
                    f"parity rule {slug!r} records a row the ledger no longer carries")
            if flatten(entry_rule["section"]) != heading:
                raise InventoryError(
                    f"parity rule {slug!r} cites section {entry_rule['section']!r} but the "
                    f"row is under {heading!r}")
            seen.add(slug)
            merged = dict(rule)
            merged.update({k: v for k, v in entry_rule.items()
                           if k not in {"row", "section"}})
            replaced = fixture_cell.startswith("**none**")
            merged["fixture_class"] = "none-replaced" if replaced else rule["fixture_class"]
            if replaced:
                merged["fixture_inputs"] = (
                    "no parity fixture: the owner reclassified this row replace on 2026-08-09")
                merged["fixture_outputs"] = (
                    "the outcome is provided through a new contract of Automonique's own design, "
                    "which the parity ledger item writes and which is authoritative")
            citations = [self.cite("feature-parity", heading, capability)]
            self.add(family, slug, capability, merged, citations,
                     detail=decision,
                     parity_owner_cell=target_owner,
                     extra={
                         "ledger_target_owner": target_owner,
                         "ledger_fixture": fixture_cell,
                         "ledger_evidence": evidence,
                         "legacy_tests": backticked(fixture_cell),
                         "coverage": ("replace" if replaced
                                      else evidence.split(":", 1)[0].split(";", 1)[0]),
                     })
        unused = sorted(set(classified) - seen)
        if unused:
            raise InventoryError(
                "rules.toml classifies parity rows the ledger no longer carries: "
                + ", ".join(unused))
        self.reconcile_count(family, rule, len(rows), len(rows))
        return len(rows)

    def parity_tables(self, heading: str) -> list[list[list[str]]]:
        out = []
        for header, table in self.docs.tables(self.docs.section("feature-parity", heading)):
            if header and header[0].lower().startswith("current capability"):
                out.append(table)
        return out

    # -- gaps --------------------------------------------------------------

    def reconcile_count(self, family: str, rule: dict, enumerated: int, covered: int) -> None:
        """The source's own count against the members it actually enumerates."""
        pattern = rule.get("claim_pattern")
        if not pattern:
            return
        source, section = rule["source"], rule["section"]
        claimed = self.docs.claim(source, section, pattern)
        match = re.search(pattern, flatten(self.docs.section(source, section)))
        if covered == claimed:
            return
        if covered < claimed:
            detail = (f"the source states {claimed} but enumerates {covered}; "
                      f"{claimed - covered} member(s) are counted and not named")
            needed = ("a structural reference from the legacy tree naming the counted "
                      "members — permitted by the clean-room boundary, but not present "
                      "in this repository")
        else:
            detail = (f"the source states {claimed} but enumerates {covered}; the "
                      f"enumeration exceeds the stated count by {covered - claimed}")
            needed = ("a reconciliation of the stated count with the enumeration in the "
                      "source document, which is a documentation fix rather than a capture")
        self.gaps.append({
            "id": f"{family}-count-discrepancy",
            "kind": "count-discrepancy",
            "detail": detail,
            "needed_to_close": needed,
            "measured": {"stated": claimed, "enumerated": covered},
            "citations": [self.cite(source, section, match.group(0))],
        })

    def measured_gaps(self) -> None:
        """Measurements taken across sections, each one counted, never estimated."""
        docs = self.docs
        modules_claimed = docs.claim("legacy-inventory", "## Shape", r"(\d+) modules")
        module_rows = docs.tables(docs.section(
            "legacy-inventory", "### Largest modules and their destinations"))[0][1]
        if len(module_rows) < modules_claimed:
            self.gaps.append({
                "id": "module-destinations-incomplete",
                "kind": "unnamed-member",
                "detail": (f"{len(module_rows)} of {modules_claimed} legacy modules carry a "
                           f"recorded Rust destination; the remaining "
                           f"{modules_claimed - len(module_rows)} are counted but not named"),
                "needed_to_close": ("a file listing of the legacy source tree, which is a "
                                    "permitted structural reference but is not checked in here"),
                "measured": {"named": len(module_rows), "total": modules_claimed},
                "citations": [self.cite("legacy-inventory", "## Shape",
                                        f"{modules_claimed} modules")],
            })

        coverage_rows = docs.tables(docs.section("legacy-inventory", "## Behavioral coverage"))[0][1]
        tests = sum(int(row[2]) for row in coverage_rows)
        files = 0
        for row in coverage_rows:
            match = re.search(r"\((\d+) files\)", row[1])
            files += int(match.group(1)) if match else len(backticked(row[1]))
        tests_claimed = docs.claim("legacy-inventory", "## Shape", r"\*\*(\d+) passing across")
        files_claimed = docs.claim("legacy-inventory", "## Shape", r"passing across (\d+) files")
        if tests != tests_claimed or files != files_claimed:
            self.gaps.append({
                "id": "behavioural-coverage-unattributed",
                "kind": "unnamed-member",
                "detail": (f"the coverage table attributes {tests} of {tests_claimed} tests and "
                           f"{files} of {files_claimed} test files to a named area; the "
                           f"remaining {tests_claimed - tests} test(s) in "
                           f"{files_claimed - files} file(s) pin behaviour this inventory "
                           f"cannot attribute"),
                "needed_to_close": ("a per-file test listing from the legacy tree, which is a "
                                    "permitted structural reference but is not checked in here"),
                "measured": {"tests_attributed": tests, "tests_total": tests_claimed,
                             "files_attributed": files, "files_total": files_claimed},
                "citations": [self.cite("legacy-inventory", "## Behavioral coverage",
                                        "They are not evenly distributed")],
            })

        for gap in self.rules.get("gap", []):
            if gap["kind"] not in GAP_KINDS:
                raise InventoryError(f"gap {gap['id']}: kind {gap['kind']!r} is outside the set")
            if not gap.get("needed_to_close"):
                raise InventoryError(f"gap {gap['id']}: a gap must say what would close it")
            self.gaps.append({
                "id": gap["id"],
                "kind": gap["kind"],
                "detail": gap["detail"],
                "needed_to_close": gap["needed_to_close"],
                "measured": None,
                "citations": [self.cite(gap["source"], gap["section"], gap["quote"])],
            })

    def cross_source(self) -> dict:
        """Two documents counting the same rows, compared rather than trusted."""
        docs = self.docs
        pinned = len(docs.tables(docs.section("legacy-inventory", "### Pinned"))[0][1])
        partial = len(docs.tables(docs.section("legacy-inventory", "### Partial"))[0][1])
        unpinned_heading = next(h for h in docs.sections("legacy-inventory")
                                if h.startswith("### Unpinned"))
        unpinned = len(docs.tables(docs.section("legacy-inventory", unpinned_heading))[0][1])
        ledger_rows = sum(len(table) for heading in docs.sections("feature-parity")
                          if heading.startswith("## ")
                          for table in self.parity_tables(heading))
        return {
            "parity_ledger_rows": ledger_rows,
            "coverage_map_pinned": pinned,
            "coverage_map_partial": partial,
            "coverage_map_unpinned": unpinned,
            "coverage_map_total": pinned + partial + unpinned,
        }

    # -- assembly ----------------------------------------------------------

    def build(self) -> dict[str, str]:
        for family, rule in self.rules["family"].items():
            self.build_family(family, rule)
        for finding in self.rules.get("unclassified", []):
            self.unclassified.append({
                "id": finding["id"],
                "family": "declared",
                "name": finding["name"],
                "why_no_class": finding["why_no_class"],
                "disposition": finding.get("disposition", ""),
                "citations": [self.cite(finding["source"], finding["section"], finding["quote"])],
            })
        self.measured_gaps()

        ids = [entry["id"] for entry in self.entries]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise InventoryError(f"duplicate entry id(s): {', '.join(duplicates)}")

        self.entries.sort(key=lambda e: e["id"])
        self.unclassified.sort(key=lambda e: e["id"])
        self.gaps.sort(key=lambda g: g["id"])

        per_class = {c: sum(1 for e in self.entries if e["surface_class"] == c)
                     for c in SURFACE_CLASSES}
        missing = [c for c, n in per_class.items() if n == 0]
        if missing:
            raise InventoryError(
                "these classes have no entry, so the inventory does not cover the seven "
                "surfaces: " + ", ".join(missing))
        per_family = {f: sum(1 for e in self.entries if e["family"] == f)
                      for f in sorted({e["family"] for e in self.entries})}
        per_fixture = {c: sum(1 for e in self.entries if e["fixture_plan"]["class"] == c)
                       for c in FIXTURE_CLASSES}
        unowned = sorted(e["id"] for e in self.entries if e["owner"] is None)
        blocked = sorted(e["id"] for e in self.entries if e["fixture_plan"]["blocked"])
        owners = {o: sum(1 for e in self.entries if e["owner"] == o)
                  for o in sorted({e["owner"] for e in self.entries if e["owner"]})}

        document = {
            "schema": SCHEMA,
            "generated_by": "tools/contract_inventory/build.py",
            "checked_by": "tools/contract_inventory/check.py",
            "item": "R0-01",
            "vocabulary": {
                "surface_classes": list(SURFACE_CLASSES),
                "granularities": list(GRANULARITIES),
                "owner_via": list(OWNER_VIA),
                "fixture_classes": list(FIXTURE_CLASSES),
                "blockers": list(BLOCKERS),
                "gap_kinds": list(GAP_KINDS),
                "corpus_status": ["present", "absent"],
                "target_owners": self.destination_vocabulary(),
            },
            "sources": [
                {
                    "key": key,
                    "path": src.PERMITTED_SOURCES[key],
                    "sha256": self.docs.digest(key),
                    "sections_cited": sorted(self.sections_used.get(key, ())),
                }
                for key in sorted(self.sections_used)
            ],
            "counts": {
                "entries": len(self.entries),
                "per_class": per_class,
                "per_family": per_family,
                "per_fixture_class": per_fixture,
                "per_owner": owners,
                "unowned": len(unowned),
                "blocked_fixture_plans": len(blocked),
                "unclassified_findings": len(self.unclassified),
                "gaps": len(self.gaps),
                "cross_source": self.cross_source(),
            },
            "unowned_entries": unowned,
            "blocked_entries": blocked,
            "entries": self.entries,
            "unclassified": self.unclassified,
            "gaps": self.gaps,
        }
        inventory = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        refuse_legacy_tokens(INVENTORY, inventory)
        coverage = render_coverage(document)
        refuse_legacy_tokens(COVERAGE, coverage)
        return {INVENTORY: inventory, COVERAGE: coverage}


def render_coverage(document: dict) -> str:
    """The measured summary, generated from the same document it describes."""
    counts = document["counts"]
    lines = [
        "# Behavioural contract inventory — measured coverage",
        "",
        "GENERATED by `tools/contract_inventory/build.py` — do not edit by hand.",
        "Regenerate with `python3 tools/contract_inventory/build.py`; verify with",
        "`python3 tools/contract_inventory/check.py`.",
        "",
        "Every number below was counted from the permitted sources listed in",
        "`inventory.json`. Nothing here is estimated, and an entry the sources do",
        "not determine is reported unowned or as a gap rather than filled in.",
        "",
        f"- entries: **{counts['entries']}**",
        f"- unowned entries: **{counts['unowned']}**",
        f"- blocked fixture plans: **{counts['blocked_fixture_plans']}**",
        f"- unclassified findings: **{counts['unclassified_findings']}**",
        f"- gaps: **{counts['gaps']}**",
        "",
        "## Entries per surface class",
        "",
        "| Surface class | Entries |",
        "|---|---:|",
    ]
    for name, value in counts["per_class"].items():
        lines.append(f"| {name} | {value} |")
    lines += ["", "## Entries per family", "", "| Family | Entries |", "|---|---:|"]
    for name, value in counts["per_family"].items():
        lines.append(f"| `{name}` | {value} |")
    lines += ["", "## Entries per target owner", "", "| Target owner | Entries |", "|---|---:|"]
    for name, value in counts["per_owner"].items():
        lines.append(f"| `{name}` | {value} |")
    lines.append(f"| _unowned_ | {counts['unowned']} |")
    lines += ["", "## Fixture plans", "",
              "A plan is blocked when it would need a secret, live network access, a",
              "production read or a production write. Nothing in the corpus index is a",
              "sanitized capture, so every entry's corpus status is `absent`.",
              "", "| Fixture class | Entries |", "|---|---:|"]
    for name, value in counts["per_fixture_class"].items():
        lines.append(f"| `{name}` | {value} |")
    lines += ["", "## Unowned entries", "",
              "The porting map does not determine a destination for these. Each one is a",
              "finding for the parity-ledger item to resolve, not an omission.", ""]
    by_id = {e["id"]: e for e in document["entries"]}
    for entry_id in document["unowned_entries"]:
        lines.append(f"- `{entry_id}` — {by_id[entry_id]['owner_reason']}")
    lines += ["", "## Unclassified findings", "",
              "Observations that fit none of the seven classes. They are listed rather",
              "than absorbed into the nearest class.", ""]
    for finding in document["unclassified"]:
        lines.append(f"- `{finding['id']}` — {finding['why_no_class']}")
    lines += ["", "## Gaps", "",
              "What the permitted sources do not contain, and what would close each one.",
              "", "| Gap | Kind | What would close it |", "|---|---|---|"]
    for gap in document["gaps"]:
        lines.append(f"| `{gap['id']}` | {gap['kind']} | {gap['needed_to_close']} |")
    lines += ["", "## Cross-source consistency", "",
              "Two documents count the same rows; the checker fails if they stop agreeing.",
              "", "| Measurement | Value |", "|---|---:|"]
    for name, value in counts["cross_source"].items():
        lines.append(f"| {name} | {value} |")
    lines += ["", "## Scope", "",
              "This inventory is evidence for the sanitized fixture corpus item and the",
              "machine-readable parity ledger item. It satisfies neither: it records what",
              "exists and where it is going, captures no fixture and closes no gate.",
              ""]
    return "\n".join(lines)


def write_atomically(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.staging-{os.getpid()}")
    staging.write_text(text)
    os.replace(staging, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="compare the checked-in copy with a fresh build; write nothing")
    parser.add_argument("--root", default=None, help="repository root to build from")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root) if args.root else REPO_ROOT
    try:
        artifacts = Builder(root).build()
    except (InventoryError, SourceError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    stale = []
    for relative, text in artifacts.items():
        path = root / relative
        if not path.exists() or path.read_text() != text:
            stale.append(relative)
        if not args.check:
            write_atomically(path, text)

    if args.check:
        if stale:
            print("FAIL: the checked-in inventory is not what its sources generate: "
                  + ", ".join(stale), file=sys.stderr)
            return 1
        print(f"ok — {len(artifacts)} generated file(s) match a fresh build")
        return 0

    print(f"wrote {len(artifacts)} file(s) under {OUTPUT_DIR}"
          + (f" ({len(stale)} changed)" if stale else " (no change)"))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT))
    raise SystemExit(main())
