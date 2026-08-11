#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Derive the machine-readable parity ledger and drift-check it (R0-08).

`docs/product-plan/reference/feature-parity.md` is the human record of what the
rewrite must preserve, replace or isolate. Prose cannot be queried and cannot be
refused, so this derives the same content as data: one entry per parity row,
each carrying exactly one status from a closed vocabulary, an owner, a fixture
reference and an evidence reference, or `null` with a reason.

Nothing here reclassifies a row. Status comes from the leading directive of the
row's own "Decision and acceptance" cell; a cell whose directive is outside the
closed set produces an explicit *unclassified* entry and a finding, never a
nearest-match guess. The 2026-08-09 owner decision is carried as cited data
read out of the Fixture column, and the generator refuses a row where the
citation and the decision cell disagree.

    python3 tools/parity/ledger.py            # verify the checked-in ledger
    python3 tools/parity/ledger.py --summary  # verify and print measured counts
    python3 tools/parity/ledger.py --write    # regenerate plan/ledgers/parity.json

Exit code is non-zero when the ledger and its Markdown source disagree, or when
any ledger invariant fails, so CI can branch on it. Wiring this into
`plan/check.py` is the follow-up the integrator performs; the module is
self-contained and standalone-runnable so that wiring is a one-line call to
`tools.parity.ledger.main()`.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "plan"))

import baseline as bl  # noqa: E402
from tools.scrub import scan as scrub  # noqa: E402

SOURCE = bl.PARITY_LEDGER
LEDGER = ROOT / "plan/ledgers/parity.json"

SCHEMA = "automonique.parity-ledger/v1"
LICENCE = "Elastic-2.0"

# The closed status vocabulary, exactly as `plan/contracts/R0-08.md` fixes it.
# A row that fits none of these is recorded unclassified; it is never coerced.
STATUSES = ("preserve", "replace", "isolate", "retire only by decision")

# Closed evidence vocabulary. `unstated` is for an entry the source records
# without an Evidence cell at all — it is a distinct fact from "no fixture".
EVIDENCE_STATES = ("pinned", "partial", "none", "unstated")

# Closed finding vocabulary. A finding is a property of the source document
# that the ledger records rather than repairs.
FINDING_KINDS = (
    "unclassified-status",
    "unclassified-evidence-state",
    "declared-count-divergence",
    "surface-without-row",
)

ORIGINS = ("table-row", "section-decision")

# Longest alternative first: a bare `retire` is not `retire only by decision`
# and must not be silently promoted to it.
DIRECTIVE = re.compile(
    r"^(retire only by decision|preserve|replace|isolate|retire)\b", re.I)
EVIDENCE_PHRASE = re.compile(r"^(pinned|partial|no fixture)\b", re.I)
# The Fixture cell is how the 2026-08-09 owner decision reaches a row.
DECISION_CITATION = re.compile(r"replace by decision (\d{4}-\d{2}-\d{2})\b")
DECLARED_COUNTS = re.compile(
    r"Of (?P<total>\d+) rows: \*\*(?P<pinned>\d+) are fully pinned, "
    r"(?P<partial>\d+) are partially pinned, and (?P<none>\d+) have no "
    r"behavioral evidence at all\.\*\*")
DECISION_HEADING = re.compile(
    r"^## Owner decision, (?P<date>\d{4}-\d{2}-\d{2}) — ", re.M)
# A prose section states its disposition on a line of exactly this shape. The
# tables' "Decision and acceptance" column and this line are the only two
# places the source declares a disposition, so they are the only two the
# generator reads.
SECTION_DECISION = re.compile(r"^Decision: \*\*(?P<text>.+)\*\*$")
HEADING = re.compile(r"^## (?P<title>.+?)\s*$")
SEPARATOR = set("-: ")

# Rows counted at keying time. A parity row may be added; one disappearing is
# the silent removal the contract forbids, so the floor never moves down
# without an explicit edit here.
TABLE_ROWS_AT_KEYING = 39

# The surfaces `plan/contracts/R0-08.md` § Objective names explicitly. Each
# must resolve to a ledger entry by key, so renaming or deleting one of them
# fails rather than quietly shrinking coverage. A surface the source carries no
# derivable entry for is declared here as a gap with its reason, and is
# reported as a finding on every run — it is never satisfied by silence.
SURFACES: tuple[tuple[str, tuple[str, ...], str | None], ...] = (
    ("client portal", ("client-request-portal",), None),
    ("client publication",
     ("internal-raw-agent-output-versus-staff-published-client-reply",), None),
    ("audits", (),
     "the source discusses audits only in the prose section 'Reconciliation "
     "and audits', which carries no Decision line and no owner, fixture or "
     "evidence cell, so no entry can be derived without inventing one"),
    ("live feed",
     ("live-slack-channel-feed-and-legacy-post-as-the-assistant-behavior",),
     None),
    ("notifications",
     ("dedicated-deployment-notifications-channel",
      "browser-desktop-notifications"), None),
    ("targets", ("learned-domain-to-server-targets",), None),
    ("operational commands",
     ("canonical-direct-command-registry-aliases-help-slack-presets-and-"
      "telegram-setmycommands",
      "ops-command-proposal-classification"), None),
)


class LedgerError(Exception):
    """The ledger cannot be derived, parsed or trusted."""


@dataclasses.dataclass(frozen=True)
class Cell:
    """One Markdown table row, with the line it came from."""

    line: int
    section: str
    cells: tuple[str, ...]


def relative(path: pathlib.Path) -> str:
    """A repository-relative path, or the absolute one for a path outside it."""
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def slug(text: str) -> str:
    """A stable key for an entry, derived from its capability text."""
    plain = text.replace("`", "").replace("*", "").replace("’", "").replace("“", "")
    plain = plain.replace("”", "")
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", plain.lower())).strip("-")


def read_source(source: pathlib.Path) -> list[str]:
    try:
        return source.read_text().splitlines()
    except OSError as exc:                                    # pragma: no cover
        raise LedgerError(f"cannot read the parity source: {exc}") from exc


PARITY_HEADER = ("current capability", "target owner",
                 "decision and acceptance", "fixture", "evidence")


def parity_rows(lines: list[str]) -> list[Cell]:
    """Data rows of every table whose header is exactly the parity header.

    Header matching is exact rather than fuzzy on purpose: a table that gains
    or loses a column stops being a parity table and its rows vanish, which the
    row-coverage floor then reports. A substring match would quietly absorb the
    change.
    """
    keep: list[Cell] = []
    current_header: tuple[str, ...] | None = None
    after_separator = False
    section = ""
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        heading = HEADING.match(line)
        if heading:
            section = heading.group("title")
        if not stripped.startswith("|"):
            current_header, after_separator = None, False
            continue
        cells = tuple(c.strip() for c in stripped.strip("|").split("|"))
        if set("".join(cells)) <= SEPARATOR:
            after_separator = True
            continue
        if current_header is None:
            current_header = tuple(c.lower() for c in cells)
            continue
        if not after_separator or current_header != PARITY_HEADER:
            continue
        if len(cells) != len(PARITY_HEADER):
            raise LedgerError(
                f"line {number} has {len(cells)} cells, expected "
                f"{len(PARITY_HEADER)}; a parity row cannot be read")
        keep.append(Cell(number, section, cells))
    return keep


def section_decisions(lines: list[str]) -> list[Cell]:
    """Prose sections that state a disposition on a `Decision: **…**` line."""
    found: list[Cell] = []
    section = ""
    for number, line in enumerate(lines, start=1):
        heading = HEADING.match(line)
        if heading:
            section = heading.group("title")
            continue
        stated = SECTION_DECISION.match(line)
        if stated:
            found.append(Cell(number, section, (stated.group("text"),)))
    return found


def directive(cell: str) -> str | None:
    """The leading status directive of a decision cell, or None."""
    plain = cell.replace("**", "").strip()
    match = DIRECTIVE.match(plain)
    if not match:
        return None
    token = match.group(1).lower()
    return token if token in STATUSES else None


def evidence_state(cell: str) -> str | None:
    plain = cell.replace("**", "").strip()
    match = EVIDENCE_PHRASE.match(plain)
    if not match:
        return None
    return {"pinned": "pinned", "partial": "partial",
            "no fixture": "none"}[match.group(1).lower()]


def owner_decision(lines: list[str],
                   source: pathlib.Path = SOURCE) -> dict:
    """The 2026-08-09 owner decision, read out of the source as data.

    The citation is a path, a line and the verbatim heading — not a
    hand-written anchor. `check_drift_reverse` re-reads that line, so a
    citation that stops pointing at the decision fails instead of rotting.
    """
    heading_line = 0
    date = ""
    for number, line in enumerate(lines, start=1):
        match = DECISION_HEADING.match(line)
        if match:
            heading_line, date = number, match.group("date")
            break
    declared = DECLARED_COUNTS.search(" ".join("\n".join(lines).split()))
    if not heading_line or declared is None:
        raise LedgerError(
            "the parity source no longer states the owner decision and its "
            "declared row counts in the shape the ledger cites; the ledger "
            "will not re-derive them")
    return {
        "id": f"owner-decision-{date}",
        "date": date,
        "cites": {
            "document": relative(source),
            "line": heading_line,
            "heading": lines[heading_line - 1].removeprefix("## ").strip(),
        },
        "declared_counts": {
            "rows": int(declared.group("total")),
            "pinned": int(declared.group("pinned")),
            "partial": int(declared.group("partial")),
            "none": int(declared.group("none")),
        },
        "effect": "rows whose Fixture cell cites this decision are recorded "
                  "replace by the decision, not by the generator",
    }


def build(source: pathlib.Path = SOURCE) -> dict:
    """Derive the whole ledger document from the Markdown source."""
    lines = read_source(source)
    decision = owner_decision(lines, source)
    decision_id = str(decision["id"])
    decision_date = str(decision["date"])

    entries: list[dict] = []
    findings: list[dict] = []
    seen: dict[str, int] = {}

    for cell in parity_rows(lines):
        capability, owner, decision_cell, fixture_cell, evidence_cell = cell.cells
        key = slug(capability)
        if key in seen:
            raise LedgerError(
                f"{source.name}:{cell.line} repeats the entry key {key!r} "
                f"first seen at line {seen[key]}; a parity row must appear "
                f"exactly once")
        seen[key] = cell.line

        status = directive(decision_cell)
        status_reason = None
        if status is None:
            leading = decision_cell.replace("**", "").strip().split(";")[0]
            status_reason = (
                f"the decision cell opens with {leading[:60]!r}, which is "
                f"outside the closed status vocabulary; classifying it needs "
                f"an owner decision, not a nearest match")
            findings.append({
                "kind": "unclassified-status",
                "subject": key,
                "detail": status_reason,
            })

        state = evidence_state(evidence_cell)
        if state is None:
            findings.append({
                "kind": "unclassified-evidence-state",
                "subject": key,
                "detail": f"the evidence cell opens with "
                          f"{evidence_cell.replace('**', '').strip()[:60]!r}, "
                          f"which is outside {EVIDENCE_STATES}",
            })
            state = "unstated"

        cited = DECISION_CITATION.search(fixture_cell)
        cited_id = None
        if cited:
            if cited.group(1) != decision_date:
                raise LedgerError(
                    f"{source.name}:{cell.line} cites a decision dated "
                    f"{cited.group(1)}, but the source records the owner "
                    f"decision as {decision_date}")
            cited_id = decision_id
            if status != "replace":
                raise LedgerError(
                    f"{source.name}:{cell.line} cites {decision_id}, which "
                    f"reclassifies to replace, but its decision cell reads "
                    f"{status!r}; the generator will not resolve that "
                    f"disagreement on its own")

        has_fixture = state != "none"
        entries.append({
            "key": key,
            "origin": "table-row",
            "section": cell.section,
            "source_line": cell.line,
            "capability": capability,
            "owner": owner or None,
            "owner_reason": None if owner else
                            "the source leaves the Target owner cell empty",
            "decision": decision_cell,
            "status": status,
            "status_reason": status_reason,
            "status_basis": "decision-and-acceptance-cell",
            "decision_ref": cited_id,
            "fixture": {
                "cell": fixture_cell,
                "reference": fixture_cell if has_fixture else None,
                "reason": None if has_fixture else fixture_cell,
            },
            "evidence": {
                "cell": evidence_cell,
                "state": state,
                "reference": evidence_cell if has_fixture else None,
                "reason": None if has_fixture else evidence_cell,
            },
        })

    for cell in section_decisions(lines):
        text = cell.cells[0]
        key = slug(cell.section)
        if key in seen:
            raise LedgerError(
                f"{source.name}:{cell.line} repeats the entry key {key!r}")
        seen[key] = cell.line
        status = directive(text)
        status_reason = None
        if status is None:
            status_reason = (
                f"the section decision opens with "
                f"{text.strip().split(';')[0][:60]!r}, which is outside the "
                f"closed status vocabulary")
            findings.append({
                "kind": "unclassified-status",
                "subject": key,
                "detail": status_reason,
            })
        entries.append({
            "key": key,
            "origin": "section-decision",
            "section": cell.section,
            "source_line": cell.line,
            "capability": cell.section,
            "owner": None,
            "owner_reason": "the source states this disposition in prose, "
                            "which carries no Target owner cell",
            "decision": text,
            "status": status,
            "status_reason": status_reason,
            "status_basis": "section-decision-line",
            "decision_ref": None,
            "fixture": {
                "cell": None,
                "reference": None,
                "reason": "no fixture is named; the source states this "
                          "disposition in prose, which carries no Fixture cell",
            },
            "evidence": {
                "cell": None,
                "state": "unstated",
                "reference": None,
                "reason": "the source states this disposition in prose, which "
                          "carries no Evidence cell",
            },
        })

    table_entries = [e for e in entries if e["origin"] == "table-row"]
    measured = {
        "pinned": sum(1 for e in table_entries if e["evidence"]["state"] == "pinned"),
        "partial": sum(1 for e in table_entries if e["evidence"]["state"] == "partial"),
        "none": sum(1 for e in table_entries if e["evidence"]["state"] == "none"),
    }
    declared = decision["declared_counts"]
    for state in ("pinned", "partial", "none"):
        if declared[state] != measured[state]:
            findings.append({
                "kind": "declared-count-divergence",
                "subject": state,
                "detail": f"{decision_id} declares {declared[state]} "
                          f"{state} row(s); the tables measure "
                          f"{measured[state]}. The measured value is what this "
                          f"ledger records; correcting the prose is an edit to "
                          f"the source document",
            })

    for name, required, gap in SURFACES:
        if not required:
            findings.append({
                "kind": "surface-without-row",
                "subject": name,
                "detail": gap or "no entry could be derived",
            })

    findings.sort(key=lambda f: (FINDING_KINDS.index(f["kind"]), f["subject"]))

    by_status = collections.Counter(
        e["status"] or "unclassified" for e in entries)
    by_state = collections.Counter(e["evidence"]["state"] for e in entries)

    return {
        "schema": SCHEMA,
        "licence": LICENCE,
        "generated_by": "tools/parity/ledger.py",
        "source": relative(source),
        "statuses": list(STATUSES),
        "evidence_states": list(EVIDENCE_STATES),
        "finding_kinds": list(FINDING_KINDS),
        "origins": list(ORIGINS),
        "decisions": [decision],
        "counts": {
            "entries": len(entries),
            "table_rows": len(table_entries),
            "section_decisions": len(entries) - len(table_entries),
            "by_status": {k: by_status.get(k, 0)
                          for k in (*STATUSES, "unclassified")},
            "by_evidence_state": {k: by_state.get(k, 0) for k in EVIDENCE_STATES},
            "covered_by_owner_decision": sum(
                1 for e in entries if e["decision_ref"]),
            "findings": len(findings),
        },
        "subsets": {
            "pinned": sorted(e["key"] for e in table_entries
                             if e["evidence"]["state"] == "pinned"),
            "partial": sorted(e["key"] for e in table_entries
                              if e["evidence"]["state"] == "partial"),
            "unevidenced": sorted(e["key"] for e in table_entries
                                  if e["evidence"]["state"] == "none"),
            "unclassified": sorted(e["key"] for e in entries
                                   if e["status"] is None),
            "covered_by_owner_decision": sorted(
                e["key"] for e in entries if e["decision_ref"]),
        },
        "surfaces": [
            {"surface": name, "entries": list(required), "gap": gap}
            for name, required, gap in SURFACES
        ],
        "findings": findings,
        "entries": sorted(entries, key=lambda e: (e["source_line"], e["key"])),
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False,
                      sort_keys=False) + "\n"


def write(document: dict, ledger: pathlib.Path = LEDGER) -> pathlib.Path:
    """Write the ledger atomically: staging path first, then rename.

    A plain write is readable half-finished. A parallel checker that reads it
    mid-write fails for a reason that has nothing to do with the ledger.
    """
    ledger.parent.mkdir(parents=True, exist_ok=True)
    staging = ledger.with_name(f".{ledger.name}.staging-{os.getpid()}")
    staging.write_text(render(document))
    os.replace(staging, ledger)
    return ledger


def load(ledger: pathlib.Path = LEDGER) -> dict:
    """Read a checked-in ledger, refusing anything outside the vocabulary.

    This is the parse-time refusal the contract asks for: a status, evidence
    state, origin or finding kind that is not in its closed set never becomes a
    ledger value that later code has to cope with.
    """
    try:
        document = json.loads(ledger.read_text())
    except OSError as exc:
        raise LedgerError(f"cannot read {ledger}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LedgerError(f"{ledger} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise LedgerError(f"{ledger} does not carry schema {SCHEMA}")
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        raise LedgerError(f"{ledger} carries no entries")
    for entry in entries:
        if not isinstance(entry, dict):
            raise LedgerError(f"{ledger} carries a non-object entry")
        key = entry.get("key")
        if not isinstance(key, str) or not key:
            raise LedgerError(f"{ledger} carries an entry with no key")
        status = entry.get("status")
        if status is not None and status not in STATUSES:
            raise LedgerError(
                f"{key}: status {status!r} is outside the closed vocabulary "
                f"{STATUSES}; an unrecognised status is refused, never "
                f"passed through")
        if status is None and not entry.get("status_reason"):
            raise LedgerError(
                f"{key}: an unclassified entry must record why, never a bare "
                f"null")
        if entry.get("origin") not in ORIGINS:
            raise LedgerError(f"{key}: origin {entry.get('origin')!r} is "
                              f"outside {ORIGINS}")
        state = entry.get("evidence", {}).get("state")
        if state not in EVIDENCE_STATES:
            raise LedgerError(
                f"{key}: evidence state {state!r} is outside {EVIDENCE_STATES}")
    for finding in document.get("findings", []):
        if not isinstance(finding, dict) or finding.get("kind") not in FINDING_KINDS:
            raise LedgerError(
                f"{ledger} carries a finding outside {FINDING_KINDS}")
    return document


def check_required_fields(document: dict) -> list[str]:
    """Owner, fixture and evidence are present, or null with a reason."""
    problems: list[str] = []
    for entry in document["entries"]:
        key = entry["key"]
        if not entry["capability"]:
            problems.append(f"{key}: capability is empty")
        if not entry["owner"] and not entry["owner_reason"]:
            problems.append(f"{key}: owner is null with no reason")
        if not entry["decision"]:
            problems.append(f"{key}: decision is empty")
        fixture = entry["fixture"]
        if not fixture["reference"] and not fixture["reason"]:
            problems.append(f"{key}: fixture is null with no reason")
        if fixture["reference"] and fixture["reason"]:
            problems.append(f"{key}: fixture records both a reference and a "
                            f"null reason")
        evidence = entry["evidence"]
        if not evidence["reference"] and not evidence["reason"]:
            problems.append(f"{key}: evidence is null with no reason")
        if evidence["state"] in ("none", "unstated") and entry["status"] == "preserve":
            problems.append(
                f"{key}: an entry with no behavioral evidence is spelled "
                f"preserve, which asserts a fidelity nobody measured")
    return problems


def check_decision_provenance(document: dict) -> list[str]:
    """The owner decision is cited data, never re-derived."""
    problems: list[str] = []
    decisions = {d["id"]: d for d in document["decisions"]}
    covered = [e for e in document["entries"] if e["decision_ref"]]
    for entry in covered:
        if entry["decision_ref"] not in decisions:
            problems.append(f"{entry['key']}: cites unknown decision "
                            f"{entry['decision_ref']!r}")
        if entry["status"] != "replace":
            problems.append(
                f"{entry['key']}: cites an owner decision that reclassifies to "
                f"replace but records status {entry['status']!r}")
        if entry["status_basis"] != "decision-and-acceptance-cell":
            problems.append(
                f"{entry['key']}: status basis {entry['status_basis']!r} — a "
                f"covered row still takes its status from its own decision "
                f"cell, so the generator cannot be re-deriving the decision")
    for decision in document["decisions"]:
        declared = decision["declared_counts"]["none"]
        if declared != len(covered):
            problems.append(
                f"{decision['id']} declares {declared} unevidenced row(s) but "
                f"{len(covered)} row(s) cite it")
    return problems


def check_row_coverage(document: dict) -> list[str]:
    """No entry disappears, none is duplicated, every named surface resolves."""
    problems: list[str] = []
    keys = [e["key"] for e in document["entries"]]
    duplicated = sorted({k for k in keys if keys.count(k) > 1})
    if duplicated:
        problems.append("entries appear more than once: " + ", ".join(duplicated))
    table_rows_now = document["counts"]["table_rows"]
    if table_rows_now < TABLE_ROWS_AT_KEYING:
        problems.append(
            f"the ledger has {table_rows_now} table rows but "
            f"{TABLE_ROWS_AT_KEYING} were keyed; a parity row may have been "
            f"silently removed")
    for decision in document["decisions"]:
        declared_total = decision["declared_counts"]["rows"]
        if declared_total != table_rows_now:
            problems.append(
                f"{decision['id']} declares {declared_total} parity rows but "
                f"the tables measure {table_rows_now}")
    present = set(keys)
    for surface in document["surfaces"]:
        missing = [k for k in surface["entries"] if k not in present]
        if missing:
            problems.append(
                f"surface {surface['surface']!r} names entries that are not in "
                f"the ledger: " + ", ".join(missing))
        if not surface["entries"] and not surface["gap"]:
            problems.append(
                f"surface {surface['surface']!r} resolves to no entry and "
                f"records no reason")
    return problems


def check_drift_reverse(document: dict,
                        source: pathlib.Path = SOURCE) -> list[str]:
    """The ledger cannot invent an entry: each one re-reads its source line."""
    problems: list[str] = []
    lines = read_source(source)
    for decision in document["decisions"]:
        cites = decision["cites"]
        number = cites["line"]
        if not 1 <= number <= len(lines) or \
                lines[number - 1].strip() != f"## {cites['heading']}":
            problems.append(
                f"{decision['id']}: {source.name}:{number} does not carry the "
                f"heading this citation records")
    for entry in document["entries"]:
        number = entry["source_line"]
        if not 1 <= number <= len(lines):
            problems.append(f"{entry['key']}: source line {number} is outside "
                            f"{source.name}")
            continue
        line = lines[number - 1]
        if entry["origin"] == "table-row":
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            expected = [entry["capability"], entry["owner"] or "",
                        entry["decision"], entry["fixture"]["cell"] or "",
                        entry["evidence"]["cell"] or ""]
            if not line.strip().startswith("|") or cells != expected:
                problems.append(
                    f"{entry['key']}: {source.name}:{number} does not carry "
                    f"the cells this entry records")
        else:
            stated = SECTION_DECISION.match(line)
            if stated is None or stated.group("text") != entry["decision"]:
                problems.append(
                    f"{entry['key']}: {source.name}:{number} does not carry "
                    f"the decision this entry records")
    return problems


def check_parser_agreement(document: dict,
                           source: pathlib.Path = SOURCE) -> list[str]:
    """Cross-check against `plan/baseline.py`'s independent table parser.

    Two parsers written from the same document is a weak control if one copies
    the other. This one does not: `plan/baseline.py` is the counter the gate
    reads, and it walks the file with different code. If they disagree about
    how many parity rows exist, one of them is wrong and the ledger says so
    instead of averaging them.
    """
    baseline_rows = sum(
        len(rows) for header, rows in bl.parse_tables(source)
        if "current capability" in header)
    ours = document["counts"]["table_rows"]
    if baseline_rows != ours:
        return [f"plan/baseline.py reads {baseline_rows} parity row(s); this "
                f"ledger records {ours}"]
    return []


def check_publication_hygiene(text: str) -> list[str]:
    """No fingerprinted third-party or private value reaches the ledger.

    The rules are the repository's own scrub fingerprints, so this is the same
    mechanism `tools/scrub/scan.py` runs — public synthetic rules here, plus
    protected rules in the publication job. The value is never printed.
    """
    rules = scrub.parse_rules(
        scrub.read_json(scrub.PUBLIC_RULES),
        expected_algorithm="sha256", require_families=True)
    findings = scrub.scan_bytes(
        text.encode(), source="parity-ledger",
        location=relative(LEDGER),
        groups=scrub.grouped_rules(rules), hmac_key=None)
    return [f"generated ledger matches scrub rule {f.rule_id} at line {f.line}"
            for f in findings]


def verify(source: pathlib.Path = SOURCE,
           ledger: pathlib.Path = LEDGER) -> tuple[dict, list[str]]:
    """Every ledger invariant. Returns the loaded document and its problems."""
    if not ledger.exists():
        raise LedgerError(
            f"{ledger} is missing — run 'python3 tools/parity/ledger.py --write'")
    document = load(ledger)
    problems: list[str] = []

    regenerated = render(build(source))
    if ledger.read_text() != regenerated:
        problems.append(
            f"{relative(ledger)} does not match what "
            f"{relative(source)} derives; a row was edited "
            f"in one place and not the other. Run "
            f"'python3 tools/parity/ledger.py --write' and commit the result")

    problems += check_drift_reverse(document, source)
    problems += check_parser_agreement(document, source)
    problems += check_row_coverage(document)
    problems += check_required_fields(document)
    problems += check_decision_provenance(document)
    problems += check_publication_hygiene(ledger.read_text())
    return document, problems


def summarise(document: dict) -> list[str]:
    counts = document["counts"]
    out = [f"  entries {counts['entries']} "
           f"({counts['table_rows']} table rows, "
           f"{counts['section_decisions']} section decisions)"]
    out.append("  by status")
    for status, number in counts["by_status"].items():
        out.append(f"    {status:<24} {number:>3}")
    out.append("  by evidence state")
    for state, number in counts["by_evidence_state"].items():
        out.append(f"    {state:<24} {number:>3}")
    out.append(f"  covered by owner decision  "
               f"{counts['covered_by_owner_decision']}")
    for name in ("pinned", "partial", "unevidenced", "unclassified"):
        members = document["subsets"][name]
        out.append(f"  {name} ({len(members)}):")
        for key in members:
            out.append(f"    {key}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true",
                        help="regenerate the ledger from its Markdown source")
    parser.add_argument("--summary", action="store_true",
                        help="print measured counts and named subsets")
    arguments = parser.parse_args(argv)

    try:
        if arguments.write:
            path = write(build())
            print(f"wrote {relative(path)}")
        document, problems = verify()
    except LedgerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        print(f"\nparity ledger: FAIL ({len(problems)} problem(s))",
              file=sys.stderr)
        return 1

    counts = document["counts"]
    print(f"ok — {counts['entries']} parity entries, "
          f"{counts['covered_by_owner_decision']} covered by owner decision, "
          f"{counts['findings']} open finding(s)")
    for finding in document["findings"]:
        print(f"finding: {finding['kind']} [{finding['subject']}] "
              f"{finding['detail']}")
    if arguments.summary:
        for line in summarise(document):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
