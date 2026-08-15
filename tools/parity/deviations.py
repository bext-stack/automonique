#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Derive the known-deviation registry and drift-check it (M2 #12).

`docs/product-plan/reference/known-deviations.md` is the human record of every
difference between the two engines that somebody investigated and accepted.
Prose cannot be queried and cannot be refused, so this derives the same content
as data: one entry per registered row, each carrying an identifier, a scope, an
action kind, a comparison field, a relation and a reason drawn from closed
vocabularies, with an owner and a date.

Nothing here reclassifies a row and nothing here invents one. A cell outside a
closed vocabulary is a refusal, not a nearest match: the Rust comparator matches
a difference against an entry by exact spelling, so an entry this tool passed
through unchecked would be an entry that silently never matches and a mismatch
that silently stays a regression.

    python3 tools/parity/deviations.py            # verify the checked-in ledger
    python3 tools/parity/deviations.py --summary  # verify and print counts
    python3 tools/parity/deviations.py --write    # regenerate the ledger

Exit code is non-zero when the ledger and its Markdown source disagree, or when
any registry invariant fails, so CI can branch on it.

# Why the empty registry is the interesting case

The registry ships empty. That is the correct posture — no
production-representative comparison has been run yet, so nothing has been
investigated and accepted — and it means the failure mode this tool has to get
right is not "a bad row" but "a row that appears without anybody noticing". The
drift check is therefore total: the ledger is regenerated from the source on
every run and compared byte for byte, so a hand-edited ledger fails whether it
gained a row or lost one.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.scrub import scan as scrub  # noqa: E402

SOURCE = ROOT / "docs/product-plan/reference/known-deviations.md"
LEDGER = ROOT / "plan/ledgers/deviations.json"

SCHEMA = "automonique.parity-deviations-ledger/v1"
LICENCE = "Elastic-2.0"

# The closed vocabularies, exactly as `automonique_protocol::parity` defines
# them. Restated here rather than imported because this tool has no Rust to call
# into; `test_deviations.py` pins each list against the Rust source so the two
# cannot drift apart silently.
ACTION_KINDS = (
    "slack-thread-reply",
    "slack-channel-post",
    "slack-approval-card",
    "slack-decision-update",
    "ticket-dispatch",
    "ticket-confirm",
    "ticket-decision",
    "telegram-send",
    "github-issue-action",
    "support-email-send",
    "no-action",
)

FIELDS = (
    "state_transition",
    "action_effect",
    "receipt",
    "receipt_timestamp",
    "rendered_message",
    "provider_event",
    "provider_event_id",
    "resource_class",
)

RELATIONS = (
    "value_differs",
    "absent_in_candidate",
    "absent_in_reference",
    "type_differs",
    "order_differs",
    "masked_nondeterministic",
)

REASONS = ("bug-fix", "deliberate-improvement")

# Fields `tools/oracle/fields.json` registers approved-nondeterministic. The
# comparator masks these before comparing, so a difference on one cannot occur
# and a row registering one explains nothing.
MASKED_FIELDS = ("receipt_timestamp", "provider_event_id")

# Closed finding vocabulary. A finding is a property of the source document that
# the ledger records rather than repairs.
FINDING_KINDS = (
    "masked-field-registered",
    "deviation-without-rationale",
)

COLUMNS = (
    "Id",
    "Scope",
    "Action kind",
    "Field",
    "Relation",
    "Reason",
    "Owner",
    "Date",
    "Rationale",
)

IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
SCOPE = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
HEADING = re.compile(r"^## (?P<title>.+?)\s*$")
SEPARATOR = set("-: ")

REGISTRY_HEADING = "Registered deviations"


class DeviationError(Exception):
    """The registry cannot be derived, parsed or trusted."""


def relative(path: pathlib.Path) -> str:
    """A repository-relative spelling, or the path itself when it is outside.

    Tests drive this tool over documents in a temporary directory, and a path
    outside the tree is a legitimate input rather than an error to raise from a
    formatting helper.
    """
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise DeviationError("a table row must be delimited by pipes")
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def registry_rows(text: str) -> list[list[str]]:
    """The rows of the one table under the registry heading.

    Located by heading rather than by position, and the heading must occur
    exactly once: a document that grew a second registry table would otherwise
    have half of it derived and half of it ignored.
    """
    lines = text.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if (match := HEADING.match(line)) and match.group("title") == REGISTRY_HEADING
    ]
    if len(starts) != 1:
        raise DeviationError(
            f"the source must contain exactly one '## {REGISTRY_HEADING}' heading"
        )
    body = lines[starts[0] + 1 :]
    header_index = next(
        (
            index
            for index, line in enumerate(body)
            if line.strip().startswith("|")
        ),
        None,
    )
    if header_index is None:
        raise DeviationError("the registry section carries no table")
    header = cells(body[header_index])
    if tuple(header) != COLUMNS:
        raise DeviationError(
            "the registry table's columns are not the ones this tool derives"
        )
    separator = body[header_index + 1] if header_index + 1 < len(body) else ""
    if not separator.strip().startswith("|") or not set(
        separator.strip().replace("|", "")
    ) <= SEPARATOR:
        raise DeviationError("the registry table has no separator row")
    rows = []
    for line in body[header_index + 2 :]:
        if not line.strip().startswith("|"):
            break
        row = cells(line)
        if len(row) != len(COLUMNS):
            raise DeviationError("a registry row has the wrong number of cells")
        rows.append(row)
    return rows


def closed(value: str, admitted: tuple[str, ...], column: str) -> str:
    if value not in admitted:
        raise DeviationError(
            f"{column} value is outside its closed vocabulary; "
            f"admitted: {', '.join(admitted)}"
        )
    return value


def entry(row: list[str]) -> dict:
    identifier, scope, kind, field, relation, reason, owner, date, rationale = row
    if not IDENTIFIER.fullmatch(identifier):
        raise DeviationError("a deviation id must be a lowercase kebab identifier")
    if not SCOPE.fullmatch(scope):
        raise DeviationError("a scope must be a lowercase kebab identifier")
    if not DATE.fullmatch(date):
        raise DeviationError("a date must be an ISO calendar date")
    if not owner:
        raise DeviationError("a deviation must name an owner")
    return {
        "action_kind": closed(kind, ACTION_KINDS, "Action kind"),
        "date": date,
        "field": closed(field, FIELDS, "Field"),
        "id": identifier,
        "owner": owner,
        "rationale": rationale,
        "reason": closed(reason, REASONS, "Reason"),
        "relation": closed(relation, RELATIONS, "Relation"),
        "scope": scope,
    }


def findings(entries: list[dict]) -> list[dict]:
    found = []
    for record in entries:
        if record["field"] in MASKED_FIELDS:
            found.append(
                {
                    "detail": (
                        "the comparator masks this field before comparing, so a "
                        "difference on it cannot occur and this entry explains "
                        "nothing"
                    ),
                    "kind": "masked-field-registered",
                    "subject": record["id"],
                }
            )
        if not record["rationale"]:
            found.append(
                {
                    "detail": (
                        "a registered deviation with no rationale records that "
                        "somebody decided, not what they decided"
                    ),
                    "kind": "deviation-without-rationale",
                    "subject": record["id"],
                }
            )
    return found


def build(source: pathlib.Path = SOURCE) -> dict:
    if not source.is_file():
        raise DeviationError(f"{relative(source)} is missing")
    text = source.read_text()
    rows = registry_rows(text)
    entries = [entry(row) for row in rows]
    identifiers = [record["id"] for record in entries]
    duplicates = sorted({name for name in identifiers if identifiers.count(name) > 1})
    if duplicates:
        raise DeviationError(
            f"the registry names {', '.join(duplicates)} more than once"
        )
    # Sorted by identifier so the ledger's order is a property of the content
    # rather than of the order somebody happened to append rows in — which is
    # also what makes the Rust registry's digest independent of the source's
    # row order.
    entries.sort(key=lambda record: record["id"])
    open_findings = findings(entries)
    return {
        "action_kinds": list(ACTION_KINDS),
        "counts": {
            "entries": len(entries),
            "findings": len(open_findings),
            "by_reason": {
                reason: sum(1 for record in entries if record["reason"] == reason)
                for reason in REASONS
            },
            "by_scope": {
                scope: sum(1 for record in entries if record["scope"] == scope)
                for scope in sorted({record["scope"] for record in entries})
            },
        },
        "entries": entries,
        "fields": list(FIELDS),
        "finding_kinds": list(FINDING_KINDS),
        "findings": open_findings,
        "generated_by": "tools/parity/deviations.py",
        "licence": LICENCE,
        "masked_fields": list(MASKED_FIELDS),
        "reasons": list(REASONS),
        "relations": list(RELATIONS),
        "schema": SCHEMA,
        "source": relative(source),
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def write(document: dict, ledger: pathlib.Path = LEDGER) -> pathlib.Path:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(render(document))
    return ledger


def load(ledger: pathlib.Path) -> dict:
    try:
        document = json.loads(ledger.read_text())
    except json.JSONDecodeError as exc:
        raise DeviationError(f"{relative(ledger)} is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise DeviationError(f"{relative(ledger)} is not a {SCHEMA} document")
    return document


def check_publication_hygiene(text: str, ledger: pathlib.Path) -> list[str]:
    """No fingerprinted third-party or private value reaches the ledger.

    The same mechanism `tools/scrub/scan.py` runs — public synthetic rules here,
    plus protected rules in the publication job. The value is never printed.
    """
    rules = scrub.parse_rules(
        scrub.read_json(scrub.PUBLIC_RULES),
        expected_algorithm="sha256",
        require_families=True,
    )
    matched = scrub.scan_bytes(
        text.encode(),
        source="deviation-registry",
        location=relative(ledger),
        groups=scrub.grouped_rules(rules),
        hmac_key=None,
    )
    return [
        f"generated ledger matches scrub rule {finding.rule_id} at line {finding.line}"
        for finding in matched
    ]


def check_vocabularies(document: dict) -> list[str]:
    """The ledger's declared vocabularies are this build's, member for member.

    A ledger that carried a wider vocabulary than the comparator would let a row
    be written that no comparison can ever match.
    """
    problems = []
    for key, expected in (
        ("action_kinds", ACTION_KINDS),
        ("fields", FIELDS),
        ("relations", RELATIONS),
        ("reasons", REASONS),
        ("masked_fields", MASKED_FIELDS),
        ("finding_kinds", FINDING_KINDS),
    ):
        if document.get(key) != list(expected):
            problems.append(
                f"{key} in the ledger is not the closed vocabulary this build defines"
            )
    return problems


def check_entries(document: dict) -> list[str]:
    problems = []
    entries = document.get("entries")
    if not isinstance(entries, list):
        return ["entries is not a list"]
    required = {
        "action_kind",
        "date",
        "field",
        "id",
        "owner",
        "rationale",
        "reason",
        "relation",
        "scope",
    }
    for record in entries:
        if not isinstance(record, dict) or set(record) != required:
            problems.append("an entry does not carry exactly the derived fields")
            continue
        if record["action_kind"] not in ACTION_KINDS:
            problems.append(f"{record['id']} names an unknown action kind")
        if record["field"] not in FIELDS:
            problems.append(f"{record['id']} names an unknown comparison field")
        if record["relation"] not in RELATIONS:
            problems.append(f"{record['id']} names an unknown relation")
        if record["reason"] not in REASONS:
            problems.append(f"{record['id']} names an unknown reason")
    counts = document.get("counts", {})
    if counts.get("entries") != len(entries):
        problems.append("the ledger's entry count disagrees with its entries")
    return problems


def verify(
    source: pathlib.Path = SOURCE, ledger: pathlib.Path = LEDGER
) -> tuple[dict, list[str]]:
    """Every registry invariant. Returns the loaded document and its problems."""
    if not ledger.exists():
        raise DeviationError(
            f"{relative(ledger)} is missing — run "
            f"'python3 tools/parity/deviations.py --write'"
        )
    document = load(ledger)
    problems: list[str] = []
    if ledger.read_text() != render(build(source)):
        problems.append(
            f"{relative(ledger)} does not match what {relative(source)} derives; "
            f"a row was edited in one place and not the other. Run "
            f"'python3 tools/parity/deviations.py --write' and commit the result"
        )
    problems += check_vocabularies(document)
    problems += check_entries(document)
    problems += check_publication_hygiene(ledger.read_text(), ledger)
    return document, problems


def summarise(document: dict) -> list[str]:
    counts = document["counts"]
    out = [f"  entries {counts['entries']}"]
    out.append("  by reason")
    for reason, number in counts["by_reason"].items():
        out.append(f"    {reason:<24} {number:>3}")
    out.append("  by scope")
    for scope, number in counts["by_scope"].items():
        out.append(f"    {scope:<24} {number:>3}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the ledger from its Markdown source",
    )
    parser.add_argument(
        "--summary", action="store_true", help="print measured counts"
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.write:
            path = write(build())
            print(f"wrote {relative(path)}")
        document, problems = verify()
    except DeviationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        print(
            f"\ndeviation registry: FAIL ({len(problems)} problem(s))", file=sys.stderr
        )
        return 1

    counts = document["counts"]
    print(
        f"ok — {counts['entries']} registered deviation(s), "
        f"{counts['findings']} open finding(s)"
    )
    for finding in document["findings"]:
        print(f"finding: {finding['kind']} [{finding['subject']}] {finding['detail']}")
    if arguments.summary:
        for line in summarise(document):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
