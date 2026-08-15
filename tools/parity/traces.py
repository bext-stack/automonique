#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Export golden parity traces from the shadow-comparison database (M2 #11).

A trace is an ordered file of canonical-JSON lines: one header, then records.
`automonique-daemon/src/parity_trace.rs` owns the format; this tool writes it,
and the two are kept in step by round-tripping the same bytes.

Anonymization happens **at capture**, never at commit review. A raw trace must
not exist in the tree even transiently, so this tool rewrites every workspace
identifier before a byte is written and then re-reads what it produced through
`tools.scrub.scan`. Output that trips a rule is refused and no file is written.

The mapping is *counter-based*, in first-seen order, not a hash of the original.
A one-way hash of a private identifier is still a fingerprint: anyone holding a
guess can confirm it. A counter leaks nothing at all, and it is deterministic
for one export because the rows come out of the database in a fixed order.

    python3 tools/parity/traces.py export --database <path> --scope <scope> \\
        --parity-row <ledger-key> --category <category> --output <directory>
    python3 tools/parity/traces.py verify <trace.cjson> ...

Exit code is non-zero when an export is refused or a trace fails verification,
so CI can branch on it.

# What an exported trace is, and what it is not

The shadow database records *intended actions*. It does not record the inbound
events that provoked them, because retaining raw inbound message content
durably is a separate decision with its own privacy cost and this milestone did
not take it. An exported trace therefore carries both engines' envelopes and no
inbound events: it is a **comparison** trace, replayable offline by
`automonique parity compare`, and it is not a **replay** trace.

`verify` reports which kind a trace is rather than pretending they are the same.
A replay trace — one the hermetic `cargo test` corpus can drive the router from
— additionally carries `inbound-event` records, and the fixtures in
`automonique-daemon/tests/fixtures/parity/` are seeded that way by hand.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.scrub import scan as scrub  # noqa: E402

TRACE_SCHEMA = "automonique.parity-trace/v1"
ENVELOPE_SCHEMA = "automonique.intended-action/v1"

# The closed category vocabulary, exactly as `automonique_protocol::parity`
# fixes it. A trace whose category is outside it cannot be scored, so it is
# refused here rather than at the point a gate decision is being taken.
CATEGORIES = (
    "happy",
    "error",
    "edge",
    "variety",
    "production-representative",
)

ENGINES = ("shadow-candidate", "legacy-observed")

PROVENANCE_CAPTURED = "captured"

# Identifier kinds this tool rewrites, and the synthetic shape each takes. The
# shapes match the grammars the Slack connector's own value types admit, so a
# trace round-trips through the replay's constructors.
SYNTHETIC = {
    "team": "T0TRACE{:04d}",
    "channel": "C0TRACE{:04d}",
    "user": "U0TRACE{:04d}",
    "thread": "17000000{:02d}.000100",
    "event": "Ev{:010d}",
}

MAX_ROWS = 4096


class TraceError(Exception):
    """The export cannot produce a trustworthy trace."""


class Anonymizer:
    """A stable, leak-free rewriting of workspace identifiers.

    One counter per kind, assigned in first-seen order. Nothing derived from
    the original value crosses into the output, so a reader of a trace learns
    how many distinct users appeared and nothing else about any of them.
    """

    def __init__(self) -> None:
        self._assigned: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {kind: 0 for kind in SYNTHETIC}

    def token(self, kind: str, value: str) -> str:
        if kind not in SYNTHETIC:
            raise TraceError(f"no synthetic shape for identifier kind {kind!r}")
        key = (kind, value)
        if key not in self._assigned:
            self._counts[kind] += 1
            self._assigned[key] = SYNTHETIC[kind].format(self._counts[kind])
        return self._assigned[key]

    def mapping(self) -> dict[str, str]:
        """Every original spelling and what it became, longest original first.

        Longest first so a rewrite over free text cannot leave a fragment of a
        longer identifier behind when a shorter one is a prefix of it.
        """
        return {
            original: synthetic
            for (_, original), synthetic in sorted(
                self._assigned.items(), key=lambda item: -len(item[0][1])
            )
        }

    def rewrite_text(self, text: str) -> str:
        for original, synthetic in self.mapping().items():
            text = text.replace(original, synthetic)
        return text


def canonical_bytes(value: Any) -> bytes:
    """Encode one value the way `automonique_protocol::wire` does.

    Sorted keys, no insignificant whitespace, integers only. A float is refused
    rather than rounded, because the Rust decoder refuses one outright and a
    trace that cannot be read back is not a trace.
    """
    reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TraceError("a trace cannot carry a floating-point number")
    if isinstance(value, dict):
        for member in value.values():
            reject_floats(member)
    elif isinstance(value, list):
        for member in value:
            reject_floats(member)


def parse_source_key(source_key: str) -> tuple[str, str]:
    """Split `slack:<team>:event:<event-id>` into its two private halves."""
    parts = source_key.split(":")
    if len(parts) != 4 or parts[0] != "slack" or parts[2] != "event":
        raise TraceError("source key is not a Slack event coordinate")
    if not parts[1] or not parts[3]:
        raise TraceError("source key has an empty coordinate")
    return parts[1], parts[3]


# Which member of which action kind names which identifier kind. A member not
# listed here is left alone; a member listed here is always rewritten, so
# adding an action kind without adding its members is a visible omission rather
# than a silent leak.
IDENTIFIER_MEMBERS = {
    "channel": "channel",
    "parent": "thread",
    "message_ts": "thread",
}


def anonymize_action(action: dict[str, Any], anonymizer: Anonymizer) -> dict[str, Any]:
    rewritten: dict[str, Any] = {}
    for member, value in action.items():
        if member == "kind":
            rewritten[member] = value
            continue
        if not isinstance(value, str):
            raise TraceError("an action member is not a string")
        kind = IDENTIFIER_MEMBERS.get(member)
        rewritten[member] = (
            anonymizer.token(kind, value) if kind else anonymizer.rewrite_text(value)
        )
    return rewritten


def anonymize_envelope(
    envelope: dict[str, Any], anonymizer: Anonymizer
) -> dict[str, Any]:
    if envelope.get("schema") != ENVELOPE_SCHEMA:
        raise TraceError("stored envelope declares an unserved schema")
    if envelope.get("engine") not in ENGINES:
        raise TraceError("stored envelope names an unknown engine")
    team, event = parse_source_key(str(envelope["source_key"]))
    action = envelope.get("action")
    if not isinstance(action, dict):
        raise TraceError("stored envelope has no action object")
    # The identifiers inside the action are assigned first, so the rewrite of
    # free text below already knows about them.
    rewritten_action = anonymize_action(action, anonymizer)
    return {
        "action": rewritten_action,
        "engine": envelope["engine"],
        "observed_at_ms": envelope["observed_at_ms"],
        "schema": ENVELOPE_SCHEMA,
        "scope": envelope["scope"],
        "sequence": envelope["sequence"],
        "source_key": "slack:{}:event:{}".format(
            anonymizer.token("team", team), anonymizer.token("event", event)
        ),
    }


def read_envelopes(database: pathlib.Path, scope: str) -> list[dict[str, Any]]:
    if not database.is_file():
        raise TraceError(f"no shadow database at {database}")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT envelope FROM intended_actions WHERE scope = ? "
            "ORDER BY source_key, sequence, engine",
            (scope,),
        ).fetchall()
    finally:
        connection.close()
    if not rows:
        raise TraceError(f"no recorded envelopes for scope {scope!r}")
    if len(rows) > MAX_ROWS:
        raise TraceError(f"scope {scope!r} has more than {MAX_ROWS} envelopes to export")
    envelopes = []
    for (blob,) in rows:
        envelopes.append(json.loads(bytes(blob).decode("utf-8")))
    return envelopes


def build_trace(
    envelopes: list[dict[str, Any]],
    *,
    scope: str,
    parity_row: str,
    category: str,
) -> list[dict[str, Any]]:
    if category not in CATEGORIES:
        raise TraceError(f"category {category!r} is outside the closed vocabulary")
    if not parity_row:
        raise TraceError("a trace must cite the parity row it is evidence for")
    anonymizer = Anonymizer()
    records = [
        {"envelope": anonymize_envelope(envelope, anonymizer), "record": "envelope"}
        for envelope in envelopes
    ]
    teams = sorted(
        {record["envelope"]["source_key"].split(":")[1] for record in records}
    )
    channels = sorted(
        {
            record["envelope"]["action"]["channel"]
            for record in records
            if "channel" in record["envelope"]["action"]
        }
    )
    if len(teams) != 1:
        raise TraceError("a trace covers exactly one workspace")
    header = {
        "category": category,
        "parity_row": parity_row,
        "provenance": PROVENANCE_CAPTURED,
        "schema": TRACE_SCHEMA,
        "scope": scope,
        "workspace": {
            # Nobody's administrator or member list is recoverable from an
            # envelope stream, and inventing one would put a claim in the trace
            # that the capture cannot support. A captured trace declares none,
            # and `verify` reports it as a comparison trace for that reason.
            "admins": [],
            "channel": channels[0] if channels else "",
            "members": [],
            "team": teams[0],
        },
    }
    return [header, *records]


def render(lines: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(line) + b"\n" for line in lines)


def scrub_rules() -> tuple[list[scrub.Rule], bytes | None]:
    """The public synthetic rules, plus the protected bundle when installed.

    A capture on a host that holds the protected bundle is judged by it. A
    capture without it is judged by the synthetic rules alone, which is a
    weaker claim — and `export` says so on success rather than letting a
    passing run read as proof that no private identifier was written.
    """
    rules = scrub.parse_rules(
        scrub.read_json(scrub.PUBLIC_RULES),
        expected_algorithm="sha256",
        require_families=True,
    )
    protected, key = scrub.protected_rules_from_environment(
        dict(__import__("os").environ),
        rules_variable="AUTOMONIQUE_SCRUB_PROTECTED_RULES_B64",
        key_variable="AUTOMONIQUE_SCRUB_HMAC_KEY_B64",
        required=False,
    )
    return rules + protected, key


def refuse_unscrubbed(payload: bytes, *, location: str) -> None:
    """Refuse a payload any installed rule matches.

    The findings are counted and their rule identifiers named; the matched
    bytes are never echoed, because a refusal that printed the value would put
    it in a terminal, a log and a CI transcript.
    """
    rules, key = scrub_rules()
    findings = scrub.scan_bytes(
        payload,
        source="trace",
        location=location,
        groups=scrub.grouped_rules(rules),
        hmac_key=key,
    )
    if findings:
        matched = sorted({finding.rule_id for finding in findings})
        raise TraceError(
            f"refusing to write {location}: {len(findings)} scrub finding(s) "
            f"from {', '.join(matched)}"
        )


def export(arguments: argparse.Namespace) -> int:
    envelopes = read_envelopes(arguments.database, arguments.scope)
    lines = build_trace(
        envelopes,
        scope=arguments.scope,
        parity_row=arguments.parity_row,
        category=arguments.category,
    )
    payload = render(lines)
    destination = arguments.output / f"{arguments.name}.cjson"
    refuse_unscrubbed(payload, location=str(destination))
    arguments.output.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    _, key = scrub_rules()
    claim = (
        "scanned with the protected rule bundle"
        if key is not None
        else "scanned with the public synthetic rules only, which is evidence "
        "the scanner ran rather than that no private identifier was written"
    )
    print(f"ok — wrote {destination} ({len(lines) - 1} record(s)); {claim}")
    return 0


def verify_lines(payload: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    text = payload.decode("utf-8")
    lines = [line for line in text.split("\n") if line]
    if not lines:
        raise TraceError("trace has no header line")
    parsed = []
    for number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"line {number} is not JSON") from exc
        if canonical_bytes(value).decode("utf-8") != line:
            raise TraceError(f"line {number} is not canonical")
        parsed.append(value)
    header, *records = parsed
    if header.get("schema") != TRACE_SCHEMA:
        raise TraceError("header declares an unserved schema")
    if header.get("category") not in CATEGORIES:
        raise TraceError("header category is outside the closed vocabulary")
    for number, record in enumerate(records, start=2):
        if record.get("record") not in {
            "inbound-event",
            "provider-interaction",
            "envelope",
        }:
            raise TraceError(f"line {number} names an undefined record kind")
    return header, records


def verify(arguments: argparse.Namespace) -> int:
    failures = 0
    for path in arguments.traces:
        payload = path.read_bytes()
        try:
            header, records = verify_lines(payload)
            refuse_unscrubbed(payload, location=str(path))
        except TraceError as exc:
            print(f"FAIL {path}: {exc}")
            failures += 1
            continue
        replayable = any(record["record"] == "inbound-event" for record in records)
        kind = "replay" if replayable else "comparison"
        print(
            f"ok — {path}: {kind} trace, {len(records)} record(s), "
            f"category {header['category']}, row {header['parity_row']}"
        )
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subcommands = parser.add_subparsers(dest="command", required=True)

    exporter = subcommands.add_parser("export", help="capture one scope's envelopes")
    exporter.add_argument("--database", type=pathlib.Path, required=True)
    exporter.add_argument("--scope", required=True)
    exporter.add_argument("--parity-row", required=True)
    exporter.add_argument("--category", required=True, choices=CATEGORIES)
    exporter.add_argument("--output", type=pathlib.Path, required=True)
    exporter.add_argument("--name", default="captured")
    exporter.set_defaults(handler=export)

    verifier = subcommands.add_parser("verify", help="check checked-in traces")
    verifier.add_argument("traces", nargs="+", type=pathlib.Path)
    verifier.set_defaults(handler=verify)

    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except TraceError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
