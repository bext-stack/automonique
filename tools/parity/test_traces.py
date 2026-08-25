#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Golden-trace capture: anonymization and canonical form."""

from __future__ import annotations

import json
import pathlib
import sqlite3
import tempfile
import unittest

from tools.parity import traces

SCOPE = "slack-ticket-routing"
ROW = "slack-socket-mode-messages-mentions-threads-commands-and-actions"


def envelope(
    *,
    engine: str = "shadow-candidate",
    sequence: int = 0,
    team: str = "T0PRIVATE1",
    event: str = "Ev0PRIVATE1",
    channel: str = "C0PRIVATE1",
    text: str = "on it",
) -> dict:
    return {
        "action": {
            "channel": channel,
            "kind": "slack-thread-reply",
            "parent": "1723542000.000100",
            "text": text,
        },
        "engine": engine,
        "observed_at_ms": 1_700_000_000_000,
        "schema": traces.ENVELOPE_SCHEMA,
        "scope": SCOPE,
        "sequence": sequence,
        "source_key": f"slack:{team}:event:{event}",
    }


def database(directory: pathlib.Path, envelopes: list[dict]) -> pathlib.Path:
    path = directory / "shadow-comparisons.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE intended_actions ("
        " action_id INTEGER PRIMARY KEY, scope TEXT NOT NULL,"
        " source_key TEXT NOT NULL, engine TEXT NOT NULL,"
        " sequence INTEGER NOT NULL, envelope BLOB NOT NULL,"
        " envelope_digest TEXT NOT NULL, observed_at_ms INTEGER NOT NULL)"
    )
    for index, value in enumerate(envelopes):
        connection.execute(
            "INSERT INTO intended_actions (scope, source_key, engine, sequence,"
            " envelope, envelope_digest, observed_at_ms) VALUES (?,?,?,?,?,?,?)",
            (
                value["scope"],
                value["source_key"],
                value["engine"],
                value["sequence"],
                traces.canonical_bytes(value),
                f"{index:064x}",
                value["observed_at_ms"],
            ),
        )
    connection.commit()
    connection.close()
    return path


class AnonymizerTest(unittest.TestCase):
    def test_the_mapping_is_counter_based_and_leaks_no_original(self) -> None:
        anonymizer = traces.Anonymizer()
        first = anonymizer.token("user", "U0SOMEBODY")
        second = anonymizer.token("user", "U0SOMEBODYELSE")
        self.assertEqual(first, "U0TRACE0001")
        self.assertEqual(second, "U0TRACE0002")
        self.assertNotIn("SOMEBODY", first + second)

    def test_one_original_always_gets_the_same_token(self) -> None:
        anonymizer = traces.Anonymizer()
        self.assertEqual(
            anonymizer.token("channel", "C0X"), anonymizer.token("channel", "C0X")
        )

    def test_kinds_have_separate_counters(self) -> None:
        anonymizer = traces.Anonymizer()
        self.assertEqual(anonymizer.token("team", "A"), "T0TRACE0001")
        self.assertEqual(anonymizer.token("channel", "A"), "C0TRACE0001")

    def test_an_unknown_kind_is_refused_rather_than_passed_through(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.Anonymizer().token("mystery", "value")

    def test_free_text_is_rewritten_longest_original_first(self) -> None:
        anonymizer = traces.Anonymizer()
        anonymizer.token("channel", "C0AB")
        anonymizer.token("channel", "C0ABCD")
        rewritten = anonymizer.rewrite_text("see C0ABCD and C0AB")
        self.assertNotIn("C0ABCD", rewritten)
        self.assertNotIn("C0AB ", rewritten)


class CanonicalFormTest(unittest.TestCase):
    def test_keys_sort_and_whitespace_is_absent(self) -> None:
        self.assertEqual(
            traces.canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}'
        )

    def test_a_float_is_refused_rather_than_rounded(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.canonical_bytes({"latency": 1.5})

    def test_a_nested_float_is_refused_too(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.canonical_bytes({"a": [{"b": 0.5}]})


class SourceKeyTest(unittest.TestCase):
    def test_a_well_formed_key_splits(self) -> None:
        self.assertEqual(
            traces.parse_source_key("slack:T0X:event:Ev0Y"), ("T0X", "Ev0Y")
        )

    def test_a_key_of_another_shape_is_refused(self) -> None:
        for value in ["", "slack:T0X", "telegram:T0X:event:Ev0Y", "slack::event:Ev0Y"]:
            with self.subTest(value=value), self.assertRaises(traces.TraceError):
                traces.parse_source_key(value)


class ExportTest(unittest.TestCase):
    def export(self, envelopes: list[dict], **overrides) -> tuple[int, pathlib.Path]:
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = database(directory, envelopes)
        output = directory / "out"
        argv = [
            "export",
            "--database",
            str(path),
            "--scope",
            overrides.get("scope", SCOPE),
            "--parity-row",
            overrides.get("row", ROW),
            "--category",
            overrides.get("category", "production-representative"),
            "--output",
            str(output),
        ]
        return traces.main(argv), output / "captured.cjson"

    def test_an_export_writes_a_canonical_verifiable_trace(self) -> None:
        code, path = self.export([envelope()])
        self.assertEqual(code, 0)
        header, records = traces.verify_lines(path.read_bytes())
        self.assertEqual(header["schema"], traces.TRACE_SCHEMA)
        self.assertEqual(header["provenance"], "captured")
        self.assertEqual(len(records), 1)

    def test_every_workspace_identifier_is_rewritten(self) -> None:
        _, path = self.export([envelope()])
        payload = path.read_text()
        for private in ["T0PRIVATE1", "Ev0PRIVATE1", "C0PRIVATE1"]:
            self.assertNotIn(private, payload)
        self.assertIn("T0TRACE0001", payload)
        self.assertIn("C0TRACE0001", payload)

    def test_an_empty_scope_is_refused_rather_than_written_empty(self) -> None:
        code, path = self.export([envelope()], scope="not-a-recorded-scope")
        self.assertEqual(code, 1)
        self.assertFalse(path.exists())

    def test_two_workspaces_in_one_scope_are_refused(self) -> None:
        code, _ = self.export(
            [envelope(team="T0PRIVATE1"), envelope(team="T0PRIVATE2", sequence=1)]
        )
        self.assertEqual(code, 1)

    def test_an_envelope_of_an_unserved_schema_is_refused(self) -> None:
        stale = envelope()
        stale["schema"] = "automonique.intended-action/v0"
        code, _ = self.export([stale])
        self.assertEqual(code, 1)

    def test_an_unknown_engine_is_refused(self) -> None:
        foreign = envelope()
        foreign["engine"] = "third-engine"
        code, _ = self.export([foreign])
        self.assertEqual(code, 1)

    def test_both_engines_export_together(self) -> None:
        _, path = self.export(
            [
                envelope(engine="shadow-candidate"),
                envelope(engine="legacy-observed", sequence=1),
            ]
        )
        _, records = traces.verify_lines(path.read_bytes())
        engines = sorted(record["envelope"]["engine"] for record in records)
        self.assertEqual(engines, ["legacy-observed", "shadow-candidate"])


class VerifyTest(unittest.TestCase):
    def trace_bytes(self, **overrides) -> bytes:
        header = {
            "category": overrides.get("category", "happy"),
            "parity_row": ROW,
            "provenance": "synthetic",
            "schema": overrides.get("schema", traces.TRACE_SCHEMA),
            "scope": SCOPE,
            "workspace": {
                "admins": [],
                "channel": "C0TRACE0001",
                "members": [],
                "team": "T0TRACE0001",
            },
        }
        records = overrides.get(
            "records", [{"envelope": envelope(), "record": "envelope"}]
        )
        return traces.render([header, *records])

    def test_a_well_formed_trace_verifies(self) -> None:
        header, records = traces.verify_lines(self.trace_bytes())
        self.assertEqual(header["scope"], SCOPE)
        self.assertEqual(len(records), 1)

    def test_a_foreign_schema_is_refused(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.verify_lines(self.trace_bytes(schema="automonique.parity-trace/v2"))

    def test_a_category_outside_the_closed_set_is_refused(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.verify_lines(self.trace_bytes(category="cheerful"))

    def test_an_undefined_record_kind_is_refused(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.verify_lines(self.trace_bytes(records=[{"record": "guess"}]))

    def test_a_non_canonical_line_is_refused(self) -> None:
        payload = self.trace_bytes().decode("utf-8")
        spaced = payload.replace('":', '" :')
        with self.assertRaises(traces.TraceError):
            traces.verify_lines(spaced.encode("utf-8"))

    def test_an_empty_file_is_refused(self) -> None:
        with self.assertRaises(traces.TraceError):
            traces.verify_lines(b"")

    def test_the_checked_in_corpus_verifies_and_is_replayable(self) -> None:
        corpus = (
            traces.ROOT
            / "rust/crates/automonique-daemon/tests/fixtures/parity"
        )
        fixtures = sorted(corpus.rglob("*.cjson"))
        self.assertTrue(fixtures, "the corpus must not be empty")
        for path in fixtures:
            with self.subTest(fixture=path.name):
                payload = path.read_bytes()
                _, records = traces.verify_lines(payload)
                self.assertTrue(
                    any(record["record"] == "inbound-event" for record in records),
                    "a corpus fixture must be replayable",
                )


if __name__ == "__main__":
    unittest.main()
