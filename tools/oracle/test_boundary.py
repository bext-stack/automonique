#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Adversarial suite for the parity-oracle boundary.

The boundary is a negative property, so this file is written as an attacker,
not as a demonstration. Every test states the
attack it runs. Attacks that succeed are kept and named, because a residual
channel that is measured is worth more than one that is assumed away —
`TimingChannelTests` and `FilesystemChannelTests` both record successful
attacks against the process, outside the release channel's scope.

Three attack surfaces, weakest assumption last:

* `ReleaseParserTests` — hostile bytes handed straight to the trust transition;
* `HostileCustodyTests` — the whole custody program is the attacker and writes
  what it likes to the release pipe;
* `HostilePluginTests` — a hostile plugin under the cooperative runner.

Every synthetic marker here is invented for this file. Nothing in it is taken
from, or derived from, any prior implementation.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import logging
import os
import pathlib
import random
import subprocess
import sys
import tempfile
import time
import unittest

from tools.oracle import channel
from tools.oracle import check_boundary
from tools.oracle import release
from tools.oracle import scan
from tools.oracle import vocabulary as vocab

# Synthetic taint. If any of these strings reaches a verdict, a log, a stream
# or a rendered line, the boundary has failed.
SOURCE_TEXT = "SYNTHETIC-SOURCE-A7 def route(state, event): return state.step(event)"
CREDENTIAL = "SYNTHETIC-CREDENTIAL-3f9c1d7b0a42"
IDENTIFIER = "SYNTHETIC-PRIVATE-ID-8801-772f"
TAINT = (SOURCE_TEXT, CREDENTIAL, IDENTIFIER)

FAST = channel.ChannelConfig(deadline_seconds=4.0, hold_release=False)


def taint_in(blob: object) -> list[str]:
    """Which markers appear in `blob`, rendered as text."""
    if isinstance(blob, (bytes, bytearray)):
        text = bytes(blob).decode("utf-8", errors="replace")
    else:
        text = str(blob)
    return [marker for marker in TAINT if marker in text]


@contextlib.contextmanager
def captured_fd(fd: int, path: pathlib.Path):
    """Point a real OS descriptor of this process at a file for the duration."""
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(ValueError):
            stream.flush()
    saved = os.dup(fd)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(handle, fd)
    os.close(handle)
    try:
        yield
    finally:
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(ValueError):
                stream.flush()
        os.dup2(saved, fd)
        os.close(saved)


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=0)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(str(record.getMessage()) + " " + str(record.args))


@contextlib.contextmanager
def captured_logging():
    handler = RecordingHandler()
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(0)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


class CustodyFixture:
    """A synthetic custody side: a directory outside the clean repository."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oracle-custody-")
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "credentials.txt").write_text(CREDENTIAL, encoding="utf-8")
        self.registry = vocab.load_registry()

    def close(self) -> None:
        self.temporary.cleanup()

    def script(self, name: str, body: str) -> pathlib.Path:
        path = self.root / name
        path.write_text(body, encoding="utf-8")
        return path

    def plugin(self, body: str) -> pathlib.Path:
        return self.script("custody_plugin.py", body)

    def custody(self, plugin_body: str, *, runner: pathlib.Path | None = None,
                environment_names: tuple[str, ...] = ("PATH", "HOME")) -> channel.Custody:
        return channel.Custody(
            plugin_path=self.plugin(plugin_body),
            working_directory=self.root,
            runner_path=runner if runner is not None else channel.RUNNER,
            environment_names=environment_names,
        )

    def compare(self, custody: channel.Custody, *, fields=("state_transition",),
                config: channel.ChannelConfig = FAST) -> release.Verdict:
        request = channel.Request("synthetic-fixture", tuple(fields))
        return channel.compare(
            request, custody, registry=self.registry, config=config
        )


NULL_PLUGIN = "def observe(request):\n    return {'outcome': 'exact', 'differences': []}\n"


def raw_writer(payload: bytes) -> str:
    """A custody program that writes exactly `payload` to the release pipe."""
    return (
        "import os, sys\n"
        "fd = int(sys.argv[1])\n"
        f"os.write(fd, {payload!r})\n"
    )


def record(outcome: str, differences: list[dict] | object = None,
           schema: str = vocab.RELEASE_SCHEMA, **extra: object) -> bytes:
    body: dict[str, object] = {
        "schema": schema,
        "outcome": outcome,
        "differences": [] if differences is None else differences,
    }
    body.update(extra)
    return json.dumps(body).encode("utf-8")


def difference(field: str, relation: str = "value_differs",
               magnitude: str = "minor") -> dict:
    return {"field": field, "relation": relation, "magnitude": magnitude}


class BoundaryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CustodyFixture()
        self.addCleanup(self.fixture.close)
        self.registry = self.fixture.registry

    def assertClean(self, verdict: release.Verdict, *extra: object) -> None:
        for blob in (verdict, verdict.render(), repr(verdict), *extra):
            found = taint_in(blob)
            self.assertEqual(found, [], f"taint released: {found}")

    def parse(self, raw: bytes | None, **kwargs) -> release.Verdict:
        return release.parse(raw, registry=self.registry, **kwargs)


class ReleaseParserTests(BoundaryTestCase):
    """Attacks handed straight to the trust transition, no process involved."""

    def test_source_text_as_field_name(self) -> None:
        verdict = self.parse(record("unexplained", [difference(SOURCE_TEXT)]))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_FIELD)
        self.assertClean(verdict)

    def test_source_text_as_extra_key(self) -> None:
        verdict = self.parse(record("exact", note=SOURCE_TEXT))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_KEY)
        self.assertClean(verdict)

    def test_source_text_as_extra_difference_key(self) -> None:
        entry = difference("state_transition")
        entry["detail"] = SOURCE_TEXT
        verdict = self.parse(record("unexplained", [entry]))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_KEY)
        self.assertClean(verdict)

    def test_source_text_as_schema(self) -> None:
        verdict = self.parse(record("exact", schema=SOURCE_TEXT))
        self.assertEqual(verdict.refusal, vocab.Refusal.BAD_SCHEMA)
        self.assertClean(verdict)

    def test_raw_source_text_is_not_json(self) -> None:
        verdict = self.parse(SOURCE_TEXT.encode("utf-8"))
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_JSON)
        self.assertClean(verdict)

    def test_duplicate_json_key_last_wins_and_is_refused(self) -> None:
        # `{"outcome":"exact", ... ,"outcome":"<source>"}`: json keeps the last
        # value, so a record that looks legal at the front is still refused.
        raw = (
            '{"schema":"%s","outcome":"exact","differences":[],"outcome":%s}'
            % (vocab.RELEASE_SCHEMA, json.dumps(SOURCE_TEXT))
        ).encode("utf-8")
        verdict = self.parse(raw)
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_OUTCOME)
        self.assertClean(verdict)

    def test_unicode_escaped_field_name(self) -> None:
        escaped = "".join(f"\\u{ord(character):04x}" for character in "state_transition")
        raw = (
            '{"schema":"%s","outcome":"unexplained","differences":'
            '[{"field":"%s","relation":"value_differs","magnitude":"minor"}]}'
            % (vocab.RELEASE_SCHEMA, escaped)
        ).encode("ascii")
        verdict = self.parse(raw)
        # Escaping is not smuggling: it decodes to a registered field and is
        # accepted, but the released string is the registry's object.
        self.assertEqual(verdict.outcome, vocab.Outcome.UNEXPLAINED)
        self.assertIs(verdict.differences[0].field, self.registry.fields[0].field_id)

    def test_whitespace_padded_field_name(self) -> None:
        verdict = self.parse(record("unexplained", [difference(" state_transition")]))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_FIELD)

    def test_precise_size_measurement_is_refused(self) -> None:
        verdict = self.parse(
            record("unexplained", [difference("state_transition", magnitude=4193)])
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_MAGNITUDE)

    def test_precise_timing_has_no_slot_at_all(self) -> None:
        entry = difference("state_transition")
        entry["duration_us"] = 1837
        verdict = self.parse(record("unexplained", [entry]))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_KEY)

    def test_reserved_outcome_cannot_be_asserted_by_the_wire(self) -> None:
        for reserved in ("refused", "timeout"):
            with self.subTest(reserved=reserved):
                verdict = self.parse(record(reserved))
                self.assertEqual(verdict.refusal, vocab.Refusal.RESERVED_OUTCOME)

    def test_oversize_record_is_discarded_whole(self) -> None:
        blob = (SOURCE_TEXT * 400).encode("utf-8")
        self.assertGreater(len(blob), vocab.RECORD_LIMIT)
        verdict = self.parse(blob)
        self.assertEqual(verdict.refusal, vocab.Refusal.OVERSIZE)
        self.assertClean(verdict)

    def test_invalid_utf8_is_refused_without_echo(self) -> None:
        verdict = self.parse(b'{"schema":"x\xff\xfe"}')
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_UTF8)

    def test_empty_and_absent_records(self) -> None:
        self.assertEqual(self.parse(b"").refusal, vocab.Refusal.EMPTY_RECORD)
        self.assertEqual(self.parse(None).refusal, vocab.Refusal.NO_RECORD)

    def test_deep_nesting_does_not_raise(self) -> None:
        verdict = self.parse(b"[" * 2000 + b"]" * 2000)
        self.assertEqual(verdict.outcome, vocab.Outcome.REFUSED)

    def test_duplicate_field_is_refused(self) -> None:
        verdict = self.parse(
            record("unexplained", [difference("receipt"), difference("receipt")])
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.DUPLICATE_FIELD)

    def test_too_many_differences(self) -> None:
        entries = [difference(field.field_id) for field in self.registry.fields]
        entries.append(difference("receipt"))
        verdict = self.parse(record("unexplained", entries))
        self.assertEqual(verdict.refusal, vocab.Refusal.TOO_MANY_DIFFERENCES)

    def test_mask_must_be_registered(self) -> None:
        verdict = self.parse(
            record(
                "equivalent",
                [difference("state_transition", relation="masked_nondeterministic")],
            )
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.MASK_NOT_REGISTERED)
        allowed = self.parse(
            record(
                "equivalent",
                [difference("receipt_timestamp", relation="masked_nondeterministic")],
            )
        )
        self.assertEqual(allowed.outcome, vocab.Outcome.EQUIVALENT)

    def test_outcome_and_differences_must_agree(self) -> None:
        self.assertEqual(
            self.parse(record("exact", [difference("receipt")])).refusal,
            vocab.Refusal.OUTCOME_DIFFERENCES_DISAGREE,
        )
        self.assertEqual(
            self.parse(record("unexplained", [])).refusal,
            vocab.Refusal.OUTCOME_DIFFERENCES_DISAGREE,
        )

    def test_unrequested_field_is_refused(self) -> None:
        verdict = self.parse(
            record("unexplained", [difference("receipt")]),
            requested=("state_transition",),
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.FIELD_NOT_REQUESTED)

    def test_difference_order_is_canonical(self) -> None:
        forward = self.parse(
            record("unexplained", [difference("receipt"), difference("action_effect")])
        )
        backward = self.parse(
            record("unexplained", [difference("action_effect"), difference("receipt")])
        )
        self.assertEqual(forward, backward)

    def test_outcome_only_policy_drops_detail(self) -> None:
        verdict = self.parse(
            record("unexplained", [difference("receipt")]),
            policy=vocab.ReleasePolicy.OUTCOME_ONLY,
        )
        self.assertEqual(verdict.outcome, vocab.Outcome.UNEXPLAINED)
        self.assertEqual(verdict.differences, ())

    def test_released_strings_are_this_side_s_objects(self) -> None:
        verdict = self.parse(record("unexplained", [difference("receipt")]))
        released = verdict.differences[0].field
        registered = self.registry.get("receipt")
        assert registered is not None
        self.assertIs(released, registered.field_id)

    def test_parse_never_raises_on_random_bytes(self) -> None:
        rng = random.Random(20260811)
        corpus = [
            SOURCE_TEXT.encode(), CREDENTIAL.encode(), IDENTIFIER.encode(),
            b'{"schema":"', b'"differences":[', b'{"field":', b'\xff\xfe',
            vocab.RELEASE_SCHEMA.encode(), b'"outcome":"exact"', b'null', b'}]',
        ]
        for _ in range(2000):
            raw = b"".join(rng.choice(corpus) for _ in range(rng.randint(1, 8)))
            verdict = self.parse(raw)
            self.assertIsInstance(verdict, release.Verdict)
            self.assertClean(verdict)


class PositiveControlTests(BoundaryTestCase):
    """A boundary that refuses everything would pass every leak test."""

    def test_a_legitimate_mismatch_crosses(self) -> None:
        verdict = self.parse(
            record(
                "unexplained",
                [difference("state_transition", "type_differs", "major")],
            )
        )
        self.assertEqual(verdict.outcome, vocab.Outcome.UNEXPLAINED)
        self.assertEqual(verdict.differences[0].relation, vocab.Relation.TYPE_DIFFERS)
        self.assertEqual(verdict.differences[0].magnitude, vocab.Magnitude.MAJOR)
        self.assertIn("state_transition", verdict.render())

    def test_every_wire_outcome_is_reachable(self) -> None:
        seen = set()
        for name, outcome in vocab.WIRE_OUTCOMES.items():
            entries = (
                [difference("state_transition")]
                if outcome in vocab.DIFFERENCES_REQUIRED
                else []
            )
            verdict = self.parse(record(name, entries))
            self.assertEqual(verdict.outcome, outcome)
            seen.add(verdict.outcome)
        self.assertEqual(len(seen), len(vocab.WIRE_OUTCOMES))

    def test_a_real_comparison_runs_end_to_end(self) -> None:
        plugin = (
            "def observe(request):\n"
            "    return {'outcome': 'unexplained', 'differences': ["
            "{'field': 'state_transition', 'relation': 'value_differs',"
            " 'magnitude': 'moderate'}]}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.UNEXPLAINED)
        self.assertEqual(len(verdict.differences), 1)

    def test_channel_capacity_bound_holds_by_enumeration(self) -> None:
        """The formula is an upper bound; enumerate a small registry and check."""
        small = vocab.Registry((self.registry.fields[0],))
        reachable = set()
        for outcome in vocab.WIRE_OUTCOMES:
            for relation in [None] + [member.value for member in vocab.Relation]:
                for magnitude in [member.value for member in vocab.Magnitude]:
                    entries = (
                        []
                        if relation is None
                        else [difference(small.fields[0].field_id, relation, magnitude)]
                    )
                    verdict = release.parse(
                        record(outcome, entries), registry=small
                    )
                    if verdict.outcome is not vocab.Outcome.REFUSED:
                        reachable.add(verdict)
        bound = vocab.released_value_count(small, vocab.ReleasePolicy.FIELD_RELATIONS)
        self.assertGreater(len(reachable), 0)
        self.assertLessEqual(len(reachable), bound)


class HostileCustodyTests(BoundaryTestCase):
    """The whole custody program is the attacker and owns the release pipe."""

    def hostile(self, body: str) -> release.Verdict:
        runner = self.fixture.script("hostile_runner.py", body)
        return self.fixture.compare(
            self.fixture.custody(NULL_PLUGIN, runner=runner)
        )

    def test_raw_source_text_on_the_pipe(self) -> None:
        verdict = self.hostile(raw_writer(SOURCE_TEXT.encode()))
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_JSON)
        self.assertClean(verdict)

    def test_credential_smuggled_as_a_field(self) -> None:
        verdict = self.hostile(
            raw_writer(record("unexplained", [difference(CREDENTIAL)]))
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_FIELD)
        self.assertClean(verdict)

    def test_identifier_smuggled_as_an_extra_key(self) -> None:
        verdict = self.hostile(raw_writer(record("exact", subject=IDENTIFIER)))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_KEY)
        self.assertClean(verdict)

    def test_second_record_appended_after_a_legal_one(self) -> None:
        payload = record("exact") + record("exact", note=SOURCE_TEXT)
        verdict = self.hostile(raw_writer(payload))
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_JSON)
        self.assertClean(verdict)

    def test_megabyte_of_source_is_discarded(self) -> None:
        verdict = self.hostile(raw_writer((SOURCE_TEXT * 20000).encode()))
        self.assertEqual(verdict.refusal, vocab.Refusal.OVERSIZE)
        self.assertClean(verdict)

    def test_partial_record_then_immediate_exit(self) -> None:
        body = (
            "import os, sys\n"
            "fd = int(sys.argv[1])\n"
            f"os.write(fd, {json.dumps(SOURCE_TEXT)[:20].encode()!r})\n"
            "os._exit(0)\n"
        )
        verdict = self.hostile(body)
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_JSON)
        self.assertClean(verdict)

    def test_legal_record_then_nonzero_exit_fails_closed(self) -> None:
        body = raw_writer(record("exact")) + "sys.exit(3)\n"
        verdict = self.hostile(body)
        self.assertEqual(verdict.refusal, vocab.Refusal.INSIDE_FAILED)

    def test_crash_mid_comparison_releases_nothing(self) -> None:
        body = (
            "import os, sys\n"
            "fd = int(sys.argv[1])\n"
            f"os.write(fd, {record('exact')!r})\n"
            "os.abort()\n"
        )
        verdict = self.hostile(body)
        self.assertEqual(verdict.refusal, vocab.Refusal.INSIDE_FAILED)
        self.assertClean(verdict)

    def test_silence_is_refused(self) -> None:
        verdict = self.hostile("import sys\n")
        self.assertEqual(verdict.refusal, vocab.Refusal.EMPTY_RECORD)

    def test_hang_is_killed_at_the_deadline(self) -> None:
        body = (
            "import os, sys, time\n"
            "fd = int(sys.argv[1])\n"
            f"os.write(fd, {record('exact')!r})\n"
            "time.sleep(60)\n"
        )
        started = time.monotonic()
        runner = self.fixture.script("hostile_runner.py", body)
        verdict = self.fixture.compare(
            self.fixture.custody(NULL_PLUGIN, runner=runner),
            config=channel.ChannelConfig(deadline_seconds=1.0, hold_release=False),
        )
        elapsed = time.monotonic() - started
        self.assertEqual(verdict.outcome, vocab.Outcome.TIMEOUT)
        self.assertLess(elapsed, 10.0)

    def test_custody_inside_the_clean_repository_is_refused(self) -> None:
        inside = channel.Custody(
            plugin_path=pathlib.Path(__file__),
            working_directory=channel.CLEAN_ROOT,
        )
        self.assertEqual(inside.rejection(), "plugin-inside-clean-root")
        verdict = self.fixture.compare(inside)
        self.assertEqual(verdict.refusal, vocab.Refusal.CUSTODY_REJECTED)


class HostilePluginTests(BoundaryTestCase):
    """A hostile plugin under the cooperative runner."""

    def test_traceback_with_a_path_and_a_source_line(self) -> None:
        plugin = (
            "def observe(request):\n"
            f"    raise RuntimeError({SOURCE_TEXT!r})\n"
        )
        custody = self.fixture.custody(plugin)

        # Positive control: the traceback really does carry the plugin path and
        # the source line when nothing seals it.
        control = self.fixture.root / "control.txt"
        with control.open("wb") as handle:
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import runpy, sys;"
                    "module = runpy.run_path(sys.argv[1]);"
                    "module['observe']({})",
                    str(custody.plugin_path),
                ],
                stdout=handle,
                stderr=handle,
                check=False,
            )
        control_text = control.read_text(encoding="utf-8", errors="replace")
        self.assertIn(SOURCE_TEXT, control_text)
        self.assertIn(str(custody.plugin_path), control_text)

        verdict = self.fixture.compare(custody)
        self.assertEqual(verdict.outcome, vocab.Outcome.ORACLE_ERROR)
        self.assertClean(verdict)
        self.assertNotIn(str(custody.plugin_path), verdict.render())

    def test_plugin_prints_a_credential_to_both_streams(self) -> None:
        plugin = (
            "import os, sys\n"
            "def observe(request):\n"
            f"    print({CREDENTIAL!r})\n"
            f"    sys.stderr.write({CREDENTIAL!r})\n"
            f"    os.write(1, {CREDENTIAL.encode()!r})\n"
            f"    os.write(2, {CREDENTIAL.encode()!r})\n"
            "    return {'outcome': 'exact', 'differences': []}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.EXACT)
        self.assertClean(verdict)

    def test_plugin_sprays_source_across_every_descriptor(self) -> None:
        # The plugin does not know which descriptor is the release pipe, so it
        # writes to all of them. One of those writes lands on the real channel.
        plugin = (
            "import os\n"
            "def observe(request):\n"
            "    for fd in range(0, 32):\n"
            "        try:\n"
            f"            os.write(fd, {SOURCE_TEXT.encode()!r})\n"
            "        except OSError:\n"
            "            pass\n"
            "    return {'outcome': 'exact', 'differences': []}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.refusal, vocab.Refusal.NOT_JSON)
        self.assertClean(verdict)

    def test_plugin_returns_a_private_identifier_as_a_value(self) -> None:
        # There is no value slot in the vocabulary, so the plugin has nowhere
        # to put it: the runner refuses the shape and the parser refuses again.
        plugin = (
            "def observe(request):\n"
            "    return {'outcome': 'unexplained', 'differences': ["
            "{'field': 'receipt', 'relation': 'value_differs',"
            f" 'magnitude': 'minor', 'value': {IDENTIFIER!r}}}]}}\n"
        )
        verdict = self.fixture.compare(
            self.fixture.custody(plugin), fields=("receipt",)
        )
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_KEY)
        self.assertClean(verdict)

    def test_plugin_reads_a_custody_credential_file_and_tries_to_return_it(self) -> None:
        plugin = (
            "import pathlib\n"
            "def observe(request):\n"
            "    secret = pathlib.Path('credentials.txt').read_text()\n"
            "    return {'outcome': 'unexplained', 'differences': ["
            "{'field': secret, 'relation': 'value_differs',"
            " 'magnitude': 'minor'}]}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_FIELD)
        self.assertClean(verdict)

    def test_plugin_returns_a_credential_from_its_environment(self) -> None:
        os.environ["ORACLE_CUSTODY_MATERIAL"] = CREDENTIAL
        self.addCleanup(os.environ.pop, "ORACLE_CUSTODY_MATERIAL", None)
        plugin = (
            "import os\n"
            "def observe(request):\n"
            "    return {'outcome': os.environ.get('ORACLE_CUSTODY_MATERIAL', 'exact'),"
            " 'differences': []}\n"
        )
        custody = self.fixture.custody(
            plugin, environment_names=("PATH", "HOME", "ORACLE_CUSTODY_MATERIAL")
        )
        verdict = self.fixture.compare(custody)
        self.assertEqual(verdict.refusal, vocab.Refusal.UNKNOWN_OUTCOME)
        self.assertClean(verdict)

    def test_credential_shaped_environment_names_are_unrepresentable(self) -> None:
        for name in ("ORACLE_TOKEN", "DB_PASSWORD", "API_SECRET", "PRIVATE_ROOT"):
            with self.subTest(name=name):
                with self.assertRaises(vocab.VocabularyError):
                    channel.Custody(
                        plugin_path=self.fixture.root / "custody_plugin.py",
                        working_directory=self.fixture.root,
                        environment_names=("PATH", name),
                    )

    def test_clean_side_environment_does_not_reach_the_custody_process(self) -> None:
        os.environ["ORACLE_CLEAN_SIDE_MARKER"] = IDENTIFIER
        self.addCleanup(os.environ.pop, "ORACLE_CLEAN_SIDE_MARKER", None)
        plugin = (
            "import json, os, pathlib\n"
            "def observe(request):\n"
            "    pathlib.Path('seen-env.json').write_text(json.dumps(sorted(os.environ)))\n"
            "    return {'outcome': 'exact', 'differences': []}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.EXACT)
        seen = json.loads((self.fixture.root / "seen-env.json").read_text())
        self.assertNotIn("ORACLE_CLEAN_SIDE_MARKER", seen)
        # `LC_CTYPE` is set by the child interpreter itself when it coerces the
        # C locale (PEP 538); it is not inherited. Measured: a child started
        # with `LANG` set has no `LC_CTYPE`, and this side has none to inherit.
        self.assertEqual(
            set(seen) - {"AUTOMONIQUE_ORACLE_PLUGIN", "HOME", "PATH"}, {"LC_CTYPE"}
        )

    def test_plugin_exits_the_process_mid_comparison(self) -> None:
        plugin = (
            "import os\n"
            "def observe(request):\n"
            "    os._exit(0)\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.refusal, vocab.Refusal.EMPTY_RECORD)

    def test_plugin_raises_a_base_exception(self) -> None:
        plugin = (
            "def observe(request):\n"
            f"    raise KeyboardInterrupt({SOURCE_TEXT!r})\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.ORACLE_ERROR)
        self.assertClean(verdict)

    def test_plugin_fails_at_import_time(self) -> None:
        plugin = f"raise SystemExit({SOURCE_TEXT!r})\n"
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.ORACLE_ERROR)
        self.assertClean(verdict)


IMPORT_THE_ORDINARY_WAY = (
    "import importlib.util, sys\n"
    "spec = importlib.util.spec_from_file_location('p', sys.argv[1])\n"
    "module = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(module)\n"
    "sys.stdout.write(module.observe({})['outcome'])\n"
)


def same_length_plugin(outcome: str, width: int) -> str:
    core = (
        "def observe(request):\n"
        f"    return {{'outcome': {outcome!r}, 'differences': []}}"
    )
    return core + " " * (width - len(core) - 1) + "\n"


class PluginFreshnessTests(BoundaryTestCase):
    """A stale compiled copy of the custody plugin must not answer a comparison."""

    def test_a_planted_stale_bytecode_cache_is_ignored(self) -> None:
        width = 96
        first = same_length_plugin("exact", width)
        second = same_length_plugin("input_rejected", width)
        self.assertEqual(len(first), len(second))

        plugin = self.fixture.root / "custody_plugin.py"
        plugin.write_text(first, encoding="utf-8")
        control = subprocess.run(
            [sys.executable, "-c", IMPORT_THE_ORDINARY_WAY, str(plugin)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(control.stdout, "exact")
        cache = list((self.fixture.root / "__pycache__").glob("custody_plugin.*.pyc"))
        self.assertEqual(len(cache), 1, "the ordinary import machinery cached it")

        # Edit of the same length, in the same mtime second: bytecode validity
        # is (mtime seconds, size), so the cache still looks current.
        stamp = plugin.stat().st_mtime
        plugin.write_text(second, encoding="utf-8")
        os.utime(plugin, (stamp, stamp))

        stale = subprocess.run(
            [sys.executable, "-c", IMPORT_THE_ORDINARY_WAY, str(plugin)],
            capture_output=True, text=True, check=False,
        )
        # Positive control: the hazard is real, not hypothetical.
        self.assertEqual(stale.stdout, "exact")

        verdict = self.fixture.compare(
            self.fixture.custody(second)
        )
        self.assertEqual(verdict.outcome, vocab.Outcome.INPUT_REJECTED)

    def test_the_channel_leaves_no_compiled_copy_behind(self) -> None:
        self.fixture.compare(self.fixture.custody(NULL_PLUGIN))
        compiled = sorted(path.name for path in self.fixture.root.rglob("*.pyc"))
        self.assertEqual(compiled, [])


class LogPathTests(BoundaryTestCase):
    """No sink of this process ever sees a pre-strip byte."""

    NOISY_PLUGIN = (
        "import os, sys\n"
        "def observe(request):\n"
        f"    os.write(1, {SOURCE_TEXT.encode()!r})\n"
        f"    os.write(2, {CREDENTIAL.encode()!r})\n"
        f"    sys.stdout.write({IDENTIFIER!r})\n"
        f"    raise RuntimeError({SOURCE_TEXT!r})\n"
    )

    def test_positive_control_the_taint_reaches_inherited_descriptors(self) -> None:
        """Without the channel's sealing, this test would see the leak."""
        custody = self.fixture.custody(self.NOISY_PLUGIN)
        out = self.fixture.root / "control-out.txt"
        err = self.fixture.root / "control-err.txt"
        with captured_fd(1, out), captured_fd(2, err):
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import runpy, sys;"
                    "module = runpy.run_path(sys.argv[1]);"
                    "module['observe']({})",
                    str(custody.plugin_path),
                ],
                check=False,
            )
        seen = taint_in(out.read_bytes() + err.read_bytes())
        self.assertEqual(sorted(seen), sorted(TAINT))

    def test_no_descriptor_log_or_stream_of_this_process_sees_taint(self) -> None:
        custody = self.fixture.custody(self.NOISY_PLUGIN)
        out = self.fixture.root / "boundary-out.txt"
        err = self.fixture.root / "boundary-err.txt"
        with captured_logging() as handler:
            with captured_fd(1, out), captured_fd(2, err):
                verdict = self.fixture.compare(custody)
        self.assertEqual(verdict.outcome, vocab.Outcome.ORACLE_ERROR)
        self.assertClean(
            verdict,
            out.read_bytes(),
            err.read_bytes(),
            "\n".join(handler.lines),
        )

    def test_a_custody_program_that_never_seals_cannot_reach_this_process(self) -> None:
        """The channel's own sealing, isolated from the runner's.

        Found by mutation: removing `stdout=DEVNULL, stderr=DEVNULL` from
        `channel.compare` failed no test, because the cooperative runner seals
        those descriptors itself. The runner is untrusted, so a test that
        depends on it measures nothing. This one uses a custody program that
        never seals, leaving `channel.py` as the only thing in the way.
        """
        body = (
            "import os, sys\n"
            "fd = int(sys.argv[1])\n"
            f"os.write(1, {SOURCE_TEXT.encode()!r})\n"
            f"os.write(2, {CREDENTIAL.encode()!r})\n"
            f"sys.stdout.write({IDENTIFIER!r})\n"
            "sys.stdout.flush()\n"
            f"os.write(fd, {record('exact')!r})\n"
        )
        runner = self.fixture.script("unsealed_runner.py", body)
        custody = self.fixture.custody(NULL_PLUGIN, runner=runner)

        # Two files, not one: two descriptors pointed at the same path keep
        # independent offsets and silently overwrite each other.
        control_out = self.fixture.root / "unsealed-control-out.txt"
        control_err = self.fixture.root / "unsealed-control-err.txt"
        with captured_fd(1, control_out), captured_fd(2, control_err):
            # Positive control: with descriptors inherited, the taint lands in
            # this process's own output. The test can see the failure it claims.
            read_fd, write_fd = os.pipe()
            try:
                subprocess.run(
                    [sys.executable, "-I", "-B", str(runner), str(write_fd), "{}"],
                    pass_fds=(write_fd,), check=False,
                )
            finally:
                os.close(write_fd)
                os.close(read_fd)
        self.assertEqual(
            sorted(taint_in(control_out.read_bytes() + control_err.read_bytes())),
            sorted(TAINT),
        )

        out = self.fixture.root / "sealed-out.txt"
        err = self.fixture.root / "sealed-err.txt"
        with captured_fd(1, out), captured_fd(2, err):
            verdict = self.fixture.compare(custody)
        self.assertEqual(verdict.outcome, vocab.Outcome.EXACT)
        self.assertClean(verdict, out.read_bytes(), err.read_bytes())

    def test_the_trust_transition_has_no_sink_and_no_debug_switch(self) -> None:
        findings = audit_module_sources()
        self.assertEqual(findings, [], f"raw-byte path has a sink: {findings}")

    def test_the_source_audit_can_fail(self) -> None:
        """Positive control for the audit: a planted sink must be found."""
        planted = (
            "import logging, os\n"
            "def parse(raw):\n"
            "    try:\n"
            "        return decode(raw)\n"
            "    except ValueError as exc:\n"
            "        if os.environ.get('ORACLE_DEBUG'):\n"
            "            print(raw)\n"
            "        logging.getLogger().error('%s', exc)\n"
            "        return None\n"
        )
        findings = audit_source("planted.py", planted)
        self.assertEqual(
            sorted({finding.split(":")[1] for finding in findings}),
            ["bound-exception", "environment", "logging-import", "logging-use", "print"],
        )
        permitted = audit_source("planted.py", planted, environment_allowed=True)
        self.assertNotIn("planted.py:environment", permitted)

    def test_debug_environment_variables_change_nothing(self) -> None:
        noisy = {
            "AUTOMONIQUE_ORACLE_DEBUG": "1",
            "ORACLE_DEBUG": "1",
            "DEBUG": "1",
            "VERBOSE": "1",
            "AUTOMONIQUE_ORACLE_RAW": "1",
            "PYTHONVERBOSE": "1",
        }
        for name, value in noisy.items():
            os.environ[name] = value
            self.addCleanup(os.environ.pop, name, None)
        verdict = self.fixture.compare(
            self.fixture.custody(self.NOISY_PLUGIN)
        )
        self.assertEqual(verdict.outcome, vocab.Outcome.ORACLE_ERROR)
        self.assertClean(verdict)


class ScanTests(BoundaryTestCase):
    """The content scan is a provenance test, and it is not vacuous."""

    def test_a_forged_verdict_with_equal_strings_is_rejected(self) -> None:
        forged = release.Verdict(
            vocab.Outcome.UNEXPLAINED,
            (
                release.Difference(
                    "".join(["state_", "transition"]),
                    vocab.Relation.VALUE_DIFFERS,
                    vocab.Magnitude.MINOR,
                ),
            ),
        )
        self.assertNotEqual(forged.differences[0].field, "")
        with self.assertRaises(scan.ScanError):
            scan.scan_verdict(forged, self.registry)

    def test_a_rebuilt_verdict_passes(self) -> None:
        verdict = self.parse(record("unexplained", [difference("state_transition")]))
        scan.scan_verdict(verdict, self.registry)

    def test_non_verdict_values_are_rejected(self) -> None:
        for value in ({"outcome": "exact"}, "exact", None, 3):
            with self.subTest(value=value):
                with self.assertRaises(scan.ScanError):
                    scan.scan_verdict(value, self.registry)


class TimingChannelTests(BoundaryTestCase):
    """A residual channel outside the release record. Measured, not assumed."""

    SLEEPER = (
        "import time\n"
        "def observe(request):\n"
        "    time.sleep(__DELAY__)\n"
        "    return {'outcome': 'exact', 'differences': []}\n"
    )

    def elapsed(self, delay: float, hold: bool) -> float:
        plugin = self.SLEEPER.replace("__DELAY__", repr(delay))
        custody = self.fixture.custody(plugin)
        config = channel.ChannelConfig(deadline_seconds=1.5, hold_release=hold)
        started = time.monotonic()
        verdict = self.fixture.compare(custody, config=config)
        self.assertEqual(verdict.outcome, vocab.Outcome.EXACT)
        return time.monotonic() - started

    def test_wall_clock_leaks_a_bit_when_the_release_is_not_held(self) -> None:
        """ATTACK SUCCEEDS. Recorded as residual risk, not as a passing control."""
        quiet = self.elapsed(0.0, hold=False)
        slow = self.elapsed(0.8, hold=False)
        self.assertGreater(slow - quiet, 0.4)

    def test_holding_the_release_to_the_deadline_closes_it(self) -> None:
        quiet = self.elapsed(0.0, hold=True)
        slow = self.elapsed(0.8, hold=True)
        self.assertLess(abs(slow - quiet), 0.3)
        self.assertGreater(quiet, 1.4)


class FilesystemChannelTests(BoundaryTestCase):
    """A residual channel outside the release channel. Measured, not assumed."""

    def test_the_custody_process_can_still_write_files(self) -> None:
        """ATTACK SUCCEEDS against the process; the boundary owns the channel only.

        The deployment control is in tools/oracle/README.md: the custody
        process must have no writable path any agent can read. This test exists
        so the gap is a measured fact rather than a footnote.
        """
        plugin = (
            "import pathlib\n"
            "def observe(request):\n"
            f"    pathlib.Path('leaked.txt').write_text({SOURCE_TEXT!r})\n"
            "    return {'outcome': 'exact', 'differences': []}\n"
        )
        verdict = self.fixture.compare(self.fixture.custody(plugin))
        self.assertEqual(verdict.outcome, vocab.Outcome.EXACT)
        self.assertClean(verdict)
        leaked = (self.fixture.root / "leaked.txt").read_text()
        self.assertIn(SOURCE_TEXT, leaked)


class RegistryAndDriftTests(unittest.TestCase):
    """The registry is closed, and the generated document cannot go stale."""

    def setUp(self) -> None:
        self.registry = vocab.load_registry()

    def test_registry_refuses_an_unknown_key(self) -> None:
        document = json.loads(vocab.REGISTRY_PATH.read_text())
        document["fields"][0]["note"] = "extra"
        with self.assertRaises(vocab.VocabularyError):
            vocab.parse_registry(document)

    def test_registry_refuses_an_unknown_area(self) -> None:
        document = json.loads(vocab.REGISTRY_PATH.read_text())
        document["fields"][0]["area"] = "anything"
        with self.assertRaises(vocab.VocabularyError):
            vocab.parse_registry(document)

    def test_registry_refuses_a_duplicate_field(self) -> None:
        document = json.loads(vocab.REGISTRY_PATH.read_text())
        document["fields"].append(dict(document["fields"][0]))
        with self.assertRaises(vocab.VocabularyError):
            vocab.parse_registry(document)

    def test_registry_refuses_a_non_ascii_description(self) -> None:
        document = json.loads(vocab.REGISTRY_PATH.read_text())
        document["fields"][0]["description"] = "— " + "x" * 200
        with self.assertRaises(vocab.VocabularyError):
            vocab.parse_registry(document)

    def test_checked_in_document_is_current(self) -> None:
        expected = check_boundary.render_document(self.registry)
        self.assertEqual(check_boundary.DOCUMENT.read_text(encoding="utf-8"), expected)

    def test_drift_check_fails_on_a_stale_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = pathlib.Path(directory) / "vocabulary.md"
            staged.write_text("stale\n", encoding="utf-8")
            original = check_boundary.DOCUMENT
            check_boundary.DOCUMENT = staged
            reported = io.StringIO()
            try:
                with contextlib.redirect_stderr(reported):
                    code = check_boundary.main([])
            finally:
                check_boundary.DOCUMENT = original
            self.assertEqual(code, 1)
            self.assertIn("is stale", reported.getvalue())

    def test_drift_check_fails_when_the_document_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = check_boundary.DOCUMENT
            check_boundary.DOCUMENT = pathlib.Path(directory) / "gone.md"
            reported = io.StringIO()
            try:
                with contextlib.redirect_stderr(reported):
                    code = check_boundary.main([])
            finally:
                check_boundary.DOCUMENT = original
            self.assertEqual(code, 1)
            self.assertIn("is missing", reported.getvalue())

    def test_drift_check_passes_on_the_checked_in_tree(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as reported:
            self.assertEqual(check_boundary.main([]), 0)
        self.assertIn("bits per comparison", reported.getvalue())

    def test_runner_constants_match_the_vocabulary(self) -> None:
        self.assertEqual(check_boundary.check_runner_constants(), [])

    def test_atomic_write_leaves_no_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "vocabulary.md"
            check_boundary.write_atomically(target, "one\n")
            check_boundary.write_atomically(target, "two\n")
            self.assertEqual(target.read_text(), "two\n")
            self.assertEqual(
                sorted(path.name for path in pathlib.Path(directory).iterdir()),
                ["vocabulary.md"],
            )


# --- source audit ---------------------------------------------------------
#
# The rule: on the raw-byte path there is no sink and no exception is ever
# bound to a name. An unbound `except` cannot interpolate a message, which is
# how a legacy path and source line reach a report in the first place.

# `channel.py` reads the environment to build the custody process's own, from
# an allow list of names. Nothing else on the path may read it at all: a value
# that changes what is released is a debug bypass however it is spelled.
AUDITED_MODULES = (("release.py", False), ("scan.py", False), ("channel.py", True))


def audit_source(label: str, source: str, *, environment_allowed: bool = False) -> list[str]:
    findings: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not environment_allowed:
            if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}:
                findings.append(f"{label}:environment")
            if isinstance(node, ast.Name) and node.id in {"environ", "getenv"}:
                findings.append(f"{label}:environment")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "logging":
                    findings.append(f"{label}:logging-import")
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "logging":
            findings.append(f"{label}:logging-import")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "print":
                findings.append(f"{label}:print")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "logging":
                findings.append(f"{label}:logging-use")
            if node.value.id == "sys" and node.attr in {"stdout", "stderr"}:
                findings.append(f"{label}:stream-use")
        if isinstance(node, ast.ExceptHandler) and node.name:
            findings.append(f"{label}:bound-exception")
    return sorted(set(findings))


def audit_module_sources() -> list[str]:
    findings: list[str] = []
    directory = pathlib.Path(__file__).parent
    for name, environment_allowed in AUDITED_MODULES:
        findings.extend(
            audit_source(
                name,
                (directory / name).read_text(encoding="utf-8"),
                environment_allowed=environment_allowed,
            )
        )
    return sorted(findings)


if __name__ == "__main__":
    unittest.main()
