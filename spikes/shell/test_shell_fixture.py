# SPDX-License-Identifier: Elastic-2.0

"""Positive and negative controls for the R0-11 shell decision fixture.

Every rule in `fixture.py` is broken here on purpose and the *named* refusal is
asserted, because a rule that has never been observed to fail is a rule nobody
has tested. `AGENTS.md` asks for a positive control beside every negative one,
so each refusal test has a sibling that proves the same input passes once the
deliberate break is undone.

    python3 spikes/shell/test_shell_fixture.py
    python3 -m unittest discover -s spikes/shell -p 'test_*.py'
"""

from __future__ import annotations

import ast
import copy
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_shell_decision  # noqa: E402
import fixture  # noqa: E402
import replay  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
UNMEASURED = HERE / "observations/2026-08-11-no-live-system.json"
SYNTHETIC = HERE / "observations/2026-08-11-synthetic-example.json"
DECISION = fixture.ROOT / "plan/decisions/R0-11-shell-boundary.json"
MODULES = ("fixture.py", "replay.py", "check_shell_decision.py", "test_shell_fixture.py")


def load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def observation(corpus: dict[str, Any], usage_class: str) -> dict[str, Any]:
    for entry in corpus["observations"]:
        if entry["class"] == usage_class:
            return entry
    raise AssertionError(f"{usage_class} missing from fixture corpus")


def measured_corpus() -> dict[str, Any]:
    """The synthetic worked example rewritten as a well-formed measured capture.

    Used only to exercise the resolved-outcome paths. It is built in the test
    rather than checked in, so no file in this repository claims a measurement
    that was never taken.
    """
    corpus = load(SYNTHETIC)
    corpus["corpus_id"] = "2026-08-11-test-measured"
    corpus["kind"] = "measured"
    corpus["capture_host_access"] = "live-system"
    for entry in corpus["observations"]:
        entry["capture_method"] = "audit_log_query"
        entry["capture_citation"] = {"kind": "system_log_query", "ref": "shell-usage-q1"}
    return corpus


def written_corpus(directory: pathlib.Path, corpus: dict[str, Any]) -> pathlib.Path:
    path = directory / f"{corpus['corpus_id']}.json"
    path.write_text(json.dumps(corpus, indent=2) + "\n")
    return path


class CheckedInFixtures(unittest.TestCase):
    """Positive controls: what is committed parses, replays and validates."""

    def test_both_corpora_parse(self) -> None:
        unmeasured = fixture.load_corpus(UNMEASURED)
        synthetic = fixture.load_corpus(SYNTHETIC)
        self.assertEqual(unmeasured["kind"], "unmeasured")
        self.assertEqual(synthetic["kind"], "synthetic")
        self.assertEqual(len(unmeasured["observations"]), len(fixture.USAGE_CLASSES))
        self.assertTrue(all(e["count"] is None for e in unmeasured["observations"]))
        self.assertTrue(all(e["reason"] for e in unmeasured["observations"]))
        self.assertTrue(all(e["count"] is not None for e in synthetic["observations"]))

    def test_every_usage_class_cites_a_document_that_exists(self) -> None:
        for name, meta in fixture.USAGE_CLASSES.items():
            with self.subTest(usage_class=name):
                self.assertTrue((fixture.ROOT / meta["source"]).is_file(), meta["source"])

    def test_checked_in_decision_inputs_are_not_stale(self) -> None:
        expected = replay.render(replay.build(replay.corpus_paths()))
        self.assertEqual(
            replay.GENERATED.read_text(), expected,
            "generated/decision-inputs.json is stale; run replay.py --write",
        )

    def test_replay_is_deterministic(self) -> None:
        paths = replay.corpus_paths()
        self.assertEqual(replay.render(replay.build(paths)), replay.render(replay.build(paths)))

    def test_no_class_is_resolvable_today(self) -> None:
        inputs = replay.load_decision_inputs()
        self.assertEqual(inputs["totals"]["resolvable_classes"], 0)
        for name, entry in inputs["classes"].items():
            with self.subTest(usage_class=name):
                self.assertFalse(entry["resolvable"])
                self.assertIsNone(entry["measured"]["count"])

    def test_decision_record_validates_and_resolves_nothing(self) -> None:
        decision = fixture.load_decision(DECISION, replay.load_decision_inputs())
        self.assertEqual(set(decision["classes"]), set(fixture.USAGE_CLASSES))
        for name, entry in decision["classes"].items():
            with self.subTest(usage_class=name):
                self.assertEqual(entry["outcome"], "unresolved")
                self.assertTrue(entry["owner_decision_required"])
                self.assertEqual(
                    {option["option"] for option in entry["options"]},
                    {"boundary", "retirement"},
                )

    def test_checker_exits_zero(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = check_shell_decision.main([])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("6 usage class(es), 0 resolvable, 6 explicitly unresolved", out.getvalue())


class CorpusRefusals(unittest.TestCase):
    """Negative controls: break one rule at a time and name the refusal."""

    def refuse(self, corpus: dict[str, Any], error: type[Exception], fragment: str) -> None:
        with self.assertRaises(error) as caught:
            fixture.parse_corpus(corpus)
        self.assertIn(fragment, str(caught.exception))

    def test_unknown_class_is_refused(self) -> None:
        corpus = load(UNMEASURED)
        observation(corpus, "file_upload")["class"] = "interactive_shell_ssh"
        self.refuse(corpus, fixture.VocabularyError, "must be one of")

    def test_missing_class_is_refused(self) -> None:
        corpus = load(UNMEASURED)
        corpus["observations"] = [
            e for e in corpus["observations"] if e["class"] != "inline_path_bridge"
        ]
        self.refuse(corpus, fixture.CompletenessError, "omits usage class(es): inline_path_bridge")

    def test_duplicate_class_is_refused(self) -> None:
        corpus = load(UNMEASURED)
        corpus["observations"].append(copy.deepcopy(observation(corpus, "file_upload")))
        self.refuse(corpus, fixture.CompletenessError, "more than once: file_upload")

    def test_number_in_an_unmeasured_corpus_is_refused(self) -> None:
        corpus = load(UNMEASURED)
        entry = observation(corpus, "file_upload")
        entry.update(
            count=17, capture_method="audit_log_query",
            capture_citation={"kind": "system_log_query", "ref": "shell-usage-q1"},
            window={"start": "2026-05-13", "end": "2026-08-10"},
        )
        entry.pop("reason")
        self.refuse(corpus, fixture.ProvenanceError, "declared 'unmeasured'")

    def test_null_count_without_a_reason_is_refused(self) -> None:
        corpus = load(UNMEASURED)
        observation(corpus, "file_upload")["reason"] = "unknown"
        self.refuse(corpus, fixture.ProvenanceError, "null with a reason, never absent")

    def test_number_without_a_capture_method_is_refused(self) -> None:
        corpus = measured_corpus()
        entry = observation(corpus, "file_upload")
        entry["capture_method"] = "none"
        self.refuse(corpus, fixture.ProvenanceError, "a number needs the method that produced it")

    def test_synthetic_method_in_a_measured_corpus_is_refused(self) -> None:
        corpus = measured_corpus()
        observation(corpus, "file_upload")["capture_method"] = "synthetic_authored"
        self.refuse(corpus, fixture.ProvenanceError, "cannot be relabelled as capture")

    def test_counting_method_in_a_synthetic_corpus_is_refused(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["capture_method"] = "audit_log_query"
        self.refuse(corpus, fixture.ProvenanceError, "synthetic corpus but claims capture method")

    def test_measured_corpus_without_host_access_is_refused(self) -> None:
        corpus = measured_corpus()
        corpus["capture_host_access"] = "none"
        self.refuse(corpus, fixture.ProvenanceError, "records no live-system access at capture")

    def test_unmarked_placeholder_is_refused(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["samples"][0]["synthetic"] = False
        self.refuse(corpus, fixture.ProvenanceError, "synthetic must be exactly true")

    def test_shape_outside_the_enum_is_refused(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["samples"][0]["shape"] = "rsync_over_ssh"
        self.refuse(corpus, fixture.VocabularyError, "samples[0].shape must be one of")

    def test_placeholder_outside_the_enum_is_refused(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["samples"][0]["placeholders"] = ["CUSTOMER"]
        self.refuse(corpus, fixture.VocabularyError, "placeholders[0] must be one of")

    def test_a_free_text_command_field_cannot_be_added(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["command"] = "an ordinary looking command"
        self.refuse(corpus, fixture.VocabularyError, "key(s) outside the closed set: command")

    def test_citation_to_a_missing_document_is_refused(self) -> None:
        corpus = load(SYNTHETIC)
        observation(corpus, "file_upload")["capture_citation"] = {
            "kind": "repository_document", "ref": "docs/product-plan/nonexistent.md",
        }
        self.refuse(corpus, fixture.ProvenanceError, "is not a file in this repository")

    def test_query_citation_must_be_a_symbolic_id(self) -> None:
        corpus = measured_corpus()
        observation(corpus, "file_upload")["capture_citation"] = {
            "kind": "system_log_query", "ref": "SELECT count(*) FROM sessions WHERE tenant = 3",
        }
        self.refuse(corpus, fixture.VocabularyError, "a query id, never the query text")

    def test_window_is_required_for_a_number(self) -> None:
        corpus = measured_corpus()
        observation(corpus, "file_upload").pop("window")
        self.refuse(corpus, fixture.VocabularyError, "window must be an object")

    def test_measured_corpus_positive_control(self) -> None:
        parsed = fixture.parse_corpus(measured_corpus())
        self.assertEqual(parsed["kind"], "measured")
        self.assertEqual(len(parsed["observations"]), len(fixture.USAGE_CLASSES))


class SanitizerControls(unittest.TestCase):
    """Every sanitizer rule is fired at least once, on data that must not land."""

    VECTORS = {
        "credential_assignment": "the capture used password=hunter2 in its connection string",
        "bearer_token": "the export used Bearer abcd1234efgh5678 for the audit API",
        "private_key_block": "the runbook pasted -----BEGIN OPENSSH PRIVATE KEY----- into the session",
        "ssh_public_key": "the session authorized ssh-ed25519 AAAAC3NzaC1lZDI1 for transfer",
        "cloud_access_key_id": "the transfer used AKIAIOSFODNN7EXAMPLE as its access key id",
        "absolute_home_path": "the upload targeted /home/operator/reports for delivery",
        "tilde_home_path": "the download wrote into ~operator/artifacts during the incident",
        "user_at_host": "the transfer ran as operator@customer-prod.example for the tenant",
        "private_ipv4": "the session connected outward to 10.11.12.13 during the window",
        "private_hostname": "the session connected to reporting-db.internal during the window",
    }

    def test_every_rule_has_a_vector(self) -> None:
        self.assertEqual(set(self.VECTORS), {rule for rule, _, _ in fixture.SANITIZER_RULES})

    def test_each_vector_is_refused_in_a_corpus(self) -> None:
        for rule, text in sorted(self.VECTORS.items()):
            with self.subTest(rule=rule):
                corpus = load(UNMEASURED)
                observation(corpus, "file_upload")["reason"] = text
                with self.assertRaises(fixture.SanitizationError) as caught:
                    fixture.parse_corpus(corpus)
                self.assertIn(f"rule {rule} matched", str(caught.exception))

    def test_each_vector_is_refused_in_a_decision_record(self) -> None:
        inputs = replay.load_decision_inputs()
        for rule, text in sorted(self.VECTORS.items()):
            with self.subTest(rule=rule):
                record = load(DECISION)
                record["classes"]["file_upload"]["options"][0]["evidence_required"].append(text)
                with self.assertRaises(fixture.SanitizationError) as caught:
                    fixture.parse_decision(record, inputs)
                self.assertIn(f"rule {rule} matched", str(caught.exception))

    def test_clean_text_positive_control(self) -> None:
        corpus = load(UNMEASURED)
        observation(corpus, "file_upload")["reason"] = (
            "the transfer log lives on the running system and no export has been supplied"
        )
        self.assertEqual(len(fixture.parse_corpus(corpus)["observations"]), 6)


class DecisionRefusals(unittest.TestCase):
    """The decision record's own rules, each broken and each restored."""

    def setUp(self) -> None:
        self.inputs = replay.load_decision_inputs()
        self.record = load(DECISION)

    def refuse(self, error: type[Exception], fragment: str, inputs: dict[str, Any] | None = None) -> None:
        with self.assertRaises(error) as caught:
            fixture.parse_decision(self.record, inputs or self.inputs)
        self.assertIn(fragment, str(caught.exception))

    def resolvable_inputs(self) -> dict[str, Any]:
        """Decision inputs in which every class carries a measured count."""
        with tempfile.TemporaryDirectory() as tmp:
            path = written_corpus(pathlib.Path(tmp), measured_corpus())
            built = replay.build([path])
        built["path"] = self.inputs["path"]
        built["sha256"] = self.inputs["sha256"]
        return built

    def test_missing_class_is_refused(self) -> None:
        self.record["classes"].pop("file_download")
        self.refuse(fixture.CompletenessError, "records no outcome for: file_download")

    def test_unknown_class_is_refused(self) -> None:
        self.record["classes"]["shell_over_ssh"] = self.record["classes"]["file_upload"]
        self.refuse(fixture.VocabularyError, "names unknown class(es): shell_over_ssh")

    def test_unresolved_without_both_options_is_refused(self) -> None:
        entry = self.record["classes"]["file_upload"]
        entry["options"] = [option for option in entry["options"] if option["option"] == "boundary"]
        self.refuse(fixture.CompletenessError, "must state both open options")

    def test_unresolved_without_owner_decision_flag_is_refused(self) -> None:
        self.record["classes"]["file_upload"]["owner_decision_required"] = False
        self.refuse(fixture.CompletenessError, "must be exactly true")

    def test_stale_decision_inputs_digest_is_refused(self) -> None:
        self.record["decision_inputs"]["sha256"] = "0" * 64
        self.refuse(fixture.ProvenanceError, "re-derive the decision")

    def test_standing_disposition_cannot_bind_this_record(self) -> None:
        self.record["standing_plan_disposition"]["binds_this_record"] = True
        self.refuse(fixture.ProvenanceError, "R0-11 asks for a per-class decision")

    def test_accepted_draft_boundary_is_refused(self) -> None:
        self.record["classes"]["file_upload"]["draft_boundary"]["accepted"] = True
        self.refuse(fixture.ProvenanceError, "not an acceptance")

    def test_boundary_on_an_unmeasured_class_is_refused(self) -> None:
        self.record["classes"]["file_upload"] = {
            "outcome": "boundary",
            "isolates": ["uploads land in one named workspace and nowhere else"],
            "permits": ["an authorized operator uploads into a session workspace"],
            "refuses": ["any upload naming a host path outside the workspace"],
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-synthetic-example", "count": 27},
        }
        self.refuse(fixture.ProvenanceError, "does not take an outcome on absent or synthetic")

    def test_bare_sandboxed_boundary_is_refused(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["file_upload"] = {
            "outcome": "boundary",
            "isolates": ["sandboxed"],
            "permits": ["an authorized operator uploads into a session workspace"],
            "refuses": ["any upload naming a host path outside the workspace"],
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 27},
        }
        self.refuse(fixture.BoundarySpecificityError, "not reassuring ones", inputs)

    def test_boundary_of_only_reassuring_words_is_refused(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["file_upload"] = {
            "outcome": "boundary",
            "isolates": ["isolated and hardened"],
            "permits": ["an authorized operator uploads into a session workspace"],
            "refuses": ["any upload naming a host path outside the workspace"],
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 27},
        }
        self.refuse(fixture.BoundarySpecificityError, "not reassuring ones", inputs)

    def test_specific_boundary_positive_control(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["file_upload"] = {
            "outcome": "boundary",
            "isolates": ["uploaded bytes land in one named workspace through the artifact service"],
            "permits": ["an operator holding shell_operator uploads into their session workspace"],
            "refuses": ["any upload naming a host path outside that workspace"],
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 27},
        }
        parsed = fixture.parse_decision(self.record, inputs)
        self.assertEqual(parsed["classes"]["file_upload"]["outcome"], "boundary")

    def test_retirement_without_a_replacement_is_a_finding(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["inline_path_bridge"] = {
            "outcome": "retirement",
            "user_path": "callers move to the artifact upload and download operations",
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 3},
        }
        self.refuse(fixture.ReplacementlessRetirement, "without a usable replacement", inputs)

    def test_retirement_without_a_user_path_is_a_finding(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["inline_path_bridge"] = {
            "outcome": "retirement",
            "replacement": "the artifact service upload and download operations",
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 3},
        }
        self.refuse(fixture.ReplacementlessRetirement, "without a usable user_path", inputs)

    def test_retirement_with_a_vague_replacement_is_a_finding(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["inline_path_bridge"] = {
            "outcome": "retirement",
            "replacement": "something more secure",
            "user_path": "callers move to the artifact upload and download operations",
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 3},
        }
        self.refuse(fixture.ReplacementlessRetirement, "does not name a replacement", inputs)

    def test_retirement_positive_control(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["inline_path_bridge"] = {
            "outcome": "retirement",
            "replacement": "the artifact service upload and download operations",
            "user_path": "a current caller switches to the artifact client and drops the host path argument",
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 3},
        }
        parsed = fixture.parse_decision(self.record, inputs)
        self.assertEqual(parsed["classes"]["inline_path_bridge"]["outcome"], "retirement")

    def test_outcome_citing_the_wrong_count_is_refused(self) -> None:
        inputs = self.resolvable_inputs()
        self.record["classes"]["inline_path_bridge"] = {
            "outcome": "retirement",
            "replacement": "the artifact service upload and download operations",
            "user_path": "a current caller switches to the artifact client and drops the host path argument",
            "owner": "owner-of-record",
            "evidence": {"corpus_id": "2026-08-11-test-measured", "count": 999},
        }
        self.refuse(fixture.ProvenanceError, "the decision inputs record", inputs)


class ReplayHarness(unittest.TestCase):
    """Staleness, atomicity and the offline claim."""

    def test_stale_generated_copy_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            generated = pathlib.Path(tmp) / "decision-inputs.json"
            generated.write_text(replay.GENERATED.read_text().replace("6", "7", 1))
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = replay.main(["--check", "--generated", str(generated)])
            self.assertEqual(code, 1)
            self.assertIn("STALE", err.getvalue())

    def test_fresh_generated_copy_passes(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = replay.main(["--check"])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("matches a replay of 2 corpus file(s)", out.getvalue())

    def test_write_is_atomic_and_leaves_no_staging_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "generated" / "decision-inputs.json"
            replay.write_atomic(target, "first\n")
            replay.write_atomic(target, "second\n")
            self.assertEqual(target.read_text(), "second\n")
            self.assertEqual(sorted(p.name for p in target.parent.iterdir()),
                             ["decision-inputs.json"])

    def test_a_failed_write_never_truncates_the_reader_visible_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "decision-inputs.json"
            target.write_text("original\n")
            with mock.patch.object(os, "replace", side_effect=OSError("rename failed")):
                with self.assertRaises(OSError):
                    replay.write_atomic(target, "replacement\n")
            self.assertEqual(target.read_text(), "original\n")

    def test_replay_produces_the_same_bytes_with_no_network_or_process(self) -> None:
        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("replay reached out to a live host")

        with mock.patch.object(socket, "socket", forbidden), \
             mock.patch.object(socket, "create_connection", forbidden), \
             mock.patch.object(socket, "getaddrinfo", forbidden), \
             mock.patch.object(subprocess, "run", forbidden), \
             mock.patch.object(subprocess, "Popen", forbidden):
            rendered = replay.render(replay.build(replay.corpus_paths()))
        self.assertEqual(rendered, replay.GENERATED.read_text())

    def test_two_corpora_counting_the_same_class_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            first = measured_corpus()
            second = measured_corpus()
            second["corpus_id"] = "2026-08-11-test-measured-two"
            paths = [written_corpus(directory, first), written_corpus(directory, second)]
            with self.assertRaises(replay.ReplayError) as caught:
                replay.build(sorted(paths))
            self.assertIn("counted by two measured corpora", str(caught.exception))

    def test_a_measured_corpus_makes_classes_resolvable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = written_corpus(pathlib.Path(tmp), measured_corpus())
            built = replay.build([path])
        self.assertEqual(built["totals"]["resolvable_classes"], len(fixture.USAGE_CLASSES))
        self.assertEqual(built["classes"]["file_upload"]["measured"]["count"], 27)
        self.assertEqual(built["classes"]["file_upload"]["measured"]["per_day"], 0.3)


class Dependencies(unittest.TestCase):
    """The Quality row: standard library only, and nothing that dials out."""

    NETWORKING = {"socket", "ssl", "http", "urllib", "ftplib", "asyncio", "requests", "httpx"}

    def imported_roots(self, path: pathlib.Path) -> set[str]:
        roots: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        return roots

    def test_every_import_is_standard_library_or_local(self) -> None:
        local = {path.stem for path in HERE.glob("*.py")}
        for name in MODULES:
            with self.subTest(module=name):
                roots = self.imported_roots(HERE / name)
                outside = sorted(roots - set(sys.stdlib_module_names) - local)
                self.assertEqual(outside, [], f"{name} imports a non-stdlib dependency")

    def test_the_fixture_itself_imports_nothing_that_reaches_a_host(self) -> None:
        for name in ("fixture.py", "replay.py", "check_shell_decision.py"):
            with self.subTest(module=name):
                roots = self.imported_roots(HERE / name)
                self.assertEqual(sorted(roots & self.NETWORKING), [])
                self.assertNotIn("subprocess", roots)


if __name__ == "__main__":
    unittest.main(verbosity=2)
