#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Controls for the R0-10 recovery drill.

Every rule the drill enforces is tested in both directions: the deliberate
breakage that must be caught, and the unbroken run that must pass. A check that
has never failed has not been tested, so there is no rule here without its
negative control.

    python3 spikes/recovery/test_recovery_drill.py
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import dependencies as dep  # noqa: E402
import drill  # noqa: E402
import recovery_set as rs  # noqa: E402

REPOSITORY_ROOT = HERE.parent.parent
FIXTURES = HERE / "fixtures"
MODULES = ("recovery_set.py", "drill.py", "dependencies.py")


def temporary_root() -> pathlib.Path:
    return pathlib.Path(tempfile.gettempdir()).resolve()


def drill_residue() -> set[pathlib.Path]:
    """Every workspace the drill could have left behind, and nothing else.

    Scoped to the drill's own workspace prefix on purpose: this machine runs
    other work in the same temporary root, and a residue check that also
    counted a passing compiler's scratch directory would fail for reasons that
    say nothing about the drill.
    """
    return set(temporary_root().glob(f"{drill.WORKSPACE_PREFIX}*"))


class SafetyRefusalTests(unittest.TestCase):
    """The drill must refuse anything it cannot prove is disposable."""

    def test_a_fresh_temporary_workspace_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            drill.assert_disposable(pathlib.Path(directory) / "workspace")

    def test_workspace_inside_the_repository_is_refused(self) -> None:
        with self.assertRaises(drill.DrillRefusal) as caught:
            drill.assert_disposable(REPOSITORY_ROOT / "spikes" / "recovery" / "w")
        self.assertIs(caught.exception.refusal,
                      drill.Refusal.WORKSPACE_INSIDE_REPOSITORY)

    def test_workspace_outside_the_temporary_root_is_refused(self) -> None:
        with self.assertRaises(drill.DrillRefusal) as caught:
            drill.assert_disposable(
                pathlib.Path("/var/lib/automonique-recovery-drill-absent"))
        self.assertIs(caught.exception.refusal,
                      drill.Refusal.WORKSPACE_NOT_UNDER_TEMPORARY_ROOT)

    def test_home_directory_is_refused(self) -> None:
        with self.assertRaises(drill.DrillRefusal) as caught:
            drill.assert_disposable(pathlib.Path.home())
        self.assertIs(caught.exception.refusal,
                      drill.Refusal.WORKSPACE_IS_HOME_OR_ROOT)

    def test_filesystem_root_is_refused(self) -> None:
        with self.assertRaises(drill.DrillRefusal) as caught:
            drill.assert_disposable(pathlib.Path("/"))
        self.assertIs(caught.exception.refusal,
                      drill.Refusal.WORKSPACE_IS_HOME_OR_ROOT)

    def test_workspace_holding_foreign_state_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            (workspace / "someone-elses.txt").write_text("not mine\n")
            with self.assertRaises(drill.DrillRefusal) as caught:
                drill.assert_disposable(workspace)
            self.assertIs(caught.exception.refusal,
                          drill.Refusal.WORKSPACE_NOT_EMPTY)

    def test_unmarked_directory_is_never_destroyed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            with self.assertRaises(drill.DrillRefusal) as caught:
                drill.assert_marked(workspace, "0123456789abcdef")
            self.assertIs(caught.exception.refusal, drill.Refusal.MARKER_MISSING)

            drill.write_marker(workspace, "0123456789abcdef")
            drill.assert_marked(workspace, "0123456789abcdef")  # positive control
            with self.assertRaises(drill.DrillRefusal) as caught:
                drill.assert_marked(workspace, "fedcba9876543210")
            self.assertIs(caught.exception.refusal,
                          drill.Refusal.MARKER_TOKEN_MISMATCH)

    def test_the_unsafe_workspace_control_creates_nothing(self) -> None:
        before = sorted(p.name for p in HERE.iterdir())
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = drill.main(["--fault", drill.Fault.UNSAFE_WORKSPACE.value])
        self.assertEqual(code, drill.EXIT_CODE[drill.Outcome.REFUSED])
        self.assertEqual(
            json.loads(captured.getvalue())["refusal"],
            drill.Refusal.WORKSPACE_INSIDE_REPOSITORY.value)
        self.assertEqual(before, sorted(p.name for p in HERE.iterdir()))


class DrillOutcomeTests(unittest.TestCase):
    """The drill itself, unbroken and broken one rule at a time."""

    def run_drill(self, fault: drill.Fault = drill.Fault.NONE) -> drill.Report:
        return drill.run(drill.Options(fault=fault))

    def verdicts(self, report: drill.Report) -> dict[str, bool]:
        return {r.invariant.value: r.ok for r in report.invariants}

    def test_unbroken_run_restores_a_coherent_point_in_time(self) -> None:
        report = self.run_drill()
        self.assertIs(report.outcome, drill.Outcome.INCOMPLETE)
        self.assertEqual(len(report.invariants), len(rs.Invariant))
        self.assertTrue(all(r.ok for r in report.invariants), report.invariants)
        self.assertTrue(report.reproducible["source_destroyed"])
        self.assertEqual(report.reproducible["watermark_event_id"],
                         drill.SEED_EVENTS + drill.EVENTS_DURING_BACKUP)
        self.assertEqual(report.reproducible["lost_events"],
                         drill.EVENTS_AFTER_BACKUP)
        self.assertEqual(report.residue, [])

    def test_naive_backup_order_leaves_rows_without_their_bytes(self) -> None:
        report = self.run_drill(drill.Fault.NAIVE_BACKUP)
        self.assertIs(report.outcome, drill.Outcome.INCONSISTENT)
        verdicts = self.verdicts(report)
        self.assertFalse(verdicts[rs.Invariant.ARTIFACT_ROW_HAS_BLOB.value])
        self.assertTrue(verdicts[rs.Invariant.DATABASE_INTEGRITY.value],
                        "the database is internally valid; only the recovery "
                        "set as a whole is torn, which is the point")
        detail = next(r.detail for r in report.invariants
                      if r.invariant is rs.Invariant.ARTIFACT_ROW_HAS_BLOB)
        self.assertIn(f"{drill.EVENTS_DURING_BACKUP} without their bytes", detail)

    def test_a_file_smuggled_from_the_source_is_detected(self) -> None:
        report = self.run_drill(drill.Fault.LEAK_SOURCE)
        self.assertIs(report.outcome, drill.Outcome.INCONSISTENT)
        self.assertFalse(
            self.verdicts(report)[rs.Invariant.TARGET_MATCHES_MANIFEST.value])
        self.assertFalse(report.reproducible["source_destroyed"])
        self.assertEqual(report.residue, [])

    def test_tampered_restored_bytes_are_detected(self) -> None:
        report = self.run_drill(drill.Fault.TAMPER_BLOB)
        self.assertIs(report.outcome, drill.Outcome.INCONSISTENT)
        verdicts = self.verdicts(report)
        self.assertFalse(verdicts[rs.Invariant.BLOB_HASH_MATCHES_ROW.value])
        self.assertFalse(verdicts[rs.Invariant.TARGET_MATCHES_MANIFEST.value])

    def test_a_failed_restore_still_leaves_no_residue(self) -> None:
        before = drill_residue()
        report = self.run_drill(drill.Fault.CRASH_MID_RESTORE)
        self.assertIs(report.outcome, drill.Outcome.FAILED)
        self.assertEqual(report.residue, [])
        self.assertIn(drill.FindingCode.RESTORE_FAILED.value,
                      [f.code.value for f in report.findings])
        self.assertEqual(before, drill_residue())

    def test_residue_is_detected_when_cleanup_is_skipped(self) -> None:
        report = self.run_drill(drill.Fault.SKIP_CLEANUP)
        self.assertIs(report.outcome, drill.Outcome.RESIDUE_LEFT)
        self.assertEqual(len(report.residue), 1)
        self.assertIn(drill.FindingCode.RESIDUE_LEFT.value,
                      [f.code.value for f in report.findings])
        left = temporary_root() / report.residue[0]
        self.assertTrue(left.is_dir())
        rs.destroy(left)                       # the control cleans up after itself
        self.assertFalse(left.exists())

    def test_a_successful_run_leaves_the_temporary_root_unchanged(self) -> None:
        before = drill_residue()
        self.run_drill()
        self.assertEqual(before, drill_residue())

    def test_a_second_run_reproduces_every_outcome(self) -> None:
        first = self.run_drill().reproducible
        second = self.run_drill().reproducible
        self.assertEqual(first, second)

    def test_the_repository_is_untouched_by_a_run(self) -> None:
        def status() -> str:
            return subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=all"],
                cwd=REPOSITORY_ROOT, capture_output=True, text=True,
                check=True).stdout

        before = status()
        self.run_drill()
        self.assertEqual(before, status())


class InvariantControlTests(unittest.TestCase):
    """One deliberate breakage per coherence invariant, plus the clean control.

    Every invariant here has been observed failing. An invariant that only ever
    passes proves that the restore ran, not that it was checked.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.directory.name)
        self.layout = rs.SourceLayout(root / "source")
        writer = rs.FixtureWriter(self.layout)
        writer.create()
        writer.commit_batch(16)
        writer.close()
        self.backup = root / "backup"
        self.manifest = rs.take_backup(self.layout, self.backup)
        self.target = root / "target"
        rs.restore(self.backup, self.target)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def verdicts(self, manifest: rs.BackupManifest | None = None) -> dict[str, bool]:
        return {r.invariant.value: r.ok for r in
                rs.verify_restored(self.target, manifest or self.manifest)}

    def test_the_untouched_restore_satisfies_every_invariant(self) -> None:
        verdicts = self.verdicts()
        self.assertEqual(len(verdicts), len(rs.Invariant))
        self.assertTrue(all(verdicts.values()), verdicts)

    def test_an_orphan_blob_is_detected(self) -> None:
        rs.write_atomic(self.target / "blobs" / "zz" / ("f" * 64), b"orphan")
        verdicts = self.verdicts()
        self.assertFalse(verdicts[rs.Invariant.NO_ORPHAN_BLOB.value])

    def test_a_missing_configuration_revision_is_detected(self) -> None:
        (self.target / "config.json").unlink()
        verdicts = self.verdicts()
        self.assertFalse(verdicts[rs.Invariant.CONFIG_REVISION_PRESENT.value])

    def test_a_configuration_file_behind_the_database_is_detected(self) -> None:
        document = json.loads((self.target / "config.json").read_text())
        document["history"] = [1]
        document["revision"] = 1
        rs.write_atomic(self.target / "config.json",
                        (json.dumps(document, indent=2, sort_keys=True)
                         + "\n").encode())
        verdicts = self.verdicts()
        self.assertFalse(verdicts[rs.Invariant.CONFIG_REVISION_PRESENT.value])

    def test_a_disagreeing_committed_counter_is_detected(self) -> None:
        connection = sqlite3.connect(self.target / "control.db")
        connection.execute("UPDATE counters SET value = value + 1")
        connection.commit()
        connection.close()
        verdicts = self.verdicts()
        self.assertFalse(verdicts[rs.Invariant.EVENT_COUNTER_AGREEMENT.value])

    def test_a_watermark_the_restore_does_not_reach_is_detected(self) -> None:
        shifted = rs.BackupManifest(
            watermark_event_id=self.manifest.watermark_event_id + 5,
            watermark_ns=self.manifest.watermark_ns,
            config_revision=self.manifest.config_revision,
            event_count=self.manifest.event_count,
            artifact_count=self.manifest.artifact_count,
            files=self.manifest.files,
        )
        verdicts = self.verdicts(shifted)
        self.assertFalse(verdicts[rs.Invariant.WATERMARK_AGREEMENT.value])

    def test_an_unreadable_database_fails_every_invariant_it_blocks(self) -> None:
        rs.write_atomic(self.target / "control.db", b"not a database at all")
        verdicts = self.verdicts()
        self.assertFalse(verdicts[rs.Invariant.DATABASE_INTEGRITY.value])
        self.assertFalse(verdicts[rs.Invariant.EVENT_COUNTER_AGREEMENT.value],
                         "an invariant that could not be evaluated is not a pass")
        self.assertEqual(len(verdicts), len(rs.Invariant))

    def test_a_backup_whose_configuration_lags_the_database_is_refused(self) -> None:
        document = json.loads(self.layout.config.read_text())
        document["history"] = [1]
        document["revision"] = 1
        rs.write_atomic(self.layout.config,
                        (json.dumps(document, indent=2, sort_keys=True)
                         + "\n").encode())
        with self.assertRaises(ValueError) as caught:
            rs.take_backup(self.layout, self.backup.parent / "backup-late")
        self.assertIn("ordering rule", str(caught.exception))

    def test_a_backup_file_that_does_not_match_its_hash_is_refused(self) -> None:
        rs.write_atomic(self.backup / "config.json", b"{}\n")
        with self.assertRaises(ValueError) as caught:
            rs.restore(self.backup, self.target.parent / "target-two")
        self.assertIn("manifest hash", str(caught.exception))

    def test_manifest_paths_hashes_and_symlinks_fail_closed(self) -> None:
        original = (self.backup / "manifest.json").read_bytes()
        document = json.loads(original)
        cases = {
            "traversal": {"../outside": "0" * 64},
            "absolute": {"/outside": "0" * 64},
            "non_digest": {"control.db": "not-a-digest"},
        }
        try:
            for label, files in cases.items():
                with self.subTest(label=label):
                    changed = {**document, "files": files}
                    rs.write_atomic(
                        self.backup / "manifest.json",
                        (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode())
                    with self.assertRaises(ValueError):
                        rs.restore(self.backup, self.target.parent / f"target-{label}")

            rs.write_atomic(self.backup / "manifest.json", original)
            source = self.backup / "control.db"
            source.unlink()
            source.symlink_to(self.layout.database)
            with self.assertRaises(ValueError) as caught:
                rs.restore(self.backup, self.target.parent / "target-symlink")
            self.assertIn("symlink", str(caught.exception))
        finally:
            rs.write_atomic(self.backup / "manifest.json", original)

    def test_duplicate_manifest_keys_and_symlinked_roots_fail_closed(self) -> None:
        manifest = (self.backup / "manifest.json").read_text()
        duplicate = manifest.replace(
            '  "files": {',
            '  "files": {"../outside": "' + ("0" * 64) + '"},\n  "files": {',
            1,
        )
        rs.write_atomic(self.backup / "manifest.json", duplicate.encode())
        with self.assertRaises(ValueError) as caught:
            rs.restore(self.backup, self.target.parent / "target-duplicate")
        self.assertIn("repeats JSON key", str(caught.exception))

        rs.write_manifest(self.backup, self.manifest)
        backup_alias = self.backup.parent / "backup-alias"
        backup_alias.symlink_to(self.backup, target_is_directory=True)
        with self.assertRaises(ValueError) as caught:
            rs.restore(backup_alias, self.target.parent / "target-backup-alias")
        self.assertIn("traverses a symlink", str(caught.exception))

        target_parent = self.backup.parent / "target-parent-alias"
        target_parent.symlink_to(self.backup.parent, target_is_directory=True)
        with self.assertRaises(ValueError) as caught:
            rs.restore(self.backup, target_parent / "escaped-target")
        self.assertIn("traverses a symlink", str(caught.exception))

    def test_a_payload_swap_to_a_symlink_cannot_race_the_open(self) -> None:
        source = self.backup / "control.db"
        outside = self.backup.parent / "outside-control.db"
        outside.write_bytes(source.read_bytes())
        real_open = os.open
        swapped = False

        def swap_before_open(path: object, flags: int, mode: int = 0o777,
                             *, dir_fd: int | None = None) -> int:
            nonlocal swapped
            if path == "control.db" and dir_fd is not None and not swapped:
                swapped = True
                source.unlink()
                source.symlink_to(outside)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(rs.os, "open", side_effect=swap_before_open):
            with self.assertRaises(ValueError) as caught:
                rs.restore(self.backup, self.target.parent / "target-race")
        self.assertTrue(swapped)
        self.assertIn("traverses a symlink", str(caught.exception))
        self.assertFalse((self.target.parent / "target-race").exists())

    def test_a_replaced_target_parent_cannot_yield_a_false_success(self) -> None:
        visible_parent = self.backup.parent / "visible-parent"
        visible_parent.mkdir()
        pinned_parent = self.backup.parent / "pinned-parent"
        outside = self.backup.parent / "outside-parent"
        outside.mkdir()
        requested = visible_parent / "target"
        real_write = rs._write_regular_at
        swapped = False

        def replace_parent(root_fd: int, relative: str, payload: bytes) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                visible_parent.rename(pinned_parent)
                visible_parent.symlink_to(outside, target_is_directory=True)
            real_write(root_fd, relative, payload)

        with mock.patch.object(rs, "_write_regular_at", side_effect=replace_parent):
            with self.assertRaises(ValueError) as caught:
                rs.restore(self.backup, requested)
        self.assertTrue(swapped)
        self.assertIn("target identity changed", str(caught.exception))
        self.assertFalse(requested.exists())
        self.assertFalse((pinned_parent / "target").exists())
        self.assertEqual(list(outside.iterdir()), [])


class ObjectiveTests(unittest.TestCase):
    """RPO and RTO carry units, and a local fixture never claims a host."""

    def measurements(self) -> list[dict[str, object]]:
        return drill.run(drill.Options()).as_document()["measurements"]

    def test_both_objectives_are_measured_with_units(self) -> None:
        measured = {m["id"]: m for m in self.measurements()}
        self.assertEqual(set(measured), {"rpo", "rto"})
        for entry in measured.values():
            self.assertEqual(entry["unit"], "seconds")
            self.assertIsInstance(entry["value"], float)
            self.assertGreaterEqual(entry["value"], 0.0)
            self.assertIn("declared_objective", entry)

    def test_a_local_fixture_never_claims_the_declared_objective(self) -> None:
        for entry in self.measurements():
            self.assertEqual(entry["scope"], drill.Scope.LOCAL_FIXTURE.value)
            self.assertEqual(entry["comparison"],
                             drill.Comparison.OUT_OF_SCOPE.value)
            self.assertIsNone(entry["objective_met"])

    def test_out_of_scope_measurements_are_recorded_as_findings(self) -> None:
        codes = [f.code for f in drill.run(drill.Options()).findings]
        self.assertEqual(
            codes.count(drill.FindingCode.OBJECTIVE_COMPARISON_OUT_OF_SCOPE), 2)

    def test_a_clean_host_measurement_is_compared_and_a_miss_is_named(self) -> None:
        objective = next(o for o in drill.DECLARED_OBJECTIVES if o.id == "rto")
        missed = drill.Measurement(id="rto", value_seconds=2400.0,
                                   scope=drill.Scope.CLEAN_HOST, method="fixture")
        comparison, detail = drill.compare_to_objective(missed, objective)
        self.assertIs(comparison, drill.Comparison.MISSED)
        self.assertIn("2400.000", detail)
        self.assertIn("1800", detail)

        met = drill.Measurement(id="rto", value_seconds=120.0,
                                scope=drill.Scope.CLEAN_HOST, method="fixture")
        comparison, detail = drill.compare_to_objective(met, objective)
        self.assertIs(comparison, drill.Comparison.MET)
        self.assertIn("120.000", detail)


class DependencyAgreementTests(unittest.TestCase):
    """The real R0-09 list is consumed and cannot be replaced by a fixture."""

    def test_the_canonical_inventory_is_consumed_and_gaps_are_findings(self) -> None:
        report = dep.consume()
        self.assertTrue(report["inventory_present"])
        self.assertIsNone(report["refused"])
        self.assertEqual(report["consumed_entries"], 21)
        self.assertEqual(len(report["objectives"]), 2)
        self.assertEqual(len(report["excluded"]), 1)
        codes = [finding["code"] for finding in report["findings"]]
        self.assertEqual(
            codes.count(dep.DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY.value),
            8)
        self.assertEqual(
            codes.count(dep.DependencyFinding.DEPENDENCY_NOT_EXERCISED.value),
            20)
        self.assertEqual(report["declared_inventory_path"],
                         dep.DECLARED_INVENTORY_PATH)
        self.assertEqual(
            (REPOSITORY_ROOT / dep.DECLARED_INVENTORY_PATH).resolve(),
            dep.CANONICAL_INVENTORY.resolve())

    def test_a_schema_shaped_fixture_cannot_replace_the_real_producer(self) -> None:
        report = dep.consume(FIXTURES / "inventory-present.json")
        self.assertTrue(report["inventory_present"])
        self.assertEqual(report["consumed_entries"], 0)
        self.assertEqual(report["refused"]["code"],
                         dep.Refusal.PATH_MISMATCH.value)
        self.assertEqual(report["findings"], [])

    def test_an_alternate_invalid_inventory_is_refused_before_parse(self) -> None:
        report = dep.consume(FIXTURES / "inventory-invalid.json")
        self.assertIsNotNone(report["refused"])
        self.assertEqual(report["refused"]["code"],
                         dep.Refusal.PATH_MISMATCH.value)
        self.assertEqual(report["findings"], [],
                         "a refused inventory yields no partial agreement")

    def test_every_malformed_shape_is_refused_by_its_own_code(self) -> None:
        encoded = dep.CANONICAL_INVENTORY.read_bytes()
        good = json.loads(encoded)
        duplicate = json.loads(encoded)
        duplicate["order"][1]["id"] = duplicate["order"][0]["id"]
        bad_order = json.loads(encoded)
        bad_order["order"][0]["position"] = 0
        cases = {
            dep.Refusal.NOT_AN_OBJECT: ["not", "an", "object"],
            dep.Refusal.UNKNOWN_SCHEMA: {**good, "schema": "something.else.v1"},
            dep.Refusal.UNKNOWN_KEY: {**good, "extra": 1},
            dep.Refusal.MISSING_KEY: {k: v for k, v in good.items()
                                      if k != "work_item"},
            dep.Refusal.DUPLICATE_ID: duplicate,
            dep.Refusal.BAD_ORDER: bad_order,
        }
        for expected, document in cases.items():
            with self.subTest(refusal=expected.value):
                with self.assertRaises(dep.InventoryRefused) as caught:
                    dep.validate_inventory(
                        (json.dumps(document, indent=2, ensure_ascii=True)
                         + "\n").encode())
                self.assertIs(caught.exception.refusal, expected)
        dep.validate_inventory(encoded)        # real-producer positive control

    def test_the_consumer_vocabulary_cannot_widen_the_drill_report(self) -> None:
        drill_codes = {code.value for code in drill.FindingCode}
        consumer_codes = {code.value for code in dep.DependencyFinding}
        self.assertTrue(consumer_codes <= drill_codes,
                        sorted(consumer_codes - drill_codes))

    def test_the_drill_report_carries_the_dependency_agreement(self) -> None:
        report = drill.run(drill.Options())
        self.assertEqual(report.dependency_report["consumed_entries"], 21)
        self.assertIsNone(report.dependency_report["refused"])
        self.assertEqual(len(report.dependency_report["findings"]), 28)
        self.assertNotIn(drill.FindingCode.INVENTORY_ABSENT,
                         [f.code for f in report.findings])


class GeneratedFileTests(unittest.TestCase):
    """The checked-in dependency list is generated, and staleness is caught."""

    def test_the_checked_in_copy_is_current(self) -> None:
        self.assertIsNone(dep.check_generated())

    def test_generation_is_byte_identical(self) -> None:
        self.assertEqual(dep.render(), dep.render())
        self.assertEqual(dep.GENERATED.read_bytes(), dep.render())

    def test_a_stale_copy_is_detected(self) -> None:
        original = dep.GENERATED.read_bytes()
        try:
            rs.write_atomic(dep.GENERATED,
                            original.replace(b'"order": 1,', b'"order": 2,', 1))
            self.assertIsNotNone(dep.check_generated())
        finally:
            rs.write_atomic(dep.GENERATED, original)
        self.assertIsNone(dep.check_generated())

    def test_a_missing_copy_is_detected(self) -> None:
        original = dep.GENERATED.read_bytes()
        try:
            dep.GENERATED.unlink()
            self.assertIn("missing", dep.check_generated())
        finally:
            rs.write_atomic(dep.GENERATED, original)
        self.assertIsNone(dep.check_generated())

    def test_the_drill_generated_copy_cannot_pose_as_r0_09_authority(self) -> None:
        document = json.loads(dep.GENERATED.read_text())
        document["schema"] = dep.INVENTORY_SCHEMA
        with self.assertRaises(dep.InventoryRefused) as caught:
            dep.parse_inventory(document)
        self.assertIs(caught.exception.refusal, dep.Refusal.UNKNOWN_KEY)


class QualityTests(unittest.TestCase):
    """Offline, no credential, no new runtime dependency."""

    def imported_names(self, module: str) -> set[str]:
        tree = ast.parse((HERE / module).read_text())
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        return names

    def repository_imports(self, module: str) -> set[tuple[str, str, str | None]]:
        tree = ast.parse((HERE / module).read_text())
        return {
            (node.module, alias.name, alias.asname)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module is not None
            and node.module.startswith("tools")
            for alias in node.names
        }

    def test_no_module_imports_anything_outside_the_standard_library(self) -> None:
        siblings = {path.stem for path in HERE.glob("*.py")}
        for module in MODULES:
            with self.subTest(module=module):
                outside = sorted(self.imported_names(module)
                                 - set(sys.stdlib_module_names) - siblings)
                expected = ["tools"] if module == "dependencies.py" else []
                self.assertEqual(outside, expected)
                repository = self.repository_imports(module)
                expected_repository = ({
                    ("tools.surface_inventory", "render", "surface_render")
                } if module == "dependencies.py" else set())
                self.assertEqual(repository, expected_repository)

    def test_no_module_reads_an_environment_variable_or_starts_a_process(self) -> None:
        forbidden_attributes = {"environ", "getenv", "environb", "putenv"}
        forbidden_modules = {"subprocess", "socket", "urllib", "http", "getpass",
                             "netrc", "ssl", "ftplib", "smtplib"}
        for module in MODULES:
            with self.subTest(module=module):
                tree = ast.parse((HERE / module).read_text())
                reached = {node.attr for node in ast.walk(tree)
                           if isinstance(node, ast.Attribute)}
                self.assertEqual(reached & forbidden_attributes, set())
                self.assertEqual(
                    self.imported_names(module) & forbidden_modules, set())

    def test_the_drill_runs_with_the_network_blocked(self) -> None:
        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("the drill opened a socket")

        with mock.patch.object(socket, "socket", refuse), \
                mock.patch.object(socket, "create_connection", refuse):
            report = drill.run(drill.Options())
            self.assertIs(report.outcome, drill.Outcome.INCOMPLETE)
            with self.assertRaises(AssertionError):
                socket.socket()                # the blocker really blocks

    def test_the_procedure_names_every_dependency_it_does_not_exercise(self) -> None:
        text = drill.procedure_text()
        undrilled = [d for d in rs.RESTORE_DEPENDENCIES
                     if d.exercised is rs.Exercise.NOT_DRILLED]
        self.assertGreater(len(undrilled), 0)
        for dependency in undrilled:
            self.assertIn(dependency.id, text)

    def test_the_procedure_mode_touches_nothing(self) -> None:
        before = drill_residue()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drill.main(["--procedure"]), 0)
        self.assertEqual(before, drill_residue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
