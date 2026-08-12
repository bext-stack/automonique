#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import inspect
import json
import dataclasses
import os
import pathlib
import sys
import unittest
from unittest import mock
import types

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import anonymous_backup  # noqa: E402
import anonymous_boundary  # noqa: E402
import anonymous_composition as composition  # noqa: E402
import recovery_plan  # noqa: E402


class AnonymousCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.first = composition.resolve_anonymous_composition()

    def test_public_resolver_has_no_inputs_and_exact_conservative_map(self) -> None:
        self.assertEqual(list(inspect.signature(composition.resolve_anonymous_composition).parameters), [])
        receipts = self.first.receipt_set.receipts
        self.assertEqual(len(receipts), 21)
        self.assertEqual([item.entry_id for item in receipts], [item.id for item in self.first.plan.entries])
        exercised = {item.entry_id for item in receipts if item.disposition is recovery_plan.Disposition.EXERCISED}
        self.assertEqual(exercised, set(composition.EXERCISED_IDS))
        self.assertEqual(len(self.first.blockers), 19)

    def test_receipt_hash_chain_and_assessment_validate(self) -> None:
        assessment = recovery_plan.validate_receipts(self.first.plan, self.first.receipt_set)
        self.assertEqual(assessment, self.first.assessment)
        hashes = {}
        for entry, receipt in zip(self.first.plan.entries, self.first.receipt_set.receipts, strict=True):
            self.assertEqual(receipt.prerequisite_receipt_hashes, tuple((required, hashes[required]) for required in entry.requires))
            hashes[entry.id] = receipt.receipt_sha256()
        self.assertFalse(assessment.structurally_complete)
        self.assertFalse(assessment.completion_eligible)

    def test_credentials_startup_artifact_verification_and_gate_stay_blocked(self) -> None:
        by_id = {item.entry_id: item for item in self.first.receipt_set.receipts}
        blocked = {
            "recoverable-secret-material", "verify-artifact-hashes",
            "start-in-disconnected-recovery", "resolve-credential-descriptors",
            "revalidate-audiences-and-tenants",
            "enable-transports-and-provider-starts",
        }
        for entry_id in blocked:
            self.assertIs(by_id[entry_id].disposition, recovery_plan.Disposition.REQUIRED_BUT_NOT_EXERCISED)
        self.assertFalse(self.first.enablement_verified_disabled)
        self.assertEqual(self.first.assessment.final_state.phase, recovery_plan.StartupPhase.ASSEMBLING_RECOVERY_SET)

    def test_measurements_are_numeric_but_objective_comparisons_are_out_of_scope(self) -> None:
        by_id = {item.id: item for item in self.first.measurements}
        self.assertEqual(by_id["rpo"].value_seconds, 1.0)
        self.assertGreaterEqual(by_id["rto"].value_seconds, 0.0)
        for measurement in by_id.values():
            self.assertIsNone(measurement.comparison)
            self.assertIsNone(measurement.objective_value_seconds)
            self.assertEqual(measurement.comparison_status, "out_of_scope")
        self.assertFalse(self.first.enablement_gate_run)
        self.assertEqual(self.first.enablement_gate_status, "not-run")

    def test_second_run_has_same_semantic_outputs_after_volatile_evidence_is_ignored(self) -> None:
        second = composition.resolve_anonymous_composition()
        first_map = [(item.entry_id, item.disposition) for item in self.first.receipt_set.receipts]
        second_map = [(item.entry_id, item.disposition) for item in second.receipt_set.receipts]
        self.assertEqual(second_map, first_map)
        self.assertEqual(second.package_receipt, self.first.package_receipt)
        self.assertEqual(second.package_recovery_point, self.first.package_recovery_point)
        self.assertEqual(second.blockers, self.first.blockers)
        first_boundary = json.loads(self.first.boundary_json)
        second_boundary = json.loads(second.boundary_json)
        self.assertEqual(second_boundary["evidence"]["worker_base_commit"], first_boundary["evidence"]["worker_base_commit"])
        self.assertEqual(second_boundary["evidence"]["worker_sha256"], first_boundary["evidence"]["worker_sha256"])

    def test_private_failure_path_closes_the_producer_descriptor(self) -> None:
        produced = anonymous_backup.produce_anonymous_backup()
        descriptor = produced.descriptor

        refused = anonymous_boundary.Result(
            anonymous_boundary.Outcome.REFUSED, None,
            anonymous_boundary.Refusal(anonymous_boundary.RefusalCode.WORKER_REFUSED, "test refusal"),
            True, 1,
        )
        with mock.patch.object(composition.anonymous_backup, "produce_anonymous_backup", return_value=produced), mock.patch.object(composition.anonymous_boundary, "run", return_value=refused):
            with self.assertRaises(composition.CompositionRefused):
                composition._run()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_stage_exceptions_are_typed_and_close_does_not_mask_primary(self) -> None:
        with mock.patch.object(composition.plan_model, "load_plan", side_effect=ValueError("bad plan")):
            with self.assertRaises(composition.CompositionRefused) as caught:
                composition.resolve_anonymous_composition()
        self.assertIs(caught.exception.refusal, composition.CompositionRefusal.PLAN_INVALID)
        with mock.patch.object(composition.anonymous_backup, "produce_anonymous_backup", side_effect=RuntimeError("producer")):
            with self.assertRaises(composition.CompositionRefused) as caught:
                composition._run()
        self.assertIs(caught.exception.refusal, composition.CompositionRefusal.PRODUCER_REFUSED)

        produced = anonymous_backup.produce_anonymous_backup()
        descriptor = produced.descriptor
        refusal = anonymous_boundary.Result(
            anonymous_boundary.Outcome.REFUSED, None,
            anonymous_boundary.Refusal(anonymous_boundary.RefusalCode.WORKER_REFUSED, "primary"),
            True, 1,
        )
        real_close = os.close
        try:
            with mock.patch.object(composition.os, "close", side_effect=OSError("close")):
                with mock.patch.object(composition.anonymous_backup, "produce_anonymous_backup", return_value=produced), mock.patch.object(composition.anonymous_boundary, "run", return_value=refusal):
                    with self.assertRaises(composition.CompositionRefused) as caught:
                        composition._run()
            self.assertIs(caught.exception.refusal, composition.CompositionRefusal.BOUNDARY_REFUSED)
        finally:
            real_close(descriptor)

    def test_minimal_forged_success_never_reaches_derivation(self) -> None:
        forged = anonymous_boundary.Result(
            anonymous_boundary.Outcome.MECHANISM_VERIFIED,
            {"verification": {}}, None, True, 0,
        )
        with self.assertRaises(composition.CompositionRefused) as caught:
            composition._validate_boundary_result(forged, {}, {}, {})
        self.assertIs(caught.exception.refusal, composition.CompositionRefusal.BOUNDARY_REFUSED)

    def test_nested_boundary_mutations_refuse(self) -> None:
        document = json.loads(self.first.boundary_json)
        original = document["evidence"]
        package_identity = original["package_memfd_identity"]
        worker_source_identity = original["worker_source"]["identity"]
        runtime_identity = original["runtime_identity"]
        mutations = (
            ("environment", ["LC_CTYPE", "EXTRA=x"]),
            ("package_memfd_identity", {**package_identity, "inode": package_identity["inode"] + 1}),
            ("worker_source", {**original["worker_source"], "identity": {**worker_source_identity, "size": 0}}),
            ("runtime_identity", {**runtime_identity, "sha256": "0" * 64}),
            ("id_maps", {**original["id_maps"], "uid_map": "0 0 2\n"}),
            ("mechanism_seconds", original["mechanism_seconds"] + 1.0),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                evidence = dict(original)
                evidence[key] = value
                forged = anonymous_boundary.Result(
                    anonymous_boundary.Outcome.MECHANISM_VERIFIED,
                    evidence, None, True, 0,
                )
                with self.assertRaises(composition.CompositionRefused):
                    composition._validate_boundary_result(
                        forged, package_identity, worker_source_identity,
                        runtime_identity,
                    )

    def test_removed_reordered_extra_and_repositioned_plans_refuse(self) -> None:
        plan = self.first.plan
        extra = dataclasses.replace(plan.entries[-1], position=22, id="extra")
        candidates = (
            dataclasses.replace(plan, entries=plan.entries[:-1]),
            dataclasses.replace(plan, entries=(plan.entries[1], plan.entries[0], *plan.entries[2:])),
            dataclasses.replace(plan, entries=(*plan.entries, extra)),
            dataclasses.replace(plan, entries=(dataclasses.replace(plan.entries[0], position=2), *plan.entries[1:])),
        )
        for candidate in candidates:
            with self.assertRaises(composition.CompositionRefused) as caught:
                composition._validate_closed_plan(candidate)
            self.assertIs(caught.exception.refusal, composition.CompositionRefusal.PLAN_INVALID)

    def test_kind_requires_verification_source_and_citation_relabels_refuse(self) -> None:
        plan = self.first.plan
        entry = plan.entries[12]
        citation = plan.objective_citations[0]
        candidates = (
            dataclasses.replace(plan, entries=(*plan.entries[:12], dataclasses.replace(entry, kind="recovery-set-input"), *plan.entries[13:])),
            dataclasses.replace(plan, entries=(*plan.entries[:12], dataclasses.replace(entry, requires=()), *plan.entries[13:])),
            dataclasses.replace(plan, entries=(*plan.entries[:12], dataclasses.replace(entry, verification="none-recorded"), *plan.entries[13:])),
            dataclasses.replace(plan, source_sha256="0" * 64),
            dataclasses.replace(plan, objective_citations=()),
            dataclasses.replace(plan, objective_citations=(dataclasses.replace(citation, source_sha256="0" * 64), *plan.objective_citations[1:])),
        )
        for candidate in candidates:
            with self.assertRaises(composition.CompositionRefused) as caught:
                composition._validate_closed_plan(candidate)
            self.assertIs(caught.exception.refusal, composition.CompositionRefusal.PLAN_INVALID)

    def test_wrong_typed_producer_result_still_closes_owned_descriptor(self) -> None:
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        wrong = types.SimpleNamespace(descriptor=read_fd)
        with mock.patch.object(composition.anonymous_backup, "produce_anonymous_backup", return_value=wrong):
            with self.assertRaises(composition.CompositionRefused) as caught:
                composition._run()
        self.assertIs(caught.exception.refusal, composition.CompositionRefusal.PRODUCER_REFUSED)
        with self.assertRaises(OSError):
            os.fstat(read_fd)


if __name__ == "__main__":
    unittest.main()
