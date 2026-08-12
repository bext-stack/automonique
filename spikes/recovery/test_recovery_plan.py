#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Model tests for canonical recovery-plan receipts; no drill is executed."""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import recovery_plan as rp  # noqa: E402


def _evidence_hash(entry_id: str) -> str:
    return hashlib.sha256(
        f"synthetic model evidence only:{entry_id}".encode()
    ).hexdigest()


def _synthetic_receipts_for_model_test(
    plan: rp.RecoveryPlan,
    dispositions: dict[str, rp.Disposition] | None = None,
) -> rp.ReceiptSet:
    """Build structural test data that is never completion-eligible."""
    requested = dispositions or {}
    receipts: list[rp.StepReceipt] = []
    receipt_hashes: dict[str, str] = {}
    state = rp.initial_state()
    for entry in plan.entries:
        disposition = requested.get(
            entry.id,
            rp.Disposition.VERIFIED_DISABLED
            if entry.kind == "enablement-gate"
            else rp.Disposition.EXERCISED,
        )
        receipt = rp.StepReceipt(
            entry_id=entry.id,
            disposition=disposition,
            prerequisite_receipt_hashes=tuple(
                (required, receipt_hashes[required]) for required in entry.requires
            ),
            evidence_sha256=_evidence_hash(entry.id),
            transition=rp.transition_for(state, entry, disposition),
        )
        receipts.append(receipt)
        receipt_hashes[entry.id] = receipt.receipt_sha256()
        state = receipt.transition.after
    return rp.ReceiptSet(tuple(receipts))


class RecoveryPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = rp.load_plan()
        self.receipt_set = _synthetic_receipts_for_model_test(self.plan)

    def assert_refused(
        self, expected: rp.ReceiptRefusal, receipt_set: rp.ReceiptSet
    ) -> None:
        with self.assertRaises(rp.ReceiptRefused) as caught:
            rp.validate_receipts(self.plan, receipt_set)
        self.assertIs(caught.exception.refusal, expected)

    def replace_receipt(self, index: int, **changes: object) -> rp.ReceiptSet:
        receipts = list(self.receipt_set.receipts)
        receipts[index] = dataclasses.replace(receipts[index], **changes)
        return dataclasses.replace(self.receipt_set, receipts=tuple(receipts))

    def test_canonical_twenty_one_positions_form_a_complete_state_chain(self) -> None:
        self.assertEqual(len(self.plan.entries), 21)
        self.assertEqual(
            [entry.position for entry in self.plan.entries], list(range(1, 22))
        )
        assessment = rp.validate_receipts(self.plan, self.receipt_set)
        self.assertTrue(assessment.structurally_complete)
        self.assertFalse(assessment.completion_eligible)
        self.assertEqual(assessment.required_but_not_exercised, ())
        self.assertEqual(assessment.final_state.receipt_cursor, 21)
        self.assertIs(
            assessment.final_state.phase,
            rp.StartupPhase.ENABLEMENT_VERIFIED_DISABLED,
        )

    def test_model_has_no_actual_execution_relabel_route(self) -> None:
        self.assertFalse(hasattr(rp, "ExecutionKind"))
        self.assertEqual(
            [field.name for field in dataclasses.fields(rp.ReceiptSet)],
            ["receipts"],
        )
        self.assertFalse(
            rp.validate_receipts(self.plan, self.receipt_set).completion_eligible
        )

    def test_missing_extra_and_duplicate_receipts_are_distinct_refusals(self) -> None:
        self.assert_refused(
            rp.ReceiptRefusal.MISSING_RECEIPT,
            dataclasses.replace(
                self.receipt_set, receipts=self.receipt_set.receipts[:-1]
            ),
        )
        extra = dataclasses.replace(
            self.receipt_set.receipts[-1], entry_id="synthetic-extra-entry"
        )
        self.assert_refused(
            rp.ReceiptRefusal.EXTRA_RECEIPT,
            dataclasses.replace(
                self.receipt_set, receipts=self.receipt_set.receipts + (extra,)
            ),
        )
        duplicate = self.receipt_set.receipts + (self.receipt_set.receipts[-1],)
        self.assert_refused(
            rp.ReceiptRefusal.DUPLICATE_RECEIPT,
            dataclasses.replace(self.receipt_set, receipts=duplicate),
        )

    def test_skipped_and_reversed_state_transitions_are_refused(self) -> None:
        original = self.receipt_set.receipts[1].transition
        skipped = dataclasses.replace(
            original,
            after=dataclasses.replace(
                original.after,
                receipt_cursor=original.after.receipt_cursor + 1,
            ),
        )
        self.assert_refused(
            rp.ReceiptRefusal.INVALID_TRANSITION,
            self.replace_receipt(1, transition=skipped),
        )
        self.assert_refused(
            rp.ReceiptRefusal.INVALID_TRANSITION,
            self.replace_receipt(
                1, transition=rp.StateTransition(original.after, original.before)
            ),
        )

    def test_reversed_receipt_order_is_refused(self) -> None:
        receipts = list(self.receipt_set.receipts)
        receipts[0], receipts[1] = receipts[1], receipts[0]
        self.assert_refused(
            rp.ReceiptRefusal.WRONG_ORDER,
            dataclasses.replace(self.receipt_set, receipts=tuple(receipts)),
        )

    def test_prerequisite_receipt_hashes_are_exact(self) -> None:
        index = next(
            index for index, entry in enumerate(self.plan.entries) if entry.requires
        )
        receipt = self.receipt_set.receipts[index]
        corrupted = list(receipt.prerequisite_receipt_hashes)
        corrupted[0] = (corrupted[0][0], "0" * 64)
        self.assert_refused(
            rp.ReceiptRefusal.PREREQUISITE_HASH_MISMATCH,
            self.replace_receipt(
                index, prerequisite_receipt_hashes=tuple(corrupted)
            ),
        )

    def test_each_external_authority_flag_must_remain_false(self) -> None:
        self.assertEqual(
            {field.name for field in dataclasses.fields(rp.ExternalAuthorityFlags)},
            {
                "transport_intake",
                "outbox_delivery",
                "provider_starts",
                "connector_sends",
                "transport_lease_acquisition",
            },
        )
        for field in dataclasses.fields(rp.ExternalAuthorityFlags):
            with self.subTest(field=field.name):
                flags = dataclasses.replace(
                    rp.ExternalAuthorityFlags(), **{field.name: True}
                )
                self.assert_refused(
                    rp.ReceiptRefusal.EXTERNAL_AUTHORITY_GRANTED,
                    self.replace_receipt(0, authorities=flags),
                )

    def test_enablement_position_can_only_be_verified_disabled(self) -> None:
        enablement_index = next(
            index
            for index, entry in enumerate(self.plan.entries)
            if entry.kind == "enablement-gate"
        )
        self.assertEqual(enablement_index, len(self.plan.entries) - 1)
        self.assert_refused(
            rp.ReceiptRefusal.ENABLEMENT_NOT_DISABLED,
            self.replace_receipt(
                enablement_index, disposition=rp.Disposition.EXERCISED
            ),
        )

    def test_no_canonical_position_is_not_applicable_without_policy(self) -> None:
        for index, entry in enumerate(self.plan.entries):
            with self.subTest(entry=entry.id):
                self.assert_refused(
                    rp.ReceiptRefusal.INVALID_NOT_APPLICABLE_REASON,
                    self.replace_receipt(
                        index, disposition=rp.Disposition.NOT_APPLICABLE
                    ),
                )

    def test_exercised_step_cannot_have_required_unrun_parent(self) -> None:
        child = next(entry for entry in self.plan.entries if entry.requires)
        parent_id = child.requires[0]
        receipt_set = _synthetic_receipts_for_model_test(
            self.plan,
            {parent_id: rp.Disposition.REQUIRED_BUT_NOT_EXERCISED},
        )
        self.assert_refused(
            rp.ReceiptRefusal.UNRESOLVED_PREREQUISITE, receipt_set
        )

    def test_verified_disabled_gate_cannot_have_required_unrun_parent(self) -> None:
        gate = next(entry for entry in self.plan.entries if entry.kind == "enablement-gate")
        parent_id = gate.requires[0]
        receipt_set = _synthetic_receipts_for_model_test(
            self.plan,
            {parent_id: rp.Disposition.REQUIRED_BUT_NOT_EXERCISED},
        )
        self.assert_refused(
            rp.ReceiptRefusal.UNRESOLVED_PREREQUISITE, receipt_set
        )

    def test_required_unrun_advances_cursor_but_not_semantic_phase(self) -> None:
        state = rp.DisconnectedStartState(
            17, rp.StartupPhase.VERIFYING_RECOVERY_SET
        )
        startup = self.plan.entries[17]
        after = rp.next_state(
            state, startup, rp.Disposition.REQUIRED_BUT_NOT_EXERCISED
        )
        self.assertEqual(after.receipt_cursor, startup.position)
        self.assertIs(after.phase, rp.StartupPhase.VERIFYING_RECOVERY_SET)
        exercised = rp.next_state(state, startup, rp.Disposition.EXERCISED)
        self.assertIs(exercised.phase, rp.StartupPhase.DISCONNECTED_STARTED)


if __name__ == "__main__":
    unittest.main()
