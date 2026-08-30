#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Hold the live parity harness to the three promises it makes.

It promises not to record live work coordinates, not to call an agreement
between clients that were never asked a real question a pass, and not to mark
an operator step satisfied. None of the three is visible in a green run, so
they are tested here rather than trusted.

Everything here is offline. The lanes that talk to a deployment or shell out to
a client checkout are exercised by running the harness, not by these tests.
"""

from __future__ import annotations

import json
import unittest
import unittest.mock

from tools import run_attention_live_parity as parity


CONTROL_EXPECTATION = {
    "inventory_contains": "review:workspace-conformance",
    "final_generation": "2",
    "final_visible_items": ["item-a", "item-b"],
}


def projection(client: str, **overrides: object) -> dict[str, object]:
    document = {
        "schema": parity.PROJECTION_SCHEMA,
        "client": client,
        "inventory": {"state": "derived", "sources": ["review:workspace-conformance"]},
        "board": {"state": "constructed"},
        "sources": {
            "review:workspace-conformance": {
                "status": {"kind": "available"},
                "generation": "2",
                "visible_items": ["item-a", "item-b"],
            }
        },
        "visible_items": [
            {
                "source": "review:workspace-conformance",
                "item": "item-a",
                "state": "needs_you",
                "reason": "review_requested",
            }
        ],
        "presents_attention": True,
    }
    document.update(overrides)
    return document


class SaltTest(unittest.TestCase):
    """Equality inside one report is the comparison; the value is not recorded."""

    def test_the_same_identifier_digests_to_the_same_token(self) -> None:
        salt = parity.Salt()
        self.assertEqual(salt.of("workspace-a"), salt.of("workspace-a"))

    def test_different_identifiers_digest_differently(self) -> None:
        salt = parity.Salt()
        self.assertNotEqual(salt.of("workspace-a"), salt.of("workspace-b"))

    def test_the_identifier_never_survives_into_the_digest(self) -> None:
        salt = parity.Salt()
        self.assertNotIn("workspace-a", salt.of("workspace-a"))

    def test_two_runs_do_not_share_a_digest_for_the_same_identifier(self) -> None:
        """An unsalted digest of a short identifier is recoverable by guessing."""
        self.assertNotEqual(parity.Salt().of("acme"), parity.Salt().of("acme"))


class CategoryTest(unittest.TestCase):
    def test_a_bare_token_is_admitted(self) -> None:
        self.assertEqual(
            parity.category("platform_v2_web_binding_unavailable"),
            "platform_v2_web_binding_unavailable",
        )

    def test_free_text_is_withheld_rather_than_reproduced(self) -> None:
        self.assertEqual(
            parity.category("workspace acme/prod refused"),
            "<non_category_text_withheld>",
        )

    def test_a_non_string_passes_through_unchanged(self) -> None:
        self.assertIsNone(parity.category(None))


class SaltedProjectionTest(unittest.TestCase):
    """Every live identifier in a driver projection is replaced by a digest."""

    def test_source_and_item_identifiers_are_digested_but_kinds_survive(self) -> None:
        salted = parity.salted_projection(projection("shelldeck"), parity.Salt())
        key = next(iter(salted["sources"]))
        self.assertTrue(key.startswith("review:#"))
        self.assertNotIn("workspace-conformance", json.dumps(salted))
        self.assertNotIn("item-a", json.dumps(salted))

    def test_an_inventory_refusal_is_reduced_to_a_category(self) -> None:
        salted = parity.salted_projection(
            projection(
                "shelldeck",
                inventory={"state": "refused", "error": "some free text here"},
            ),
            parity.Salt(),
        )
        self.assertEqual(salted["inventory"]["error"], "<non_category_text_withheld>")

    def test_equality_between_clients_survives_the_same_salt(self) -> None:
        salt = parity.Salt()
        left = parity.salted_projection(projection("shelldeck"), salt)
        right = parity.salted_projection(projection("mobile"), salt)
        self.assertEqual(parity.comparable(left), parity.comparable(right))


class ComparisonTest(unittest.TestCase):
    """What the clients must agree about, and what they need not."""

    def test_identical_projections_do_not_disagree(self) -> None:
        self.assertEqual(
            parity.disagreements(
                {"shelldeck": projection("shelldeck"), "mobile": projection("mobile")}
            ),
            [],
        )

    def test_inventory_order_is_not_a_disagreement(self) -> None:
        """Each client may hold the source set in its own order.

        ShellDeck orders by source kind and Mobile alphabetically. The shared
        corpus fixes which sources exist, not the order a client holds them in.
        """
        other = projection("mobile")
        other["inventory"] = {
            "state": "derived",
            "sources": ["review:workspace-conformance"][::-1],
        }
        self.assertEqual(
            parity.disagreements({"a": projection("shelldeck"), "b": other}), []
        )

    def test_a_different_generation_is_a_disagreement(self) -> None:
        other = projection("mobile")
        other["sources"]["review:workspace-conformance"]["generation"] = "1"
        found = parity.disagreements({"a": projection("shelldeck"), "b": other})
        self.assertEqual([entry["dimension"] for entry in found], ["sources"])

    def test_a_different_item_set_is_a_disagreement(self) -> None:
        other = projection("mobile")
        other["sources"]["review:workspace-conformance"]["visible_items"] = ["item-a"]
        self.assertTrue(parity.disagreements({"a": projection("shelldeck"), "b": other}))

    def test_a_missing_source_is_a_disagreement(self) -> None:
        other = projection("mobile")
        other["inventory"] = {"state": "derived", "sources": []}
        other["sources"] = {}
        found = parity.disagreements({"a": projection("shelldeck"), "b": other})
        self.assertIn("inventory", [entry["dimension"] for entry in found])

    def test_item_order_within_a_source_is_a_disagreement(self) -> None:
        """The corpus fixes per-source order, so a reordering is a difference."""
        other = projection("mobile")
        other["sources"]["review:workspace-conformance"]["visible_items"] = [
            "item-b",
            "item-a",
        ]
        self.assertTrue(parity.disagreements({"a": projection("shelldeck"), "b": other}))


class ControlTest(unittest.TestCase):
    """The fence against three drivers agreeing because none of them ran."""

    def test_a_driver_reproducing_the_control_passes(self) -> None:
        self.assertIsNone(
            parity.control_matches(projection("shelldeck"), CONTROL_EXPECTATION)
        )

    def test_a_driver_that_derived_no_inventory_is_caught(self) -> None:
        empty = projection("shelldeck", inventory={"state": "refused", "error": "x"})
        self.assertIsNotNone(parity.control_matches(empty, CONTROL_EXPECTATION))

    def test_a_driver_that_stopped_at_the_first_generation_is_caught(self) -> None:
        stalled = projection("shelldeck")
        stalled["sources"]["review:workspace-conformance"]["generation"] = "1"
        self.assertIsNotNone(parity.control_matches(stalled, CONTROL_EXPECTATION))

    def test_a_driver_showing_nothing_is_caught(self) -> None:
        silent = projection("shelldeck")
        silent["sources"]["review:workspace-conformance"]["visible_items"] = []
        self.assertIsNotNone(parity.control_matches(silent, CONTROL_EXPECTATION))


class SuccessionTest(unittest.TestCase):
    """A comparison over a deployment that never moved proves nothing."""

    def read(self, revision: int | None) -> dict[str, object]:
        if revision is None:
            return {
                "source": {"kind": "review", "id": "workspace-a"},
                "read": {"kind": "refusal", "category": "platform_v2_unavailable"},
            }
        snapshot = json.dumps({"revision": revision}).encode("utf-8")
        import base64

        return {
            "source": {"kind": "review", "id": "workspace-a"},
            "read": {
                "kind": "snapshot",
                "snapshot_canonical_base64": base64.b64encode(snapshot).decode("ascii"),
            },
        }

    def test_two_reads_of_the_same_generation_share_a_signature(self) -> None:
        self.assertEqual(
            parity.pass_signature([self.read(4)]), parity.pass_signature([self.read(4)])
        )

    def test_a_moved_generation_changes_the_signature(self) -> None:
        self.assertNotEqual(
            parity.pass_signature([self.read(4)]), parity.pass_signature([self.read(5)])
        )

    def test_a_refusal_and_a_snapshot_are_not_the_same_read(self) -> None:
        self.assertNotEqual(
            parity.pass_signature([self.read(None)]), parity.pass_signature([self.read(1)])
        )

    def test_an_undecodable_snapshot_is_named_rather_than_ignored(self) -> None:
        entry = {
            "source": {"kind": "review", "id": "workspace-a"},
            "read": {"kind": "snapshot", "snapshot_canonical_base64": "not base64!!"},
        }
        self.assertIn("undecodable", parity.pass_signature([entry]))


class HostedProjectionTest(unittest.TestCase):
    """The deployment's own reducer output, renamed but never re-decided."""

    def test_a_degraded_cockpit_projects_a_refusal_and_shows_nothing(self) -> None:
        result = parity.hosted_projection(
            {
                "mode": "partial",
                "degradation": {
                    "state": "unavailable",
                    "category": "platform_v2_web_binding_unavailable",
                },
                "attention": {"state": "unavailable", "category": "platform_v2_unavailable"},
            },
            parity.Salt(),
        )
        self.assertEqual(result["inventory"]["state"], "refused")
        self.assertEqual(
            result["inventory"]["error"], "platform_v2_web_binding_unavailable"
        )
        self.assertFalse(result["presents_attention"])

    def test_a_v2_cockpit_projects_its_inbox_with_digested_identifiers(self) -> None:
        result = parity.hosted_projection(
            {
                "mode": "v2",
                "attention": {"state": "available", "category": None},
                "inbox": {
                    "omitted": "0",
                    "sources": {"attention": {"state": "available"}},
                    "items": [
                        {
                            "id": "review:workspace-a:item-a",
                            "source_kind": "review",
                            "source_id": "workspace-a",
                            "source_revision": "7",
                            "state": "needs_you",
                            "reason": "review_requested",
                        }
                    ],
                },
            },
            parity.Salt(),
        )
        self.assertTrue(result["presents_attention"])
        key = next(iter(result["sources"]))
        self.assertTrue(key.startswith("review:#"))
        self.assertEqual(result["sources"][key]["generation"], "7")
        self.assertNotIn("workspace-a", json.dumps(result))
        self.assertNotIn("item-a", json.dumps(result))

    def test_a_source_identifier_containing_a_colon_keeps_its_item(self) -> None:
        """`kind:source:item` is split from the right, or the item is lost."""
        result = parity.hosted_projection(
            {
                "mode": "v2",
                "attention": {"state": "available"},
                "inbox": {
                    "omitted": "0",
                    "items": [
                        {
                            "id": "review:has:colons:item-z",
                            "source_kind": "review",
                            "source_id": "has:colons",
                            "source_revision": "1",
                        }
                    ],
                },
            },
            parity.Salt(),
        )
        key = next(iter(result["sources"]))
        self.assertEqual(len(result["sources"][key]["visible_items"]), 1)


class TargetTest(unittest.TestCase):
    """Enumerating workspaces reads the graph; it decides nothing about sources."""

    def page(self, records: list[dict[str, object]]) -> str:
        import base64

        return base64.b64encode(
            json.dumps({"items": records}).encode("utf-8")
        ).decode("ascii")

    def targets(self, records: list[dict[str, object]]) -> list[tuple[str, str]]:
        run = parity.Run.__new__(parity.Run)
        return parity.Run.targets(run, [self.page(records)])

    def test_a_workspace_with_its_project_relation_is_a_target(self) -> None:
        self.assertEqual(
            self.targets(
                [
                    {
                        "identity": {"kind": "user_workspace", "id": "w"},
                        "relations": [
                            {
                                "kind": "user_workspace_project",
                                "target": {"kind": "project", "id": "p"},
                            }
                        ],
                    }
                ]
            ),
            [("p", "w")],
        )

    def test_a_workspace_without_a_project_relation_is_not_a_target(self) -> None:
        self.assertEqual(
            self.targets(
                [{"identity": {"kind": "user_workspace", "id": "w"}, "relations": []}]
            ),
            [],
        )

    def test_a_record_of_another_kind_is_not_a_target(self) -> None:
        self.assertEqual(
            self.targets([{"identity": {"kind": "project", "id": "p"}, "relations": []}]),
            [],
        )

    def test_an_undecodable_page_is_skipped_rather_than_raising(self) -> None:
        run = parity.Run.__new__(parity.Run)
        self.assertEqual(parity.Run.targets(run, ["not base64!!"]), [])


class OperatorStepTest(unittest.TestCase):
    """Subtracting is not signing."""

    def test_every_gui_step_is_described_and_none_is_marked_reducible(self) -> None:
        identifiers = [step["id"] for step in parity.GUI_RESIDUE]
        self.assertEqual(
            identifiers, ["LIVE-GUI-1", "LIVE-GUI-2", "LIVE-GUI-3", "LIVE-GUI-4"]
        )
        for step in parity.GUI_RESIDUE:
            self.assertFalse(step["reducible"])
            self.assertTrue(step["residue"].strip())
            self.assertTrue(step["machine_verified"].strip())

    def test_the_harness_records_no_state_that_could_satisfy_a_step(self) -> None:
        """No key in this report can be mistaken for a sign-off."""
        rendered = json.dumps(list(parity.GUI_RESIDUE))
        for forbidden in ("signed_off", "satisfied", "complete"):
            self.assertNotIn(f'"{forbidden}"', rendered)


class ReportStateTest(unittest.TestCase):
    """`passed` is never true while a control did not run or a check did not fire."""

    def build(self, checks: list[dict[str, object]]) -> dict[str, object]:
        args = parity.parse_args([])

        def prepare(self: parity.Run) -> None:
            self.checks.extend(checks)

        with unittest.mock.patch.object(parity.Run, "prepare", prepare):
            with unittest.mock.patch.object(parity.Run, "control", lambda self: {}):
                with unittest.mock.patch.object(
                    parity.Run, "read_lane", lambda self: {"state": "failed"}
                ):
                    with unittest.mock.patch.object(
                        parity, "cockpit_read", lambda *a, **k: {"state": "blocked"}
                    ):
                        with unittest.mock.patch.object(
                            parity, "repository", lambda root: {"state": "unavailable"}
                        ):
                            return parity.build_report(args)

    def test_without_a_control_no_agreement_is_reported_as_evidence(self) -> None:
        report = self.build([{"name": "x", "state": "passed"}])
        self.assertFalse(report["passed"])
        self.assertEqual(report["live_verification"]["state"], "blocked")
        self.assertIn("known-answer control", report["live_verification"]["reason"])

    def test_a_failed_check_is_reported_as_failed(self) -> None:
        report = self.build(
            [
                {"name": "control_replays_through_shelldeck", "state": "passed"},
                {"name": "live_projection_parity", "state": "failed"},
            ]
        )
        self.assertEqual(report["live_verification"]["state"], "failed")

    def test_the_report_names_where_each_reducer_lives(self) -> None:
        report = self.build([])
        for client in parity.CLIENTS:
            self.assertIn(client, report["reducers"])
        self.assertIn("read from the deployment", report["reducers"]["hosted"])


if __name__ == "__main__":
    unittest.main()
