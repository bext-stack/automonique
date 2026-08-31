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
        self.assertEqual([entry["dimension"] for entry in found], ["items"])

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


class HostedAsymmetryTest(unittest.TestCase):
    """A dimension a client cannot express never takes part in a comparison."""

    def hosted(self, **overrides: object) -> dict[str, object]:
        document = projection(
            "hosted",
            inventory={"state": "observed", "sources": ["review:workspace-conformance"]},
        )
        document.update(overrides)
        return document

    def test_the_cockpit_does_not_speak_for_the_source_inventory(self) -> None:
        """Its wire shape is an inbox of items, not a source set.

        A source it inventoried, read, and found empty is indistinguishable from
        one it never had, so comparing its source set against a replayed
        client's would report a disagreement about the cockpit's wire shape and
        call it a disagreement about attention.
        """
        reduced = parity.comparable(self.hosted())
        self.assertIsNone(reduced["inventory"])
        self.assertIsNone(reduced["status"])

    def test_an_idle_source_is_not_a_disagreement_with_the_cockpit(self) -> None:
        replayed = projection("shelldeck")
        replayed["inventory"]["sources"].append("orchestration:workspace-conformance")
        replayed["sources"]["orchestration:workspace-conformance"] = {
            "status": {"kind": "available"},
            "generation": "9",
            "visible_items": [],
        }
        self.assertEqual(
            parity.disagreements({"hosted": self.hosted(), "shelldeck": replayed}), []
        )

    def test_the_cockpit_still_speaks_for_items_and_generations(self) -> None:
        other = self.hosted()
        other["sources"]["review:workspace-conformance"]["generation"] = "1"
        found = parity.disagreements({"hosted": other, "shelldeck": projection("shelldeck")})
        self.assertEqual([entry["dimension"] for entry in found], ["items"])

    def test_two_replayed_clients_still_compare_their_inventories(self) -> None:
        other = projection("mobile")
        other["inventory"] = {"state": "derived", "sources": []}
        other["sources"] = {}
        found = parity.disagreements({"a": projection("shelldeck"), "b": other})
        self.assertIn("inventory", [entry["dimension"] for entry in found])

    def test_the_scope_names_who_took_part_in_each_dimension(self) -> None:
        scope = parity.comparison_scope(
            {
                "hosted": self.hosted(),
                "shelldeck": projection("shelldeck"),
                "mobile": projection("mobile"),
            }
        )
        self.assertEqual(scope["inventory"], ["mobile", "shelldeck"])
        self.assertEqual(scope["items"], ["hosted", "mobile", "shelldeck"])
        self.assertEqual(
            scope["presents_attention"], ["hosted", "mobile", "shelldeck"]
        )

    def test_a_dimension_only_one_client_speaks_to_is_not_agreement(self) -> None:
        """One speaker is not a comparison, and must not read as one."""
        scope = parity.comparison_scope({"hosted": self.hosted()})
        self.assertEqual(scope["inventory"], [])
        self.assertEqual(
            parity.disagreements({"hosted": self.hosted()}), []
        )


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

    def test_no_step_claims_the_operator_half_of_a_two_screen_comparison(
        self,
    ) -> None:
        """The residue that survives every automated check is a person.

        LIVE-GUI-2 has had the most subtracted from it: the deployed page's
        rendering is observed by `--cockpit-render-check` and its projection is
        compared here. Both meet at the projection. Neither says one human saw
        the same item on two screens, and no residue may imply otherwise.
        """
        step = next(
            entry for entry in parity.GUI_RESIDUE if entry["id"] == "LIVE-GUI-2"
        )
        self.assertIn("same person", step["residue"])
        self.assertFalse(step["reducible"])

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
                    parity.Run, "read_lane", lambda self, project: {"state": "failed"}
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


class CaptureArgumentsTest(unittest.TestCase):
    """The live read is asked for in a way the deployment can actually answer.

    Both of these were once missing, and each turned a fact about how the
    harness asked into a published fact about the deployment.
    """

    def run_for(self, argv: list[str]) -> parity.Run:
        return parity.Run(parity.parse_args(argv))

    def test_every_live_capture_names_a_project(self) -> None:
        # `PlatformV2Request::QueryWorkContexts` has no project-less encoding.
        # Without `--project` the client's own encoder refuses the request, the
        # read never reaches the network, and the capture records a `protocol`
        # error that reads exactly like the deployment answering badly.
        arguments = self.run_for([]).capture_arguments("wc2_project_x")
        self.assertIn("--project", arguments)
        self.assertEqual(arguments[arguments.index("--project") + 1], "wc2_project_x")

    def test_a_loopback_probe_carries_the_canonical_host_and_the_tls_hop(self) -> None:
        # A web entry that answers for one canonical name over TLS answers 400
        # to a request addressed to 127.0.0.1. Without these the flag silently
        # means "the lane check cannot run".
        arguments = self.run_for(
            ["--hosted-loopback", "http://127.0.0.1:8080", "--hosted-host", "entry.example"]
        ).capture_arguments("wc2_project_x")
        self.assertIn("--host-header", arguments)
        self.assertEqual(arguments[arguments.index("--host-header") + 1], "entry.example")
        self.assertEqual(
            arguments[arguments.index("--forwarded-proto") + 1],
            parity.LOOPBACK_FORWARDED_PROTO,
        )

    def test_a_public_edge_probe_claims_no_host_of_its_own(self) -> None:
        arguments = self.run_for(
            ["--hosted-endpoint", "https://entry.example"]
        ).capture_arguments("wc2_project_x")
        self.assertNotIn("--host-header", arguments)
        self.assertNotIn("--forwarded-proto", arguments)


class LaneReasonTest(unittest.TestCase):
    """The refusal sentence is said only about an actual refusal.

    Everything else a non-negotiated lane can mean — not reached, addressed
    wrongly, credential refused, never asked — is a different finding and only
    one of them is about the attention lane.
    """

    def test_a_deployment_that_did_not_answer_is_not_a_refusal(self) -> None:
        reason = parity.lane_reason(
            {"state": "error", "category": "unexpected_status", "http_status": 503}
        )
        self.assertIn("503", reason)
        self.assertIn("did not answer", reason)
        self.assertNotIn("refuses its Platform v2 attention lane", reason)

    def test_a_request_the_deployment_rejected_is_named_as_such(self) -> None:
        reason = parity.lane_reason(
            {"state": "error", "category": "unexpected_status", "http_status": 400}
        )
        self.assertIn("400", reason)
        self.assertIn("as addressed", reason)
        self.assertNotIn("refuses its Platform v2 attention lane", reason)

    def test_a_refused_credential_is_not_a_refused_lane(self) -> None:
        reason = parity.lane_reason(
            {"state": "error", "category": "unauthorized", "http_status": 401}
        )
        self.assertIn("credential", reason)
        self.assertNotIn("refuses its Platform v2 attention lane", reason)

    def test_a_lane_that_was_never_read_is_not_reported_as_a_refusal(self) -> None:
        # No project, no cockpit answer: the lane was never asked anything, so
        # the deployment said nothing about it either way.
        reason = parity.lane_reason({})
        self.assertIn("never read", reason)
        self.assertNotIn("refuses its Platform v2 attention lane", reason)

    def test_no_status_at_all_is_reported_as_unreached(self) -> None:
        reason = parity.lane_reason({"state": "error", "category": "io"})
        self.assertIn("could not be reached", reason)

    def test_a_typed_refusal_is_the_one_outcome_reported_as_a_refusal(self) -> None:
        reason = parity.lane_reason(
            {"state": "refused", "category": "platform_v2_web_binding_unavailable"}
        )
        self.assertIn("refuses its Platform v2 attention lane", reason)
        self.assertIn("platform_v2_web_binding_unavailable", reason)

    def test_the_observation_records_the_status_beside_the_category(self) -> None:
        observed = parity.lane_observation(
            {
                "state": "error",
                "category": "unexpected_status",
                "http_status": 503,
                "http_content_type": "application/json",
            }
        )
        self.assertEqual(observed["http_status"], 503)
        self.assertEqual(observed["http_content_type"], "application/json")

    def test_free_text_never_enters_the_observation_as_a_category(self) -> None:
        observed = parity.lane_observation({"state": "error", "category": "a live path /home/x"})
        self.assertEqual(observed["category"], "<non_category_text_withheld>")


class WorkContextReasonTest(unittest.TestCase):
    """A read that errored is not an empty graph."""

    def test_a_failed_read_is_not_reported_as_an_empty_graph(self) -> None:
        reason = parity.work_context_reason({"state": "error", "category": "protocol"})
        self.assertIn("none was obtained", reason)
        self.assertNotIn("names no user workspace", reason)

    def test_a_refused_read_is_not_reported_as_an_empty_graph(self) -> None:
        reason = parity.work_context_reason(
            {"state": "refused", "category": "platform_v2_project_denied"}
        )
        self.assertIn("none was obtained", reason)
        self.assertIn("platform_v2_project_denied", reason)
        self.assertNotIn("names no user workspace", reason)

    def test_a_read_that_succeeded_and_was_empty_says_so(self) -> None:
        reason = parity.work_context_reason(
            {"state": "available", "pages_canonical_base64": []}
        )
        self.assertIn("was read and names no user workspace", reason)
        self.assertNotIn("none was obtained", reason)

    def test_a_failed_read_reports_the_status_it_saw(self) -> None:
        reason = parity.work_context_reason(
            {"state": "error", "category": "unexpected_status", "http_status": 503}
        )
        self.assertIn("503", reason)


class CockpitProjectsTest(unittest.TestCase):
    """The project the live read names is one the deployment named."""

    def test_the_projects_the_cockpit_named_are_returned_in_order(self) -> None:
        self.assertEqual(
            parity.cockpit_projects(
                {"projects": [{"id": "wc2_project_a"}, {"id": "wc2_project_b"}]}
            ),
            ["wc2_project_a", "wc2_project_b"],
        )

    def test_a_cockpit_that_named_none_yields_none(self) -> None:
        self.assertEqual(parity.cockpit_projects({"projects": []}), [])
        self.assertEqual(parity.cockpit_projects({}), [])

    def test_a_malformed_entry_is_skipped_rather_than_raising(self) -> None:
        self.assertEqual(
            parity.cockpit_projects({"projects": ["wc2_project_a", {"id": 7}, {"id": "ok"}]}),
            ["ok"],
        )


if __name__ == "__main__":
    unittest.main()
