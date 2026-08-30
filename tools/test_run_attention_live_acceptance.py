#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Hold the live acceptance harness to the two promises it makes.

The harness makes a security promise — nothing from a deployment response
reaches the report unless it is an allow-listed field of a type the web entry
serializes — and an honesty promise: a check reports `passed` only for an
observation it actually made. Both are easy to break by accident and neither is
visible in a green run, so they are tested here rather than trusted.
"""

from __future__ import annotations

import json
import pathlib
import shlex
import tempfile
import unittest
import unittest.mock

from tools import run_attention_live_acceptance as live


HOSTED = live.Origin(key="hosted", url="https://example.invalid")


def outcome(status: int, body: dict[str, object], realm: str = "") -> dict[str, object]:
    observed, counts = live.observable(json.dumps(body).encode("utf-8"))
    result: dict[str, object] = {
        "url": "https://example.invalid/probe",
        "http_status": status,
        "observed": observed,
    }
    if counts:
        result["observed_counts"] = counts
    if realm:
        result["www_authenticate"] = realm
    return result


class ProjectionTest(unittest.TestCase):
    """Nothing reaches the report that the allow list does not name."""

    def test_unknown_key_is_dropped_whatever_its_value_type(self) -> None:
        # A key gate that only applied to scalars would let a nested object
        # through wholesale, which is the whole leak this guards against.
        projected = live.scrub(
            {
                "schema": "automonique.dashboard.platform/v2",
                "surprise": "plain",
                "nested": {"schema": "smuggled"},
                "listed": ["smuggled"],
            }
        )
        self.assertEqual(projected, {"schema": "automonique.dashboard.platform/v2"})

    def test_secret_marked_keys_are_dropped_even_when_allow_listed_below(self) -> None:
        projected = live.scrub(
            {
                "pairing_token": "s3cret",
                "authorization": {"schema": "smuggled"},
                "credential_id": "abc",
                "session_cookie": "abc",
                "schema": "kept",
            }
        )
        self.assertEqual(projected, {"schema": "kept"})

    def test_live_work_identifiers_and_free_text_are_not_allow_listed(self) -> None:
        projected = live.scrub(
            {
                "resources": [
                    {
                        "resource": {
                            "authority": "automonique",
                            "kind": "session",
                            "id": "workspace-of-a-real-customer",
                        },
                        "freshness": "fresh",
                        "revision": "7",
                        "summary": "whatever the daemon happened to be doing",
                        "observed_at_ms": "1756000000000",
                    }
                ]
            }
        )
        self.assertEqual(
            projected,
            {
                "resources": [
                    {
                        "resource": {"authority": "automonique", "kind": "session"},
                        "freshness": "fresh",
                        "revision": "7",
                    }
                ]
            },
        )

    def test_refusal_explanation_is_admitted_only_as_a_category_token(self) -> None:
        self.assertEqual(
            live.scrub({"inventory": {"state": "refused", "explanation": "snapshot_too_large"}}),
            {"inventory": {"state": "refused", "explanation": "snapshot_too_large"}},
        )
        self.assertEqual(
            live.scrub({"inventory": {"explanation": "failed while running: rm -rf /home/someone"}}),
            {"inventory": {"explanation": "<non_category_text_withheld>"}},
        )

    def test_oversized_scalars_are_dropped(self) -> None:
        self.assertEqual(live.scrub({"revision": "x" * (live.SCALAR_LIMIT + 1)}), {})

    def test_identical_projections_collapse_and_the_true_count_survives(self) -> None:
        session = {
            "session": {"resource": {"authority": "automonique", "kind": "session", "id": "a"}},
            "attachable": True,
        }
        body = {"schema": "s", "sessions": [dict(session) for _ in range(45)]}
        observed, counts = live.observable(json.dumps(body).encode("utf-8"))
        self.assertEqual(len(observed["sessions"]), 1)
        self.assertEqual(counts["sessions"], 45)
        self.assertEqual(counts["sessions.distinct_projections"], 1)

    def test_an_empty_body_projects_to_nothing_rather_than_a_complaint(self) -> None:
        self.assertEqual(live.observable(b""), ({}, {}))

    def test_the_home_directory_never_appears_in_a_recorded_path(self) -> None:
        home = pathlib.Path.home().resolve()
        self.assertEqual(
            live.redacted_path(home / "state" / "web-entry"),
            f"{live.HOME_PLACEHOLDER}/state/web-entry",
        )


class GateTest(unittest.TestCase):
    """An unauthenticated refusal under the right realm is the desired result."""

    def gate(self, produced: dict[str, object]) -> dict[str, object]:
        with unittest.mock.patch.object(live, "request", return_value=produced):
            return live.check_gate(HOSTED, live.GATES[0], 1.0)

    def test_a_refusal_naming_the_expected_realm_passes(self) -> None:
        result = self.gate(outcome(401, {}, 'Basic realm="Monique Operations", charset="UTF-8"'))
        self.assertEqual(result["state"], "passed")

    def test_a_surface_served_without_authorization_is_a_finding(self) -> None:
        result = self.gate(outcome(200, {"schema": "anything"}))
        self.assertEqual(result["state"], "failed")
        self.assertIn("without authorization", result["reason"])

    def test_a_refusal_under_a_different_realm_fails(self) -> None:
        result = self.gate(outcome(401, {}, 'Bearer realm="Somewhere Else"'))
        self.assertEqual(result["state"], "failed")

    def test_an_unexpected_refusal_category_fails(self) -> None:
        with unittest.mock.patch.object(
            live,
            "request",
            return_value=outcome(401, {"error": "not_that_one"}, 'Bearer realm="Automonique Mobile"'),
        ):
            result = live.check_gate(HOSTED, live.GATES[1], 1.0)
        self.assertEqual(result["state"], "failed")

    def test_an_unreachable_deployment_blocks_rather_than_fails(self) -> None:
        result = self.gate({"url": "https://example.invalid/x", "unreachable": "Timeout"})
        self.assertEqual(result["state"], "blocked")
        self.assertIn("unreachable", result["reason"])


class AuthorizedReadTest(unittest.TestCase):
    """A read behind the gate is never reported as passing without one."""

    probe = live.AUTHORIZED[0]

    def read(self, produced: dict[str, object]) -> dict[str, object]:
        with unittest.mock.patch.object(live, "request", return_value=produced):
            return live.check_authorized(HOSTED, self.probe, "user:pass", "ENV", 1.0)

    def test_without_a_credential_the_read_is_blocked_not_attempted(self) -> None:
        with unittest.mock.patch.object(live, "request") as called:
            result = live.check_authorized(HOSTED, self.probe, None, "ENV", 1.0)
        called.assert_not_called()
        self.assertEqual(result["state"], "blocked")
        self.assertIn("$ENV", result["reason"])

    def test_the_expected_schema_passes(self) -> None:
        result = self.read(outcome(200, {"schema": self.probe.schema}))
        self.assertEqual(result["state"], "passed")

    def test_a_different_schema_fails_rather_than_passing_on_the_status(self) -> None:
        result = self.read(outcome(200, {"schema": "automonique.dashboard.platform/v1"}))
        self.assertEqual(result["state"], "failed")

    def test_a_rejected_credential_fails(self) -> None:
        self.assertEqual(self.read(outcome(401, {}))["state"], "failed")

    def test_an_unrouted_path_fails_because_the_build_predates_the_surface(self) -> None:
        result = self.read(outcome(404, {}))
        self.assertEqual(result["state"], "failed")
        self.assertIn("predates", result["reason"])


class AttentionCorpusTest(unittest.TestCase):
    """An empty corpus is not something the GUI steps can be run against."""

    def corpus(self, inventory: dict[str, object], resources: int) -> dict[str, object]:
        return live.check_attention_corpus(
            {
                "name": "hosted_attention_projection",
                "state": "passed",
                "endpoint": "https://example.invalid/api/platform",
                "observed": {"health": "operational", "inventory": inventory},
                "observed_counts": {"resources": resources, "sessions": 3},
            }
        )

    def test_a_refused_inventory_blocks_and_names_the_category(self) -> None:
        result = self.corpus(
            {"state": "refused", "explanation": "snapshot_too_large"}, 0
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["inventory_refusal"], "snapshot_too_large")

    def test_an_available_but_empty_inventory_still_blocks(self) -> None:
        self.assertEqual(self.corpus({"state": "available"}, 0)["state"], "blocked")

    def test_an_available_populated_inventory_passes(self) -> None:
        self.assertEqual(self.corpus({"state": "available"}, 12)["state"], "passed")

    def test_an_unread_projection_leaves_the_corpus_unknown(self) -> None:
        result = live.check_attention_corpus({"name": "x", "state": "blocked"})
        self.assertEqual(result["state"], "blocked")


class BuildAttributionTest(unittest.TestCase):
    """A build whose digest no manifest records cannot be attributed."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        binary = self.root / "bin" / "automonique-web-entry"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"deployed")
        self.digest = live.digest(binary)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self, relative: str, binary_sha256: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": "automonique.web-entry-release/v1",
                    "source_sha": "c0ffee",
                    "binary_sha256": binary_sha256,
                }
            ),
            encoding="utf-8",
        )

    def test_a_manifest_recording_the_running_digest_resolves_it(self) -> None:
        self.manifest("releases/a/manifest.json", self.digest)
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "resolved")
        self.assertEqual(described["attributed_by"][0]["source_sha"], "c0ffee")

    def test_a_manifest_describing_a_different_binary_does_not_resolve_it(self) -> None:
        self.manifest("releases/a/manifest.json", "00" * 32)
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "unresolved")
        self.assertEqual(described["binary_sha256"], self.digest)
        self.assertNotIn("source_sha", described)

    def test_an_unresolved_build_fails_the_attribution_check(self) -> None:
        self.manifest("releases/a/manifest.json", "00" * 32)
        builds = live.build_identity(self.root, self.root)
        result = live.check_build_attribution(builds)
        self.assertEqual(result["state"], "failed")
        self.assertTrue(builds["hosted_and_nonprod_identical"])

    def test_no_release_root_blocks_rather_than_failing(self) -> None:
        result = live.check_build_attribution(live.build_identity(None, None))
        self.assertEqual(result["state"], "blocked")


class SelfReportedBuildTest(unittest.TestCase):
    """A binary that names itself is attributable with no manifest at all."""

    REVISION = "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6"
    OTHER = "d5666f9c85080609f58f2d201dbe15ae1b8fcbb3"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.binary = self.root / "bin" / "automonique-web-entry"
        self.binary.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def install(self, script: str) -> None:
        """Stand in for the deployed entry, answering only the identity flag."""
        self.binary.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
        self.binary.chmod(0o700)
        self.digest = live.digest(self.binary)

    def answering(self, revision: str | None, provenance: str) -> None:
        document = json.dumps(
            {
                "schema": live.BUILD_IDENTITY_SCHEMA,
                "source_revision": revision,
                "provenance": provenance,
                "build_target": "x86_64-unknown-linux-gnu",
            }
        )
        self.install("printf '%s' " + shlex.quote(document))

    def manifest(self, relative: str, binary_sha256: str, source_sha: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": "automonique.web-entry-release/v1",
                    "source_sha": source_sha,
                    "binary_sha256": binary_sha256,
                }
            ),
            encoding="utf-8",
        )

    def test_a_committed_build_resolves_itself_without_any_manifest(self) -> None:
        self.answering(self.REVISION, "committed")
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "resolved")
        self.assertEqual(described["source_revision"], self.REVISION)
        self.assertEqual(described["release_manifests_inspected"], 0)

    def test_a_modified_build_names_nothing_it_can_be_signed_off_against(self) -> None:
        self.answering(self.REVISION, "modified")
        described = live.describe_build(self.root, "hosted")
        self.assertFalse(described["self_reported"]["attributable"])
        self.assertEqual(described["source_attribution"], "unresolved")
        # The head it sat on is still recorded. It is just not an attribution.
        self.assertEqual(described["self_reported"]["source_revision"], self.REVISION)

    def test_an_unknown_build_is_unresolved_rather_than_guessed_at(self) -> None:
        self.answering(None, "unknown")
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "unresolved")
        self.assertIsNone(described["self_reported"]["source_revision"])

    def test_a_binary_predating_the_flag_says_so_instead_of_failing_silently(
        self,
    ) -> None:
        self.install("exit 64")
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["self_reported"]["state"], "unavailable")
        self.assertIn("predates", described["self_reported"]["reason"])
        self.assertEqual(described["source_attribution"], "unresolved")

    def test_a_non_json_or_foreign_schema_answer_is_not_believed(self) -> None:
        self.install("echo not-json")
        self.assertEqual(live.self_reported_build(self.binary)["state"], "unavailable")
        self.install("printf '%s' " + shlex.quote('{"schema":"something.else/v1"}'))
        self.assertEqual(live.self_reported_build(self.binary)["state"], "unavailable")

    def test_a_manifest_naming_another_revision_for_these_bytes_contradicts(
        self,
    ) -> None:
        self.answering(self.REVISION, "committed")
        self.manifest("manifest.json", self.digest, self.OTHER)
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "contradicted")
        result = live.check_build_attribution({"hosted": described})
        self.assertEqual(result["state"], "failed")
        self.assertIn("disagree", result["reason"])

    def test_a_manifest_agreeing_with_the_binary_resolves_without_complaint(
        self,
    ) -> None:
        self.answering(self.REVISION, "committed")
        self.manifest("manifest.json", self.digest, self.REVISION)
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "resolved")
        self.assertEqual(described["source_revision"], self.REVISION)

    def test_a_stale_manifest_for_other_bytes_does_not_contradict(self) -> None:
        # The live defect: `bin/` replaced, the release pointer never moved. The
        # manifest describes another binary, so it says nothing about this one,
        # and the binary's own answer stands.
        self.answering(self.REVISION, "committed")
        self.manifest("releases/a/manifest.json", "00" * 32, self.OTHER)
        described = live.describe_build(self.root, "hosted")
        self.assertEqual(described["source_attribution"], "resolved")
        self.assertEqual(described["source_revision"], self.REVISION)


class SignOffTest(unittest.TestCase):
    """Only a complete, current, attributed sign-off closes the checklist."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def signoff(self, **overrides: object) -> dict[str, object]:
        body = {
            "schema": live.SIGNOFF_SCHEMA,
            "operator": "an operator",
            "signed_at": "2026-08-29T16:00:00Z",
            "signed_off_ids": sorted(live.MANUAL_IDS),
        }
        body.update(overrides)
        path = self.root / "signoff.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return live.operator_checklist(path)

    def test_no_sign_off_leaves_every_step_awaiting_an_operator(self) -> None:
        record = live.operator_checklist(None)
        self.assertFalse(record["signed_off"])
        self.assertTrue(
            all(step["state"] == "awaiting_operator" for step in record["steps"])
        )

    def test_a_complete_sign_off_closes_the_checklist_and_is_hashed(self) -> None:
        record = self.signoff()
        self.assertTrue(record["signed_off"])
        self.assertEqual(record["state"], "complete")
        self.assertEqual(len(record["source_sha256"]), 64)

    def test_a_partial_sign_off_names_what_is_missing(self) -> None:
        record = self.signoff(signed_off_ids=["LIVE-GUI-1"])
        self.assertFalse(record["signed_off"])
        self.assertIn("LIVE-GUI-4", record["reason"])

    def test_a_sign_off_naming_an_unknown_step_is_refused_outright(self) -> None:
        record = self.signoff(signed_off_ids=[*sorted(live.MANUAL_IDS), "LIVE-GUI-99"])
        self.assertFalse(record["signed_off"])
        self.assertIn("LIVE-GUI-99", record["reason"])

    def test_another_schema_is_refused(self) -> None:
        self.assertFalse(self.signoff(schema="something.else/v1")["signed_off"])

    def test_an_unattributed_sign_off_is_refused(self) -> None:
        self.assertFalse(self.signoff(operator="")["signed_off"])
        self.assertFalse(self.signoff(signed_at=None)["signed_off"])

    def test_an_unreadable_or_malformed_file_is_refused_not_crashed_on(self) -> None:
        self.assertFalse(live.operator_checklist(self.root / "absent.json")["signed_off"])
        broken = self.root / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        self.assertFalse(live.operator_checklist(broken)["signed_off"])

    def test_the_shipped_template_signs_nothing_off(self) -> None:
        template = (
            pathlib.Path(live.__file__).resolve().parent
            / "fixtures"
            / "attention-live-acceptance-signoff.example.json"
        )
        record = live.operator_checklist(template)
        self.assertFalse(record["signed_off"])


class ReportTest(unittest.TestCase):
    """`passed` is never true while anything is unproven."""

    def report(self, checks: list[dict[str, object]]) -> dict[str, object]:
        args = live.parse_args([])
        with unittest.mock.patch.object(live, "build_origins", return_value=([], checks)):
            with unittest.mock.patch.object(
                live, "check_build_attribution", return_value={"name": "b", "state": "passed"}
            ):
                with unittest.mock.patch.object(
                    live, "repository", return_value={"state": "unavailable"}
                ):
                    return live.run(args)

    def test_a_blocked_check_prevents_passing(self) -> None:
        report = self.report([{"name": "a", "state": "blocked", "reason": "no credential"}])
        self.assertFalse(report["passed"])
        self.assertEqual(report["live_verification"]["state"], "blocked")

    def test_a_failed_check_is_reported_as_failed_not_merely_blocked(self) -> None:
        report = self.report(
            [{"name": "a", "state": "failed"}, {"name": "b", "state": "blocked"}]
        )
        self.assertEqual(report["live_verification"]["state"], "failed")

    def test_all_automated_checks_passing_is_still_not_a_pass(self) -> None:
        report = self.report([{"name": "a", "state": "passed"}])
        self.assertFalse(report["passed"])
        self.assertEqual(report["live_verification"]["state"], "automated_only")


if __name__ == "__main__":
    unittest.main()
