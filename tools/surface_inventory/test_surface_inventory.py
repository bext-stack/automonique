#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Prove each surface-inventory rule can fail, and that it passes as written.

Every negative control mutates a copy of the *checked-in* inventory and asserts
the named failure; every one has a positive control beside it. Nothing here
restates a constant from `model.py`: the fixtures are the real document and the
real validator, because a fixture that copies the implementation only proves
the implementation equals itself.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import shutil
import tempfile
import unittest

from tools.surface_inventory import hygiene, model, render, verify

ROOT = pathlib.Path(__file__).resolve().parents[2]


def entry(document: dict, section: str, entry_id: str) -> dict:
    for candidate in document["sections"][section]["entries"]:
        if candidate["id"] == entry_id:
            return candidate
    raise AssertionError(f"{section}/{entry_id} is not in the inventory")


class InventoryFixture(unittest.TestCase):
    """Loads the real inventory once; each test mutates its own deep copy."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.original = model.load()

    def setUp(self) -> None:
        self.document = copy.deepcopy(self.original)

    def errors(self) -> list[str]:
        return model.errors(self.document, ROOT)

    def assertRefused(self, fragment: str) -> None:
        found = self.errors()
        self.assertTrue(
            any(fragment in problem for problem in found),
            f"expected a finding containing {fragment!r}; got {found}",
        )

    def assertAccepted(self) -> None:
        self.assertEqual(self.errors(), [])


class CheckedInDocument(InventoryFixture):
    def test_the_checked_in_inventory_is_valid(self) -> None:
        self.assertAccepted()

    def test_the_checked_in_inventory_is_clean(self) -> None:
        self.assertEqual(hygiene.scan_strings(model.strings(self.document)), [])

    def test_every_required_section_is_present(self) -> None:
        self.assertEqual(
            sorted(self.document["sections"]), sorted(model.SECTION_ORDER))

    def test_derived_views_match_the_checked_in_copies(self) -> None:
        source = model.INVENTORY.read_bytes()
        views = verify.derived(self.document, source, model.INVENTORY.parent)
        for path, payload in views.items():
            self.assertEqual(path.read_bytes(), payload,
                             f"{path.name} is not what the inventory renders")

    def test_rendering_is_byte_stable(self) -> None:
        source = model.INVENTORY.read_bytes()
        first = verify.derived(self.document, source, model.INVENTORY.parent)
        second = verify.derived(model.load(), source, model.INVENTORY.parent)
        self.assertEqual(first, second)


class SectionCoverage(InventoryFixture):
    def test_a_missing_section_is_refused(self) -> None:
        del self.document["sections"]["runbooks"]
        self.assertRefused("sections.runbooks is missing")

    def test_an_invented_section_is_refused(self) -> None:
        self.document["sections"]["escalations"] = {
            "empty_reason": None, "entries": [], "gaps": []}
        self.assertRefused("is not one of the ten required sections")

    def test_an_empty_section_without_a_reason_is_refused(self) -> None:
        self.document["sections"]["tenants"]["entries"] = []
        self.assertRefused("states no reason")

    def test_an_empty_section_with_a_reason_is_accepted(self) -> None:
        self.document["sections"]["tenants"]["entries"] = []
        self.document["sections"]["tenants"]["empty_reason"] = (
            "nothing to record until a tenant register is reachable")
        self.assertAccepted()

    def test_a_duplicate_entry_id_is_refused(self) -> None:
        section = self.document["sections"]["roles"]["entries"]
        section.append(copy.deepcopy(section[0]))
        self.assertRefused("duplicate entry ID")


class ClosedVocabulary(InventoryFixture):
    def test_an_unknown_class_is_refused(self) -> None:
        entry(self.document, "tenants", "automonique-tenant")["class"] = "customer"
        self.assertRefused("is not in the closed vocabulary")

    def test_an_unknown_field_is_refused(self) -> None:
        entry(self.document, "tenants", "automonique-tenant")["notes"] = "free text"
        self.assertRefused("unknown field(s): notes")

    def test_an_unknown_gap_reason_is_refused(self) -> None:
        self.document["sections"]["roles"]["gaps"][0]["reason"] = "we did not look"
        self.assertRefused("reason='we did not look' is not in the closed vocabulary")


class CredentialSafety(InventoryFixture):
    def test_a_credential_cannot_carry_a_value(self) -> None:
        entry(self.document, "credentials", "transport")["value"] = "not-a-real-token"
        self.assertRefused("unknown field(s): value")

    def test_a_credential_cannot_carry_an_example(self) -> None:
        entry(self.document, "credentials", "transport")["example"] = {
            "value": "synthetic-token", "kind": "synthetic-placeholder"}
        self.assertRefused("unknown field(s): example")

    def test_a_credential_must_state_that_its_secret_is_withheld(self) -> None:
        entry(self.document, "credentials", "transport")["withheld"] = []
        self.assertRefused("must record that its secret material is withheld")

    def test_a_withheld_record_has_nowhere_to_write_the_value(self) -> None:
        entry(self.document, "credentials", "transport")["withheld"][0]["value"] = "x"
        self.assertRefused("it has no field that could hold the value it withholds")

    def test_an_unknown_shape_is_refused(self) -> None:
        record = entry(self.document, "credentials", "transport")["withheld"][0]
        record["shape"] = "the actual key"
        self.assertRefused("shape='the actual key' is not in the closed vocabulary")


class Provenance(InventoryFixture):
    def test_a_quote_that_is_not_in_the_cited_file_is_refused(self) -> None:
        self.document["citations"]["ops-objectives"]["quote"] = (
            "Initial acceptance objectives are RPO <= 1 minute.")
        self.assertRefused("quoted words are not in")

    def test_a_citation_to_a_missing_file_is_refused(self) -> None:
        self.document["citations"]["ops-objectives"]["path"] = "docs/not-here.md"
        self.assertRefused("cited file does not exist")

    def test_an_entry_citing_nothing_known_is_refused(self) -> None:
        entry(self.document, "roles", "service-owner")["citation"] = "hearsay"
        self.assertRefused("cites unknown citation 'hearsay'")

    def test_a_number_without_a_citation_is_refused(self) -> None:
        objective = entry(self.document, "budgets",
                          "recovery-point-objective-control-state")
        objective["limit"]["citation"] = "remembered"
        self.assertRefused("a number without a citation is a recalled number")

    def test_a_number_its_citation_does_not_contain_is_refused(self) -> None:
        row = entry(self.document, "retention", "business-audit")
        row["ttl"] = {"value": 90, "unit": "day",
                      "citation": "ops-retention-fields"}
        row["ttl_gap"] = None
        self.assertRefused("does not appear in the words it cites")

    def test_the_cited_objectives_carry_their_own_numbers(self) -> None:
        for identifier in ("recovery-point-objective-control-state",
                           "recovery-time-objective-same-host-class"):
            row = entry(self.document, "budgets", identifier)
            quote = self.document["citations"][row["limit"]["citation"]]["quote"]
            self.assertIn(str(row["limit"]["value"]), quote)

    def test_a_number_beside_a_gap_reason_is_refused(self) -> None:
        objective = entry(self.document, "budgets",
                          "recovery-point-objective-control-state")
        objective["limit_gap"] = "policy-configurable-no-default"
        self.assertRefused("limit is recorded, so limit_gap must be null")

    def test_a_null_ttl_without_a_reason_is_refused(self) -> None:
        entry(self.document, "retention", "business-audit")["ttl_gap"] = None
        self.assertRefused("ttl is null, so ttl_gap must say why")

    def test_a_ttl_with_a_citation_is_accepted(self) -> None:
        row = entry(self.document, "retention", "business-audit")
        row["ttl"] = {"value": 5, "unit": "minute", "citation": "ops-objectives"}
        row["ttl_gap"] = None
        self.assertAccepted()

    def test_a_retention_row_without_a_governing_policy_is_refused(self) -> None:
        entry(self.document, "retention", "business-audit")["governing_policy"] = "x"
        self.assertRefused("governing_policy must cite the policy")


class Ownership(InventoryFixture):
    def test_an_unregistered_owner_is_refused(self) -> None:
        entry(self.document, "roles", "service-owner")["owner"] = "someone"
        self.assertRefused("is not in the owner registry")

    def test_a_null_owner_without_a_reason_is_refused(self) -> None:
        entry(self.document, "retention", "business-audit")["owner_gap"] = None
        self.assertRefused("owner is null, so owner_gap must say why")

    def test_an_owner_beside_a_gap_reason_is_refused(self) -> None:
        row = entry(self.document, "roles", "service-owner")
        row["owner_gap"] = "unassigned-in-corpus"
        self.assertRefused("owner is recorded, so owner_gap must be null")


class CrossReferences(InventoryFixture):
    def test_a_dangling_retention_reference_is_refused(self) -> None:
        row = entry(self.document, "artifact_classes", "inbound-attachment")
        row["retention_ref"] = "forever"
        self.assertRefused("names no entry in the retention section")

    def test_an_artifact_without_a_retention_class_needs_a_reason(self) -> None:
        row = entry(self.document, "artifact_classes", "inbound-attachment")
        row["retention_ref"] = None
        self.assertRefused("retention_ref is null, so retention_gap must say why")


class RestoreDependencies(InventoryFixture):
    def test_a_dependency_on_nothing_is_refused(self) -> None:
        row = entry(self.document, "backup_dependencies", "verify-manifests")
        row["requires"] = ["a-backup-someone-assumed"]
        self.assertRefused("which is not a restorable entry in this section")

    def test_a_cycle_is_refused(self) -> None:
        first = entry(self.document, "backup_dependencies", "verify-manifests")
        second = entry(self.document, "backup_dependencies", "verify-policy-versions")
        first["requires"] = [second["id"]]
        second["requires"] = [first["id"]]
        self.assertRefused("restore dependencies do not form an order")

    def test_a_verification_step_must_order_something(self) -> None:
        entry(self.document, "backup_dependencies", "verify-manifests")["requires"] = []
        self.assertRefused("puts nothing in order")

    def test_a_recovery_input_cannot_require_a_step(self) -> None:
        row = entry(self.document, "backup_dependencies", "policy-and-bundle-hashes")
        row["requires"] = ["verify-database-integrity"]
        self.assertRefused("cannot itself require a restore step")

    def test_the_order_is_deterministic(self) -> None:
        entries = model.section_entries(self.document, "backup_dependencies")
        first, problems = model.restore_order(entries)
        self.assertEqual(problems, [])
        shuffled = list(reversed(entries))
        second, problems = model.restore_order(shuffled)
        self.assertEqual(problems, [])
        self.assertEqual(first, second)

    def test_every_dependency_precedes_what_needs_it(self) -> None:
        entries = model.section_entries(self.document, "backup_dependencies")
        order, _ = model.restore_order(entries)
        position = {name: index for index, name in enumerate(order)}
        for row in entries:
            for dependency in row["requires"]:
                self.assertLess(position[dependency], position[row["id"]])

    def test_the_export_carries_a_cited_objective(self) -> None:
        exported = json.loads(verify.derived(
            self.document, b"", model.INVENTORY.parent)[
                model.INVENTORY.parent / "restore-dependencies.json"])
        self.assertTrue(exported["objectives"])
        for objective in exported["objectives"]:
            cited = ROOT / objective["source"]["path"]
            self.assertIn(objective["source"]["quote"], cited.read_text())

    def test_an_export_without_a_cited_objective_is_refused(self) -> None:
        for row in self.document["sections"]["budgets"]["entries"]:
            if row["class"] == "recovery-objective":
                row["limit"] = None
                row["limit_gap"] = "policy-configurable-no-default"
        with self.assertRaises(render.RenderError):
            render.render_restore(self.document, b"")


class RunbookSafety(InventoryFixture):
    def test_a_runbook_cannot_be_executable(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        row["documentation_only"] = False
        self.assertRefused("documentation_only must be true")

    def test_an_unwritten_runbook_cannot_carry_steps(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        row["steps"] = [{"kind": "inspect", "text": "look at the lease table"}]
        self.assertRefused("cannot carry steps")

    def test_a_written_runbook_step_may_be_prose(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "inspect",
                         "text": "read the lease owner and epoch from the operator view"}]
        self.assertAccepted()

    def test_a_shell_command_in_a_step_is_refused(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "mutate",
                         "text": "run `sudo systemctl restart` on the host"}]
        self.assertRefused("is never executable from it")

    def test_an_sql_repair_in_a_step_is_refused(self) -> None:
        row = entry(self.document, "runbooks", "stable-development-state-recovery")
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "mutate",
                         "text": "DELETE FROM the lease table to clear the owner"}]
        self.assertRefused("is never executable from it")

    def test_a_shell_prompt_in_a_step_is_refused(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "inspect", "text": "$ status --json"}]
        self.assertRefused("is never executable from it")

    def test_a_command_in_a_trigger_is_refused(self) -> None:
        entry(self.document, "runbooks", "stuck-lease")["trigger"] = (
            "journalctl -u the-service shows a stuck lease")
        self.assertRefused("is never executable from it")

    def test_a_production_runbook_records_no_mutating_step(self) -> None:
        row = entry(self.document, "runbooks", "stuck-lease")
        self.assertTrue(row["production_touching"])
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "mutate", "text": "clear the lease by hand"}]
        self.assertRefused("it is documentation only")

    def test_an_unknown_step_kind_is_refused(self) -> None:
        row = entry(self.document, "runbooks", "clean-host-bootstrap")
        row["procedure_status"] = "written"
        row["steps"] = [{"kind": "execute", "text": "start the bootstrap"}]
        self.assertRefused("kind='execute' is not in the closed vocabulary")


class ExternalRoles(InventoryFixture):
    def test_a_platform_role_may_never_confer_an_automonique_role(self) -> None:
        entry(self.document, "actor_mappings", "discord-actor")["confers_role"] = True
        self.assertRefused("confers_role must be false")


class SyntheticMarking(InventoryFixture):
    def test_an_unmarked_placeholder_is_refused(self) -> None:
        row = entry(self.document, "tenants", "automonique-tenant")
        row["example"]["value"] = "northwind-trading"
        self.assertRefused("must be marked in the value itself")

    def test_a_routable_reserved_value_is_refused(self) -> None:
        row = entry(self.document, "actor_mappings", "repository-candidate-actor")
        row["example"]["value"] = "candidate@automonique.dev"
        self.assertRefused("reserved, non-routable namespace")

    def test_a_marked_placeholder_is_accepted(self) -> None:
        row = entry(self.document, "tenants", "automonique-tenant")
        row["example"]["value"] = "synthetic-tenant-b"
        self.assertAccepted()


class HygieneRules(unittest.TestCase):
    def test_a_personal_address_is_refused(self) -> None:
        self.assertTrue(hygiene.scan_text("owner is ada@northwind-trading.com", "x"))

    def test_a_reserved_address_is_accepted(self) -> None:
        self.assertEqual(hygiene.scan_text("candidate@automonique.invalid", "x"), [])

    def test_a_real_host_name_is_refused(self) -> None:
        finding = hygiene.scan_text("restore onto db-01.northwind-trading.com", "x")
        self.assertTrue(any("host-shaped name" in item for item in finding))

    def test_a_reserved_host_name_is_accepted(self) -> None:
        self.assertEqual(hygiene.scan_text("restore onto host-a.invalid", "x"), [])

    def test_a_repository_path_is_not_a_host_name(self) -> None:
        self.assertEqual(hygiene.scan_text(
            "docs/product-plan/requirements/operations-and-governance.md", "x"), [])

    def test_a_schema_identifier_is_not_a_host_name(self) -> None:
        self.assertEqual(hygiene.scan_text("automonique.surface-inventory/v1", "x"), [])

    def test_an_absolute_home_path_is_refused(self) -> None:
        finding = hygiene.scan_text("the workspace lives at /home/operator/work", "x")
        self.assertTrue(any("absolute home path" in item for item in finding))

    def test_a_network_address_is_refused(self) -> None:
        finding = hygiene.scan_text("the broker answers on 10.4.2.9", "x")
        self.assertTrue(any("IPv4 literal" in item for item in finding))

    def test_secret_shapes_are_refused(self) -> None:
        for text in (
            "-----BEGIN PRIVATE KEY-----",
            "Authorization: Bearer abcdefghijklmnopqrst",
            "eyJhbGciOiJIUzI1NiJ9abcdefg",
            "password = hunter2",
            "AbcdEfghIjklMnop0123456789QrstUvwx",
        ):
            with self.subTest(text=text[:16]):
                self.assertTrue(hygiene.scan_text(text, "x"),
                                f"{text[:16]!r} was not refused")

    def test_prose_about_credentials_is_not_a_secret(self) -> None:
        self.assertEqual(hygiene.scan_text(
            "the descriptor records owner, purpose, audience and rotation deadline",
            "x"), [])

    def test_a_finding_never_echoes_the_value(self) -> None:
        secret = "AbcdEfghIjklMnop0123456789QrstUvwx"
        for finding in hygiene.scan_text(f"key = {secret}", "x"):
            self.assertNotIn(secret, finding)


class DerivedViewDrift(unittest.TestCase):
    """The checked-in copy must fail when it stops matching the inventory."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.surface = pathlib.Path(self.temporary.name) / "surface"
        self.surface.mkdir()
        for name in ("inventory.json", "README.md", "restore-dependencies.json"):
            shutil.copy(model.INVENTORY.parent / name, self.surface / name)
        self.inventory = self.surface / "inventory.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_check(self, *, write: bool = False):
        return verify.check(self.inventory, root=ROOT, write=write)

    def test_the_copied_tree_is_current(self) -> None:
        status, findings, _ = self.run_check()
        self.assertEqual((status, findings), (0, []))

    def test_a_stale_readme_fails(self) -> None:
        readme = self.surface / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nedited by hand\n")
        status, findings, _ = self.run_check()
        self.assertEqual(status, 1)
        self.assertTrue(any("is stale" in item for item in findings), findings)

    def test_a_stale_export_fails(self) -> None:
        export = self.surface / "restore-dependencies.json"
        export.write_bytes(b"{}\n")
        status, findings, _ = self.run_check()
        self.assertEqual(status, 1)
        self.assertTrue(any("is stale" in item for item in findings), findings)

    def test_a_missing_view_fails(self) -> None:
        (self.surface / "README.md").unlink()
        status, findings, _ = self.run_check()
        self.assertEqual(status, 1)
        self.assertTrue(any("is missing" in item for item in findings), findings)

    def test_write_restores_and_reverifies(self) -> None:
        readme = self.surface / "README.md"
        readme.write_bytes(b"stale\n")
        status, findings, report = self.run_check(write=True)
        self.assertEqual((status, findings), (0, []))
        self.assertTrue(any("rewrote" in line for line in report))
        self.assertEqual(self.run_check()[0], 0)

    def test_a_changed_inventory_changes_the_views(self) -> None:
        document = json.loads(self.inventory.read_text())
        document["sections"]["roles"]["entries"][0]["summary"] = "changed"
        self.inventory.write_text(json.dumps(document, indent=2) + "\n")
        status, findings, _ = self.run_check()
        self.assertEqual(status, 1)
        self.assertTrue(any("is stale" in item for item in findings), findings)

    def test_an_unreadable_inventory_is_a_configuration_error(self) -> None:
        self.inventory.write_text("{not json")
        status, findings, _ = self.run_check()
        self.assertEqual(status, 2)
        self.assertTrue(findings)

    def test_a_write_that_fails_leaves_no_partial_file(self) -> None:
        target = self.surface / "README.md"
        before = target.read_bytes()
        real_replace = os.replace

        def explode(*args, **kwargs):
            raise OSError("interrupted")

        os.replace = explode
        try:
            with self.assertRaises(OSError):
                verify.write_atomic(target, b"half a file")
        finally:
            os.replace = real_replace
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual([p.name for p in self.surface.iterdir()
                          if ".staging" in p.name], [])


class QualityBoundary(unittest.TestCase):
    """The checker runs offline, reads no secret and adds no dependency."""

    MODULES = ("model.py", "hygiene.py", "render.py", "verify.py",
               "__init__.py", "__main__.py")

    def sources(self):
        for name in self.MODULES:
            yield name, (pathlib.Path(__file__).parent / name).read_text()

    def test_every_import_is_the_standard_library(self) -> None:
        import ast
        import sys

        for name, source in self.sources():
            for node in ast.walk(ast.parse(source)):
                roots: list[str] = []
                if isinstance(node, ast.Import):
                    roots = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    roots = [node.module.split(".")[0]]
                for root in roots:
                    with self.subTest(module=name, imported=root):
                        self.assertIn(
                            root,
                            set(sys.stdlib_module_names) | {"tools"},
                            f"{name} imports {root}, which is not the standard "
                            f"library and would be a new runtime dependency")

    def test_no_module_reads_the_environment(self) -> None:
        import re as regex

        reader = regex.compile(r"\bos\.environ\b|\bgetenv\b|\benviron\[")
        for name, source in self.sources():
            with self.subTest(module=name):
                self.assertIsNone(
                    reader.search(source),
                    f"{name} reads the process environment; the checker takes "
                    f"no secret and no configuration from it")

    def test_it_verifies_with_networking_blocked(self) -> None:
        import socket

        def refuse(*args, **kwargs):
            raise AssertionError("the checker attempted a network call")

        saved = (socket.socket, socket.create_connection, socket.getaddrinfo)
        socket.socket, socket.create_connection, socket.getaddrinfo = (
            refuse, refuse, refuse)
        try:
            status, findings, _ = verify.check(model.INVENTORY, root=ROOT,
                                               write=False)
        finally:
            (socket.socket, socket.create_connection,
             socket.getaddrinfo) = saved
        self.assertEqual((status, findings), (0, []))


if __name__ == "__main__":
    unittest.main()
