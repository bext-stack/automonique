#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Prove the identifier inventory and every rule that guards it can still fail.

Each rule below is exercised twice: once broken, so the named failure is
observed, and once whole, so the pass is observed. A rule that has never failed
is an untested assertion, which is what `plan/doctrine.md` and `BOOT-001`'s
gate self-test exist to prevent.

The perturbations that need a mutated corpus operate on a temporary copy of
`docs/product-plan/`, because that directory is outside this item's lease and
must not be edited even briefly.

    python3 tools/identifiers/test_inventory.py
    python3 -m unittest tools/identifiers/test_inventory.py
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import inventory

ROOT = inventory.ROOT


def temporary_corpus() -> tempfile.TemporaryDirectory:
    """A throwaway root carrying a copy of the permitted corpus."""
    handle = tempfile.TemporaryDirectory(prefix="automonique-identifier-inventory-")
    root = pathlib.Path(handle.name)
    (root / inventory.CORPUS).parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / inventory.CORPUS, root / inventory.CORPUS)
    return handle


def rewrite(root: pathlib.Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text()
    if old not in text:
        raise AssertionError(f"{relative} does not contain {old!r} to perturb")
    path.write_text(text.replace(old, new, 1))


def legacy_identifier_from_the_sanctioned_inventory() -> str:
    """The predecessor prefix, read out of the one file permitted to spell it.

    Reading it here rather than writing it keeps this test from becoming the
    place a legacy identifier appears, which is the rule it is testing.
    """
    text = (ROOT / inventory.SANCTIONED_LEGACY_INVENTORY).read_text()
    lengths = {rule["length"] for rule in inventory.LEGACY_TOKEN_FINGERPRINTS}
    digests = {rule["digest"] for rule in inventory.LEGACY_TOKEN_FINGERPRINTS}
    for word in inventory.WORD.findall(text):
        if len(word) in lengths:
            if hashlib.sha256(word.lower().encode()).hexdigest() in digests:
                return word
    raise AssertionError(
        "the fingerprints match nothing in the sanctioned inventory, so this "
        "test cannot obtain the value it must prove is refused"
    )


class CheckedInCopy(unittest.TestCase):
    def test_the_checked_in_inventory_is_what_the_sources_derive(self):
        self.assertEqual(inventory.verify(ROOT), 0)

    def test_regeneration_is_byte_identical(self):
        self.assertEqual(inventory.render(ROOT), inventory.render(ROOT))

    def test_a_stale_checked_in_copy_is_reported_with_its_first_bad_line(self):
        actual = inventory.render(ROOT)
        broken = actual.replace(b'"durable"', b'"presentation-only"', 1)
        self.assertNotEqual(actual, broken)
        message = inventory.first_difference(broken, actual)
        self.assertIn(inventory.OUTPUT_RELATIVE, message)
        self.assertIn("the sources derive", message)

    def test_a_planted_identifier_is_not_echoed_by_the_drift_message(self):
        planted = legacy_identifier_from_the_sanctioned_inventory()
        actual = inventory.render(ROOT)
        broken = actual.replace(
            b'"schema"', f'"negative_control": "{planted}_DB", "schema"'.encode(), 1
        )
        message = inventory.first_difference(broken, actual)
        self.assertIn("redacted", message)
        self.assertNotIn(planted, message)
        self.assertIn("names a legacy identifier", message)

    def test_an_ordinary_drift_message_still_quotes_the_line(self):
        actual = inventory.render(ROOT)
        broken = actual.replace(b'"durable"', b'"presentation-only"', 1)
        message = inventory.first_difference(broken, actual)
        self.assertNotIn("redacted", message)
        self.assertIn("presentation-only", message)

    def test_the_generated_document_passes_its_own_scrub(self):
        inventory.scrub(inventory.render(ROOT).decode(), "the checked-in copy")

    def test_generate_writes_atomically_and_leaves_no_staging_file(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            self.assertEqual(inventory.generate(root), 0)
            written = root / inventory.OUTPUT_RELATIVE
            self.assertTrue(written.is_file())
            leftovers = [
                path.name
                for path in written.parent.iterdir()
                if path.name != written.name
            ]
            self.assertEqual(leftovers, [])
            self.assertEqual(written.read_bytes(), inventory.render(root))


class BackwardDrift(unittest.TestCase):
    """A permitted source that gains a name the inventory does not classify."""

    def test_a_new_legacy_token_in_the_corpus_fails(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            self.assertIsNotNone(inventory.build(root))
            rewrite(
                root,
                f"{inventory.CORPUS}/requirements/target-architecture.md",
                "### One binary rule",
                "### One binary rule\n\nA new shim `legacy-brandnew` is installed.\n",
            )
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(root)
            message = str(raised.exception)
            self.assertIn("legacy-brandnew", message)
            self.assertIn("no declaration, family or withheld fingerprint", message)

    def test_a_new_workspace_crate_is_absorbed_and_changes_the_output(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            before = inventory.render(root)
            rewrite(
                root,
                f"{inventory.CORPUS}/requirements/target-architecture.md",
                "│  ├─ automonique-policy/",
                "│  ├─ automonique-brandnew/ a crate nobody declared\n"
                "│  ├─ automonique-policy/",
            )
            after = inventory.render(root)
            self.assertNotEqual(before, after)
            self.assertIn(b"automonique-brandnew", after)

    def test_a_new_family_member_changes_the_recorded_absorption(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            before = json.loads(inventory.render(root))
            rewrite(
                root,
                f"{inventory.CORPUS}/requirements/state-and-protocols.md",
                "The physical `legacy_*` tables",
                "A new `legacy_brandnew_rows` table exists. The physical `legacy_*` tables",
            )
            after = json.loads(inventory.render(root))
            family_before = before["families"][0]
            family_after = after["families"][0]
            self.assertEqual(
                family_after["absorbed_count"], family_before["absorbed_count"] + 1
            )
            self.assertIn("legacy_brandnew_rows", family_after["absorbed"])


class ForwardDrift(unittest.TestCase):
    """A permitted source that loses a name the inventory still classifies."""

    def test_a_removed_declared_legacy_token_fails(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            self.assertIsNotNone(inventory.build(root))
            for relative in inventory.corpus_files(root):
                path = root / relative
                text = path.read_text()
                if "`legacyd`" in text:
                    path.write_text(text.replace("`legacyd`", "`the daemon shim`"))
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(root)
            message = str(raised.exception)
            self.assertIn("legacyd", message)
            self.assertIn("no longer extracts it", message)

    def test_a_cited_entry_losing_its_evidence_fails(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            self.assertIsNotNone(inventory.build(root))
            rewrite(
                root,
                inventory.VERIFICATION_ROLLOUT,
                "every `automonique.dev-metrics/v1` manifest",
                "every `automonique.dev-metrics/v1` document",
            )
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(root)
            self.assertIn("no longer has its evidence", str(raised.exception))

    def test_a_region_whose_section_disappears_fails(self):
        with temporary_corpus() as name:
            root = pathlib.Path(name)
            rewrite(
                root,
                f"{inventory.CORPUS}/requirements/agent-integrations.md",
                "## Normalized event model",
                "## Normalised event model",
            )
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(root)
            message = str(raised.exception)
            self.assertIn("Normalized event model", message)
            self.assertIn("would extract nothing", message)


class ClosedVocabulary(unittest.TestCase):
    def test_an_unknown_class_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.Declaration(disposition="mostly-durable").validate("x")
        self.assertIn("mostly-durable", str(raised.exception))

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.Declaration(
                disposition="durable", kind="table", spelling_form="literal"
            ).validate("x")
        self.assertIn("kind 'table'", str(raised.exception))

    def test_an_unknown_spelling_form_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.Declaration(
                disposition="durable", kind="command", spelling_form="freehand"
            ).validate("x")
        self.assertIn("spelling form 'freehand'", str(raised.exception))

    def test_a_valid_declaration_is_accepted(self):
        inventory.durable("command").validate("automonique status")

    def test_the_generated_document_uses_only_the_closed_vocabularies(self):
        document = json.loads(inventory.render(ROOT))
        for entry in document["entries"]:
            self.assertIn(entry["kind"], inventory.KINDS)
            self.assertIn(entry["class"], inventory.CLASSES)
            self.assertIn(entry["spelling_form"], inventory.SPELLING_FORMS)


class ForwardingIntegrity(unittest.TestCase):
    def test_a_compatibility_entry_without_a_counterpart_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.Declaration(
                disposition="compatibility-only",
                kind="command",
                spelling_form="literal",
                reason="because",
                authorized_by=inventory.MIGRATION_PLAN,
            ).validate("legacy-nowhere")
        self.assertIn("would forward to nothing", str(raised.exception))

    def test_a_compatibility_entry_without_a_reason_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.Declaration(
                disposition="compatibility-only",
                kind="command",
                spelling_form="literal",
                forwards_to="automonique",
                authorized_by=inventory.MIGRATION_PLAN,
            ).validate("legacy-quiet")
        self.assertIn("must say why", str(raised.exception))

    def test_a_dangling_forward_fails_the_build(self):
        broken = dict(inventory.LEGACY_TOKEN_DECLARATIONS)
        broken["legacyd"] = inventory.alias(
            "command",
            "automonique nonexistent-subcommand",
            "a target no permitted source declares",
            inventory.TARGET_ARCHITECTURE,
        )
        regions = tuple(
            dataclasses.replace(region, overrides=broken)
            if region.id == "legacy-tokens"
            else region
            for region in inventory.REGIONS
        )
        with mock.patch.object(inventory, "REGIONS", regions):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(ROOT)
        message = str(raised.exception)
        self.assertIn("automonique nonexistent-subcommand", message)
        self.assertIn("would forward to nothing", message)

    def test_every_forward_in_the_checked_in_copy_resolves(self):
        document = json.loads(inventory.render(ROOT))
        durable = set(document["durable_names"])
        self.assertTrue(document["compatibility_forwards"])
        for name, row in document["compatibility_forwards"].items():
            self.assertIn(row["forwards_to"], durable, name)
            for extra in row["also"]:
                self.assertIn(extra, durable, name)


class Citation(unittest.TestCase):
    def test_a_citation_outside_the_permitted_corpus_is_refused(self):
        outside = inventory.CITED + (
            inventory.Cited(
                "automonique-lab",
                inventory.durable("service"),
                "AGENTS.md",
                "automonique-lab",
            ),
        )
        with mock.patch.object(inventory, "CITED", outside):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(ROOT)
        message = str(raised.exception)
        self.assertIn("outside the permitted corpus", message)
        self.assertIn("AGENTS.md", message)

    def test_every_entry_in_the_checked_in_copy_cites_the_permitted_corpus(self):
        document = json.loads(inventory.render(ROOT))
        rows = (
            document["entries"]
            + document["unclassified"]
            + document["out_of_scope"]
            + document["withheld"]
        )
        self.assertTrue(rows)
        for row in rows:
            files = row["source"]["files"]
            self.assertTrue(files, row)
            for relative in files:
                self.assertTrue(
                    relative.startswith(f"{inventory.CORPUS}/"), relative
                )
                self.assertTrue((ROOT / relative).is_file(), relative)


class ScrubHygiene(unittest.TestCase):
    def test_a_legacy_identifier_is_refused(self):
        planted = legacy_identifier_from_the_sanctioned_inventory()
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.scrub(f"a reason mentioning {planted}_DB", "a test string")
        message = str(raised.exception)
        self.assertIn("names a legacy identifier", message)
        self.assertNotIn(planted, message)

    def test_a_neutral_string_is_accepted(self):
        inventory.scrub(
            "canonical AUTOMONIQUE_RUNNER, alias LEGACY_RUNNER, package "
            "@automonique/sdk, schema automonique.dev-metrics/v1",
            "a test string",
        )

    def test_an_absolute_home_path_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.scrub("evidence at /home/operator/notes.md", "a test string")
        self.assertIn("absolute home path", str(raised.exception))

    def test_an_email_address_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.scrub("owner person@example.com", "a test string")
        self.assertIn("personal email address", str(raised.exception))

    def test_a_bare_ip_address_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.scrub("host 10.20.30.40 answered", "a test string")
        self.assertIn("bare IP address", str(raised.exception))

    def test_a_host_name_is_refused(self):
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.scrub("published at console.internal", "a test string")
        self.assertIn("host name", str(raised.exception))

    def test_a_rotted_fingerprint_fails_the_anti_vacuity_guard(self):
        rotted = ({"length": 4, "digest": "0" * 64, "reason": "rotted"},)
        with mock.patch.object(inventory, "LEGACY_TOKEN_FINGERPRINTS", rotted):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.guard_scrub_rules(ROOT)
        self.assertIn("proves nothing", str(raised.exception))

    def test_the_live_fingerprint_passes_the_anti_vacuity_guard(self):
        inventory.guard_scrub_rules(ROOT)

    def test_a_withheld_spelling_does_not_appear_in_the_output(self):
        rendered = inventory.render(ROOT).decode()
        document = json.loads(rendered)
        self.assertEqual(len(document["withheld"]), 1)
        extracted = inventory.unprefixed_environment_variables(
            inventory.read(ROOT, inventory.SANCTIONED_LEGACY_INVENTORY),
            inventory.SANCTIONED_LEGACY_INVENTORY,
        )
        withheld = [
            name
            for name in extracted
            if hashlib.sha256(name.encode()).hexdigest()
            in inventory.WITHHELD_ENVIRONMENT_VARIABLES
        ]
        self.assertEqual(len(withheld), 1)
        for name in withheld:
            self.assertNotIn(name, rendered)

    def test_a_withheld_fingerprint_matching_nothing_is_refused(self):
        dead = dict(inventory.WITHHELD_ENVIRONMENT_VARIABLES)
        dead["f" * 64] = inventory.Declaration(
            disposition="withheld", reason="a fingerprint of nothing"
        )
        with mock.patch.object(inventory, "WITHHELD_ENVIRONMENT_VARIABLES", dead):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.build(ROOT)
        self.assertIn("dead permission", str(raised.exception))


class Coverage(unittest.TestCase):
    def test_all_seven_kinds_are_represented(self):
        document = json.loads(inventory.render(ROOT))
        counts = document["counts"]["by_kind_including_unclassified"]
        self.assertEqual(sorted(counts), sorted(inventory.KINDS))
        for kind, count in counts.items():
            self.assertGreater(count, 0, kind)

    def test_all_three_classes_are_exercised(self):
        document = json.loads(inventory.render(ROOT))
        for name, count in document["counts"]["by_class"].items():
            self.assertGreater(count, 0, name)

    def test_unclassified_names_are_listed_rather_than_absorbed(self):
        document = json.loads(inventory.render(ROOT))
        self.assertGreater(len(document["unclassified"]), 0)
        classified = {entry["name"] for entry in document["entries"]}
        for finding in document["unclassified"]:
            self.assertNotIn(finding["name"], classified)
            self.assertTrue(finding["reason"])

    def test_every_region_extracts_at_least_its_minimum(self):
        for region in inventory.REGIONS:
            extracted = region.extract(ROOT)
            self.assertGreaterEqual(len(extracted), region.minimum, region.id)

    def test_a_region_that_stops_matching_is_refused(self):
        thin = inventory.Region(
            id="thin",
            description="a region whose parser has rotted",
            extract=lambda root: {"only": (inventory.MIGRATION_PLAN,)},
            default=inventory.durable("command"),
            minimum=5,
        )
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.resolve_region(ROOT, thin, inventory.Built())
        self.assertIn("makes the backward drift check vacuous", str(raised.exception))


class ConsumerContract(unittest.TestCase):
    """The comparison `R1-17` records as blocked on this item."""

    GENERATED = "rust/crates/automonique-protocol/src/compat/generated.rs"

    def registry_pairs(self) -> list[tuple[str, str]]:
        text = (ROOT / self.GENERATED).read_text()
        canonical = self.arms(text, "CanonicalName", "spelling")
        legacy = self.arms(text, "LegacyName", "spelling")
        forwards = self.arms(text, "LegacyName", "canonical")
        constants = re.findall(r"pub const ([A-Z0-9_]+): Self = Self\((\d+)\);", text)
        index = {name: int(value) for name, value in constants}
        pairs = []
        for position, alias_spelling in enumerate(legacy):
            target_constant = forwards[position].removeprefix("CanonicalName::")
            pairs.append((alias_spelling, canonical[index[target_constant]]))
        return pairs

    @staticmethod
    def arms(text: str, type_name: str, accessor: str) -> list[str]:
        block = text.split(f"impl {type_name} {{", 1)[1]
        body = block.split(f"pub const fn {accessor}(", 1)[1]
        body = body.split("\n    }", 1)[0]
        values = re.findall(r"=> (?:\"([^\"]+)\"|([A-Za-z:_]+))", body)
        return [quoted or bare for quoted, bare in values]

    def test_every_registry_canonical_name_is_durable_in_the_inventory(self):
        document = json.loads(inventory.render(ROOT))
        durable = set(document["durable_names"])
        pairs = self.registry_pairs()
        self.assertTrue(pairs)
        for _, canonical in pairs:
            self.assertIn(canonical, durable)

    def test_every_registry_alias_forwards_where_the_inventory_says(self):
        document = json.loads(inventory.render(ROOT))
        forwards = document["compatibility_forwards"]
        pairs = self.registry_pairs()
        self.assertTrue(pairs)
        for alias_spelling, canonical in pairs:
            self.assertIn(alias_spelling, forwards, alias_spelling)
            row = forwards[alias_spelling]
            self.assertIn(canonical, [row["forwards_to"], *row["also"]], alias_spelling)

    def test_the_namespace_exception_set_is_not_empty(self):
        document = json.loads(inventory.render(ROOT))
        exceptions = document["legacy_exceptions"]
        self.assertTrue(exceptions)
        for row in exceptions:
            self.assertTrue(inventory.is_legacy_token(row["name"]))
            self.assertTrue(row["authorized_by"].startswith(f"{inventory.CORPUS}/"))


if __name__ == "__main__":
    unittest.main()
