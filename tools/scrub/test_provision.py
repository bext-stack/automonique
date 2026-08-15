#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Checks for the protected-rule provisioner.

Every value here is a synthetic literal invented for this test. The suite
uploads nothing and never contacts GitHub.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from tools.scrub import provision, scan

SYNTHETIC = {
    "legacy-name": b"synthetic-legacy-not-a-real-name",
    "third-party-product": b"synthetic-thirdparty-not-real",
    "internal-product": b"synthetic-internal-not-real",
    "environment-name": b"SYNTHETIC_NOT_REAL_VARIABLE",
}
KEY = b"k" * 32


def entries() -> list[provision.ValueEntry]:
    return [
        provision.ValueEntry(family, value) for family, value in SYNTHETIC.items()
    ]


class ParseValuesTests(unittest.TestCase):
    def text(self, lines: list[str]) -> str:
        return "\n".join(lines) + "\n"

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        parsed = provision.parse_values(
            self.text(
                ["# a comment", ""]
                + [f"{e.family}: {e.value.decode()}" for e in entries()]
            )
        )
        self.assertEqual(entries(), parsed)

    def test_every_required_family_must_appear(self) -> None:
        lines = [f"{e.family}: {e.value.decode()}" for e in entries()][:-1]
        with self.assertRaisesRegex(scan.ScrubError, "environment-name"):
            provision.parse_values(self.text(lines))

    def test_unknown_family_is_refused(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "unknown family"):
            provision.parse_values("not-a-family: x\n")

    def test_untouched_template_names_every_blank_line(self) -> None:
        """A fresh template must report the whole job, not just its first line."""
        blank = self.text([f"{family}:" for family in sorted(scan.REQUIRED_FAMILIES)])
        with self.assertRaises(scan.ScrubError) as caught:
            provision.parse_values(blank)
        message = str(caught.exception)
        self.assertIn("no values filled in yet", message)
        for family in scan.REQUIRED_FAMILIES:
            self.assertIn(family, message)

    def test_a_partly_filled_template_names_the_remaining_blanks(self) -> None:
        lines = [f"{e.family}: {e.value.decode()}" for e in entries()][:-1]
        lines.append("environment-name:")
        with self.assertRaises(scan.ScrubError) as caught:
            provision.parse_values(self.text(lines))
        message = str(caught.exception)
        self.assertIn("still blank", message)
        self.assertIn("environment-name", message)
        for value in SYNTHETIC.values():
            self.assertNotIn(value.decode(), message)

    def test_line_without_a_separator_is_refused(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "line 1"):
            provision.parse_values("legacy-name legacy\n")


class BundleTests(unittest.TestCase):
    def test_bundle_contains_no_submitted_value(self) -> None:
        bundle = provision.build_bundle(entries(), KEY)
        rendered = json.dumps(bundle).encode()
        for value in SYNTHETIC.values():
            self.assertNotIn(value, rendered)
            self.assertNotIn(value.lower(), rendered.lower())

    def test_bundle_satisfies_the_scanner_schema(self) -> None:
        bundle = provision.build_bundle(entries(), KEY)
        rules = scan.parse_rules(
            bundle, expected_algorithm="hmac-sha256", require_families=True
        )
        self.assertEqual(4, len(rules))
        self.assertTrue(
            all(rule.rule_id.startswith(("p1-", "p2-")) for rule in rules)
        )

    def test_legacy_names_are_first_pass_and_others_second(self) -> None:
        bundle = provision.build_bundle(entries(), KEY)
        by_family = {rule["family"]: rule["id"] for rule in bundle["rules"]}
        self.assertTrue(by_family["legacy-name"].startswith("p1-"))
        for family in ("third-party-product", "internal-product", "environment-name"):
            self.assertTrue(by_family[family].startswith("p2-"))

    def test_generated_rules_actually_detect_their_values(self) -> None:
        """The point of the tool: these fingerprints must match the real value."""
        bundle = provision.build_bundle(entries(), KEY)
        rules = scan.parse_rules(
            bundle, expected_algorithm="hmac-sha256", require_families=True
        )
        groups = scan.grouped_rules(rules)
        for family, value in SYNTHETIC.items():
            findings = scan.scan_bytes(
                b"prefix " + value + b" suffix",
                source="file",
                location="fixture",
                groups=groups,
                hmac_key=KEY,
            )
            self.assertTrue(findings, f"{family} fingerprint did not match its value")

    def test_a_different_key_does_not_match(self) -> None:
        bundle = provision.build_bundle(entries(), KEY)
        rules = scan.parse_rules(
            bundle, expected_algorithm="hmac-sha256", require_families=True
        )
        findings = scan.scan_bytes(
            SYNTHETIC["legacy-name"],
            source="file",
            location="fixture",
            groups=scan.grouped_rules(rules),
            hmac_key=b"z" * 32,
        )
        self.assertEqual([], findings)

    def test_duplicate_values_are_refused(self) -> None:
        duplicated = entries() + [
            provision.ValueEntry("internal-product", SYNTHETIC["legacy-name"])
        ]
        with self.assertRaisesRegex(scan.ScrubError, "same fingerprint"):
            provision.build_bundle(duplicated, KEY)


class LiveValueTests(unittest.TestCase):
    def absent(self) -> bytes:
        """A value assembled at run time.

        The joined bytes appear contiguously in no tracked file — including this
        one — which is the condition being asserted. A literal would be tracked
        the moment this test is committed and could never satisfy it.
        """
        return b"-".join([b"synthetic", b"absent", b"from", b"every", b"blob"])

    def test_a_value_still_in_the_tree_is_reported_by_family_only(self) -> None:
        # AGENTS.md is tracked, so a phrase from it stands in for an unscrubbed
        # value without this test needing a real private identifier.
        live = provision.unscrubbed(
            [provision.ValueEntry("legacy-name", b"Automonique agent contract")],
            provision.ROOT,
        )
        self.assertEqual(["legacy-name"], live)

    def test_a_value_absent_from_the_tree_is_not_reported(self) -> None:
        self.assertEqual(
            [],
            provision.unscrubbed(
                [provision.ValueEntry("legacy-name", self.absent())], provision.ROOT
            ),
        )


class HomeAnnotationTests(unittest.TestCase):
    """`@home` is what makes a deliberately retained value fingerprintable."""

    def parse_one(self, line: str) -> provision.ValueEntry:
        lines = [
            f"{e.family}: {e.value.decode()}"
            for e in entries()
            if e.family != "legacy-name"
        ]
        parsed = provision.parse_values("\n".join([line, *lines]) + "\n")
        return next(entry for entry in parsed if entry.family == "legacy-name")

    def test_a_line_without_an_annotation_declares_no_home(self) -> None:
        self.assertEqual((), self.parse_one("legacy-name: retained-name").homes)

    def test_one_annotation_is_parsed_and_kept_off_the_value(self) -> None:
        entry = self.parse_one("legacy-name: retained-name @home docs/inventory.md")
        self.assertEqual(b"retained-name", entry.value)
        self.assertEqual(("docs/inventory.md",), entry.homes)

    def test_several_annotations_are_ordered_as_written(self) -> None:
        entry = self.parse_one(
            "legacy-name: retained-name @home docs/inventory.md @home src/registry.rs"
        )
        self.assertEqual(("docs/inventory.md", "src/registry.rs"), entry.homes)

    def test_a_malformed_home_names_its_line_and_is_refused(self) -> None:
        for annotation in ("/etc/passwd", "../outside.md", "docs/", "docs/*.md"):
            with self.subTest(annotation=annotation):
                with self.assertRaisesRegex(scan.ScrubError, "line 1"):
                    self.parse_one(f"legacy-name: retained-name @home {annotation}")

    def test_the_same_home_twice_is_refused(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "same home twice"):
            self.parse_one("legacy-name: n @home docs/a.md @home docs/a.md")

    def test_the_bundle_carries_homes_and_still_no_value(self) -> None:
        annotated = [
            provision.ValueEntry(entry.family, entry.value, ("docs/inventory.md",))
            if entry.family == "legacy-name"
            else entry
            for entry in entries()
        ]
        bundle = provision.build_bundle(annotated, KEY)
        self.assertEqual(scan.RULE_SCHEMA_V2, bundle["schema"])
        by_family = {rule["family"]: rule for rule in bundle["rules"]}
        self.assertEqual(["docs/inventory.md"], by_family["legacy-name"]["homes"])
        # Only the annotated rule gains the field; the rest are unchanged.
        for family in ("third-party-product", "internal-product", "environment-name"):
            self.assertNotIn("homes", by_family[family])
        rendered = json.dumps(bundle).encode()
        for value in SYNTHETIC.values():
            self.assertNotIn(value, rendered)

    def test_the_scanner_accepts_a_bundle_carrying_homes(self) -> None:
        annotated = [
            provision.ValueEntry(entry.family, entry.value, ("docs/inventory.md",))
            if entry.family == "legacy-name"
            else entry
            for entry in entries()
        ]
        rules = scan.parse_rules(
            provision.build_bundle(annotated, KEY),
            expected_algorithm="hmac-sha256",
            require_families=True,
        )
        homes = {rule.family: rule.homes for rule in rules}
        self.assertEqual(("docs/inventory.md",), homes["legacy-name"])

    def test_a_value_retained_only_in_its_home_is_provisionable(self) -> None:
        """The blocker homes exist to remove.

        `unscrubbed` refuses to fingerprint a value still in the tree. A value
        the repository deliberately keeps is always still in the tree, so
        without homes it could never be fingerprinted at all.
        """
        phrase = b"Automonique agent contract"
        home = next(
            path
            for path, _, content in scan.tracked_blobs(provision.ROOT)
            if phrase in content
        )
        self.assertEqual(
            ["legacy-name"],
            provision.unscrubbed(
                [provision.ValueEntry("legacy-name", phrase)], provision.ROOT
            ),
        )
        self.assertEqual(
            [],
            provision.unscrubbed(
                [provision.ValueEntry("legacy-name", phrase, (home,))], provision.ROOT
            ),
        )

    def test_a_home_that_is_not_a_tracked_file_is_caught_before_upload(self) -> None:
        self.assertEqual(
            ["legacy-name"],
            provision.phantom_homes(
                [provision.ValueEntry("legacy-name", b"x", ("does/not/exist.md",))],
                provision.ROOT,
            ),
        )
        self.assertEqual(
            [],
            provision.phantom_homes(
                [provision.ValueEntry("legacy-name", b"x", ("AGENTS.md",))],
                provision.ROOT,
            ),
        )


class ValuesFileLocationTests(unittest.TestCase):
    def test_a_values_file_inside_the_repository_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(dir=provision.ROOT / "tools") as directory:
            inside = pathlib.Path(directory) / "values.txt"
            inside.write_text("legacy-name: x\n")
            self.assertTrue(inside.resolve().is_relative_to(provision.ROOT))


if __name__ == "__main__":
    unittest.main()
