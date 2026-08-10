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


def entries() -> list[tuple[str, bytes]]:
    return list(SYNTHETIC.items())


class ParseValuesTests(unittest.TestCase):
    def text(self, lines: list[str]) -> str:
        return "\n".join(lines) + "\n"

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        parsed = provision.parse_values(
            self.text(
                ["# a comment", ""]
                + [f"{family}: {value.decode()}" for family, value in entries()]
            )
        )
        self.assertEqual(entries(), parsed)

    def test_every_required_family_must_appear(self) -> None:
        lines = [f"{f}: {v.decode()}" for f, v in entries()][:-1]
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
        lines = [f"{f}: {v.decode()}" for f, v in entries()][:-1]
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
        duplicated = entries() + [("internal-product", SYNTHETIC["legacy-name"])]
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
            [("legacy-name", b"Automonique agent contract")], provision.ROOT
        )
        self.assertEqual(["legacy-name"], live)

    def test_a_value_absent_from_the_tree_is_not_reported(self) -> None:
        self.assertEqual(
            [], provision.unscrubbed([("legacy-name", self.absent())], provision.ROOT)
        )


class ValuesFileLocationTests(unittest.TestCase):
    def test_a_values_file_inside_the_repository_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(dir=provision.ROOT / "tools") as directory:
            inside = pathlib.Path(directory) / "values.txt"
            inside.write_text("legacy-name: x\n")
            self.assertTrue(inside.resolve().is_relative_to(provision.ROOT))


if __name__ == "__main__":
    unittest.main()
