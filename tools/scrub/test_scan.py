#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import pathlib
import subprocess
import tempfile
import unittest

from tools.scrub import scan


class ScrubScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = pathlib.Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Automonique Fixture")
        self.git("config", "user.email", "fixture@automonique.invalid")
        (self.repository / "clean.txt").write_bytes(
            b"Monique bext-stack legacy_fixture\n"
        )
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean synthetic baseline")
        self.rules = scan.parse_rules(
            scan.read_json(scan.PUBLIC_RULES),
            expected_algorithm="sha256",
            require_families=True,
        )
        document = json.loads(
            pathlib.Path(scan.__file__).with_name("synthetic-vectors.json").read_text()
        )
        self.vectors = {
            entry["rule_id"]: base64.b64decode(entry["value_base64"], validate=True)
            for entry in document["vectors"]
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", *args], cwd=self.repository, capture_output=True, check=True
        )

    def findings(self, rules: list[scan.Rule] | None = None) -> list[scan.Finding]:
        found, _, _ = scan.scan_repository(self.repository, rules or self.rules)
        return found

    def test_clean_tree_and_retained_identifiers_pass(self) -> None:
        self.assertEqual([], self.findings())
        allowlist = scan.load_allowlist(scan.ALLOWLIST)
        self.assertEqual(4, len(allowlist))
        self.assertTrue(all(entry["reason"] for entry in allowlist))

    def test_each_synthetic_family_fails_without_echoing_value(self) -> None:
        for rule_id, value in self.vectors.items():
            with self.subTest(rule_id=rule_id):
                (self.repository / "probe.bin").write_bytes(b"prefix\x00" + value)
                self.git("add", "probe.bin")
                found = self.findings()
                matching = [finding for finding in found if finding.rule_id == rule_id]
                self.assertEqual(1, len(matching))
                rendered = "\n".join(scan.render_finding(item) for item in found)
                self.assertIn(f"rule={rule_id}", rendered)
                self.assertNotIn(value.decode(), rendered)
                (self.repository / "probe.bin").unlink()
                self.git("add", "-u", "probe.bin")

    def test_commit_message_and_ancestor_are_scanned(self) -> None:
        value = self.vectors["synthetic-internal-product"]
        (self.repository / "second.txt").write_text("clean\n")
        self.git("add", "second.txt")
        self.git("commit", "-q", "-m", value.decode())
        (self.repository / "third.txt").write_text("still clean\n")
        self.git("add", "third.txt")
        self.git("commit", "-q", "-m", "clean tip")
        matching = [
            finding
            for finding in self.findings()
            if finding.rule_id == "synthetic-internal-product"
        ]
        self.assertEqual(1, len(matching))
        self.assertEqual("commit", matching[0].source)

    def test_add_then_delete_blob_remains_a_finding(self) -> None:
        value = self.vectors["synthetic-third-party-product"]
        (self.repository / "removed.bin").write_bytes(value)
        self.git("add", "removed.bin")
        self.git("commit", "-q", "-m", "add historical fixture")
        self.git("rm", "-q", "removed.bin")
        self.git("commit", "-q", "-m", "remove historical fixture")
        matching = [
            finding
            for finding in self.findings()
            if finding.rule_id == "synthetic-third-party-product"
        ]
        self.assertEqual(1, len(matching))
        self.assertEqual("historical-blob", matching[0].source)

    def test_matching_filename_is_redacted(self) -> None:
        value = self.vectors["synthetic-environment-name"]
        filename = value.decode()
        (self.repository / filename).write_text("clean body\n")
        self.git("add", filename)
        found = self.findings()
        matching = [
            finding
            for finding in found
            if finding.rule_id == "synthetic-environment-name"
        ]
        self.assertEqual(1, len(matching))
        self.assertEqual("path", matching[0].source)
        rendered = scan.render_finding(matching[0])
        self.assertIn('location="<redacted-path>"', rendered)
        self.assertNotIn(filename, rendered)

    def test_public_rule_document_cannot_contain_plain_values(self) -> None:
        document = scan.read_json(scan.PUBLIC_RULES)
        document["rules"][0]["value"] = "not permitted"
        with self.assertRaisesRegex(scan.ScrubError, "fingerprint metadata"):
            scan.parse_rules(
                document, expected_algorithm="sha256", require_families=True
            )

    def test_duplicate_fingerprint_is_rejected(self) -> None:
        document = scan.read_json(scan.PUBLIC_RULES)
        duplicate = dict(document["rules"][0])
        duplicate["id"] = "different-safe-id"
        duplicate["family"] = "environment-name"
        document["rules"].append(duplicate)
        with self.assertRaisesRegex(scan.ScrubError, "duplicate fingerprint"):
            scan.parse_rules(
                document, expected_algorithm="sha256", require_families=True
            )

    def test_allowlist_cannot_authorize_an_extra_entry(self) -> None:
        document = scan.read_json(scan.ALLOWLIST)
        document["entries"].append(
            {
                "id": "new-exemption",
                "retained": "too broad",
                "reason": "synthetic pressure test",
                "decision": "plan/gates.md#gate-scrub",
            }
        )
        path = self.repository / "allowlist.json"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(scan.ScrubError, "not authorized"):
            scan.load_allowlist(path)

    def test_missing_or_incomplete_protected_rules_fail_closed(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "required"):
            scan.protected_rules_from_environment(
                {},
                rules_variable="RULES",
                key_variable="KEY",
                required=True,
            )
        incomplete = {
            "schema": scan.RULE_SCHEMA,
            "rules": [
                {
                    "id": "p1-001",
                    "family": "legacy-name",
                    "algorithm": "hmac-sha256",
                    "length": 4,
                    "digest": "0" * 64,
                }
            ],
        }
        environment = {
            "RULES": base64.b64encode(json.dumps(incomplete).encode()).decode(),
            "KEY": base64.b64encode(b"k" * 32).decode(),
        }
        with self.assertRaisesRegex(scan.ScrubError, "missing required families"):
            scan.protected_rules_from_environment(
                environment,
                rules_variable="RULES",
                key_variable="KEY",
                required=True,
            )

    def test_protected_hmac_rules_use_the_same_redacted_path(self) -> None:
        key = b"p" * 32
        rules: list[scan.Rule] = []
        for family, value in zip(sorted(scan.REQUIRED_FAMILIES), self.vectors.values()):
            prefix = "p1" if family == "legacy-name" else "p2"
            rules.append(
                scan.Rule(
                    f"{prefix}-{len(rules) + 1:03d}",
                    family,
                    "hmac-sha256",
                    len(value),
                    hmac.new(key, value, hashlib.sha256).hexdigest(),
                )
            )
        value = next(iter(self.vectors.values()))
        (self.repository / "protected.bin").write_bytes(value)
        self.git("add", "protected.bin")
        found, _, _ = scan.scan_repository(self.repository, rules, hmac_key=key)
        self.assertEqual(1, len(found))
        self.assertNotIn(value.decode(), scan.render_finding(found[0]))

    def test_shallow_history_is_rejected(self) -> None:
        head = self.git("rev-parse", "HEAD").stdout
        (self.repository / ".git/shallow").write_bytes(head)
        with self.assertRaisesRegex(scan.ScrubError, "non-shallow"):
            scan.scan_repository(self.repository, self.rules)


if __name__ == "__main__":
    unittest.main()
