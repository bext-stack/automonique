#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import pathlib
import subprocess
import tempfile
import unittest
from typing import Any

from tools.scrub import scan


class ScannerFixture(unittest.TestCase):
    """A small Git repository carrying the retained identifiers and nothing else."""

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

    def findings(
        self,
        rules: list[scan.Rule] | None = None,
        *,
        scope: str = "full",
        commits: str | None = None,
    ) -> list[scan.Finding]:
        found, _, _ = scan.scan_repository(
            self.repository, rules or self.rules, scope=scope, commits=commits
        )
        return found

    def head(self, offset: int = 0) -> str:
        return (
            self.git("rev-parse", f"HEAD~{offset}" if offset else "HEAD")
            .stdout.decode()
            .strip()
        )


class ScrubScannerTests(ScannerFixture):
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


class ScopeTests(ScannerFixture):
    """`--scope tree` answers a smaller question, and only that one."""

    def test_tree_scope_skips_history_that_full_scope_finds(self) -> None:
        deleted = self.vectors["synthetic-third-party-product"]
        message = self.vectors["synthetic-internal-product"]
        (self.repository / "removed.bin").write_bytes(deleted)
        self.git("add", "removed.bin")
        self.git("commit", "-q", "-m", message.decode())
        self.git("rm", "-q", "removed.bin")
        self.git("commit", "-q", "-m", "remove historical fixture")

        full = {finding.source for finding in self.findings()}
        self.assertEqual({"historical-blob", "commit"}, full)
        self.assertEqual([], self.findings(scope="tree"))

    def test_tree_scope_still_reads_the_tracked_tree_and_path_names(self) -> None:
        value = self.vectors["synthetic-environment-name"]
        (self.repository / value.decode()).write_text("clean body\n")
        (self.repository / "present.bin").write_bytes(
            self.vectors["synthetic-legacy-name"]
        )
        self.git("add", "-A")
        sources = {finding.source for finding in self.findings(scope="tree")}
        self.assertEqual({"path", "file"}, sources)

    def test_tree_scope_survives_a_shallow_clone(self) -> None:
        """The push job's whole point: no history, so no history requirement."""
        head = self.git("rev-parse", "HEAD").stdout
        (self.repository / ".git/shallow").write_bytes(head)
        self.assertEqual([], self.findings(scope="tree"))

    def test_an_unknown_scope_is_refused(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "unknown scan scope"):
            scan.scan_repository(self.repository, self.rules, scope="everything")


class CommitRangeTests(ScannerFixture):
    """`--commits` scans exactly the messages a push introduced."""

    def setUp(self) -> None:
        super().setUp()
        self.base = self.head()
        value = self.vectors["synthetic-internal-product"]
        (self.repository / "second.txt").write_text("clean\n")
        self.git("add", "second.txt")
        self.git("commit", "-q", "-m", value.decode())
        self.tip = self.head()

    def test_a_range_containing_the_message_finds_it(self) -> None:
        found = self.findings(scope="tree", commits=f"{self.base}..{self.tip}")
        self.assertEqual(1, len(found))
        self.assertEqual("commit", found[0].source)
        self.assertEqual(self.tip, found[0].location)

    def test_a_range_excluding_the_message_does_not(self) -> None:
        self.assertEqual(
            [], self.findings(scope="tree", commits=f"{self.tip}..{self.tip}")
        )

    def test_tree_scope_without_a_range_reads_no_message_at_all(self) -> None:
        self.assertEqual([], self.findings(scope="tree"))

    def test_full_scope_narrows_to_the_range_when_one_is_given(self) -> None:
        """A range is a narrowing, not an addition, so it must not double-count."""
        found = self.findings(commits=f"{self.base}..{self.tip}")
        self.assertEqual(
            1, len([item for item in found if item.source == "commit"])
        )

    def test_a_range_that_is_not_a_revision_selector_is_refused(self) -> None:
        for hostile in ("--all", "-n1", "main -- .", "main;rm", ""):
            with self.subTest(range=hostile):
                with self.assertRaisesRegex(scan.ScrubError, "revision selector"):
                    self.findings(scope="tree", commits=hostile)


class SanctionedHomeTests(ScannerFixture):
    """A rule may name files whose *content* it does not judge, and no more."""

    def setUp(self) -> None:
        super().setUp()
        self.value = self.vectors["synthetic-legacy-name"]
        self.rule = scan.Rule(
            "synthetic-legacy-name",
            "legacy-name",
            "sha256",
            len(self.value),
            hashlib.sha256(self.value).hexdigest(),
            ("inventory.md",),
        )
        (self.repository / "inventory.md").write_bytes(b"classified: " + self.value)
        self.git("add", "inventory.md")
        self.git("commit", "-q", "-m", "add the sanctioned inventory")

    def test_content_in_a_declared_home_is_not_a_finding(self) -> None:
        self.assertEqual([], self.findings([self.rule], scope="tree"))

    def test_the_same_content_elsewhere_still_is(self) -> None:
        (self.repository / "elsewhere.md").write_bytes(b"copied: " + self.value)
        self.git("add", "elsewhere.md")
        found = self.findings([self.rule], scope="tree")
        self.assertEqual(1, len(found))
        self.assertEqual("elsewhere.md", found[0].location)

    def test_a_home_does_not_exempt_its_own_file_name(self) -> None:
        """A home is about content. A path is a different disclosure."""
        named = self.value.decode()
        rule = dataclasses.replace(self.rule, homes=("inventory.md", named))
        (self.repository / named).write_text("clean body\n")
        self.git("add", named)
        found = self.findings([rule], scope="tree")
        self.assertEqual(["path"], [finding.source for finding in found])

    def test_a_home_does_not_exempt_history_or_a_commit_message(self) -> None:
        """The sanctioned copy is the one in the tree. The others are copies."""
        (self.repository / "transient.md").write_bytes(b"copied: " + self.value)
        self.git("add", "transient.md")
        self.git("commit", "-q", "-m", self.value.decode())
        self.git("rm", "-q", "transient.md")
        self.git("commit", "-q", "-m", "remove the transient copy")
        sources = {finding.source for finding in self.findings([self.rule])}
        self.assertEqual({"historical-blob", "commit"}, sources)

    def test_one_rules_home_does_not_widen_another(self) -> None:
        other = self.vectors["synthetic-internal-product"]
        unexempt = scan.Rule(
            "synthetic-internal-product",
            "internal-product",
            "sha256",
            len(other),
            hashlib.sha256(other).hexdigest(),
        )
        path = self.repository / "inventory.md"
        path.write_bytes(path.read_bytes() + b"\nand: " + other)
        self.git("add", "inventory.md")
        found = self.findings([self.rule, unexempt], scope="tree")
        self.assertEqual(["synthetic-internal-product"], [f.rule_id for f in found])

    def test_a_home_naming_no_tracked_file_is_a_configuration_error(self) -> None:
        rule = dataclasses.replace(self.rule, homes=("does/not/exist.md",))
        with self.assertRaisesRegex(scan.ScrubError, "not a tracked file") as caught:
            self.findings([rule], scope="tree")
        # The refusal names the rule, never the path, because the rule document
        # arrives from a secret and this message goes to a CI log.
        self.assertNotIn("does/not/exist.md", str(caught.exception))


class HomeSchemaTests(unittest.TestCase):
    """Homes are an exemption, so a malformed one is refused, not repaired."""

    def document(self, homes: Any, *, schema: str = scan.RULE_SCHEMA_V2) -> dict:
        rule = {
            "id": "p1-001",
            "family": "legacy-name",
            "algorithm": "hmac-sha256",
            "length": 4,
            "digest": "0" * 64,
        }
        if homes is not None:
            rule["homes"] = homes
        return {"schema": schema, "rules": [rule]}

    def parse(self, document: dict) -> list[scan.Rule]:
        return scan.parse_rules(
            document, expected_algorithm="hmac-sha256", require_families=False
        )

    def test_a_v1_document_may_not_carry_homes(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "fingerprint metadata"):
            self.parse(self.document(["a.md"], schema=scan.RULE_SCHEMA))

    def test_a_v2_document_without_homes_is_still_valid(self) -> None:
        self.assertEqual((), self.parse(self.document(None))[0].homes)

    def test_a_v2_document_with_homes_carries_them(self) -> None:
        self.assertEqual(("a/b.md",), self.parse(self.document(["a/b.md"]))[0].homes)

    def test_an_unknown_schema_is_refused(self) -> None:
        with self.assertRaisesRegex(scan.ScrubError, "unsupported shape or schema"):
            self.parse(self.document(None, schema="automonique.scrub-rules/v3"))

    def test_malformed_homes_are_refused(self) -> None:
        cases = {
            "empty or non-list": [],
            "not a non-empty string": [""],
            "surrounding whitespace": [" a.md"],
            "not a relative POSIX path": ["/etc/passwd"],
            "empty or relative segment": ["../outside.md"],
            "naming a directory": ["docs/"],
            "glob character": ["docs/*.md"],
            "same home twice": ["a.md", "a.md"],
        }
        for expected, homes in cases.items():
            with self.subTest(homes=homes):
                with self.assertRaisesRegex(scan.ScrubError, expected):
                    self.parse(self.document(homes))
        with self.assertRaisesRegex(scan.ScrubError, "not a non-empty string"):
            self.parse(self.document([123]))
        with self.assertRaisesRegex(scan.ScrubError, "empty or non-list"):
            self.parse(self.document("a.md"))
        with self.assertRaisesRegex(scan.ScrubError, "more than"):
            self.parse(
                self.document([f"file{index}.md" for index in range(
                    scan.MAX_HOMES_PER_RULE + 1
                )])
            )

    def test_the_shipped_public_rules_declare_no_home(self) -> None:
        """Nothing public is exempt from a public rule; only a bundle may be."""
        rules = scan.parse_rules(
            scan.read_json(scan.PUBLIC_RULES),
            expected_algorithm="sha256",
            require_families=True,
        )
        self.assertTrue(all(rule.homes == () for rule in rules))


if __name__ == "__main__":
    unittest.main()
