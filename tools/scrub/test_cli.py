#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""End-to-end checks for the program CI actually runs.

`test_scan.py` exercises the scanner's functions and `test_provision.py` the
bundle builder. Neither exercises `scan.py` as a command: its arguments, its
environment, its stdout, or its exit codes. The publication job's *success*
path — a protected rule bundle and key decoded from two base64 environment
values — had never been executed at all, so a defect in it would have surfaced
only after the owner installed the secrets and pushed to `main`.

These tests drive the real producer into the real command: `provision.py` builds
the bundle, it is passed exactly as the workflow passes it, and `scan.py` is
run as a subprocess so the assertions are about observed exit codes rather than
about return values from an imported function.

Every identifier here is a stand-in invented in this file. Values that a rule
fingerprints are assembled at run time, so no tracked blob in this repository
contains one contiguously.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from tools.scrub import provision, scan

RULES_ENV = "AUTOMONIQUE_SCRUB_PROTECTED_RULES_B64"
KEY_ENV = "AUTOMONIQUE_SCRUB_HMAC_KEY_B64"
KEY = b"cli-fixture-key-32-bytes-exactly"
# Retained identifiers, present in every fixture tree. They are the allow-list
# row: the scan must stay silent about them.
RETAINED = b"Monique bext-stack legacy_fixture\n"


def standin(*parts: str, separator: str = "-") -> bytes:
    """Join a stand-in identifier at run time.

    Written as a literal, the value would live in this tracked file, and a test
    that asserts a value is absent from every blob could never pass.
    """
    return separator.join(parts).encode()


# The value the protected bundle below covers, and the one the development-mode
# scan cannot see. Nothing in the repository fingerprints it.
COVERED = standin("standin", "identifier", "under", "test")
FIRST_PASS = standin("standin", "first", "pass", "name")
INTERNAL = standin("standin", "internal", "product")
ENVIRONMENT_NAME = standin("STANDIN", "ENVIRONMENT", "NAME", separator="_")


def protected_environment(
    covered: bytes, *, homes: tuple[str, ...] = ()
) -> tuple[dict[str, str], str]:
    """Build the two secrets the publication job receives, and name the rule.

    The bundle comes from `provision.build_bundle` rather than from a literal
    written here: the point of the test is that what the provisioner produces is
    what the scanner accepts, and a hand-built document would only prove this
    file agrees with itself.
    """
    document = provision.build_bundle(
        [
            provision.ValueEntry("legacy-name", FIRST_PASS),
            provision.ValueEntry("third-party-product", covered, homes),
            provision.ValueEntry("internal-product", INTERNAL),
            provision.ValueEntry("environment-name", ENVIRONMENT_NAME),
        ],
        KEY,
    )
    covered_rule = next(
        rule["id"]
        for rule in document["rules"]
        if rule["family"] == "third-party-product"
    )
    environment = {
        RULES_ENV: base64.b64encode(json.dumps(document).encode()).decode(),
        KEY_ENV: base64.b64encode(KEY).decode(),
    }
    return environment, covered_rule


class CommandFixture(unittest.TestCase):
    """A small, complete Git repository plus a way to run the real command."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = pathlib.Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Automonique Fixture")
        self.git("config", "user.email", "fixture@automonique.invalid")
        self.write("doc.md", RETAINED)
        self.git("add", "doc.md")
        self.git("commit", "-q", "-m", "clean baseline")
        self.public_rules = scan.parse_rules(
            scan.read_json(scan.PUBLIC_RULES),
            expected_algorithm="sha256",
            require_families=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", *arguments], cwd=self.repository, capture_output=True, check=True
        )

    def write(self, name: str, content: bytes) -> None:
        (self.repository / name).write_bytes(content)

    def reintroduce(self, value: bytes, *, in_message: bool) -> None:
        """Put a value back into the fixture, in a file or a commit message."""
        if in_message:
            self.write("doc.md", RETAINED + b"an unrelated edit\n")
            self.git("add", "doc.md")
            self.git("commit", "-q", "-m", value.decode())
        else:
            self.write("doc.md", RETAINED + b"regression: " + value + b"\n")
            self.git("add", "doc.md")
            self.git("commit", "-q", "-m", "an edit with a clean message")

    def run_scan(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        child = dict(os.environ)
        # A developer who happens to hold the real secrets must not get a
        # different result from this suite than CI does.
        for name in (RULES_ENV, KEY_ENV):
            child.pop(name, None)
        child.update(environment or {})
        return subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(scan.__file__)),
                "--repository",
                str(self.repository),
                "--rules",
                str(scan.PUBLIC_RULES),
                "--allowlist",
                str(scan.ALLOWLIST),
                *arguments,
            ],
            capture_output=True,
            text=True,
            env=child,
            check=False,
        )

    def assertValueAbsent(
        self, result: subprocess.CompletedProcess[str], value: bytes
    ) -> None:
        combined = result.stdout + result.stderr
        self.assertNotIn(value.decode(), combined)


class DevelopmentModeTests(CommandFixture):
    def test_clean_tree_exits_zero_and_reports_the_coverage_it_had(self) -> None:
        result = self.run_scan()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            f"{len(self.public_rules)} synthetic and 0 protected rules",
            result.stdout,
        )
        # Allow-list row: the retained identifiers are in the tree and silent.
        self.assertEqual("", result.stderr)

    def test_a_pass_without_protected_rules_states_what_it_did_not_check(self) -> None:
        """The misreading this gate has to survive is a green tick."""
        self.assertIn(scan.COVERAGE_NOTE, self.run_scan().stdout)

    def test_the_note_is_absent_once_protected_rules_are_installed(self) -> None:
        environment, _ = protected_environment(COVERED)
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            f"{len(self.public_rules)} synthetic and 4 protected rules", result.stdout
        )
        self.assertNotIn(scan.COVERAGE_NOTE, result.stdout)


class MissingProtectedRulesTests(CommandFixture):
    """The contract's `Missing protected rules` row, both halves."""

    def test_publication_refuses_while_private_development_still_runs(self) -> None:
        refused = self.run_scan("--require-protected")
        self.assertEqual(2, refused.returncode)
        self.assertIn("configuration error", refused.stderr)
        self.assertIn(RULES_ENV, refused.stderr)
        self.assertIn(KEY_ENV, refused.stderr)
        self.assertEqual("", refused.stdout)
        self.assertEqual(0, self.run_scan().returncode)

    def test_a_bundle_without_its_key_is_refused(self) -> None:
        environment, _ = protected_environment(COVERED)
        del environment[KEY_ENV]
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(2, result.returncode)
        self.assertIn(KEY_ENV, result.stderr)

    def test_a_short_key_is_refused(self) -> None:
        environment, _ = protected_environment(COVERED)
        environment[KEY_ENV] = base64.b64encode(b"k" * 31).decode()
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(2, result.returncode)
        self.assertIn("32 bytes", result.stderr)


class ProtectedReintroductionTests(CommandFixture):
    def test_a_file_reintroduction_names_rule_file_and_line(self) -> None:
        self.reintroduce(COVERED, in_message=False)
        environment, rule_id = protected_environment(COVERED)
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(1, result.returncode)
        self.assertIn(
            scan.render_finding(scan.Finding(rule_id, "file", "doc.md", 2)),
            result.stderr,
        )
        self.assertValueAbsent(result, COVERED)

    def test_a_commit_message_reintroduction_is_found(self) -> None:
        self.reintroduce(COVERED, in_message=True)
        environment, rule_id = protected_environment(COVERED)
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(1, result.returncode)
        sources = {
            line.split(" source=")[1].split(" ")[0]
            for line in result.stderr.splitlines()
            if line.startswith(f"finding rule={rule_id} ")
        }
        self.assertEqual({"commit"}, sources)
        self.assertValueAbsent(result, COVERED)


class CoverageIsExactlyTheInstalledRulesTests(CommandFixture):
    """What `0 protected rules` means, measured rather than asserted.

    These two run the same command over the same tree and differ only in whether
    a rule covers the identifier that is in it. They are a matched pair: the
    negative result below is only informative because the positive one passes.
    """

    def test_without_protected_rules_a_reintroduction_is_invisible(self) -> None:
        self.reintroduce(COVERED, in_message=False)
        result = self.run_scan()
        self.assertEqual(0, result.returncode)
        self.assertIn("0 protected rules", result.stdout)
        self.assertEqual("", result.stderr)

    def test_with_a_protected_rule_the_same_tree_fails(self) -> None:
        self.reintroduce(COVERED, in_message=False)
        environment, rule_id = protected_environment(COVERED)
        result = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(1, result.returncode)
        self.assertIn(f"rule={rule_id}", result.stderr)


class PushScopeTests(CommandFixture):
    """The two flags the `protected-push-scrub` job runs with."""

    def revision(self, reference: str = "HEAD") -> str:
        return self.git("rev-parse", reference).stdout.decode().strip()

    def test_tree_scope_states_which_question_it_answered(self) -> None:
        result = self.run_scan("--scope", "tree")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(scan.SCOPE_NOTE, result.stdout)
        self.assertIn("currently tracked", result.stdout)
        self.assertIn("0 commit messages", result.stdout)

    def test_full_scope_does_not_carry_the_tree_note(self) -> None:
        self.assertNotIn(scan.SCOPE_NOTE, self.run_scan().stdout)

    def test_a_deleted_value_is_invisible_to_the_push_job_and_visible_to_publication(
        self,
    ) -> None:
        """The honest limit of a push gate, measured rather than asserted.

        This is the pair that justifies keeping `publication-scrub` around: the
        push job cannot see what a clone still exposes, so a green push tick is
        never evidence that a rewrite is unnecessary.
        """
        self.reintroduce(COVERED, in_message=False)
        self.write("doc.md", RETAINED)
        self.git("add", "doc.md")
        self.git("commit", "-q", "-m", "remove the regression")
        environment, rule_id = protected_environment(COVERED)

        pushed = self.run_scan(
            "--require-protected", "--scope", "tree", environment=environment
        )
        self.assertEqual(0, pushed.returncode, pushed.stderr)

        publication = self.run_scan("--require-protected", environment=environment)
        self.assertEqual(1, publication.returncode)
        self.assertIn(f"rule={rule_id}", publication.stderr)
        self.assertValueAbsent(publication, COVERED)

    def test_the_pushed_range_carries_the_commit_message_the_tree_lost(self) -> None:
        base = self.revision()
        self.reintroduce(COVERED, in_message=True)
        tip = self.revision()
        environment, rule_id = protected_environment(COVERED)

        without = self.run_scan(
            "--require-protected", "--scope", "tree", environment=environment
        )
        self.assertEqual(0, without.returncode, without.stderr)

        with_range = self.run_scan(
            "--require-protected",
            "--scope",
            "tree",
            "--commits",
            f"{base}..{tip}",
            environment=environment,
        )
        self.assertEqual(1, with_range.returncode)
        self.assertIn(f"rule={rule_id} source=commit", with_range.stderr)
        self.assertValueAbsent(with_range, COVERED)

    def test_a_range_that_is_not_a_revision_selector_is_a_configuration_error(
        self,
    ) -> None:
        result = self.run_scan("--scope", "tree", "--commits", "main;rm -rf /")
        self.assertEqual(2, result.returncode)
        self.assertIn("revision selector", result.stderr)


class SanctionedHomeCommandTests(CommandFixture):
    """A retained value passes in its home and fails one file over."""

    def test_a_bundle_home_suppresses_the_file_it_names(self) -> None:
        self.write("inventory.md", b"classified: " + COVERED + b"\n")
        self.git("add", "inventory.md")
        self.git("commit", "-q", "-m", "add the sanctioned inventory")
        environment, rule_id = protected_environment(
            COVERED, homes=("inventory.md",)
        )

        exempt = self.run_scan(
            "--require-protected", "--scope", "tree", environment=environment
        )
        self.assertEqual(0, exempt.returncode, exempt.stderr)

        self.write("elsewhere.md", b"copied: " + COVERED + b"\n")
        self.git("add", "elsewhere.md")
        result = self.run_scan(
            "--require-protected", "--scope", "tree", environment=environment
        )
        self.assertEqual(1, result.returncode)
        self.assertIn(
            scan.render_finding(scan.Finding(rule_id, "file", "elsewhere.md", 1)),
            result.stderr,
        )
        self.assertValueAbsent(result, COVERED)

    def test_a_home_naming_no_tracked_file_refuses_the_run(self) -> None:
        environment, _ = protected_environment(COVERED, homes=("inventory.md",))
        result = self.run_scan(
            "--require-protected", "--scope", "tree", environment=environment
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("not a tracked file", result.stderr)
        # The rule ID is nameable; the path came from a secret and is not.
        self.assertNotIn("inventory.md", result.stderr)


if __name__ == "__main__":
    unittest.main()
