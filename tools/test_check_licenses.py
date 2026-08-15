#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import pathlib
import tempfile
import unittest
import unittest.mock

from tools import check_licenses


class TemporaryTreeFixture(unittest.TestCase):
    """An empty tree the checker can be pointed at."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, text: str) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class LicenceBoundaryTests(TemporaryTreeFixture):
    def test_product_and_apache_roots_accept_their_licences(self) -> None:
        paths = [
            self.write("rust/src/lib.rs", "// SPDX-License-Identifier: Elastic-2.0\n"),
            self.write("sdk/client.ts", "// SPDX-License-Identifier: Apache-2.0\n"),
            # A connector is product code under `rust/crates/`, not a root of
            # its own — the 2026-08-15 decision. It is Elastic-2.0 like the rest
            # of the daemon it is built for.
            self.write(
                "rust/crates/automonique-slack-connector/src/lib.rs",
                "// SPDX-License-Identifier: Elastic-2.0\n",
            ),
        ]
        self.assertEqual(check_licenses.check_paths(self.root, paths), [])

    def test_a_connector_carrying_apache_is_refused(self) -> None:
        """The boundary has to refuse the licence the documents used to promise."""
        path = self.write(
            "rust/crates/automonique-support-connector/src/lib.rs",
            "// SPDX-License-Identifier: Apache-2.0\n",
        )
        problems = check_licenses.check_paths(self.root, [path])
        self.assertEqual(1, len(problems))
        self.assertIn("expected Elastic-2.0", problems[0])

    def test_missing_and_wrong_identifiers_are_refused(self) -> None:
        paths = [
            self.write("rust/src/lib.rs", "fn main() {}\n"),
            self.write("sdk/client.ts", "// SPDX-License-Identifier: Elastic-2.0\n"),
        ]
        problems = check_licenses.check_paths(self.root, paths)
        self.assertEqual(len(problems), 2)
        self.assertIn("missing SPDX-License-Identifier: Elastic-2.0", problems[0])
        self.assertIn("expected Apache-2.0", problems[1])

    def test_non_source_files_are_ignored(self) -> None:
        path = self.write("sdk/fixture.bin", "no header")
        self.assertEqual(check_licenses.check_paths(self.root, [path]), [])


class DeclaredRootTests(TemporaryTreeFixture):
    """A declared root that does not exist gates nothing, and must say so.

    The negative control this suite was missing: every test above passes just
    as well when `APACHE_ROOTS` names a directory that is not in the tree,
    because a rule about paths cannot be exercised by paths that do not exist.
    """

    def roots(self, declared: set[str]):
        return unittest.mock.patch.object(check_licenses, "APACHE_ROOTS", declared)

    def test_a_root_that_exists_produces_no_problem(self) -> None:
        self.write("sdk/client.ts", "// SPDX-License-Identifier: Apache-2.0\n")
        with self.roots({"sdk"}):
            self.assertEqual([], check_licenses.check_declared_roots(self.root))

    def test_a_phantom_root_is_a_problem(self) -> None:
        self.write("sdk/client.ts", "// SPDX-License-Identifier: Apache-2.0\n")
        with self.roots({"sdk", "connectors"}):
            problems = check_licenses.check_declared_roots(self.root)
        self.assertEqual(1, len(problems))
        self.assertIn("connectors/", problems[0])
        self.assertIn("gates nothing", problems[0])

    def test_a_file_masquerading_as_a_root_is_still_a_problem(self) -> None:
        """`sdk` has to be a directory. A file named `sdk` gates nothing either."""
        (self.root / "connectors").write_text("not a directory\n")
        with self.roots({"connectors"}):
            self.assertEqual(1, len(check_licenses.check_declared_roots(self.root)))

    def test_this_repository_declares_only_roots_that_exist(self) -> None:
        """The live state, asserted rather than assumed.

        The 2026-08-15 decision settled this: `sdk/` is the only Apache root,
        the connectors stay Elastic-2.0, and the two roots that never existed
        are gone. Nothing is pending, so a phantom root is now a plain failure
        with no exemption to route it through.
        """
        self.assertEqual([], check_licenses.check_declared_roots(check_licenses.ROOT))
        for name in check_licenses.APACHE_ROOTS:
            self.assertTrue((check_licenses.ROOT / name).is_dir(), name)

    def test_the_connector_crates_are_not_under_an_apache_root(self) -> None:
        """The decision's substance, not just its bookkeeping.

        Option 2 kept the connectors Elastic-2.0 where they already were. If one
        is ever moved below an Apache root, that is the deliberate relicensing
        `LICENSE-POLICY.md` reserves for owner review, and it should fail here
        first.
        """
        crates = check_licenses.ROOT / "rust/crates"
        connectors = sorted(crates.glob("*-connector"))
        self.assertTrue(connectors, "no connector crates found to check")
        for crate in connectors:
            relative = crate.relative_to(check_licenses.ROOT)
            self.assertNotIn(relative.parts[0], check_licenses.APACHE_ROOTS)
            self.assertEqual(
                "Elastic-2.0", check_licenses.expected_identifier(relative)
            )


if __name__ == "__main__":
    unittest.main()
