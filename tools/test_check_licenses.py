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
            self.write("integrations/example.py", "# SPDX-License-Identifier: Apache-2.0\n"),
            self.write("connectors/chat.rs", "// SPDX-License-Identifier: Apache-2.0\n"),
        ]
        self.assertEqual(check_licenses.check_paths(self.root, paths), [])

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

    def roots(self, declared: set[str], *, pending: set[str] = frozenset()):
        return unittest.mock.patch.multiple(
            check_licenses,
            APACHE_ROOTS=declared,
            PENDING_ROOT_DECISION=pending,
        )

    def test_a_root_that_exists_produces_neither_problem_nor_notice(self) -> None:
        self.write("sdk/client.ts", "// SPDX-License-Identifier: Apache-2.0\n")
        with self.roots({"sdk"}):
            self.assertEqual(([], []), check_licenses.check_declared_roots(self.root))

    def test_a_phantom_root_is_a_problem(self) -> None:
        self.write("sdk/client.ts", "// SPDX-License-Identifier: Apache-2.0\n")
        with self.roots({"sdk", "connectors"}):
            problems, notices = check_licenses.check_declared_roots(self.root)
        self.assertEqual([], notices)
        self.assertEqual(1, len(problems))
        self.assertIn("connectors/", problems[0])
        self.assertIn("gates nothing", problems[0])

    def test_a_file_masquerading_as_a_root_is_still_a_problem(self) -> None:
        """`sdk` has to be a directory. A file named `sdk` gates nothing either."""
        (self.root / "connectors").write_text("not a directory\n")
        with self.roots({"connectors"}):
            problems, _ = check_licenses.check_declared_roots(self.root)
        self.assertEqual(1, len(problems))

    def test_a_pending_root_is_a_notice_and_not_a_problem(self) -> None:
        with self.roots({"connectors"}, pending={"connectors"}):
            problems, notices = check_licenses.check_declared_roots(self.root)
        self.assertEqual([], problems)
        self.assertEqual(1, len(notices))
        self.assertIn(check_licenses.PENDING_DECISION_MEMO, notices[0])

    def test_the_pending_set_only_covers_roots_that_are_declared(self) -> None:
        """A stale pending entry must not be able to hide a future root."""
        self.assertLessEqual(
            check_licenses.PENDING_ROOT_DECISION, check_licenses.APACHE_ROOTS
        )

    def test_this_repository_declares_the_roots_it_is_pending_on(self) -> None:
        """The live state, asserted rather than assumed.

        When the owner's decision lands, whichever option it is, this test is
        the one that has to change: either the directories exist, or the roots
        are gone from `APACHE_ROOTS`, and either way `PENDING_ROOT_DECISION`
        empties.
        """
        problems, notices = check_licenses.check_declared_roots(check_licenses.ROOT)
        self.assertEqual([], problems)
        self.assertEqual(
            sorted(check_licenses.PENDING_ROOT_DECISION),
            sorted(
                name
                for name in check_licenses.APACHE_ROOTS
                if not (check_licenses.ROOT / name).is_dir()
            ),
        )
        self.assertEqual(len(check_licenses.PENDING_ROOT_DECISION), len(notices))


if __name__ == "__main__":
    unittest.main()
