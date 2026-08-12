#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import pathlib
import tempfile
import unittest

from tools import check_licenses


class LicenceBoundaryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
