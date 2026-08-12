#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Live and structural controls for the disposable recovery boundary."""

from __future__ import annotations

import ast
import errno
import json
import os
import pathlib
import resource
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import clean_boundary as boundary  # noqa: E402


class BoundaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capability = boundary.probe()
        if cls.capability.refusal is not None:
            raise AssertionError(cls.capability.refusal.as_document())
        cls.result = boundary.run_boundary(timeout=5.0)
        if cls.result.outcome is not boundary.Outcome.VERIFIED:
            detail = None if cls.result.refusal is None else cls.result.refusal.as_document()
            raise AssertionError(detail)
        assert cls.result.evidence is not None
        cls.evidence = cls.result.evidence

    def test_atomic_namespace_mask_is_exact_and_reported_by_exec_clean_pid1(self) -> None:
        pinned = {
            "CLONE_NEWUSER": 0x10000000,
            "CLONE_NEWNS": 0x00020000,
            "CLONE_NEWPID": 0x20000000,
            "CLONE_NEWNET": 0x40000000,
            "CLONE_NEWIPC": 0x08000000,
            "CLONE_NEWUTS": 0x04000000,
            "CLONE_NEWCGROUP": 0x02000000,
        }
        expected = 0x7E020000
        self.assertEqual(boundary.NAMESPACE_FLAGS, pinned)
        self.assertEqual(boundary.EXACT_NAMESPACE_FLAGS, expected)
        self.assertEqual(self.evidence["namespace_flags"], expected)
        identities = self.evidence["namespace_identities"]
        self.assertEqual(set(identities), {"parent", "child"})
        for name in boundary.NAMESPACE_NAMES:
            with self.subTest(namespace=name):
                self.assertNotEqual(
                    identities["parent"][name], identities["child"][name]
                )
        self.assertEqual(self.evidence["pid"], 1)
        self.assertEqual(self.evidence["uid"], 0)
        self.assertEqual(boundary._uid_map(os.getuid()), f"0 {os.getuid()} 1\n")
        self.assertIsNone(self.evidence["id_maps"]["gid_map"])
        self.assertEqual(
            self.evidence["id_maps"]["supplementary_groups"],
            self.evidence["supplementary_groups"],
        )

    def test_landlock_abi_and_allow_rules_are_exact(self) -> None:
        self.assertGreaterEqual(self.capability.landlock_abi, boundary.MIN_LANDLOCK_ABI)
        self.assertEqual(self.evidence["landlock_abi"], self.capability.landlock_abi)
        self.assertEqual(
            self.evidence["landlock_allowed_paths"],
            [
                {"path": path.as_posix(), "access": access}
                for path, access in boundary._allow_paths()
            ],
        )
        self.assertNotIn(
            ROOT.as_posix(),
            [rule["path"] for rule in self.evidence["landlock_allowed_paths"]],
        )

    def test_repository_read_is_denied_inside_the_live_boundary(self) -> None:
        self.assertTrue((ROOT / "AGENTS.md").is_file(), "positive host control")
        self.assertTrue(self.evidence["repo_read_denied"])
        self.assertEqual(self.evidence["repo_read_errno"], errno.EACCES)

    def test_privileges_network_and_descriptors_are_closed(self) -> None:
        self.assertEqual(self.evidence["no_new_privs"], 1)
        for capability_set in self.evidence["capabilities"].values():
            self.assertEqual(capability_set, [0, 0])
        self.assertEqual(self.evidence["network_connect_errno"], errno.EACCES)
        self.assertEqual(self.evidence["open_fds"], [boundary.REPORT_FD])
        self.assertEqual(
            self.evidence["environment"],
            ["LC_CTYPE"],
            "execve receives an empty environment; CPython adds only its "
            "locale-coercion marker before the worker begins",
        )
        self.assertTrue(self.result.reaped)
        self.assertEqual(self.result.wait_status, 0)

    def test_report_schema_rejects_minimal_forgery_and_nonzero_exit(self) -> None:
        def collect(document: object, exit_code: int) -> boundary.BoundaryResult:
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                os.write(write_fd, (json.dumps(document) + "\n").encode())
                os.close(write_fd)
                os._exit(exit_code)
            os.close(write_fd)
            try:
                return boundary._wait_report(pid, read_fd, 2.0)
            finally:
                os.close(read_fd)

        minimal = collect({"outcome": "verified"}, 0)
        self.assertIs(minimal.outcome, boundary.Outcome.REFUSED)
        self.assertIs(minimal.refusal.code, boundary.RefusalCode.REPORT_INVALID)
        self.assertEqual(minimal.wait_status, 0)

        exit_seven = collect(self.evidence, 7)
        self.assertIs(exit_seven.outcome, boundary.Outcome.REFUSED)
        self.assertIs(exit_seven.refusal.code, boundary.RefusalCode.REPORT_INVALID)
        self.assertNotEqual(exit_seven.wait_status, 0)

    def test_parent_death_signal_kills_the_protected_child(self) -> None:
        observed = boundary.parent_death_probe(timeout=2.0)
        self.assertTrue(observed["launcher_reaped"])
        self.assertEqual(observed["launcher_wait_status"], 0)
        self.assertTrue(observed["protected_pidfd_readable"])
        self.assertEqual(observed["pdeath_signal"], 9)
        self.assertEqual(self.evidence["parent_death"]["pdeath_signal"], 9)
        self.assertTrue(
            self.evidence["parent_death"]["parent_pidfd_live_after_prctl"]
        )

    def test_high_inherited_fd_is_closed_after_soft_limit_is_lowered(self) -> None:
        old_soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        high_fd = 512
        if hard != resource.RLIM_INFINITY and hard <= high_fd:
            self.skipTest("hard descriptor limit is too low for the control")
        original = os.open("/dev/null", os.O_RDONLY)
        os.dup2(original, high_fd, inheritable=True)
        os.close(original)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
            result = boundary.run_boundary(timeout=5.0)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (old_soft, hard))
            os.close(high_fd)
        self.assertIs(result.outcome, boundary.Outcome.VERIFIED)
        self.assertEqual(result.evidence["open_fds"], [boundary.REPORT_FD])

    def test_missing_parent_control_is_a_typed_fail_closed_refusal(self) -> None:
        result = boundary._launch(
            timeout=2.0,
            send_control=False,
            repository_probe=ROOT / "AGENTS.md",
        )
        self.assertIs(result.outcome, boundary.Outcome.REFUSED)
        self.assertIsNotNone(result.refusal)
        self.assertIs(result.refusal.code, boundary.RefusalCode.CONTROL_MISSING)
        self.assertTrue(result.reaped)
        self.assertIsNotNone(result.wait_status)

    def test_timeout_kills_and_reaps_without_a_fallback(self) -> None:
        result = boundary._launch(
            timeout=0.05,
            send_control=True,
            repository_probe=ROOT / "AGENTS.md",
            test_delay=0.25,
        )
        self.assertIs(result.outcome, boundary.Outcome.REFUSED)
        self.assertIsNotNone(result.refusal)
        self.assertIs(result.refusal.code, boundary.RefusalCode.TIMEOUT)
        self.assertTrue(result.reaped)
        self.assertIsNotNone(result.wait_status)

    def test_the_primitive_imports_only_the_standard_library(self) -> None:
        source = pathlib.Path(boundary.__file__).read_text()
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertEqual(imported - sys.stdlib_module_names, set())
        self.assertNotIn("subprocess", imported)


if __name__ == "__main__":
    unittest.main()
