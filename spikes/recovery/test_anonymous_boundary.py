#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import resource
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import anonymous_backup as producer  # noqa: E402
import anonymous_boundary as boundary  # noqa: E402


def produced():
    item = producer.produce_anonymous_backup()
    return item.descriptor, item.receipt


def sealed(payload: bytes) -> int:
    descriptor = os.memfd_create(
        "boundary-negative", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(descriptor, payload)
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, boundary.REQUIRED_SEALS)
    return descriptor


class AnonymousBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        descriptor, receipt = produced()
        try:
            cls.result = boundary.run(descriptor, receipt, timeout=5)
        finally:
            os.close(descriptor)
        if cls.result.outcome is not boundary.Outcome.MECHANISM_VERIFIED:
            raise AssertionError(cls.result.as_document())
        assert cls.result.evidence is not None
        cls.evidence = cls.result.evidence

    def test_canonical_launch_binds_every_trust_coordinate(self) -> None:
        self.assertTrue(self.result.reaped)
        self.assertEqual(self.result.wait_status, 0)
        self.assertEqual(self.evidence["worker_sha256"],
                         boundary.PINNED_WORKER_SHA256)
        self.assertEqual(self.evidence["worker_git_blob"],
                         boundary.PINNED_WORKER_GIT_BLOB)
        self.assertEqual(self.evidence["worker_base_commit"],
                         boundary.PINNED_BASE_COMMIT)
        self.assertEqual(self.evidence["worker_seals"], boundary.REQUIRED_SEALS)
        self.assertEqual(self.evidence["package_seals"], boundary.REQUIRED_SEALS)
        verification = self.evidence["verification"]
        self.assertFalse(verification["launchable"])
        self.assertFalse(verification["authorizing"])
        self.assertEqual(verification["position_receipts_emitted"], [])
        self.assertEqual(verification["event_count"], 4)
        self.assertEqual(verification["artifact_count"], 4)
        self.assertFalse(self.evidence["objective_eligible"])
        self.assertFalse(self.evidence["rto_objective_eligible"])

    def test_namespace_privilege_repository_network_and_fds_are_closed(self) -> None:
        self.assertEqual(self.evidence["pid"], 1)
        self.assertEqual(self.evidence["uid"], 0)
        self.assertEqual(self.evidence["no_new_privs"], 1)
        self.assertTrue(all(not any(words)
                            for words in self.evidence["capabilities"].values()))
        self.assertEqual(self.evidence["repo_read_errno"], 13)
        self.assertEqual(self.evidence["network_connect_errno"], 13)
        self.assertEqual(self.evidence["open_fds"], [3, 4, 5])
        self.assertGreater(self.evidence["mechanism_seconds"], 0)

    def test_working_tree_substitution_and_pinned_constant_changes_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / boundary.PINNED_WORKER_RELATIVE
            target.parent.mkdir(parents=True)
            target.write_bytes(
                (boundary.ROOT / boundary.PINNED_WORKER_RELATIVE).read_bytes()
                .replace(b"Pure verifier", b"Evil verifier", 1))
            with self.assertRaises(ValueError):
                boundary._read_pinned_worker(root)

        descriptor, receipt = produced()
        try:
            with mock.patch.object(boundary, "PINNED_WORKER_SHA256", "0" * 64):
                result = boundary.run(descriptor, receipt)
        finally:
            os.close(descriptor)
        self.assertIs(result.refusal.code,
                      boundary.RefusalCode.WORKER_SOURCE_INVALID)

        descriptor, receipt = produced()
        try:
            with mock.patch.object(boundary, "PINNED_WORKER_SIZE", 1):
                result = boundary.run(descriptor, receipt)
        finally:
            os.close(descriptor)
        self.assertIs(result.refusal.code,
                      boundary.RefusalCode.WORKER_SOURCE_INVALID)

    def test_package_substitution_unsealed_and_receipt_substitution_refuse(self) -> None:
        descriptor, receipt = produced()
        image = os.pread(descriptor, receipt.package_size, 0)
        os.close(descriptor)
        mutated = bytearray(image); mutated[100] ^= 1
        candidate = sealed(bytes(mutated))
        try:
            result = boundary.run(candidate, receipt)
        finally:
            os.close(candidate)
        self.assertIs(result.refusal.code, boundary.RefusalCode.PACKAGE_INVALID)

        unsealed = os.memfd_create(
            "unsealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.write(unsealed, image)
        try:
            result = boundary.run(unsealed, receipt)
        finally:
            os.close(unsealed)
        self.assertIs(result.refusal.code, boundary.RefusalCode.PACKAGE_INVALID)

        descriptor, receipt = produced()
        bad = boundary.recovery_artifact.PackageReceipt(
            receipt.schema, "0" * 64, receipt.package_sha256,
            receipt.package_size, receipt.entry_count)
        try:
            result = boundary.run(descriptor, bad)
        finally:
            os.close(descriptor)
        self.assertIs(result.refusal.code, boundary.RefusalCode.RECEIPT_INVALID)

    def test_forged_report_and_nonzero_exit_refuse(self) -> None:
        for exit_code in (0, 7):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                os.write(write_fd,
                         b'{"outcome":"anonymous_recovery_mechanism_verified",'
                         b'"evidence":{}}\n')
                os.close(write_fd)
                os._exit(exit_code)
            os.close(write_fd)
            result = boundary._collect(pid, read_fd, 2, {})
            self.assertIs(result.refusal.code,
                          boundary.RefusalCode.REPORT_INVALID)
            self.assertTrue(result.reaped)

    def test_timeout_reaps_and_parent_death_is_proven(self) -> None:
        descriptor, receipt = produced()
        try:
            result = boundary.run(
                descriptor, receipt, timeout=0.05, _test_delay=0.25)
        finally:
            os.close(descriptor)
        self.assertIs(result.refusal.code, boundary.RefusalCode.TIMEOUT)
        self.assertTrue(result.reaped)
        death = boundary.parent_death_probe()
        self.assertTrue(death["launcher_reaped"])
        self.assertTrue(death["protected_pidfd_readable"])

    def test_high_inherited_fd_is_closed(self) -> None:
        old_soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        high_fd = 512
        if hard != resource.RLIM_INFINITY and hard <= high_fd:
            self.skipTest("hard descriptor limit too low")
        source = os.open("/dev/null", os.O_RDONLY)
        os.dup2(source, high_fd, inheritable=True); os.close(source)
        descriptor, receipt = produced()
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
            result = boundary.run(descriptor, receipt, timeout=5)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (old_soft, hard))
            os.close(descriptor); os.close(high_fd)
        self.assertIs(result.outcome, boundary.Outcome.MECHANISM_VERIFIED)
        self.assertEqual(result.evidence["open_fds"], [3, 4, 5])

    def test_worker_memfd_is_kernel_immutable(self) -> None:
        payload, _ = boundary._read_pinned_worker()
        descriptor, identity = boundary._sealed_memfd("worker-test", payload)
        try:
            self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS),
                             boundary.REQUIRED_SEALS)
            self.assertEqual(identity["size"], boundary.PINNED_WORKER_SIZE)
            with self.assertRaises(OSError):
                os.pwrite(descriptor, b"x", 0)
            with self.assertRaises(OSError):
                os.ftruncate(descriptor, 0)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
