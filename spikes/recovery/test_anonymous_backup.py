#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import dataclasses
import concurrent.futures
import fcntl
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import anonymous_backup as anonymous  # noqa: E402
import recovery_artifact as artifact  # noqa: E402


class AnonymousBackupTests(unittest.TestCase):
    def produce(self):
        item = anonymous.produce_anonymous_backup()
        self.addCleanup(os.close, item.descriptor)
        return item

    def test_online_snapshot_is_sealed_verified_and_objective_ineligible(self) -> None:
        item = self.produce()
        self.assertTrue(item.concurrent_commit_observed)
        self.assertTrue(artifact.attest_package_seals(item.descriptor))
        self.assertEqual(item.receipt, item.verified.receipt)
        self.assertEqual(item.verified.recovery_point.derived_rpo_seconds, 1.0)
        self.assertFalse(item.verified.recovery_point.objective_eligible)

    def test_exact_seals_prevent_write_grow_shrink_and_seal_changes(self) -> None:
        item = self.produce()
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        self.assertEqual(fcntl.fcntl(item.descriptor, fcntl.F_GET_SEALS), required)
        with self.assertRaises(OSError):
            os.pwrite(item.descriptor, b"x", 0)
        with self.assertRaises(OSError):
            os.ftruncate(item.descriptor, item.receipt.package_size + 1)
        unsealed = os.memfd_create("unsealed-copy", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, unsealed)
        os.write(unsealed, os.pread(item.descriptor, item.receipt.package_size, 0))
        with self.assertRaises(artifact.ArtifactRefused):
            artifact.verify_package_fd(unsealed)

    def test_repeated_production_has_exact_snapshot_coordinates(self) -> None:
        first = self.produce()
        second = self.produce()
        self.assertEqual(first.receipt, second.receipt)
        journal = next(entry.payload for entry in first.verified.entries if entry.entry_id == "audit-journal")
        self.assertEqual([json.loads(line)["event_id"] for line in journal.splitlines()], [1, 2, 3, 4])

    def test_twenty_concurrent_producers_are_isolated_and_byte_identical(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            produced = list(executor.map(lambda _: anonymous.produce_anonymous_backup(), range(20)))
        try:
            self.assertEqual(len({item.receipt for item in produced}), 1)
            self.assertTrue(all(item.concurrent_commit_observed for item in produced))
            self.assertTrue(all(artifact.attest_package_seals(item.descriptor) for item in produced))
        finally:
            for item in produced:
                os.close(item.descriptor)

    def test_arbitrary_blob_and_extra_manifest_member_refuse(self) -> None:
        item = self.produce()
        entries = list(item.verified.entries)
        for entry_id, mutate in (
            ("artifact-blob", lambda doc: doc["blobs"][0].update(payload_hex="00" * 128, sha256="0" * 64)),
            ("artifact-metadata", lambda doc: doc["manifest"]["members"].update({"extra": "0" * 64})),
        ):
            candidate = list(entries)
            index = next(i for i, entry in enumerate(candidate) if entry.entry_id == entry_id)
            document = json.loads(candidate[index].payload)
            mutate(document)
            candidate[index] = dataclasses.replace(candidate[index], payload=anonymous._json(document))
            with self.assertRaises(artifact.ArtifactRefused):
                artifact._create_sealed_anonymous_package(tuple(candidate))

    def test_unreferenced_secret_shaped_blob_refuses(self) -> None:
        item = self.produce()
        entries = list(item.verified.entries)
        index = next(i for i, entry in enumerate(entries) if entry.entry_id == "artifact-blob")
        document = json.loads(entries[index].payload)
        payload = b"token=synthetic-do-not-export"
        digest = hashlib.sha256(payload).hexdigest()
        document["blobs"].append({"payload_hex": payload.hex(), "sha256": digest, "size": len(payload)})
        entries[index] = dataclasses.replace(entries[index], payload=anonymous._json(document))
        with self.assertRaises(artifact.ArtifactRefused) as caught:
            artifact._create_sealed_anonymous_package(tuple(entries))
        self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.SEMANTIC_MISMATCH)

    def test_extra_schema_and_closed_policy_field_refuse(self) -> None:
        item = self.produce()
        entries = list(item.verified.entries)
        database_index = next(i for i, entry in enumerate(entries) if entry.entry_id == "control-database")
        connection = sqlite3.connect(":memory:")
        connection.deserialize(entries[database_index].payload)
        connection.execute("CREATE VIEW injected AS SELECT 1 AS value")
        database = connection.serialize()
        connection.close()
        candidate = list(entries)
        candidate[database_index] = dataclasses.replace(candidate[database_index], payload=database)
        with self.assertRaises(artifact.ArtifactRefused):
            artifact._create_sealed_anonymous_package(tuple(candidate))
        policy_index = next(i for i, entry in enumerate(entries) if entry.entry_id == "policy-bundle-hashes")
        policy = json.loads(entries[policy_index].payload)
        policy["extra"] = False
        candidate = list(entries)
        candidate[policy_index] = dataclasses.replace(candidate[policy_index], payload=anonymous._json(policy))
        with self.assertRaises(artifact.ArtifactRefused):
            artifact._create_sealed_anonymous_package(tuple(candidate))

    def test_wrong_cadence_and_loss_endpoint_refuse(self) -> None:
        item = self.produce()
        entries = list(item.verified.entries)
        index = next(i for i, entry in enumerate(entries) if entry.entry_id == "snapshot-metadata")
        for key, value in (("fixed_backup_cadence_seconds", 61), ("newest_durable_at_loss_unix_ns", 6_000_000_000)):
            document = json.loads(entries[index].payload)
            document[key] = value
            candidate = list(entries)
            candidate[index] = dataclasses.replace(candidate[index], payload=anonymous._json(document))
            with self.assertRaises(artifact.ArtifactRefused):
                artifact._create_sealed_anonymous_package(tuple(candidate))


if __name__ == "__main__":
    unittest.main()
