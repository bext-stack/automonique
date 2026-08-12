#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import dataclasses
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import recovery_artifact as artifact  # noqa: E402


class RecoveryArtifactTests(unittest.TestCase):
    def create(self, root: pathlib.Path, name: str = "recovery.sqlite"):
        path = root / name
        receipt = artifact.create_package(path, artifact.canonical_fixture_entries())
        return path, receipt

    def verify(self, path: pathlib.Path):
        descriptor = artifact.open_package(path)
        try:
            return artifact.verify_package_fd(descriptor)
        finally:
            os.close(descriptor)

    def test_canonical_fixture_round_trips_with_both_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, created = self.create(pathlib.Path(directory))
            verified = self.verify(path)
            self.assertEqual(verified.receipt, created)
            self.assertEqual(len(verified.entries), len(artifact.REQUIRED_ENTRIES))
            self.assertEqual({entry.entry_id for entry in verified.entries}, set(artifact.REQUIRED_BY_ID))
            credential = next(entry for entry in verified.entries if entry.artifact_class is artifact.ArtifactClass.CREDENTIAL_DESCRIPTOR)
            for forbidden in (b"token", b"password", b"secret", b"ciphertext"):
                self.assertNotIn(forbidden, credential.payload.lower())
            self.assertEqual(verified.recovery_point.derived_rpo_seconds, 60.0)
            self.assertEqual(verified.recovery_point.scope, "synthetic-fixture")
            self.assertFalse(verified.recovery_point.objective_eligible)

    def test_creation_is_byte_deterministic_and_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first, first_receipt = self.create(root, "first.sqlite")
            second, second_receipt = self.create(root, "second.sqlite")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_receipt.root_sha256, second_receipt.root_sha256)
            self.assertEqual(first_receipt.package_sha256, second_receipt.package_sha256)

    def test_duplicate_missing_extra_and_traversal_are_distinct(self) -> None:
        entries = artifact.canonical_fixture_entries()
        cases = (
            (entries + (entries[0],), artifact.ArtifactRefusal.DUPLICATE_ENTRY),
            (entries[:-1], artifact.ArtifactRefusal.MISSING_ENTRY),
            (entries + (dataclasses.replace(entries[0], entry_id="extra"),), artifact.ArtifactRefusal.DUPLICATE_ENTRY),
            ((dataclasses.replace(entries[0], path_name="../escape"), *entries[1:]), artifact.ArtifactRefusal.INVALID_ENTRY),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index, (candidate, refusal) in enumerate(cases):
                with self.subTest(refusal=refusal):
                    with self.assertRaises(artifact.ArtifactRefused) as caught:
                        artifact.create_package(root / f"case-{index}", candidate)
                    self.assertIs(caught.exception.refusal, refusal)

    def test_missing_and_true_extra_entry_refuse(self) -> None:
        entries = artifact.canonical_fixture_entries()
        extra = artifact.ArtifactEntry("extra", "extra/data", artifact.ArtifactClass.CONFIGURATION, b"x")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(artifact.ArtifactRefused) as caught:
                artifact.create_package(pathlib.Path(directory) / "extra.sqlite", entries + (extra,))
            self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.EXTRA_ENTRY)

    def test_wrong_entry_types_and_non_regular_descriptor_refuse(self) -> None:
        entries = artifact.canonical_fixture_entries()
        malformed = dataclasses.replace(entries[0], payload=bytearray(b"not-bytes"))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(artifact.ArtifactRefused) as caught:
                artifact.create_package(pathlib.Path(directory) / "typed.sqlite", (malformed, *entries[1:]))
            self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.INVALID_ENTRY)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    artifact.verify_package_fd(directory_fd)
                self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.SYMLINK_OR_TYPE)
            finally:
                os.close(directory_fd)

    def test_credential_value_and_non_invalid_audience_refuse(self) -> None:
        entries = artifact.canonical_fixture_entries()
        index = next(i for i, entry in enumerate(entries) if entry.artifact_class is artifact.ArtifactClass.CREDENTIAL_DESCRIPTOR)
        for payload in (
            b'{"descriptors":[{"audience":"real.example","id":"fixture","provider":"synthetic","version":"v1"}],"schema":"automonique.synthetic-credential-descriptors/v1"}\n',
            b'{"descriptors":[{"audience":"fixture.invalid","id":"fixture","provider":"synthetic","secret":"value","version":"v1"}],"schema":"automonique.synthetic-credential-descriptors/v1"}\n',
        ):
            candidate = list(entries)
            candidate[index] = dataclasses.replace(candidate[index], payload=payload)
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    artifact.create_package(pathlib.Path(directory) / "credential.sqlite", tuple(candidate))
                self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.INVALID_CREDENTIAL_DESCRIPTOR)

    def test_final_and_parent_symlinks_are_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            outside = root / "outside"
            outside.mkdir()
            final = root / "final.sqlite"
            final.symlink_to(outside / "target.sqlite")
            with self.assertRaises(artifact.ArtifactRefused):
                artifact.create_package(final, artifact.canonical_fixture_entries())
            alias = root / "alias"
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(artifact.ArtifactRefused) as caught:
                artifact.create_package(alias / "escaped.sqlite", artifact.canonical_fixture_entries())
            self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.SYMLINK_OR_TYPE)
            self.assertFalse((outside / "escaped.sqlite").exists())

    def test_already_open_descriptor_ignores_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path, receipt = self.create(root)
            descriptor = artifact.open_package(path)
            replacement, _ = self.create(root, "replacement.sqlite")
            path.rename(root / "pinned.sqlite")
            replacement.rename(path)
            try:
                self.assertEqual(artifact.verify_package_fd(descriptor).receipt, receipt)
            finally:
                os.close(descriptor)

    def test_entry_byte_mutation_and_manifest_digest_mutation_refuse(self) -> None:
        for statement, refusal in (
            ("UPDATE entries SET payload = X'00', size = 1 WHERE entry_id = 'artifact-blob'", artifact.ArtifactRefusal.DIGEST_MISMATCH),
            ("UPDATE package_manifest SET root_sha256 = printf('%064d', 0)", artifact.ArtifactRefusal.DIGEST_MISMATCH),
        ):
            with tempfile.TemporaryDirectory() as directory:
                path, _ = self.create(pathlib.Path(directory))
                connection = sqlite3.connect(path)
                connection.execute(statement)
                connection.commit()
                connection.close()
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    self.verify(path)
                self.assertIs(caught.exception.refusal, refusal)

    def test_cross_entry_coordinate_drift_refuses_before_publication(self) -> None:
        mutations = (
            ("artifact-metadata", {"artifacts": [{"id": "fixture", "sha256": "0" * 64}], "tombstones": [{"id": "deleted-fixture", "revision": 1}]}),
            ("configuration-workspaces", {"configuration_revision": 2, "workspaces": [{"id": "fixture-workspace", "revision": 1}]}),
            ("policy-bundle-hashes", {"configuration_revision": 1, "policy_revision": 2, "sha256": "5" * 64}),
            ("release-manifests-schemas", {"configuration_revision": 1, "policy_revision": 1, "release": "synthetic-v1", "required_credential_descriptors": [{"audience": "recovery-fixture.invalid", "id": "other", "version": "v1"}], "schema_versions": [1]}),
            ("snapshot-metadata", {"derived_rpo_seconds": 0.0, "fixed_backup_cadence_seconds": 60, "method": "synthetic-package-fixture", "newest_durable_at_loss_unix_ns": 61_000_000_000, "objective_eligible": False, "scope": "synthetic-fixture", "snapshot_watermark_unix_ns": 1_000_000_000, "watermark_event_id": 2}),
        )
        for entry_id, document in mutations:
            with self.subTest(entry_id=entry_id), tempfile.TemporaryDirectory() as directory:
                entries = list(artifact.canonical_fixture_entries())
                index = next(i for i, entry in enumerate(entries) if entry.entry_id == entry_id)
                entries[index] = dataclasses.replace(entries[index], payload=artifact._json(document))
                path = pathlib.Path(directory) / "drift.sqlite"
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    artifact.create_package(path, tuple(entries))
                self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.SEMANTIC_MISMATCH)
                self.assertFalse(path.exists())

    def test_noncanonical_state_secret_authority_and_journal_shapes_refuse(self) -> None:
        mutations = (
            ("context-memory-automation", {"api_token": "live-looking-value"}),
            ("corresponding-source-locks", b"not-json\n"),
            (
                "disconnected-start-bundle",
                {
                    "mode": "connected",
                    "network_authority": True,
                    "provider_authority": True,
                },
            ),
            ("audit-journal", b'{"event_id":1,"event_id":2}\n'),
        )
        for entry_id, value in mutations:
            with self.subTest(entry_id=entry_id), tempfile.TemporaryDirectory() as directory:
                entries = list(artifact.canonical_fixture_entries())
                index = next(i for i, entry in enumerate(entries) if entry.entry_id == entry_id)
                payload = value if isinstance(value, bytes) else artifact._json(value)
                entries[index] = dataclasses.replace(entries[index], payload=payload)
                path = pathlib.Path(directory) / "noncanonical.sqlite"
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    artifact.create_package(path, tuple(entries))
                self.assertIs(
                    caught.exception.refusal,
                    artifact.ArtifactRefusal.SEMANTIC_MISMATCH,
                )
                self.assertFalse(path.exists())

    def test_schema_version_extra_table_and_malformed_class_refuse(self) -> None:
        cases = (
            ("PRAGMA user_version = 2", artifact.ArtifactRefusal.SCHEMA_MISMATCH),
            ("CREATE TABLE injected (value TEXT) STRICT", artifact.ArtifactRefusal.SCHEMA_MISMATCH),
            ("UPDATE entries SET artifact_class = 'unknown' WHERE entry_id = 'artifact-blob'", artifact.ArtifactRefusal.INVALID_ENTRY),
        )
        for statement, refusal in cases:
            with tempfile.TemporaryDirectory() as directory:
                path, _ = self.create(pathlib.Path(directory))
                connection = sqlite3.connect(path)
                connection.execute(statement)
                connection.commit()
                connection.close()
                with self.assertRaises(artifact.ArtifactRefused) as caught:
                    self.verify(path)
                self.assertIs(caught.exception.refusal, refusal)

    def test_creation_never_overwrites_an_existing_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, receipt = self.create(pathlib.Path(directory))
            before = path.read_bytes()
            with self.assertRaises(artifact.ArtifactRefused) as caught:
                artifact.create_package(path, artifact.canonical_fixture_entries())
            self.assertIs(caught.exception.refusal, artifact.ArtifactRefusal.ALREADY_EXISTS)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(self.verify(path).receipt, receipt)
            self.assertEqual([item.name for item in path.parent.iterdir()], [path.name])


if __name__ == "__main__":
    unittest.main()
