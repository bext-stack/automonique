#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Independent controls for the pure anonymous package verifier."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import anonymous_backup as producer  # noqa: E402
import anonymous_worker as worker  # noqa: E402


def canonical_package() -> bytes:
    backup = producer.produce_anonymous_backup()
    try:
        return os.pread(
            backup.descriptor, backup.receipt.package_size, 0)
    finally:
        os.close(backup.descriptor)


def canonical_json(value: object) -> bytes:
    return (json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ) + "\n").encode("ascii")


def root_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256(
        b"automonique.synthetic-recovery-package/root/v1\0")
    rows = connection.execute(
        "SELECT entry_id,path_name,artifact_class,size,sha256 "
        "FROM entries ORDER BY entry_id").fetchall()
    for row in rows:
        for value in row:
            encoded = str(value).encode()
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def mutate_entry(
    package: bytes,
    entry_id: str,
    payload: bytes,
    *,
    update_entry_digest: bool = True,
    update_root: bool = True,
) -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(package)
        if update_entry_digest:
            connection.execute(
                "UPDATE entries SET payload=?,size=?,sha256=? WHERE entry_id=?",
                (payload, len(payload), hashlib.sha256(payload).hexdigest(), entry_id),
            )
        else:
            connection.execute(
                "UPDATE entries SET payload=? WHERE entry_id=?", (payload, entry_id))
        if update_root:
            connection.execute(
                "UPDATE package_manifest SET root_sha256=?", (root_digest(connection),))
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()


def replace_root(package: bytes, digest: str) -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(package)
        connection.execute(
            "UPDATE package_manifest SET root_sha256=?", (digest,))
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()


class AnonymousWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.package = canonical_package()

    def refuse(
        self, package: bytes, expected: worker.RefusalCode
    ) -> worker.WorkerRefused:
        with self.assertRaises(worker.WorkerRefused) as caught:
            worker.verify_package_bytes(package)
        self.assertIs(caught.exception.code, expected)
        return caught.exception

    def refuse_after_fixed_image_gate(
        self, package: bytes, expected: worker.RefusalCode
    ) -> worker.WorkerRefused:
        """Exercise defense-in-depth semantics behind the singleton byte gate."""
        public_code = (
            worker.RefusalCode.PACKAGE_SIZE_INVALID
            if len(package) != worker.EXPECTED_PACKAGE_SIZE
            else worker.RefusalCode.PACKAGE_DIGEST_INVALID
        )
        self.refuse(package, public_code)
        with (
            mock.patch.object(worker, "EXPECTED_PACKAGE_SIZE", len(package)),
            mock.patch.object(
                worker, "EXPECTED_PACKAGE_SHA256",
                hashlib.sha256(package).hexdigest(),
            ),
        ):
            return self.refuse(package, expected)

    def test_canonical_package_has_closed_non_authorizing_verification(self) -> None:
        verified = worker.verify_package_bytes(self.package)
        self.assertEqual(verified.schema,
                         "automonique.anonymous-worker-verification/v1")
        self.assertEqual(verified.package_sha256,
                         hashlib.sha256(self.package).hexdigest())
        self.assertEqual(len(self.package), worker.EXPECTED_PACKAGE_SIZE)
        self.assertEqual(verified.package_sha256,
                         worker.EXPECTED_PACKAGE_SHA256)
        self.assertEqual(verified.entry_count, 14)
        self.assertEqual(verified.event_count, 4)
        self.assertEqual(verified.artifact_count, 4)
        self.assertEqual(verified.checks, worker.CHECK_NAMES)
        self.assertEqual(
            verified.external_authority, worker.ExternalAuthority())
        self.assertTrue(all(
            value is False
            for value in verified.external_authority.as_document().values()))
        self.assertFalse(verified.launchable)
        self.assertFalse(verified.authorizing)
        self.assertEqual(verified.position_receipts_emitted, ())
        self.assertFalse(verified.recovery_point.objective_eligible)
        document = verified.as_document()
        self.assertEqual(set(document), {
            "schema", "package_sha256", "root_sha256", "package_size",
            "entry_count", "recovery_point", "event_count", "artifact_count",
            "checks", "external_authority", "scope", "launchable",
            "authorizing", "position_receipts_emitted",
        })

    def test_wrong_type_empty_and_oversize_refuse(self) -> None:
        with self.assertRaises(worker.WorkerRefused) as caught:
            worker.verify_package_bytes(bytearray(self.package))  # type: ignore[arg-type]
        self.assertIs(caught.exception.code, worker.RefusalCode.TYPE_INVALID)
        self.refuse(b"", worker.RefusalCode.PACKAGE_SIZE_INVALID)
        self.refuse(
            b"x" * (worker.PACKAGE_LIMIT + 1),
            worker.RefusalCode.PACKAGE_SIZE_INVALID,
        )

    def test_trailing_bytes_and_deleted_secret_free_pages_refuse(self) -> None:
        appended = self.package + b"SECRET_VALUE=trailing-not-logical-sqlite"
        self.assertIn(b"SECRET_VALUE", appended)
        self.refuse(appended, worker.RefusalCode.PACKAGE_SIZE_INVALID)

        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(self.package)
            connection.execute("PRAGMA secure_delete=OFF")
            secret = b"SECRET_VALUE=deleted-but-still-in-free-pages:" + b"x" * 4096
            connection.execute(
                "INSERT INTO entries VALUES (?,?,?,?,?,?)",
                ("temporary-secret", "temporary/secret.bin", "artifact-blob",
                 secret, len(secret), hashlib.sha256(secret).hexdigest()),
            )
            connection.commit()
            connection.execute(
                "DELETE FROM entries WHERE entry_id='temporary-secret'")
            connection.commit()
            deleted = connection.serialize()
        finally:
            connection.close()
        self.assertIn(b"SECRET_VALUE", deleted)
        with self.assertRaises(worker.WorkerRefused) as caught:
            worker.verify_package_bytes(deleted)
        self.assertIn(caught.exception.code, {
            worker.RefusalCode.PACKAGE_SIZE_INVALID,
            worker.RefusalCode.PACKAGE_DIGEST_INVALID,
        })

    def test_secret_credential_with_recomputed_entry_and_root_refuses(self) -> None:
        payload = canonical_json({
            "descriptors": [{
                "audience": "real.example",
                "id": "live-bot",
                "provider": "external",
                "secret": "must-not-cross",
                "version": "v1",
            }],
            "schema": "automonique.synthetic-credential-descriptors/v1",
        })
        candidate = mutate_entry(
            self.package, "synthetic-credential-descriptor", payload)
        refusal = self.refuse_after_fixed_image_gate(
            candidate, worker.RefusalCode.SEMANTIC_INVALID)
        self.assertIn("credential", refusal.detail)

    def test_extra_self_consistent_blob_refuses(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.deserialize(self.package)
        original = connection.execute(
            "SELECT payload FROM entries WHERE entry_id='artifact-blob'").fetchone()[0]
        connection.close()
        document = json.loads(original)
        secret = b"SECRET_VALUE=synthetic-do-not-export"
        document["blobs"].append({
            "payload_hex": secret.hex(),
            "sha256": hashlib.sha256(secret).hexdigest(),
            "size": len(secret),
        })
        candidate = mutate_entry(
            self.package, "artifact-blob", canonical_json(document))
        refusal = self.refuse_after_fixed_image_gate(
            candidate, worker.RefusalCode.SEMANTIC_INVALID)
        self.assertIn("blob set", refusal.detail)

        document = json.loads(original)
        document["secret_value"] = "must-not-cross"
        candidate = mutate_entry(
            self.package, "artifact-blob", canonical_json(document))
        # Public verification rejects at the fixed-image digest before semantic
        # inspection; the exact-key semantic rule remains defense in depth.
        self.refuse_after_fixed_image_gate(
            candidate, worker.RefusalCode.SEMANTIC_INVALID)

    def test_outer_schema_view_and_inner_control_view_refuse(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(self.package)
            connection.execute("CREATE VIEW injected AS SELECT 1 AS value")
            connection.commit()
            outer = connection.serialize()
        finally:
            connection.close()
        self.refuse_after_fixed_image_gate(
            outer, worker.RefusalCode.PACKAGE_SCHEMA_INVALID)

        connection = sqlite3.connect(":memory:")
        connection.deserialize(self.package)
        control = connection.execute(
            "SELECT payload FROM entries WHERE entry_id='control-database'").fetchone()[0]
        connection.close()
        inner_connection = sqlite3.connect(":memory:")
        try:
            inner_connection.deserialize(control)
            inner_connection.execute("CREATE VIEW injected AS SELECT 1 AS value")
            inner_connection.commit()
            inner = inner_connection.serialize()
        finally:
            inner_connection.close()
        candidate = mutate_entry(self.package, "control-database", inner)
        self.refuse_after_fixed_image_gate(
            candidate, worker.RefusalCode.CONTROL_DATABASE_INVALID)

    def test_entry_digest_and_root_digest_mutations_refuse_distinctly(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.deserialize(self.package)
        original = connection.execute(
            "SELECT payload FROM entries WHERE entry_id='policy-bundle-hashes'").fetchone()[0]
        connection.close()
        changed = bytearray(original)
        changed[0] ^= 1
        digest_candidate = mutate_entry(
            self.package,
            "policy-bundle-hashes",
            bytes(changed),
            update_entry_digest=False,
            update_root=False,
        )
        self.refuse_after_fixed_image_gate(
            digest_candidate, worker.RefusalCode.DIGEST_INVALID)
        root_candidate = replace_root(self.package, "0" * 64)
        self.refuse_after_fixed_image_gate(
            root_candidate, worker.RefusalCode.ROOT_DIGEST_INVALID)

    def test_manifest_and_entry_coordinate_mutations_refuse(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(self.package)
            connection.execute(
                "UPDATE package_manifest SET schema='attacker-package/v1'")
            connection.commit()
            manifest = connection.serialize()
        finally:
            connection.close()
        self.refuse_after_fixed_image_gate(
            manifest, worker.RefusalCode.MANIFEST_INVALID)

        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(self.package)
            connection.execute(
                "UPDATE entries SET path_name='credentials/live.json' "
                "WHERE entry_id='synthetic-credential-descriptor'")
            connection.execute(
                "UPDATE package_manifest SET root_sha256=?", (root_digest(connection),))
            connection.commit()
            coordinate = connection.serialize()
        finally:
            connection.close()
        self.refuse_after_fixed_image_gate(
            coordinate, worker.RefusalCode.ENTRY_INVALID)

    def test_every_fixed_authority_definition_is_closed(self) -> None:
        mutations = {
            "disconnected-start-bundle": {
                "mode": "connected", "network_authority": True,
                "provider_authority": True,
            },
            "context-memory-automation": {
                "automations": ["launch"], "context": [], "memory": [],
            },
            "corresponding-source-locks": {
                "dependency_lock_sha256": "1" * 64, "source_sha256": "9" * 64,
            },
            "last-known-good-seed-verifier": {
                "seed_sha256": "3" * 64, "verifier_sha256": "9" * 64,
            },
            "tool-extension-manifests": {
                "extensions": [], "hooks": [], "tools": ["shell"],
            },
            "policy-bundle-hashes": {
                "configuration_revision": 1, "policy_revision": 1,
                "sha256": "5" * 64, "extra": False,
            },
            "release-manifests-schemas": {
                "configuration_revision": 1, "policy_revision": 2,
                "release": "anonymous-v1", "schema_versions": [1],
            },
        }
        for entry_id, document in mutations.items():
            with self.subTest(entry=entry_id):
                candidate = mutate_entry(
                    self.package, entry_id, canonical_json(document))
                self.refuse_after_fixed_image_gate(
                    candidate, worker.RefusalCode.SEMANTIC_INVALID)

    def test_module_is_pure_stdlib_and_has_no_launch_entrypoint(self) -> None:
        source = pathlib.Path(worker.__file__).read_text()
        tree = ast.parse(source)
        imported: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
                elif isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
        self.assertEqual(imported - sys.stdlib_module_names, set())
        self.assertFalse({"execve", "fork", "clone", "system", "popen"} & calls)
        self.assertNotIn("socket", imported)
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("__main__", source)


if __name__ == "__main__":
    unittest.main()
