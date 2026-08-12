#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Pathless, non-authorizing synthetic online backup package producer."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3

import recovery_artifact as artifact


@dataclasses.dataclass(frozen=True)
class AnonymousBackup:
    descriptor: int
    receipt: artifact.PackageReceipt
    verified: artifact.VerifiedPackage
    concurrent_commit_observed: bool


def produce_anonymous_backup() -> AnonymousBackup:
    """Produce one fixed synthetic online snapshot in memory and seal it."""
    database_uri = f"file:automonique-anonymous-{os.urandom(16).hex()}?mode=memory&cache=shared"
    source = sqlite3.connect(database_uri, uri=True)
    concurrent = sqlite3.connect(database_uri, uri=True)
    target = sqlite3.connect(":memory:")
    fired = False
    try:
        source.executescript(
            "CREATE TABLE artifacts (artifact_index INTEGER PRIMARY KEY, artifact_id TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL) STRICT;"
            "CREATE TABLE events (event_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id), written_ns INTEGER NOT NULL) STRICT;"
        )
        source.execute("PRAGMA foreign_keys=ON")
        concurrent.execute("PRAGMA foreign_keys=ON")
        for index in range(1, 4):
            _commit(concurrent, index)

        def progress(status: int, remaining: int, total: int) -> None:
            nonlocal fired
            if not fired:
                fired = True
                _commit(concurrent, 4)

        source.backup(target, pages=1, progress=progress, sleep=0.0)
        database = target.serialize()
        events = list(target.execute("SELECT event_id,kind,artifact_id,written_ns FROM events ORDER BY event_id"))
        rows = list(target.execute("SELECT artifact_index,artifact_id,sha256,size_bytes FROM artifacts ORDER BY artifact_index"))
        if not fired or [row[0] for row in events] != [1, 2, 3, 4]:
            raise RuntimeError("deterministic concurrent online commit was not snapshotted")
        _commit(concurrent, 5)
        entries = _entries(database, events, rows)
        sealed = artifact._create_sealed_anonymous_package(entries)
        verified = artifact.verify_package_fd(sealed.descriptor)
        if verified.receipt != sealed.receipt:
            os.close(sealed.descriptor)
            raise RuntimeError("sealed publication receipt differs")
        return AnonymousBackup(sealed.descriptor, sealed.receipt, verified, True)
    finally:
        target.close()
        concurrent.close()
        source.close()


def _commit(connection: sqlite3.Connection, index: int) -> None:
    payload = _payload(index)
    digest = hashlib.sha256(payload).hexdigest()
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("INSERT INTO artifacts VALUES (?,?,?,?)", (index, f"artifact-{index:06d}", digest, len(payload)))
    connection.execute("INSERT INTO events VALUES (?,?,?,?)", (index, "artifact_recorded", f"artifact-{index:06d}", index * 1_000_000_000))
    connection.commit()


def _payload(index: int) -> bytes:
    block = hashlib.sha256(f"20260811:{index}".encode()).digest()
    return (block * 5)[:128]


def _entries(database: bytes, events, rows) -> tuple[artifact.ArtifactEntry, ...]:
    blobs = [{"payload_hex": _payload(row[0]).hex(), "sha256": row[2], "size": row[3]} for row in rows]
    config = _json({"configuration_revision": 1, "history": [1], "schema": "automonique.anonymous-config/v1", "secret_values": None})
    members = {"control.db": hashlib.sha256(database).hexdigest(), "config.json": hashlib.sha256(config).hexdigest()}
    for row in rows:
        members[f"blobs/{row[2][:2]}/{row[2]}"] = row[2]
    metadata = {"artifacts": [{"id": row[1], "sha256": row[2], "size": row[3]} for row in rows], "manifest": {"members": members, "schema": "automonique.anonymous-backup-manifest/v1", "watermark_event_id": 4, "watermark_ns": 4_000_000_000}, "profile": "anonymous-online-v1", "tombstones": []}
    replacements = {
        "artifact-metadata": _json(metadata),
        "artifact-blob": _json({"blobs": blobs, "schema": "automonique.anonymous-blobs/v1"}),
        "audit-journal": b"".join(_json({"artifact_id": row[2], "event_id": row[0], "kind": row[1], "written_ns": row[3]}) for row in events),
        "snapshot-metadata": _json({"derived_rpo_seconds": 1.0, "fixed_backup_cadence_seconds": 60, "method": "anonymous-online-backup", "newest_durable_at_loss_unix_ns": 5_000_000_000, "objective_eligible": False, "scope": "anonymous-synthetic", "snapshot_watermark_unix_ns": 4_000_000_000, "watermark_event_id": 4}),
        "control-database": database,
        "configuration-workspaces": config,
        "policy-bundle-hashes": _json({"configuration_revision": 1, "policy_revision": 1, "sha256": "5" * 64}),
        "release-manifests-schemas": _json({"configuration_revision": 1, "policy_revision": 1, "release": "anonymous-v1", "schema_versions": [1]}),
    }
    return tuple(dataclasses.replace(entry, payload=replacements.get(entry.entry_id, entry.payload)) for entry in artifact.canonical_fixture_entries())


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
