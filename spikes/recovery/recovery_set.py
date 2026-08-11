#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The synthetic recovery set the R0-10 baseline recovery drill operates on.

`docs/product-plan/requirements/operations-and-governance.md` § Backup and
disaster recovery names one consistent recovery set. This module models that
set at fixture scale with the three components whose *coherence rules* can be
proven locally:

- a SQLite control database that also carries the audit journal;
- a content-addressed artifact blob store;
- a non-secret configuration revision file.

Everything the fixture contains is derived from a fixed seed. Nothing here
reads a production system, an environment variable, a credential, or the live
repository, and nothing here opens a socket.

Two ordering rules make a coherent point in time provable rather than assumed:

1. **blob before row** — an artifact's bytes are durable before the row that
   references them commits, so any committed row's blob already exists;
2. **config file before setting** — a configuration revision is durable in the
   file before the database records that it is current, so a database snapshot
   never names a revision the file has not reached.

The backup then takes the *database* snapshot first and derives the blob set
and the configuration file from it. A backup that copies the components in any
other order can hold a row whose blob it never copied — which is the failure
`Fault.NAIVE_BACKUP` reproduces deliberately in `drill.py`.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

BLOB_BYTES = 128
CONFIG_EVERY = 8
MANIFEST_SCHEMA = "automonique.recovery.backup-manifest.v1"


class DependencyKind(enum.Enum):
    """Closed vocabulary for what a restore depends on."""

    DATABASE = "database"
    ARTIFACT_BLOB_STORE = "artifact_blob_store"
    AUDIT_JOURNAL = "audit_journal"
    CONFIG_REVISION = "config_revision"
    KEY_MATERIAL = "key_material"
    RELEASE_MANIFEST = "release_manifest"
    RUNTIME = "runtime"
    SERVICE_DEFINITION = "service_definition"
    HOST = "host"


class DependencySource(enum.Enum):
    """Where a restore obtains the dependency from."""

    BACKUP_ARTIFACT = "backup_artifact"
    ESCROWED_KEY = "escrowed_key"
    EXTERNAL_PROVIDER = "external_provider"
    HOST_PROVISIONING = "host_provisioning"


class Verification(enum.Enum):
    """How the restore proves the dependency arrived intact."""

    SHA256 = "sha256"
    SQLITE_INTEGRITY_CHECK = "sqlite_integrity_check"
    REFERENTIAL_INVARIANT = "referential_invariant"
    NONE_DECLARED = "none_declared"


class Exercise(enum.Enum):
    """Whether *this* drill exercises the dependency, or only names it."""

    DRILLED = "drilled"
    NOT_DRILLED = "not_drilled"


class Invariant(enum.Enum):
    """The coherence rules a restored recovery set must satisfy."""

    TARGET_MATCHES_MANIFEST = "target_matches_manifest"
    DATABASE_INTEGRITY = "database_integrity"
    EVENT_COUNTER_AGREEMENT = "event_counter_agreement"
    WATERMARK_AGREEMENT = "watermark_agreement"
    ARTIFACT_ROW_HAS_BLOB = "artifact_row_has_blob"
    BLOB_HASH_MATCHES_ROW = "blob_hash_matches_row"
    NO_ORPHAN_BLOB = "no_orphan_blob"
    CONFIG_REVISION_PRESENT = "config_revision_present"


@dataclass(frozen=True)
class Dependency:
    """One entry of the restore dependency list, in restore order."""

    id: str
    order: int
    kind: DependencyKind
    source: DependencySource
    verified_by: Verification
    exercised: Exercise
    owner_class: str
    note: str

    def as_document(self) -> dict[str, object]:
        return {
            "id": self.id,
            "order": self.order,
            "kind": self.kind.value,
            "source": self.source.value,
            "verified_by": self.verified_by.value,
            "exercised": self.exercised.value,
            "owner_class": self.owner_class,
            "note": self.note,
        }


# The dependency list this drill needs in order to restore, in restore order.
# `DRILLED` entries are the ones the local drill actually restores and verifies.
# `NOT_DRILLED` entries are the ones a real clean-host drill would add; they are
# named here so the gap is enumerated rather than implied.
RESTORE_DEPENDENCIES: tuple[Dependency, ...] = (
    Dependency(
        id="host",
        order=1,
        kind=DependencyKind.HOST,
        source=DependencySource.HOST_PROVISIONING,
        verified_by=Verification.NONE_DECLARED,
        exercised=Exercise.NOT_DRILLED,
        owner_class="platform-operations",
        note="a disposable host of the declared class, provisioned empty; the "
             "local drill substitutes an empty directory and therefore measures "
             "no provisioning cost",
    ),
    Dependency(
        id="runtime",
        order=2,
        kind=DependencyKind.RUNTIME,
        source=DependencySource.HOST_PROVISIONING,
        verified_by=Verification.NONE_DECLARED,
        exercised=Exercise.NOT_DRILLED,
        owner_class="platform-operations",
        note="the release runtime and its pinned dependencies; the local drill "
             "reuses the running interpreter and therefore proves nothing about "
             "runtime installation",
    ),
    Dependency(
        id="release-manifest",
        order=3,
        kind=DependencyKind.RELEASE_MANIFEST,
        source=DependencySource.BACKUP_ARTIFACT,
        verified_by=Verification.SHA256,
        exercised=Exercise.NOT_DRILLED,
        owner_class="release-engineering",
        note="current and previous release manifests, schemas and compatibility "
             "metadata; the fixture carries no release identity to restore",
    ),
    Dependency(
        id="control-database",
        order=4,
        kind=DependencyKind.DATABASE,
        source=DependencySource.BACKUP_ARTIFACT,
        verified_by=Verification.SQLITE_INTEGRITY_CHECK,
        exercised=Exercise.DRILLED,
        owner_class="control-plane",
        note="the SQLite control database, snapshotted online; the snapshot "
             "defines the recovery point every other component is filtered by",
    ),
    Dependency(
        id="audit-journal",
        order=5,
        kind=DependencyKind.AUDIT_JOURNAL,
        source=DependencySource.BACKUP_ARTIFACT,
        verified_by=Verification.REFERENTIAL_INVARIANT,
        exercised=Exercise.DRILLED,
        owner_class="control-plane",
        note="the event journal through the snapshot watermark; restored inside "
             "the control database and checked against the committed counter",
    ),
    Dependency(
        id="artifact-blobs",
        order=6,
        kind=DependencyKind.ARTIFACT_BLOB_STORE,
        source=DependencySource.BACKUP_ARTIFACT,
        verified_by=Verification.SHA256,
        exercised=Exercise.DRILLED,
        owner_class="control-plane",
        note="content-addressed artifact bytes for exactly the rows the snapshot "
             "carries; neither a missing blob nor an orphan blob is a coherent "
             "point in time",
    ),
    Dependency(
        id="config-revision",
        order=7,
        kind=DependencyKind.CONFIG_REVISION,
        source=DependencySource.BACKUP_ARTIFACT,
        verified_by=Verification.REFERENTIAL_INVARIANT,
        exercised=Exercise.DRILLED,
        owner_class="control-plane",
        note="non-secret configuration revision history; the revision the "
             "database calls current must exist in the restored file",
    ),
    Dependency(
        id="recoverable-secret-material",
        order=8,
        kind=DependencyKind.KEY_MATERIAL,
        source=DependencySource.ESCROWED_KEY,
        verified_by=Verification.NONE_DECLARED,
        exercised=Exercise.NOT_DRILLED,
        owner_class="security-operations",
        note="encrypted credential ciphertext plus a separately escrowed "
             "recovery key, or external-provider references; the drill holds no "
             "credential of any kind and cannot resolve a descriptor",
    ),
    Dependency(
        id="service-definition",
        order=9,
        kind=DependencyKind.SERVICE_DEFINITION,
        source=DependencySource.HOST_PROVISIONING,
        verified_by=Verification.NONE_DECLARED,
        exercised=Exercise.NOT_DRILLED,
        owner_class="platform-operations",
        note="the service unit that starts the restored installation in "
             "disconnected recovery mode; the local drill never starts a service, "
             "so recovery-mode startup is outside what it measures",
    ),
)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_atomic(path: pathlib.Path, payload: bytes) -> None:
    """Write `payload` to `path` through a staging name and one rename.

    A reader in an earlier parallel run here saw a half-written file from a
    plain write, so every producer in this spike stages and renames.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(path.name + ".staging")
    with staging.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    staging.replace(path)


@dataclass(frozen=True)
class SourceLayout:
    """Where the live fixture keeps each component."""

    root: pathlib.Path

    @property
    def database(self) -> pathlib.Path:
        return self.root / "control.db"

    @property
    def blobs(self) -> pathlib.Path:
        return self.root / "blobs"

    @property
    def config(self) -> pathlib.Path:
        return self.root / "config.json"

    def blob_path(self, digest: str) -> pathlib.Path:
        return self.blobs / digest[:2] / digest


SCHEMA = """
CREATE TABLE events (
    event_id    INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,
    artifact_id TEXT    NOT NULL REFERENCES artifacts(artifact_id),
    written_ns  INTEGER NOT NULL
);
CREATE TABLE artifacts (
    artifact_id TEXT    PRIMARY KEY,
    sha256      TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL
);
CREATE TABLE counters (
    name  TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE settings (
    name  TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
);
"""


class FixtureWriter:
    """A writer that keeps the fixture's ordering rules on every transaction."""

    def __init__(self, layout: SourceLayout, seed: int = 20260811) -> None:
        self.layout = layout
        self.seed = seed
        self.events = 0
        self.config_revision = 1
        self._connection: sqlite3.Connection | None = None

    # -- lifecycle ------------------------------------------------------

    def create(self) -> None:
        self.layout.root.mkdir(parents=True, exist_ok=True)
        self.layout.blobs.mkdir(parents=True, exist_ok=True)
        self._write_config(1)
        connection = self._open()
        connection.executescript(SCHEMA)
        connection.execute(
            "INSERT INTO counters(name, value) VALUES ('events_committed', 0)")
        connection.execute(
            "INSERT INTO settings(name, value) VALUES ('config_revision', 1)")
        connection.commit()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _open(self) -> sqlite3.Connection:
        if self._connection is None:
            connection = sqlite3.connect(self.layout.database, timeout=30.0)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            self._connection = connection
        return self._connection

    # -- the fixture's own ordering rules -------------------------------

    def _payload(self, index: int) -> bytes:
        seed = f"{self.seed}:{index}".encode()
        block = hashlib.sha256(seed).digest()
        return (block * ((BLOB_BYTES // len(block)) + 1))[:BLOB_BYTES]

    def _write_config(self, revision: int) -> None:
        document = {
            "schema": "automonique.recovery.config-revision.v1",
            "revision": revision,
            "history": list(range(1, revision + 1)),
            "secret_values": None,
        }
        write_atomic(
            self.layout.config,
            (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
        )

    def commit_batch(self, count: int, pace_seconds: float = 0.0) -> int:
        """Commit `count` transactions and return the last event id."""
        connection = self._open()
        for _ in range(count):
            index = self.events + 1
            payload = self._payload(index)
            digest = sha256_bytes(payload)
            # rule 1: the blob is durable before the row that references it.
            write_atomic(self.layout.blob_path(digest), payload)
            next_revision = self.config_revision
            if index % CONFIG_EVERY == 0:
                next_revision = self.config_revision + 1
                # rule 2: the file reaches the revision before the row does.
                self._write_config(next_revision)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO artifacts(artifact_id, sha256, size_bytes) "
                "VALUES (?, ?, ?)",
                (f"artifact-{index:06d}", digest, len(payload)),
            )
            connection.execute(
                "INSERT INTO events(event_id, kind, artifact_id, written_ns) "
                "VALUES (?, ?, ?, ?)",
                (index, "artifact_recorded", f"artifact-{index:06d}",
                 time.time_ns()),
            )
            connection.execute(
                "UPDATE counters SET value = ? WHERE name = 'events_committed'",
                (index,),
            )
            if next_revision != self.config_revision:
                connection.execute(
                    "UPDATE settings SET value = ? WHERE name = 'config_revision'",
                    (next_revision,),
                )
            connection.commit()
            self.events = index
            self.config_revision = next_revision
            if pace_seconds:
                time.sleep(pace_seconds)
        return self.events


@dataclass(frozen=True)
class BackupManifest:
    """Exactly what one backup carries, and the point in time it carries."""

    watermark_event_id: int
    watermark_ns: int
    config_revision: int
    event_count: int
    artifact_count: int
    files: dict[str, str] = field(default_factory=dict)

    def as_document(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "watermark_event_id": self.watermark_event_id,
            "watermark_ns": self.watermark_ns,
            "config_revision": self.config_revision,
            "event_count": self.event_count,
            "artifact_count": self.artifact_count,
            "files": dict(sorted(self.files.items())),
        }

    @classmethod
    def from_document(cls, document: dict[str, object]) -> "BackupManifest":
        if document.get("schema") != MANIFEST_SCHEMA:
            raise ValueError(f"unknown manifest schema {document.get('schema')!r}")
        return cls(
            watermark_event_id=int(document["watermark_event_id"]),
            watermark_ns=int(document["watermark_ns"]),
            config_revision=int(document["config_revision"]),
            event_count=int(document["event_count"]),
            artifact_count=int(document["artifact_count"]),
            files={str(k): str(v) for k, v in dict(document["files"]).items()},
        )


def snapshot_database(
    source: pathlib.Path,
    target: pathlib.Path,
    on_first_page: Callable[[], None] | None = None,
) -> None:
    """Copy `source` to `target` with SQLite's supported online backup API.

    `on_first_page` fires once, part way through the copy, so a caller can
    commit to the source on a second connection while the backup is in flight
    and prove the backup is online rather than quiesced. No second thread is
    involved: the callback runs inside the copy, which is what makes the
    interleaving deterministic. SQLite restarts the copy when the source
    changes underneath it, so the finished target is still one point in time —
    the later one.
    """
    fired: list[bool] = []

    def progress(status: int, remaining: int, total: int) -> None:
        if on_first_page is not None and not fired:
            fired.append(True)
            on_first_page()

    reader = sqlite3.connect(source, timeout=30.0)
    writer = sqlite3.connect(target, timeout=30.0)
    try:
        reader.backup(writer, pages=1, progress=progress, sleep=0.01)
    finally:
        writer.close()
        reader.close()


def read_snapshot_state(database: pathlib.Path) -> tuple[int, int, int, int, list[tuple[str, str]]]:
    """Return watermark id, watermark ns, config revision, count and rows."""
    connection = sqlite3.connect(database, timeout=30.0)
    try:
        watermark = connection.execute(
            "SELECT COALESCE(MAX(event_id), 0) FROM events").fetchone()[0]
        watermark_ns = connection.execute(
            "SELECT COALESCE(MAX(written_ns), 0) FROM events").fetchone()[0]
        revision = connection.execute(
            "SELECT value FROM settings WHERE name = 'config_revision'"
        ).fetchone()[0]
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        rows = connection.execute(
            "SELECT artifact_id, sha256 FROM artifacts ORDER BY artifact_id"
        ).fetchall()
    finally:
        connection.close()
    return int(watermark), int(watermark_ns), int(revision), int(count), list(rows)


def take_backup(
    layout: SourceLayout,
    backup_root: pathlib.Path,
    on_first_page: Callable[[], None] | None = None,
) -> BackupManifest:
    """Take the consistent recovery set, database snapshot first."""
    backup_root.mkdir(parents=True, exist_ok=True)
    database = backup_root / "control.db"
    snapshot_database(layout.database, database, on_first_page)
    watermark, watermark_ns, revision, count, rows = read_snapshot_state(database)

    files: dict[str, str] = {}
    for _, digest in rows:
        target = backup_root / "blobs" / digest[:2] / digest
        payload = layout.blob_path(digest).read_bytes()
        if sha256_bytes(payload) != digest:
            raise ValueError(f"source blob {digest} does not match its own name")
        write_atomic(target, payload)
        files[target.relative_to(backup_root).as_posix()] = digest

    config_document = json.loads(layout.config.read_text())
    if revision not in config_document["history"]:
        raise ValueError(
            "configuration file has not reached the revision the snapshot "
            "records as current; the fixture's ordering rule was violated")
    write_atomic(
        backup_root / "config.json",
        (json.dumps(config_document, indent=2, sort_keys=True) + "\n").encode(),
    )
    files["config.json"] = sha256_file(backup_root / "config.json")
    files["control.db"] = sha256_file(database)

    manifest = BackupManifest(
        watermark_event_id=watermark,
        watermark_ns=watermark_ns,
        config_revision=revision,
        event_count=count,
        artifact_count=len(rows),
        files=files,
    )
    write_manifest(backup_root, manifest)
    return manifest


def take_naive_backup(
    layout: SourceLayout,
    backup_root: pathlib.Path,
    between_components: Callable[[], None] | None = None,
) -> BackupManifest:
    """Copy the same components in the *wrong* order, on purpose.

    Blobs first, then the database. Anything committed between the two copies
    leaves a row in the backup whose bytes the backup never took. This exists
    so the consistency check has a failure it is known to catch; it is never a
    procedure this repository proposes.
    """
    backup_root.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    for blob in sorted(layout.blobs.rglob("*")):
        if not blob.is_file():
            continue
        digest = blob.name
        target = backup_root / "blobs" / digest[:2] / digest
        write_atomic(target, blob.read_bytes())
        files[target.relative_to(backup_root).as_posix()] = digest

    if between_components is not None:
        between_components()

    database = backup_root / "control.db"
    snapshot_database(layout.database, database)
    watermark, watermark_ns, revision, count, rows = read_snapshot_state(database)
    write_atomic(
        backup_root / "config.json",
        (json.dumps(json.loads(layout.config.read_text()), indent=2,
                    sort_keys=True) + "\n").encode(),
    )
    files["config.json"] = sha256_file(backup_root / "config.json")
    files["control.db"] = sha256_file(database)

    manifest = BackupManifest(
        watermark_event_id=watermark,
        watermark_ns=watermark_ns,
        config_revision=revision,
        event_count=count,
        artifact_count=len(rows),
        files=files,
    )
    write_manifest(backup_root, manifest)
    return manifest


def write_manifest(backup_root: pathlib.Path, manifest: BackupManifest) -> None:
    write_atomic(
        backup_root / "manifest.json",
        (json.dumps(manifest.as_document(), indent=2, sort_keys=True)
         + "\n").encode(),
    )


def read_manifest(backup_root: pathlib.Path) -> BackupManifest:
    return BackupManifest.from_document(
        json.loads((backup_root / "manifest.json").read_text()))


def restore(backup_root: pathlib.Path, target_root: pathlib.Path) -> BackupManifest:
    """Restore into an empty target, reading only the backup artifact.

    The manifest is the only index consulted, so nothing outside the backup can
    reach the target through this function.
    """
    if target_root.exists():
        raise ValueError(f"restore target already exists: {target_root.name}")
    manifest = read_manifest(backup_root)
    target_root.mkdir(parents=True, mode=0o700)
    for relative, digest in sorted(manifest.files.items()):
        payload = (backup_root / relative).read_bytes()
        if sha256_bytes(payload) != digest:
            raise ValueError(f"backup file {relative} does not match its manifest hash")
        write_atomic(target_root / relative, payload)
    return manifest


@dataclass(frozen=True)
class InvariantResult:
    invariant: Invariant
    ok: bool
    detail: str

    def as_document(self) -> dict[str, object]:
        return {"invariant": self.invariant.value, "ok": self.ok,
                "detail": self.detail}


def _walk_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def verify_restored(
    target_root: pathlib.Path, manifest: BackupManifest
) -> list[InvariantResult]:
    """Prove the restored state is one coherent point in time, not merely present."""
    results: list[InvariantResult] = []

    present = {
        path.relative_to(target_root).as_posix(): sha256_file(path)
        for path in _walk_files(target_root)
    }
    expected = dict(manifest.files)
    unbacked = sorted(set(present) - set(expected))
    absent = sorted(set(expected) - set(present))
    corrupt = sorted(
        name for name, digest in expected.items()
        if name in present and present[name] != digest)
    results.append(InvariantResult(
        Invariant.TARGET_MATCHES_MANIFEST,
        not unbacked and not absent and not corrupt,
        f"{len(present)} file(s) present; {len(unbacked)} not in the backup "
        f"manifest {unbacked[:3]}; {len(absent)} missing {absent[:3]}; "
        f"{len(corrupt)} hash mismatch {corrupt[:3]}",
    ))

    database = target_root / "control.db"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(database, timeout=30.0)
        connection.execute("SELECT COUNT(*) FROM events").fetchone()
    except sqlite3.DatabaseError as error:
        if connection is not None:
            connection.close()
        # An unreadable database leaves the remaining invariants unevaluated.
        # They are reported as violated, not as passing: a rule that could not
        # be checked has not been satisfied.
        results.append(InvariantResult(
            Invariant.DATABASE_INTEGRITY, False,
            f"the restored database could not be read: {type(error).__name__}: "
            f"{error}"))
        for invariant in (Invariant.EVENT_COUNTER_AGREEMENT,
                          Invariant.WATERMARK_AGREEMENT,
                          Invariant.ARTIFACT_ROW_HAS_BLOB,
                          Invariant.BLOB_HASH_MATCHES_ROW,
                          Invariant.NO_ORPHAN_BLOB,
                          Invariant.CONFIG_REVISION_PRESENT):
            results.append(InvariantResult(
                invariant, False,
                "not evaluated: the restored database could not be read"))
        return results
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        results.append(InvariantResult(
            Invariant.DATABASE_INTEGRITY, integrity == "ok",
            f"PRAGMA integrity_check returned {integrity!r}"))

        events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        highest = connection.execute(
            "SELECT COALESCE(MAX(event_id), 0) FROM events").fetchone()[0]
        counter = connection.execute(
            "SELECT value FROM counters WHERE name = 'events_committed'"
        ).fetchone()[0]
        results.append(InvariantResult(
            Invariant.EVENT_COUNTER_AGREEMENT,
            events == highest == counter,
            f"{events} event row(s), highest id {highest}, committed counter "
            f"{counter}"))
        results.append(InvariantResult(
            Invariant.WATERMARK_AGREEMENT,
            highest == manifest.watermark_event_id,
            f"restored highest event id {highest}, manifest watermark "
            f"{manifest.watermark_event_id}"))

        rows = connection.execute(
            "SELECT artifact_id, sha256 FROM artifacts ORDER BY artifact_id"
        ).fetchall()
    finally:
        connection.close()

    missing_blobs: list[str] = []
    bad_hashes: list[str] = []
    referenced: set[str] = set()
    for artifact_id, digest in rows:
        referenced.add(digest)
        blob = target_root / "blobs" / digest[:2] / digest
        if not blob.is_file():
            missing_blobs.append(artifact_id)
        elif sha256_file(blob) != digest:
            bad_hashes.append(artifact_id)
    results.append(InvariantResult(
        Invariant.ARTIFACT_ROW_HAS_BLOB, not missing_blobs,
        f"{len(rows)} artifact row(s); {len(missing_blobs)} without their bytes "
        f"{missing_blobs[:3]}"))
    results.append(InvariantResult(
        Invariant.BLOB_HASH_MATCHES_ROW, not bad_hashes,
        f"{len(bad_hashes)} blob(s) whose bytes disagree with the row "
        f"{bad_hashes[:3]}"))

    stored = {path.name for path in _walk_files(target_root)
              if path.parent.parent.name == "blobs"}
    orphans = sorted(stored - referenced)
    results.append(InvariantResult(
        Invariant.NO_ORPHAN_BLOB, not orphans,
        f"{len(stored)} stored blob(s); {len(orphans)} referenced by no row "
        f"{orphans[:3]}"))

    config_path = target_root / "config.json"
    if config_path.is_file():
        document = json.loads(config_path.read_text())
        history = list(document.get("history", []))
        ok = manifest.config_revision in history
        detail = (f"database calls revision {manifest.config_revision} current; "
                  f"restored file reached {document.get('revision')} with "
                  f"{len(history)} revision(s) of history")
    else:
        ok, detail = False, "no configuration revision file was restored"
    results.append(InvariantResult(Invariant.CONFIG_REVISION_PRESENT, ok, detail))
    return results


def destroy(root: pathlib.Path) -> None:
    """Remove a fixture directory. Callers assert disposability first."""
    shutil.rmtree(root, ignore_errors=False)
