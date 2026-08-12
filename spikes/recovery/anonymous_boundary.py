#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Pinned same-kernel launcher for the anonymous recovery mechanism.

The launcher authenticates a reviewed worker source from an exact prior base,
copies it to an immutable memfd, and executes a fixed wrapper with only report,
package and worker descriptors.  Success is mechanism evidence only: it grants
no clean-host, startup, objective, credential, transport or production claim.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import resource
import select
import signal
import stat
import sys
import time
from typing import Any

try:
    from . import clean_boundary as cb
    from . import recovery_artifact
except ImportError:
    import clean_boundary as cb  # type: ignore[no-redef]
    import recovery_artifact  # type: ignore[no-redef]

ROOT = pathlib.Path(__file__).absolute().parents[2]
PINNED_BASE_COMMIT = "d4ca8a55094c21250873eb0d6eaff3034fd3f3b9"
PINNED_WORKER_RELATIVE = pathlib.PurePosixPath(
    "spikes/recovery/anonymous_worker.py")
PINNED_WORKER_SHA256 = (
    "5894ccfba4afbeff1dd1339186f9304f3f25b76ebd78513806c3bc54bc7b7e6e"
)
PINNED_WORKER_GIT_BLOB = "c8fd83077edd724f671e463084ca2d7518ec0805"
PINNED_WORKER_SIZE = 25_406

PACKAGE_SCHEMA = "automonique.synthetic-recovery-package/anonymous-online-v1"
PACKAGE_SHA256 = "d5edac7cbf5474314d5ed7d1a3f40d7225d343eda21a134ba283b0d62b91bbd8"
PACKAGE_ROOT_SHA256 = "291b5610ff729d19802667c0336ebc9ac20611a161ff8e2e50718b15628fffba"
PACKAGE_SIZE = 45_056
PACKAGE_ENTRY_COUNT = 14
REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)

REPORT_FD = 3
PACKAGE_FD = 4
WORKER_FD = 5
REPORT_LIMIT = cb.REPORT_LIMIT
MAX_FD_FALLBACK = 1 << 20

CHECK_NAMES = (
    "package_bytes_bounded", "package_database_integrity",
    "package_schema_exact", "manifest_exact", "entry_coordinates_exact",
    "entry_digests_exact", "root_digest_exact",
    "control_database_integrity", "control_database_schema_exact",
    "event_journal_exact", "artifact_blob_relationships_exact",
    "snapshot_exact", "configuration_policy_release_exact",
    "disconnected_definition_exact", "credential_metadata_only_exact",
    "context_source_seed_tool_exact",
)
EXTERNAL_AUTHORITY = {
    "credentials": False, "network": False, "providers": False,
    "tools": False, "transports": False,
}


class Outcome(enum.Enum):
    MECHANISM_VERIFIED = "anonymous_recovery_mechanism_verified"
    REFUSED = "refused"


class RefusalCode(enum.Enum):
    WORKER_SOURCE_INVALID = "worker_source_invalid"
    WORKER_COPY_INVALID = "worker_copy_invalid"
    PACKAGE_INVALID = "package_invalid"
    RECEIPT_INVALID = "receipt_invalid"
    CLONE_REFUSED = "clone_refused"
    UID_MAP_REFUSED = "uid_map_refused"
    CONTROL_INVALID = "control_invalid"
    WORKER_REFUSED = "worker_refused"
    REPORT_INVALID = "report_invalid"
    REPORT_OVERSIZE = "report_oversize"
    TIMEOUT = "timeout"
    PLATFORM_REFUSED = "platform_refused"


EXPECTED_RECEIPT = recovery_artifact.PackageReceipt(
    PACKAGE_SCHEMA, PACKAGE_ROOT_SHA256, PACKAGE_SHA256,
    PACKAGE_SIZE, PACKAGE_ENTRY_COUNT,
)


def _receipt_document(receipt: object) -> dict[str, Any]:
    if type(receipt) is not recovery_artifact.PackageReceipt:
        raise TypeError("receipt must be the exact producer PackageReceipt type")
    document = dataclasses.asdict(receipt)
    if set(document) != {
        "schema", "root_sha256", "package_sha256", "package_size", "entry_count",
    }:
        raise TypeError("producer receipt fields differ")
    return document


@dataclasses.dataclass(frozen=True)
class Refusal:
    code: RefusalCode
    detail: str

    def as_document(self) -> dict[str, str]:
        return {"code": self.code.value, "detail": self.detail}


@dataclasses.dataclass(frozen=True)
class Result:
    outcome: Outcome
    evidence: dict[str, Any] | None
    refusal: Refusal | None
    reaped: bool
    wait_status: int | None

    def as_document(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "evidence": self.evidence,
            "refusal": None if self.refusal is None else self.refusal.as_document(),
            "reaped": self.reaped,
            "wait_status": self.wait_status,
        }


def _refused(
    code: RefusalCode,
    detail: str,
    *,
    reaped: bool = False,
    wait_status: int | None = None,
) -> Result:
    return Result(Outcome.REFUSED, None, Refusal(code, detail), reaped, wait_status)


def _canonical(value: object) -> bytes:
    return (json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ) + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _identity(descriptor: int) -> dict[str, int]:
    metadata = os.fstat(descriptor)
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(65_536, size - offset), offset)
        if not chunk:
            raise ValueError("descriptor became short during bounded read")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _git_blob(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()  # noqa: S324 - Git object ID


def _open_lexical(root: pathlib.Path, relative: pathlib.PurePosixPath) -> int:
    if (not root.is_absolute() or relative.is_absolute()
            or any(part in ("", ".", "..") for part in relative.parts)):
        raise ValueError("pinned worker path is not canonical lexical input")
    descriptor = os.open(
        root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in root.parts[1:] + relative.parts[:-1]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = following
        worker = os.open(
            relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=descriptor,
        )
        return worker
    finally:
        os.close(descriptor)


def _read_pinned_worker(
    root: pathlib.Path = ROOT,
    relative: pathlib.PurePosixPath = PINNED_WORKER_RELATIVE,
) -> tuple[bytes, dict[str, int]]:
    descriptor = -1
    try:
        descriptor = _open_lexical(root, relative)
        before = _identity(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != PINNED_WORKER_SIZE:
            raise ValueError("worker source is not the pinned-size regular file")
        payload = _read_exact(descriptor, PINNED_WORKER_SIZE)
        after = _identity(descriptor)
        if before != after:
            raise ValueError("worker source identity changed during read")
        if hashlib.sha256(payload).hexdigest() != PINNED_WORKER_SHA256:
            raise ValueError("worker source SHA-256 differs from reviewed base")
        if _git_blob(payload) != PINNED_WORKER_GIT_BLOB:
            raise ValueError("worker source Git blob differs from reviewed base")
        return payload, before
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sealed_memfd(name: str, payload: bytes) -> tuple[int, dict[str, int]]:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short memfd write")
            view = view[written:]
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
            raise ValueError("worker memfd exact seal set differs")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, _identity(descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def _package_coordinates(descriptor: int) -> tuple[bytes, dict[str, int]]:
    before = _identity(descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != PACKAGE_SIZE:
        raise ValueError("package is not the pinned-size regular memfd")
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise ValueError("package is not a sealable memfd") from exc
    if seals != REQUIRED_SEALS:
        raise ValueError("package exact immutable seals differ")
    payload = _read_exact(descriptor, PACKAGE_SIZE)
    after = _identity(descriptor)
    if before != after:
        raise ValueError("package identity changed during read")
    if hashlib.sha256(payload).hexdigest() != PACKAGE_SHA256:
        raise ValueError("package bytes differ from pinned producer receipt")
    return payload, before


def _runtime_identity() -> dict[str, Any]:
    executable = pathlib.Path(sys.executable).resolve()
    metadata = executable.stat()
    digest = hashlib.sha256()
    with executable.open("rb") as handle:
        while chunk := handle.read(65_536):
            digest.update(chunk)
    return {
        "path": executable.as_posix(), "device": metadata.st_dev,
        "inode": metadata.st_ino, "size": metadata.st_size,
        "sha256": digest.hexdigest(), "implementation": sys.implementation.name,
        "version": list(sys.version_info[:3]),
    }


WRAPPER = r'''
import ctypes, errno, fcntl, hashlib, json, os, pathlib, socket, sys, types
REPORT_FD = 3
PACKAGE_FD = 4
WORKER_FD = 5
EXPECTED = json.loads(sys.argv[1])
REQUIRED_SEALS = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                  fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
SYS_CAPGET = 125
CAP_VERSION_3 = 0x20080522
PR_GET_NO_NEW_PRIVS = 39
class Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]
def emit(document):
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > 16384:
        raise RuntimeError("report exceeds fixed bound")
    offset = 0
    while offset < len(payload):
        offset += os.write(REPORT_FD, payload[offset:])
def read_exact(fd, size):
    chunks = []; offset = 0
    while offset < size:
        chunk = os.pread(fd, min(65536, size - offset), offset)
        if not chunk: raise ValueError("sealed descriptor became short")
        chunks.append(chunk); offset += len(chunk)
    return b"".join(chunks)
def identity(fd):
    value = os.fstat(fd)
    return {"device": value.st_dev, "inode": value.st_ino, "size": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}
def runtime_identity():
    executable = pathlib.Path(sys.executable).resolve(); value = executable.stat()
    digest = hashlib.sha256()
    with executable.open("rb") as handle:
        while chunk := handle.read(65536): digest.update(chunk)
    return {"path": executable.as_posix(), "device": value.st_dev,
            "inode": value.st_ino, "size": value.st_size,
            "sha256": digest.hexdigest(), "implementation": sys.implementation.name,
            "version": list(sys.version_info[:3])}
def denied(path):
    try:
        with open(path, "rb"): return 0
    except OSError as exc: return exc.errno
try:
    if fcntl.fcntl(PACKAGE_FD, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        raise ValueError("package seals differ in child")
    if fcntl.fcntl(WORKER_FD, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        raise ValueError("worker seals differ in child")
    if identity(PACKAGE_FD) != EXPECTED["package_memfd_identity"]:
        raise ValueError("package memfd identity differs in child")
    if identity(WORKER_FD) != EXPECTED["worker_memfd_identity"]:
        raise ValueError("worker memfd identity differs in child")
    package = read_exact(PACKAGE_FD, EXPECTED["package_receipt"]["package_size"])
    worker = read_exact(WORKER_FD, EXPECTED["worker_size"])
    if hashlib.sha256(package).hexdigest() != EXPECTED["package_receipt"]["package_sha256"]:
        raise ValueError("package digest differs in child")
    if hashlib.sha256(worker).hexdigest() != EXPECTED["worker_sha256"]:
        raise ValueError("worker digest differs in child")
    module = types.ModuleType("automonique_pinned_anonymous_worker")
    module.__file__ = "<sealed-worker-memfd>"
    sys.modules[module.__name__] = module
    exec(compile(worker, module.__file__, "exec", dont_inherit=True), module.__dict__)
    verification = module.verify_package_bytes(package).as_document()
    libc = ctypes.CDLL(None, use_errno=True)
    header = Header(CAP_VERSION_3, 0); data = (Data * 2)()
    if libc.syscall(SYS_CAPGET, ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "capget")
    capabilities = {"effective": [data[0].effective, data[1].effective],
                    "permitted": [data[0].permitted, data[1].permitted],
                    "inheritable": [data[0].inheritable, data[1].inheritable]}
    no_new_privs = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.1); network_errno = sock.connect_ex(("127.0.0.1", 9))
    finally: sock.close()
    open_fds = []
    for name in os.listdir("/proc/self/fd"):
        if name.isdecimal():
            try: fcntl.fcntl(int(name), fcntl.F_GETFD)
            except OSError as exc:
                if exc.errno != errno.EBADF: raise
            else: open_fds.append(int(name))
    evidence = {"run_id": EXPECTED["run_id"], "verification": verification,
        "package_receipt": EXPECTED["package_receipt"],
        "package_memfd_identity": identity(PACKAGE_FD),
        "package_seals": fcntl.fcntl(PACKAGE_FD, fcntl.F_GET_SEALS),
        "worker_source": EXPECTED["worker_source"],
        "worker_memfd_identity": identity(WORKER_FD),
        "worker_seals": fcntl.fcntl(WORKER_FD, fcntl.F_GET_SEALS),
        "worker_sha256": EXPECTED["worker_sha256"],
        "worker_git_blob": EXPECTED["worker_git_blob"],
        "worker_base_commit": EXPECTED["worker_base_commit"],
        "runtime_identity": runtime_identity(),
        "namespace_flags": EXPECTED["namespace_flags"],
        "namespace_identities": EXPECTED["namespace_identities"],
        "id_maps": EXPECTED["id_maps"], "pid": os.getpid(), "uid": os.getuid(),
        "no_new_privs": no_new_privs, "capabilities": capabilities,
        "repo_read_errno": denied(EXPECTED["repository_probe"]),
        "network_connect_errno": network_errno, "open_fds": open_fds,
        "environment": sorted(os.environ), "scope": "pinned-anonymous-mechanism-only",
        "objective_eligible": False, "position_receipts_emitted": [],
        "external_authority": {"credentials": False, "network": False,
          "providers": False, "tools": False, "transports": False},
        "seccomp_installed": False}
    if os.getpid() != 1 or os.getuid() != 0 or no_new_privs != 1:
        raise RuntimeError("boundary process identity or no_new_privs differs")
    if any(any(words) for words in capabilities.values()):
        raise RuntimeError("capabilities are not empty")
    if evidence["repo_read_errno"] != errno.EACCES or network_errno != errno.EACCES:
        raise RuntimeError("repository or network remained accessible")
    if open_fds != [REPORT_FD, PACKAGE_FD, WORKER_FD]:
        raise RuntimeError("unexpected descriptor survived exec")
    if evidence["runtime_identity"] != EXPECTED["runtime_identity"]:
        raise RuntimeError("runtime identity differs")
    emit({"outcome": "anonymous_recovery_mechanism_verified", "evidence": evidence})
except BaseException as exc:
    emit({"outcome": "refused", "refusal": {"code": "worker_refused",
          "detail": type(exc).__name__ + ": " + str(exc)}})
    raise SystemExit(1)
'''


def _close_except(*preserved: int) -> None:
    kept = frozenset(preserved)
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        configured = os.sysconf("SC_OPEN_MAX")
        maximum = configured if hard == resource.RLIM_INFINITY else max(hard, configured)
        if maximum < 3 or maximum > MAX_FD_FALLBACK:
            raise OSError(errno.E2BIG, "bounded descriptor fallback unavailable")
        names = [str(value) for value in range(3, int(maximum))]
    for name in names:
        if not name.isdecimal():
            continue
        descriptor = int(name)
        if descriptor > 2 and descriptor not in kept:
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise


def _remap(report_fd: int, package_fd: int, worker_fd: int) -> None:
    copies: list[tuple[int, int]] = []
    try:
        for source, destination in (
            (report_fd, REPORT_FD), (package_fd, PACKAGE_FD),
            (worker_fd, WORKER_FD),
        ):
            copy = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 16)
            copies.append((copy, destination))
        for copy, destination in copies:
            os.dup2(copy, destination, inheritable=True)
    finally:
        for copy, _ in copies:
            os.close(copy)
    _close_except(REPORT_FD, PACKAGE_FD, WORKER_FD)


def _child(
    control_fd: int,
    report_fd: int,
    package_fd: int,
    worker_fd: int,
    control_timeout: float,
    delay: float,
    parent_pidfd: int,
) -> None:
    try:
        cb._prctl_checked(cb.PR_SET_PDEATHSIG, signal.SIGKILL, "PR_SET_PDEATHSIG")
        if select.select([parent_pidfd], [], [], 0)[0]:
            raise RuntimeError("original parent died while arming worker")
        os.close(parent_pidfd)
        ready, _, _ = select.select([control_fd], [], [], control_timeout)
        raw = os.read(control_fd, REPORT_LIMIT) if ready else b""
        os.close(control_fd)
        if not raw.startswith(cb.CONTROL_TOKEN + b"\n"):
            raise ValueError("parent control document absent")
        expected = json.loads(raw[2:], object_pairs_hook=_unique_object)
        expected["id_maps"]["supplementary_groups"] = os.getgroups()
        _close_except(report_fd, package_fd, worker_fd)
        if delay:
            time.sleep(delay)
        cb._install_landlock()
        cb._drop_capabilities()
        os.environ.clear()
        _remap(report_fd, package_fd, worker_fd)
        for descriptor in (0, 1, 2):
            try:
                os.close(descriptor)
            except OSError:
                pass
        executable = pathlib.Path(sys.executable).resolve().as_posix()
        os.execve(
            executable,
            [executable, "-I", "-S", "-c", WRAPPER,
             json.dumps(expected, sort_keys=True, separators=(",", ":"))],
            {},
        )
    except BaseException as exc:
        cb._child_refusal(
            report_fd, cb.RefusalCode.WORKER_REFUSED,
            f"{type(exc).__name__}: {exc}")


def _clone(
    control_fd: int, report_fd: int, package_fd: int, worker_fd: int,
    control_timeout: float, delay: float, parent_pidfd: int,
) -> int:
    arguments = cb.CloneArgs(
        flags=cb.EXACT_NAMESPACE_FLAGS, exit_signal=signal.SIGCHLD)
    ctypes.set_errno(0)
    pid = cb.LIBC.syscall(
        cb.SYS_CLONE3, ctypes.byref(arguments), ctypes.sizeof(arguments))
    if pid < 0:
        raise OSError(ctypes.get_errno(), cb._errno_detail("clone3"))
    if pid == 0:
        _child(control_fd, report_fd, package_fd, worker_fd,
               control_timeout, delay, parent_pidfd)
        os._exit(1)
    return int(pid)


def _verification_valid(value: object) -> bool:
    if type(value) is not dict or set(value) != {
        "schema", "package_sha256", "root_sha256", "package_size",
        "entry_count", "recovery_point", "event_count", "artifact_count",
        "checks", "external_authority", "scope", "launchable", "authorizing",
        "position_receipts_emitted",
    }:
        return False
    return (
        value["schema"] == "automonique.anonymous-worker-verification/v1"
        and value["package_sha256"] == PACKAGE_SHA256
        and value["root_sha256"] == PACKAGE_ROOT_SHA256
        and value["package_size"] == PACKAGE_SIZE
        and value["entry_count"] == PACKAGE_ENTRY_COUNT
        and value["event_count"] == value["artifact_count"] == 4
        and value["checks"] == list(CHECK_NAMES)
        and value["external_authority"] == EXTERNAL_AUTHORITY
        and value["scope"] == "pure-anonymous-package-verifier"
        and value["launchable"] is False
        and value["authorizing"] is False
        and value["position_receipts_emitted"] == []
        and value["recovery_point"] == {
            "fixed_backup_cadence_seconds": 60,
            "snapshot_watermark_unix_ns": 4_000_000_000,
            "newest_durable_at_loss_unix_ns": 5_000_000_000,
            "derived_rpo_seconds": 1.0,
            "scope": "anonymous-synthetic", "objective_eligible": False,
        }
    )


EVIDENCE_KEYS = frozenset({
    "run_id", "verification", "package_receipt", "package_memfd_identity",
    "package_seals", "worker_source", "worker_memfd_identity", "worker_seals",
    "worker_sha256", "worker_git_blob", "worker_base_commit",
    "runtime_identity", "namespace_flags", "namespace_identities", "id_maps",
    "pid", "uid", "no_new_privs", "capabilities", "repo_read_errno",
    "network_connect_errno", "open_fds", "environment", "scope",
    "objective_eligible", "position_receipts_emitted", "external_authority",
    "seccomp_installed",
})


def _valid_namespaces(value: object) -> bool:
    if type(value) is not dict or set(value) != {"parent", "child"}:
        return False
    for side in ("parent", "child"):
        if type(value[side]) is not dict or set(value[side]) != set(cb.NAMESPACE_NAMES):
            return False
    return all(value["parent"][name] != value["child"][name]
               for name in cb.NAMESPACE_NAMES)


def _validate_evidence(value: object, expected: dict[str, Any]) -> dict[str, Any] | None:
    if type(value) is not dict or set(value) != EVIDENCE_KEYS:
        return None
    caps = value["capabilities"]
    maps = value["id_maps"]
    checks = (
        value["run_id"] == expected["run_id"],
        _verification_valid(value["verification"]),
        value["package_receipt"] == _receipt_document(EXPECTED_RECEIPT),
        value["package_memfd_identity"] == expected["package_memfd_identity"],
        value["package_seals"] == REQUIRED_SEALS,
        value["worker_source"] == expected["worker_source"],
        value["worker_memfd_identity"] == expected["worker_memfd_identity"],
        value["worker_seals"] == REQUIRED_SEALS,
        value["worker_sha256"] == PINNED_WORKER_SHA256,
        value["worker_git_blob"] == PINNED_WORKER_GIT_BLOB,
        value["worker_base_commit"] == PINNED_BASE_COMMIT,
        value["runtime_identity"] == expected["runtime_identity"],
        value["namespace_flags"] == cb.EXACT_NAMESPACE_FLAGS,
        _valid_namespaces(value["namespace_identities"]),
        value["pid"] == 1, value["uid"] == 0, value["no_new_privs"] == 1,
        value["repo_read_errno"] == errno.EACCES,
        value["network_connect_errno"] == errno.EACCES,
        value["open_fds"] == [REPORT_FD, PACKAGE_FD, WORKER_FD],
        value["environment"] == ["LC_CTYPE"],
        value["scope"] == "pinned-anonymous-mechanism-only",
        value["objective_eligible"] is False,
        value["position_receipts_emitted"] == [],
        value["external_authority"] == EXTERNAL_AUTHORITY,
        value["seccomp_installed"] is False,
    )
    if not all(checks):
        return None
    if (type(caps) is not dict or set(caps) != {"effective", "permitted", "inheritable"}
            or any(words != [0, 0] for words in caps.values())):
        return None
    if (type(maps) is not dict
            or set(maps) != {"uid_map", "gid_map", "supplementary_groups"}
            or type(maps["uid_map"]) is not str
            or maps["uid_map"].split() != ["0", str(os.getuid()), "1"]
            or maps["gid_map"] is not None
            or type(maps["supplementary_groups"]) is not list):
        return None
    return value


def _collect(
    pid: int, report_fd: int, timeout: float, expected: dict[str, Any],
) -> Result:
    os.set_blocking(report_fd, False)
    deadline = time.monotonic() + timeout
    payload = bytearray()
    wait_status: int | None = None
    pipe_open = True
    try:
        while time.monotonic() < deadline:
            if pipe_open:
                ready, _, _ = select.select(
                    [report_fd], [], [],
                    max(0.0, min(0.05, deadline - time.monotonic())))
                if ready:
                    part = os.read(report_fd, REPORT_LIMIT + 1 - len(payload))
                    if part:
                        payload.extend(part)
                        if len(payload) > REPORT_LIMIT:
                            os.kill(pid, signal.SIGKILL)
                            _, status = os.waitpid(pid, 0)
                            return _refused(
                                RefusalCode.REPORT_OVERSIZE,
                                "child report exceeded fixed bound",
                                reaped=True, wait_status=status)
                    else:
                        pipe_open = False
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                wait_status = status
            if wait_status is not None and not pipe_open:
                break
        else:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            return _refused(
                RefusalCode.TIMEOUT, "pinned worker exceeded deadline",
                reaped=True, wait_status=status)
        if wait_status is None:
            _, wait_status = os.waitpid(pid, 0)
    finally:
        os.close(report_fd)
    try:
        document = json.loads(bytes(payload), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _refused(
            RefusalCode.REPORT_INVALID, f"report is not unique-key JSON: {exc}",
            reaped=True, wait_status=wait_status)
    if type(document) is not dict or document.get("outcome") not in {
        Outcome.MECHANISM_VERIFIED.value, Outcome.REFUSED.value,
    }:
        return _refused(
            RefusalCode.REPORT_INVALID, "report lacks closed outcome",
            reaped=True, wait_status=wait_status)
    if document["outcome"] == Outcome.REFUSED.value:
        refusal = document.get("refusal")
        if (set(document) != {"outcome", "refusal"}
                or type(refusal) is not dict
                or set(refusal) != {"code", "detail"}
                or refusal["code"] != RefusalCode.WORKER_REFUSED.value
                or type(refusal["detail"]) is not str):
            return _refused(
                RefusalCode.REPORT_INVALID, "child refusal shape differs",
                reaped=True, wait_status=wait_status)
        return _refused(
            RefusalCode.WORKER_REFUSED, refusal["detail"],
            reaped=True, wait_status=wait_status)
    if set(document) != {"outcome", "evidence"} or wait_status != 0:
        return _refused(
            RefusalCode.REPORT_INVALID,
            "success report has extra fields or nonzero exit",
            reaped=True, wait_status=wait_status)
    evidence = _validate_evidence(document["evidence"], expected)
    if evidence is None:
        return _refused(
            RefusalCode.REPORT_INVALID,
            "success report fails exact nested schema or parent bindings",
            reaped=True, wait_status=wait_status)
    return Result(Outcome.MECHANISM_VERIFIED, evidence, None, True, wait_status)


def run(
    package_fd: int,
    receipt: recovery_artifact.PackageReceipt,
    timeout: float = 10.0,
    *,
    _test_delay: float = 0.0,
) -> Result:
    """Launch the exact pinned mechanism over one exact sealed package."""
    try:
        receipt_document = _receipt_document(receipt)
    except TypeError as exc:
        return _refused(RefusalCode.RECEIPT_INVALID, str(exc))
    if receipt != EXPECTED_RECEIPT:
        return _refused(
            RefusalCode.RECEIPT_INVALID,
            "producer receipt differs from pinned anonymous coordinates")
    if type(package_fd) is not int or package_fd < 0:
        return _refused(RefusalCode.PACKAGE_INVALID, "package FD is invalid")
    if timeout <= 0 or timeout > 30:
        return _refused(
            RefusalCode.TIMEOUT,
            "timeout must be greater than zero and at most 30 seconds")
    capability = cb.probe()
    if capability.refusal is not None:
        return _refused(
            RefusalCode.PLATFORM_REFUSED, capability.refusal.detail)
    owned_package = worker_memfd = -1
    control_read = control_write = report_read = report_write = parent_pidfd = -1
    try:
        try:
            worker_source, worker_source_identity = _read_pinned_worker()
        except (OSError, ValueError) as exc:
            return _refused(
                RefusalCode.WORKER_SOURCE_INVALID,
                f"reviewed worker source refused: {type(exc).__name__}: {exc}")
        try:
            worker_memfd, worker_memfd_identity = _sealed_memfd(
                "automonique-pinned-worker", worker_source)
            if (_read_exact(worker_memfd, PINNED_WORKER_SIZE) != worker_source
                    or hashlib.sha256(_read_exact(
                        worker_memfd, PINNED_WORKER_SIZE)).hexdigest()
                    != PINNED_WORKER_SHA256):
                raise ValueError("sealed worker copy differs")
        except (OSError, ValueError) as exc:
            return _refused(
                RefusalCode.WORKER_COPY_INVALID,
                f"sealed worker copy refused: {type(exc).__name__}: {exc}")
        try:
            owned_package = os.dup(package_fd)
            os.set_inheritable(owned_package, False)
            _, package_identity = _package_coordinates(owned_package)
        except (OSError, ValueError) as exc:
            return _refused(
                RefusalCode.PACKAGE_INVALID,
                f"sealed package refused: {type(exc).__name__}: {exc}")
        if not hasattr(os, "pidfd_open"):
            return _refused(
                RefusalCode.CLONE_REFUSED, "pidfd_open is required")
        expected: dict[str, Any] = {
            "run_id": os.urandom(16).hex(),
            "package_receipt": receipt_document,
            "package_memfd_identity": package_identity,
            "worker_source": {
                "relative_path": PINNED_WORKER_RELATIVE.as_posix(),
                "identity": worker_source_identity,
                "size": PINNED_WORKER_SIZE,
            },
            "worker_memfd_identity": worker_memfd_identity,
            "worker_size": PINNED_WORKER_SIZE,
            "worker_sha256": PINNED_WORKER_SHA256,
            "worker_git_blob": PINNED_WORKER_GIT_BLOB,
            "worker_base_commit": PINNED_BASE_COMMIT,
            "runtime_identity": _runtime_identity(),
            "namespace_flags": cb.EXACT_NAMESPACE_FLAGS,
            "namespace_identities": {}, "id_maps": {},
            "repository_probe": (ROOT / "AGENTS.md").as_posix(),
        }
        parent_namespaces = cb._namespace_identities()
        parent_pidfd = os.pidfd_open(os.getpid())
        control_read, control_write = os.pipe2(os.O_CLOEXEC)
        report_read, report_write = os.pipe2(os.O_CLOEXEC)
        rto_started_ns = time.monotonic_ns()
        try:
            pid = _clone(
                control_read, report_write, owned_package, worker_memfd,
                min(timeout, 1.0), _test_delay, parent_pidfd)
        except OSError as exc:
            return _refused(
                RefusalCode.CLONE_REFUSED, f"atomic clone refused: {exc}")
        os.close(control_read); control_read = -1
        os.close(report_write); report_write = -1
        os.close(parent_pidfd); parent_pidfd = -1
        try:
            expected["namespace_identities"] = cb._namespace_pair(
                parent_namespaces, cb._namespace_identities(pid))
            pathlib.Path(f"/proc/{pid}/uid_map").write_text(
                cb._uid_map(os.getuid()), encoding="ascii")
            uid_map = pathlib.Path(f"/proc/{pid}/uid_map").read_text()
            gid_map = pathlib.Path(f"/proc/{pid}/gid_map").read_text()
            expected["id_maps"] = {
                "uid_map": uid_map,
                "gid_map": None if not gid_map.strip() else gid_map,
                "supplementary_groups": [],
            }
        except OSError as exc:
            os.close(control_write); control_write = -1
            os.kill(pid, signal.SIGKILL); _, status = os.waitpid(pid, 0)
            return _refused(
                RefusalCode.UID_MAP_REFUSED, f"UID map refused: {exc}",
                reaped=True, wait_status=status)
        control = _canonical(expected)
        if len(control) + 2 > REPORT_LIMIT:
            os.kill(pid, signal.SIGKILL); _, status = os.waitpid(pid, 0)
            return _refused(
                RefusalCode.CONTROL_INVALID, "control exceeds fixed bound",
                reaped=True, wait_status=status)
        os.write(control_write, cb.CONTROL_TOKEN + b"\n" + control)
        os.close(control_write); control_write = -1
        result = _collect(pid, report_read, timeout, expected)
        report_read = -1
        if result.outcome is Outcome.MECHANISM_VERIFIED and result.evidence is not None:
            ended = time.monotonic_ns()
            result.evidence.update({
                "mechanism_started_monotonic_ns": rto_started_ns,
                "mechanism_ended_monotonic_ns": ended,
                "mechanism_seconds": (ended - rto_started_ns) / 1_000_000_000,
                "rto_objective_eligible": False,
            })
        return result
    finally:
        for descriptor in (
            owned_package, worker_memfd, control_read, control_write,
            report_read, report_write, parent_pidfd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def parent_death_probe(timeout: float = 2.0) -> dict[str, Any]:
    return cb.parent_death_probe(timeout)
