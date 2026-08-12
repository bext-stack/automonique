#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""A fail-closed disposable Linux boundary for the R0-10 recovery drill.

This is deliberately a standalone boundary probe, not a general sandbox.  It creates one
exec-clean PID 1 with all required namespaces in a single ``clone3`` call,
maps only the caller's UID, installs a closed Landlock ABI 4 policy, drops
capabilities, and returns a bounded evidence document through one pipe.  There
is no namespace, Landlock, architecture, or timeout fallback.  The inline
worker is trusted probe code; this primitive deliberately installs no seccomp
filter and is not a hostile-code sandbox.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import errno
import json
import os
import pathlib
import platform
import resource
import select
import signal
import struct
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]

SYS_CLONE3 = 435
SYS_CAPGET = 125
SYS_CAPSET = 126
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

NAMESPACE_FLAGS = {
    "CLONE_NEWUSER": CLONE_NEWUSER,
    "CLONE_NEWNS": CLONE_NEWNS,
    "CLONE_NEWPID": CLONE_NEWPID,
    "CLONE_NEWNET": CLONE_NEWNET,
    "CLONE_NEWIPC": CLONE_NEWIPC,
    "CLONE_NEWUTS": CLONE_NEWUTS,
    "CLONE_NEWCGROUP": CLONE_NEWCGROUP,
}
EXACT_NAMESPACE_FLAGS = sum(NAMESPACE_FLAGS.values())

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_HANDLED_FS = (1 << 15) - 1
LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
LANDLOCK_HANDLED_NET = (
    LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
)

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_SET_SECUREBITS = 28
PR_SET_PDEATHSIG = 1
SECBIT_NOROOT = 1 << 0
SECBIT_NOROOT_LOCKED = 1 << 1
SECBIT_NO_SETUID_FIXUP = 1 << 2
SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3
CAP_VERSION_3 = 0x20080522

REPORT_FD = 3
REPORT_LIMIT = 16 * 1024
CONTROL_TOKEN = b"G"
PDEATH_READY_TOKEN = b"P"
MIN_LANDLOCK_ABI = 4
NAMESPACE_NAMES = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
MAX_FD_FALLBACK = 1 << 20


class Outcome(enum.Enum):
    VERIFIED = "verified"
    REFUSED = "refused"


class RefusalCode(enum.Enum):
    WRONG_PLATFORM = "wrong_platform"
    LANDLOCK_UNAVAILABLE = "landlock_unavailable"
    LANDLOCK_ABI_TOO_OLD = "landlock_abi_too_old"
    CLONE_REFUSED = "clone_refused"
    UID_MAP_REFUSED = "uid_map_refused"
    NAMESPACE_IDENTITY_REFUSED = "namespace_identity_refused"
    PARENT_DIED = "parent_died"
    CONTROL_MISSING = "control_missing"
    LANDLOCK_REFUSED = "landlock_refused"
    PRIVILEGE_DROP_REFUSED = "privilege_drop_refused"
    EXEC_REFUSED = "exec_refused"
    WORKER_REFUSED = "worker_refused"
    REPORT_INVALID = "report_invalid"
    REPORT_OVERSIZE = "report_oversize"
    TIMEOUT = "timeout"


@dataclasses.dataclass(frozen=True)
class Refusal:
    code: RefusalCode
    detail: str

    def as_document(self) -> dict[str, str]:
        return {"code": self.code.value, "detail": self.detail}


@dataclasses.dataclass(frozen=True)
class CapabilityProbe:
    architecture: str
    landlock_abi: int | None
    refusal: Refusal | None

    @property
    def supported(self) -> bool:
        return self.refusal is None


@dataclasses.dataclass(frozen=True)
class BoundaryResult:
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


class CloneArgs(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("pidfd", ctypes.c_ulonglong),
        ("child_tid", ctypes.c_ulonglong),
        ("parent_tid", ctypes.c_ulonglong),
        ("exit_signal", ctypes.c_ulonglong),
        ("stack", ctypes.c_ulonglong),
        ("stack_size", ctypes.c_ulonglong),
        ("tls", ctypes.c_ulonglong),
        ("set_tid", ctypes.c_ulonglong),
        ("set_tid_size", ctypes.c_ulonglong),
        ("cgroup", ctypes.c_ulonglong),
    ]


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
LIBC.prctl.restype = ctypes.c_int


def _errno_detail(operation: str) -> str:
    number = ctypes.get_errno()
    return f"{operation}: errno {number} ({os.strerror(number)})"


def landlock_abi() -> int | None:
    ctypes.set_errno(0)
    result = LIBC.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    return int(result) if result >= 0 else None


def probe() -> CapabilityProbe:
    architecture = platform.machine()
    if platform.system() != "Linux" or architecture != "x86_64":
        return CapabilityProbe(
            architecture,
            None,
            Refusal(
                RefusalCode.WRONG_PLATFORM,
                f"requires Linux x86_64, found {platform.system()} {architecture}",
            ),
        )
    abi = landlock_abi()
    if abi is None:
        return CapabilityProbe(
            architecture,
            None,
            Refusal(RefusalCode.LANDLOCK_UNAVAILABLE, _errno_detail("Landlock ABI")),
        )
    if abi < MIN_LANDLOCK_ABI:
        return CapabilityProbe(
            architecture,
            abi,
            Refusal(
                RefusalCode.LANDLOCK_ABI_TOO_OLD,
                f"Landlock ABI {abi}; requires at least {MIN_LANDLOCK_ABI}",
            ),
        )
    return CapabilityProbe(architecture, abi, None)


def _syscall_checked(number: int, operation: str, *arguments: object) -> int:
    ctypes.set_errno(0)
    result = LIBC.syscall(number, *arguments)
    if result < 0:
        raise OSError(ctypes.get_errno(), _errno_detail(operation))
    return int(result)


def _prctl_checked(option: int, argument: int, operation: str) -> None:
    ctypes.set_errno(0)
    if LIBC.prctl(option, argument, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), _errno_detail(operation))


def _allow_paths() -> tuple[tuple[pathlib.Path, int], ...]:
    read_tree = (
        LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
    )
    runtime = pathlib.Path("/usr")
    if not runtime.is_dir():
        raise OSError(errno.ENOENT, "the exact /usr runtime allow rule is absent")
    if ROOT.is_relative_to(runtime):
        raise OSError(
            errno.EPERM,
            "repository is beneath the runtime allow rule and cannot be isolated",
        )
    proc_fds = pathlib.Path("/proc/self/fd")
    if not proc_fds.is_dir():
        raise OSError(errno.ENOENT, "the exact /proc/self/fd attestation rule is absent")
    return (
        (runtime, read_tree),
        (proc_fds, LANDLOCK_ACCESS_FS_READ_DIR),
    )


def _install_landlock() -> tuple[int, list[dict[str, int | str]]]:
    abi = landlock_abi()
    if abi is None or abi < MIN_LANDLOCK_ABI:
        found = "unavailable" if abi is None else str(abi)
        raise OSError(
            errno.ENOPROTOOPT,
            f"Landlock ABI changed after the parent probe: {found}",
        )
    ruleset_bytes = struct.pack("=QQ", LANDLOCK_HANDLED_FS, LANDLOCK_HANDLED_NET)
    ruleset_buffer = ctypes.create_string_buffer(ruleset_bytes)
    ruleset_fd = _syscall_checked(
        SYS_LANDLOCK_CREATE_RULESET,
        "landlock_create_ruleset",
        ctypes.byref(ruleset_buffer),
        len(ruleset_bytes),
        0,
    )
    allowed: list[dict[str, int | str]] = []
    try:
        for path, access in _allow_paths():
            path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule_bytes = struct.pack("=Qi", access, path_fd)
                rule_buffer = ctypes.create_string_buffer(rule_bytes)
                _syscall_checked(
                    SYS_LANDLOCK_ADD_RULE,
                    "landlock_add_rule",
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule_buffer),
                    0,
                )
            finally:
                os.close(path_fd)
            allowed.append({"path": path.as_posix(), "access": access})
        _prctl_checked(PR_SET_NO_NEW_PRIVS, 1, "PR_SET_NO_NEW_PRIVS")
        _syscall_checked(
            SYS_LANDLOCK_RESTRICT_SELF,
            "landlock_restrict_self",
            ruleset_fd,
            0,
        )
    finally:
        os.close(ruleset_fd)
    return abi, allowed


def _drop_capabilities() -> None:
    securebits = (
        SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED
    )
    _prctl_checked(PR_SET_SECUREBITS, securebits, "PR_SET_SECUREBITS")
    header = CapHeader(CAP_VERSION_3, 0)
    data = (CapData * 2)()
    _syscall_checked(
        SYS_CAPSET,
        "capset",
        ctypes.byref(header),
        ctypes.byref(data),
    )


def _write_json(fd: int, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > REPORT_LIMIT:
        payload = (
            json.dumps({
                "outcome": Outcome.REFUSED.value,
                "refusal": {
                    "code": RefusalCode.REPORT_OVERSIZE.value,
                    "detail": "child report exceeded its fixed bound",
                },
            }, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
    offset = 0
    while offset < len(payload):
        offset += os.write(fd, payload[offset:])


def _namespace_identities(pid: int | str = "self") -> dict[str, dict[str, int]]:
    identities: dict[str, dict[str, int]] = {}
    for name in NAMESPACE_NAMES:
        status = os.stat(f"/proc/{pid}/ns/{name}")
        identities[name] = {"device": status.st_dev, "inode": status.st_ino}
    return identities


def _namespace_pair(
    parent: dict[str, dict[str, int]], child: dict[str, dict[str, int]]
) -> dict[str, dict[str, dict[str, int]]]:
    if set(parent) != set(NAMESPACE_NAMES) or set(child) != set(NAMESPACE_NAMES):
        raise OSError(errno.EPROTO, "namespace identity set is incomplete")
    unchanged = [name for name in NAMESPACE_NAMES if parent[name] == child[name]]
    if unchanged:
        raise OSError(
            errno.EPROTO,
            f"clone3 did not create fresh namespaces: {unchanged}",
        )
    return {"parent": parent, "child": child}


def _close_inherited_except(report_fd: int) -> None:
    proc_fds = pathlib.Path("/proc/self/fd")
    if proc_fds.is_dir():
        try:
            names = os.listdir(proc_fds)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise
        else:
            descriptors = []
            for name in names:
                try:
                    descriptor = int(name)
                except ValueError:
                    continue
                if descriptor > 2 and descriptor != report_fd:
                    descriptors.append(descriptor)
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
            return

    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    configured = os.sysconf("SC_OPEN_MAX")
    if hard == resource.RLIM_INFINITY:
        hard = configured
    maximum = max(int(hard), int(configured))
    if maximum < 3 or maximum > MAX_FD_FALLBACK:
        raise OSError(errno.E2BIG, "bounded descriptor fallback is unavailable")
    os.closerange(3, report_fd)
    os.closerange(report_fd + 1, maximum)


def _child_refusal(fd: int, code: RefusalCode, detail: str) -> None:
    try:
        _write_json(fd, {
            "outcome": Outcome.REFUSED.value,
            "refusal": {"code": code.value, "detail": detail},
        })
    finally:
        os._exit(1)


WORKER = r'''
import ctypes, errno, fcntl, json, os, socket, sys

REPORT_FD = int(sys.argv[1])
REPO_PROBE = sys.argv[2]
LANDLOCK_ABI = int(sys.argv[3])
ALLOWED_PATHS = json.loads(sys.argv[4])
NAMESPACE_FLAGS = int(sys.argv[5])
NAMESPACE_IDENTITIES = json.loads(sys.argv[6])
ID_MAP_EVIDENCE = json.loads(sys.argv[7])
PARENT_DEATH_EVIDENCE = json.loads(sys.argv[8])
SYS_CAPGET = 125
CAP_VERSION_3 = 0x20080522
PR_GET_NO_NEW_PRIVS = 39

class Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]

def emit(document):
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > 16384:
        raise RuntimeError("report bound exceeded")
    offset = 0
    while offset < len(payload):
        offset += os.write(REPORT_FD, payload[offset:])

try:
    libc = ctypes.CDLL(None, use_errno=True)
    header = Header(CAP_VERSION_3, 0)
    data = (Data * 2)()
    if libc.syscall(SYS_CAPGET, ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "capget")
    caps = {
        "effective": [data[0].effective, data[1].effective],
        "permitted": [data[0].permitted, data[1].permitted],
        "inheritable": [data[0].inheritable, data[1].inheritable],
    }
    try:
        with open(REPO_PROBE, "rb"):
            repo_denied = False
            repo_errno = 0
    except OSError as exc:
        repo_denied = exc.errno in (errno.EACCES, errno.EPERM)
        repo_errno = exc.errno
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.1)
        network_errno = sock.connect_ex(("127.0.0.1", 9))
    finally:
        sock.close()
    open_fds = []
    candidates = [int(name) for name in os.listdir("/proc/self/fd")
                  if name.isdecimal()]
    for fd in candidates:
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            open_fds.append(fd)
    no_new_privs = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    evidence = {
        "outcome": "verified",
        "pid": os.getpid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "supplementary_groups": os.getgroups(),
        "id_maps": ID_MAP_EVIDENCE,
        "parent_death": PARENT_DEATH_EVIDENCE,
        "namespace_flags": NAMESPACE_FLAGS,
        "namespace_identities": NAMESPACE_IDENTITIES,
        "landlock_abi": LANDLOCK_ABI,
        "landlock_allowed_paths": ALLOWED_PATHS,
        "no_new_privs": no_new_privs,
        "capabilities": caps,
        "repo_read_denied": repo_denied,
        "repo_read_errno": repo_errno,
        "network_connect_errno": network_errno,
        "open_fds": open_fds,
        "environment": sorted(os.environ),
        "scope": "standalone-boundary-probe",
        "seccomp_installed": False,
        "worker_trust": "trusted-inline-probe",
    }
    if evidence["pid"] != 1:
        raise RuntimeError("exec-clean worker is not PID 1")
    if evidence["uid"] != 0:
        raise RuntimeError("parent UID was not mapped to child UID 0")
    if no_new_privs != 1:
        raise RuntimeError("no_new_privs is not set")
    if any(any(words) for words in caps.values()):
        raise RuntimeError("capset did not clear every capability word")
    if not repo_denied or repo_errno != errno.EACCES:
        raise RuntimeError("repository read was not denied by Landlock")
    if network_errno != errno.EACCES:
        raise RuntimeError("TCP connect was not denied by Landlock")
    if open_fds != [REPORT_FD]:
        raise RuntimeError("an unexpected descriptor survived exec")
    if evidence["supplementary_groups"] != ID_MAP_EVIDENCE["supplementary_groups"]:
        raise RuntimeError("supplementary group evidence changed across exec")
    emit(evidence)
except BaseException as exc:
    emit({"outcome": "refused", "refusal": {
        "code": "worker_refused", "detail": type(exc).__name__ + ": " + str(exc)}})
    raise SystemExit(1)
'''


def _exec_worker(
    report_fd: int,
    repository_probe: pathlib.Path,
    abi: int,
    allowed: list[dict[str, int | str]],
    namespace_identities: dict[str, dict[str, dict[str, int]]],
    id_maps: dict[str, Any],
    parent_death: dict[str, Any],
) -> None:
    os.chdir("/")
    if report_fd != REPORT_FD:
        os.dup2(report_fd, REPORT_FD, inheritable=True)
        os.close(report_fd)
    else:
        os.set_inheritable(REPORT_FD, True)
    _close_inherited_except(REPORT_FD)
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    executable = pathlib.Path(sys.executable).resolve().as_posix()
    os.execve(
        executable,
        [executable, "-I", "-S", "-c", WORKER, str(REPORT_FD),
         repository_probe.as_posix(), str(abi), json.dumps(allowed),
         str(EXACT_NAMESPACE_FLAGS), json.dumps(namespace_identities),
         json.dumps(id_maps), json.dumps(parent_death)],
        {},
    )


def _child(
    control_fd: int,
    report_fd: int,
    repository_probe: pathlib.Path,
    control_timeout: float,
    test_delay: float,
    original_parent_pid: int,
    parent_pidfd: int,
) -> None:
    try:
        _prctl_checked(PR_SET_PDEATHSIG, signal.SIGKILL, "PR_SET_PDEATHSIG")
        if select.select([parent_pidfd], [], [], 0)[0]:
            _child_refusal(
                report_fd,
                RefusalCode.PARENT_DIED,
                "original parent pidfd became readable while arming protection",
            )
        os.close(parent_pidfd)
        parent_death = {
            "original_parent_pid": original_parent_pid,
            "pdeath_signal": int(signal.SIGKILL),
            "parent_pidfd_live_after_prctl": True,
        }
        ready, _, _ = select.select([control_fd], [], [], control_timeout)
        raw_control = os.read(control_fd, REPORT_LIMIT) if ready else b""
        os.close(control_fd)
        if not raw_control.startswith(CONTROL_TOKEN + b"\n"):
            _child_refusal(
                report_fd,
                RefusalCode.CONTROL_MISSING,
                "parent UID-map control token was absent",
            )
        try:
            control = json.loads(raw_control[2:])
            namespace_identities = control["namespace_identities"]
            id_maps = control["id_maps"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            _child_refusal(
                report_fd,
                RefusalCode.CONTROL_MISSING,
                "parent control document is invalid",
            )
        id_maps["supplementary_groups"] = os.getgroups()
        _close_inherited_except(report_fd)
        if test_delay:
            time.sleep(test_delay)
        abi, allowed = _install_landlock()
        _drop_capabilities()
        os.environ.clear()
        # Boundary facts cross exec only as argv; the worker's environment and
        # inherited descriptors are otherwise empty.
        _exec_worker(
            report_fd,
            repository_probe,
            abi,
            allowed,
            namespace_identities,
            id_maps,
            parent_death,
        )
    except OSError as exc:
        code = (
            RefusalCode.LANDLOCK_REFUSED
            if "landlock" in str(exc).lower()
            else RefusalCode.PRIVILEGE_DROP_REFUSED
        )
        _child_refusal(report_fd, code, f"{type(exc).__name__}: {exc}")
    except BaseException as exc:
        _child_refusal(
            report_fd,
            RefusalCode.EXEC_REFUSED,
            f"{type(exc).__name__}: {exc}",
        )


def _clone_child(
    control_fd: int,
    report_fd: int,
    repository_probe: pathlib.Path,
    control_timeout: float,
    test_delay: float,
    original_parent_pid: int,
    parent_pidfd: int,
) -> int:
    arguments = CloneArgs(flags=EXACT_NAMESPACE_FLAGS, exit_signal=signal.SIGCHLD)
    ctypes.set_errno(0)
    pid = LIBC.syscall(SYS_CLONE3, ctypes.byref(arguments), ctypes.sizeof(arguments))
    if pid < 0:
        raise OSError(ctypes.get_errno(), _errno_detail("clone3"))
    if pid == 0:
        _child(
            control_fd,
            report_fd,
            repository_probe,
            control_timeout,
            test_delay,
            original_parent_pid,
            parent_pidfd,
        )
        os._exit(1)
    return int(pid)


def _refused(
    code: RefusalCode,
    detail: str,
    *,
    reaped: bool = False,
    wait_status: int | None = None,
) -> BoundaryResult:
    return BoundaryResult(
        Outcome.REFUSED,
        None,
        Refusal(code, detail),
        reaped,
        wait_status,
    )


def _uid_map(parent_uid: int) -> str:
    if type(parent_uid) is not int or parent_uid < 0:
        raise ValueError("parent UID must be a non-negative integer")
    return f"0 {parent_uid} 1\n"


VERIFIED_KEYS = frozenset({
    "outcome", "pid", "uid", "gid", "supplementary_groups", "id_maps",
    "parent_death",
    "namespace_flags", "namespace_identities", "landlock_abi",
    "landlock_allowed_paths", "no_new_privs", "capabilities",
    "repo_read_denied", "repo_read_errno", "network_connect_errno",
    "open_fds", "environment", "scope", "seccomp_installed", "worker_trust",
})


def _exact_int(value: object, expected: int | None = None) -> bool:
    return type(value) is int and (expected is None or value == expected)


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


def _valid_namespace_evidence(value: object) -> bool:
    if type(value) is not dict or set(value) != {"parent", "child"}:
        return False
    for side in ("parent", "child"):
        identities = value[side]
        if type(identities) is not dict or set(identities) != set(NAMESPACE_NAMES):
            return False
        for identity in identities.values():
            if (
                type(identity) is not dict
                or set(identity) != {"device", "inode"}
                or not _exact_int(identity["device"])
                or not _exact_int(identity["inode"])
                or identity["inode"] <= 0
            ):
                return False
    return all(value["parent"][name] != value["child"][name]
               for name in NAMESPACE_NAMES)


def _validate_verified_document(
    document: object, wait_status: int
) -> dict[str, Any] | None:
    if type(document) is not dict or set(document) != VERIFIED_KEYS:
        return None
    if wait_status != 0 or document["outcome"] != Outcome.VERIFIED.value:
        return None
    scalar_checks = (
        _exact_int(document["pid"], 1),
        _exact_int(document["uid"], 0),
        _exact_int(document["gid"]) and document["gid"] >= 0,
        _exact_int(document["namespace_flags"], EXACT_NAMESPACE_FLAGS),
        _exact_int(document["landlock_abi"]),
        _exact_int(document["no_new_privs"], 1),
        document["repo_read_denied"] is True,
        _exact_int(document["repo_read_errno"], errno.EACCES),
        _exact_int(document["network_connect_errno"], errno.EACCES),
        document["scope"] == "standalone-boundary-probe",
        document["seccomp_installed"] is False,
        document["worker_trust"] == "trusted-inline-probe",
    )
    if not all(scalar_checks) or document["landlock_abi"] < MIN_LANDLOCK_ABI:
        return None
    groups = document["supplementary_groups"]
    if (
        type(groups) is not list
        or any(not _exact_int(group) for group in groups)
        or document["open_fds"] != [REPORT_FD]
    ):
        return None
    if document["environment"] != ["LC_CTYPE"]:
        return None
    maps = document["id_maps"]
    if (
        type(maps) is not dict
        or set(maps) != {"uid_map", "gid_map", "supplementary_groups"}
        or type(maps["uid_map"]) is not str
        or maps["uid_map"].split() != ["0", str(os.getuid()), "1"]
        or maps["gid_map"] is not None
        or maps["supplementary_groups"] != groups
    ):
        return None
    parent_death = document["parent_death"]
    if (
        type(parent_death) is not dict
        or set(parent_death) != {
            "original_parent_pid", "pdeath_signal",
            "parent_pidfd_live_after_prctl",
        }
        or not _exact_int(parent_death["original_parent_pid"], os.getpid())
        or not _exact_int(parent_death["pdeath_signal"], signal.SIGKILL)
        or parent_death["parent_pidfd_live_after_prctl"] is not True
    ):
        return None
    if not _valid_namespace_evidence(document["namespace_identities"]):
        return None
    caps = document["capabilities"]
    if (
        type(caps) is not dict
        or set(caps) != {"effective", "permitted", "inheritable"}
        or any(
            type(words) is not list
            or len(words) != 2
            or any(not _exact_int(word, 0) for word in words)
            for words in caps.values()
        )
    ):
        return None
    if document["landlock_allowed_paths"] != [
        {"path": path.as_posix(), "access": access} for path, access in _allow_paths()
    ]:
        return None
    return document


def _wait_report(pid: int, report_fd: int, timeout: float) -> BoundaryResult:
    os.set_blocking(report_fd, False)
    deadline = time.monotonic() + timeout
    payload = bytearray()
    wait_status: int | None = None
    pipe_open = True
    while time.monotonic() < deadline:
        if pipe_open:
            ready, _, _ = select.select(
                [report_fd], [], [], max(0.0, min(0.05, deadline - time.monotonic()))
            )
            if ready:
                part = os.read(report_fd, REPORT_LIMIT + 1 - len(payload))
                if part:
                    payload.extend(part)
                    if len(payload) > REPORT_LIMIT:
                        os.kill(pid, signal.SIGKILL)
                        _, status = os.waitpid(pid, 0)
                        return _refused(
                            RefusalCode.REPORT_OVERSIZE,
                            "child report exceeded its fixed bound",
                            reaped=True,
                            wait_status=status,
                        )
                else:
                    pipe_open = False
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            wait_status = status
            if not pipe_open:
                break
        if wait_status is not None and not pipe_open:
            break
    else:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        return _refused(
            RefusalCode.TIMEOUT,
            "boundary child exceeded its deadline",
            reaped=True,
            wait_status=status,
        )

    if wait_status is None:
        _, wait_status = os.waitpid(pid, 0)
    try:
        document = json.loads(bytes(payload), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _refused(
            RefusalCode.REPORT_INVALID,
            f"child report is not one JSON document: {exc}",
            reaped=True,
            wait_status=wait_status,
        )
    if type(document) is not dict or document.get("outcome") not in {
        Outcome.VERIFIED.value, Outcome.REFUSED.value,
    }:
        return _refused(
            RefusalCode.REPORT_INVALID,
            "child report lacks a closed outcome",
            reaped=True,
            wait_status=wait_status,
        )
    if document["outcome"] == Outcome.REFUSED.value:
        raw = document.get("refusal")
        try:
            if type(document) is not dict or set(document) != {"outcome", "refusal"}:
                raise TypeError
            if type(raw) is not dict or set(raw) != {"code", "detail"}:
                raise TypeError
            code = RefusalCode(raw["code"])
            detail = raw["detail"]
            if type(detail) is not str:
                raise TypeError
        except (KeyError, TypeError, ValueError):
            return _refused(
                RefusalCode.REPORT_INVALID,
                "child refusal is not typed",
                reaped=True,
                wait_status=wait_status,
            )
        return _refused(code, detail, reaped=True, wait_status=wait_status)
    verified = _validate_verified_document(document, wait_status)
    if verified is None:
        return _refused(
            RefusalCode.REPORT_INVALID,
            "verified report fails its exact schema, type, invariant, or exit check",
            reaped=True,
            wait_status=wait_status,
        )
    return BoundaryResult(
        Outcome.VERIFIED,
        verified,
        None,
        True,
        wait_status,
    )


def _launch(
    *,
    timeout: float,
    send_control: bool,
    repository_probe: pathlib.Path,
    test_delay: float = 0.0,
) -> BoundaryResult:
    capability = probe()
    if capability.refusal is not None:
        return _refused(capability.refusal.code, capability.refusal.detail)
    parent_namespaces = _namespace_identities()
    if not hasattr(os, "pidfd_open"):
        return _refused(
            RefusalCode.CLONE_REFUSED,
            "pidfd_open is required to close the parent-death race",
        )
    parent_pidfd = os.pidfd_open(os.getpid())
    control_read, control_write = os.pipe2(os.O_CLOEXEC)
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    try:
        try:
            pid = _clone_child(
                control_read,
                report_write,
                repository_probe,
                min(timeout, 1.0),
                test_delay,
                os.getpid(),
                parent_pidfd,
            )
        except OSError as exc:
            return _refused(
                RefusalCode.CLONE_REFUSED,
                f"atomic namespace clone refused: {exc}",
            )
        os.close(control_read)
        control_read = -1
        os.close(report_write)
        report_write = -1
        os.close(parent_pidfd)
        parent_pidfd = -1
        try:
            child_namespaces = _namespace_identities(pid)
            namespace_identities = _namespace_pair(
                parent_namespaces, child_namespaces)
            pathlib.Path(f"/proc/{pid}/uid_map").write_text(
                _uid_map(os.getuid()), encoding="ascii")
            uid_map = pathlib.Path(f"/proc/{pid}/uid_map").read_text()
            gid_map_text = pathlib.Path(f"/proc/{pid}/gid_map").read_text()
            id_maps = {
                "uid_map": uid_map,
                "gid_map": None if not gid_map_text.strip() else gid_map_text,
                "supplementary_groups": [],
            }
        except OSError as exc:
            os.close(control_write)
            control_write = -1
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            refusal_code = (
                RefusalCode.NAMESPACE_IDENTITY_REFUSED
                if exc.errno == errno.EPROTO
                else RefusalCode.UID_MAP_REFUSED
            )
            return _refused(
                refusal_code,
                f"parent namespace/UID-only evidence refused: "
                f"{type(exc).__name__}: {exc}",
                reaped=True,
                wait_status=status,
            )
        if send_control:
            control = json.dumps({
                "namespace_identities": namespace_identities,
                "id_maps": id_maps,
            }, sort_keys=True, separators=(",", ":")).encode()
            os.write(control_write, CONTROL_TOKEN + b"\n" + control)
        os.close(control_write)
        control_write = -1
        return _wait_report(pid, report_read, timeout)
    finally:
        for descriptor in (
            control_read, control_write, report_read, report_write, parent_pidfd
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def parent_death_probe(timeout: float = 2.0) -> dict[str, Any]:
    """Fork a protected child, kill its parent, and observe death by pidfd."""
    if not hasattr(os, "pidfd_open"):
        raise OSError(errno.ENOSYS, "pidfd_open is required")
    announce_read, announce_write = os.pipe2(os.O_CLOEXEC)
    release_read, release_write = os.pipe2(os.O_CLOEXEC)
    launcher = os.fork()
    if launcher == 0:
        try:
            os.close(announce_read)
            os.close(release_write)
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            original_parent = os.getpid()
            protected = os.fork()
            if protected == 0:
                os.close(ready_read)
                _prctl_checked(
                    PR_SET_PDEATHSIG, signal.SIGKILL, "PR_SET_PDEATHSIG"
                )
                if os.getppid() != original_parent:
                    os._exit(2)
                os.write(ready_write, PDEATH_READY_TOKEN)
                os.close(ready_write)
                signal.pause()
                os._exit(3)
            os.close(ready_write)
            ready, _, _ = select.select([ready_read], [], [], timeout)
            token = os.read(ready_read, 1) if ready else b""
            os.close(ready_read)
            if token != PDEATH_READY_TOKEN:
                os.kill(protected, signal.SIGKILL)
                os._exit(4)
            os.write(announce_write, f"{protected}\n".encode("ascii"))
            os.close(announce_write)
            released, _, _ = select.select([release_read], [], [], timeout)
            if not released or os.read(release_read, 1) != CONTROL_TOKEN:
                os.kill(protected, signal.SIGKILL)
                os._exit(5)
            os.close(release_read)
            os._exit(0)
        except BaseException:
            os._exit(6)

    os.close(announce_write)
    os.close(release_read)
    protected_pid: int | None = None
    pidfd = -1
    launcher_reaped = False
    try:
        ready, _, _ = select.select([announce_read], [], [], timeout)
        if not ready:
            raise TimeoutError("protected child did not arm parent-death signal")
        protected_pid = int(os.read(announce_read, 64).strip())
        pidfd = os.pidfd_open(protected_pid)
        os.write(release_write, CONTROL_TOKEN)
        _, launcher_status = os.waitpid(launcher, 0)
        launcher_reaped = True
        dead, _, _ = select.select([pidfd], [], [], timeout)
        if not dead:
            os.kill(protected_pid, signal.SIGKILL)
            raise TimeoutError("protected child survived its parent")
        return {
            "launcher_reaped": True,
            "launcher_wait_status": launcher_status,
            "protected_pid": protected_pid,
            "protected_pidfd_readable": True,
            "pdeath_signal": int(signal.SIGKILL),
        }
    finally:
        for descriptor in (announce_read, release_write, pidfd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if not launcher_reaped:
            waited, _ = os.waitpid(launcher, os.WNOHANG)
            if waited == 0:
                os.kill(launcher, signal.SIGKILL)
                os.waitpid(launcher, 0)
        if protected_pid is not None:
            try:
                os.kill(protected_pid, signal.SIGKILL)
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise


def run_boundary(
    timeout: float = 5.0,
    repository_probe: pathlib.Path = ROOT / "AGENTS.md",
) -> BoundaryResult:
    """Run one bounded disposable worker, or return a typed refusal."""
    if timeout <= 0 or timeout > 30:
        return _refused(
            RefusalCode.TIMEOUT,
            "timeout must be greater than zero and no more than 30 seconds",
        )
    return _launch(
        timeout=timeout,
        send_control=True,
        repository_probe=repository_probe.resolve(),
    )


def main() -> int:
    result = run_boundary()
    print(json.dumps(result.as_document(), indent=2, sort_keys=True))
    return 0 if result.outcome is Outcome.VERIFIED else 1


if __name__ == "__main__":
    raise SystemExit(main())
