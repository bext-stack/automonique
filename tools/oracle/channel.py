#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The one channel between the custody process and agent context.

The custody process is started here with exactly three descriptors it can
write to, and two of them go nowhere:

    fd 0  /dev/null      nothing to read
    fd 1  /dev/null      a print, a warning, a traceback: discarded by the OS
    fd 2  /dev/null      an interpreter crash message: discarded by the OS
    fd R  release pipe   read here, capped, and parsed by tools/oracle/release.py

`close_fds` is on and `pass_fds` names the release pipe alone, so the child
inherits no other descriptor of this process — not the parent's terminal, not
its log file, not a socket. That is what "raw output has no path to agent
context" means operationally: there is no second path to filter, because there
is no second path.

The child's environment is built from an allow list of variable *names*, so
this side never pushes a clean-side value into a contaminated process, and
never has to remember to strip one on the way back.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import selectors
import subprocess
import sys
import time

from tools.oracle import release
from tools.oracle import vocabulary as vocab

CLEAN_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = pathlib.Path(__file__).with_name("runner.py")
DEFAULT_ENVIRONMENT_NAMES: tuple[str, ...] = ("PATH", "HOME", "LANG", "TMPDIR")


@dataclasses.dataclass(frozen=True)
class Request:
    """What the clean side asks to have compared. Closed vocabulary both ways."""

    fixture: str
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if not vocab.FIXTURE_ID.fullmatch(self.fixture):
            raise vocab.VocabularyError("fixture ID must be lowercase and hyphenated")
        if not self.fields:
            raise vocab.VocabularyError("a request must name at least one field")
        if len(set(self.fields)) != len(self.fields):
            raise vocab.VocabularyError("a request names a field twice")

    def validate(self, registry: vocab.Registry) -> None:
        for field in self.fields:
            if registry.get(field) is None:
                raise vocab.VocabularyError("request names an unregistered field")

    def encode(self) -> str:
        # Built by hand from validated parts: this string lands in the child's
        # argv, which is world-readable in the process table.
        joined = ",".join(f'"{field}"' for field in self.fields)
        return f'{{"fixture":"{self.fixture}","fields":[{joined}]}}'


@dataclasses.dataclass(frozen=True)
class Custody:
    """The custody side: what holds legacy source, and where it runs."""

    plugin_path: pathlib.Path
    working_directory: pathlib.Path
    interpreter: str = sys.executable
    runner_path: pathlib.Path = RUNNER
    environment_names: tuple[str, ...] = DEFAULT_ENVIRONMENT_NAMES

    def __post_init__(self) -> None:
        vocab.check_environment_names(self.environment_names)

    def rejection(self) -> str | None:
        """Why this custody configuration cannot be run, or None."""
        plugin = self.plugin_path.resolve()
        if not plugin.is_file():
            return "plugin"
        if plugin.is_relative_to(CLEAN_ROOT):
            # Legacy source inside the clean repository is the contamination
            # this gate exists to prevent; refuse before running anything.
            return "plugin-inside-clean-root"
        working = self.working_directory.resolve()
        if not working.is_dir():
            return "working-directory"
        if working.is_relative_to(CLEAN_ROOT):
            return "working-directory-inside-clean-root"
        if not self.runner_path.resolve().is_file():
            return "runner"
        return None

    def environment(self) -> dict[str, str]:
        inherited = {
            name: os.environ[name]
            for name in self.environment_names
            if name in os.environ
        }
        inherited["AUTOMONIQUE_ORACLE_PLUGIN"] = str(self.plugin_path.resolve())
        return inherited


@dataclasses.dataclass(frozen=True)
class ChannelConfig:
    """How much the channel will wait for, and how much it will let through."""

    deadline_seconds: float = 30.0
    policy: vocab.ReleasePolicy = vocab.ReleasePolicy.FIELD_RELATIONS
    record_limit: int = vocab.RECORD_LIMIT
    # Return only at the deadline, so the custody process cannot signal through
    # how long it took. Costs one deadline per comparison; measured in
    # tools/oracle/test_boundary.py.
    hold_release: bool = True
    restrict_to_requested_fields: bool = True


def compare(
    request: Request,
    custody: Custody,
    *,
    registry: vocab.Registry,
    config: ChannelConfig = ChannelConfig(),
) -> release.Verdict:
    """Run one comparison and return the only value allowed out of it."""
    started = time.monotonic()
    deadline = started + config.deadline_seconds
    try:
        request.validate(registry)
    except vocab.VocabularyError:
        return _hold(release.refused(vocab.Refusal.CUSTODY_REJECTED), deadline, config)
    if custody.rejection() is not None:
        return _hold(release.refused(vocab.Refusal.CUSTODY_REJECTED), deadline, config)

    raw, oversize, timed_out = None, False, False
    read_fd, write_fd = os.pipe()
    process = None
    try:
        process = subprocess.Popen(
            [
                custody.interpreter,
                # -I: no PYTHON* variable of this side reaches the child and no
                # directory is prepended to its import path.
                # -B: no compiled copy of legacy source is left in the custody
                # tree, and no stale one is created for the next run to read.
                "-I",
                "-B",
                str(custody.runner_path.resolve()),
                str(write_fd),
                request.encode(),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(custody.working_directory.resolve()),
            env=custody.environment(),
            pass_fds=(write_fd,),
            close_fds=True,
        )
    except OSError:
        os.close(write_fd)
        os.close(read_fd)
        return _hold(release.refused(vocab.Refusal.CUSTODY_REJECTED), deadline, config)

    try:
        os.close(write_fd)
        raw, oversize, timed_out = _read_capped(read_fd, config.record_limit, deadline)
    finally:
        os.close(read_fd)
        failed = _reap(process, deadline)

    if timed_out:
        return _hold(release.TIMED_OUT, deadline, config)
    if oversize:
        return _hold(release.refused(vocab.Refusal.OVERSIZE), deadline, config)
    if failed:
        # Fail closed: a custody process that crashed or was killed cannot
        # vouch for whatever it managed to write first.
        return _hold(release.refused(vocab.Refusal.INSIDE_FAILED), deadline, config)

    verdict = release.parse(
        raw,
        registry=registry,
        policy=config.policy,
        requested=request.fields if config.restrict_to_requested_fields else None,
        limit=config.record_limit,
    )
    del raw
    return _hold(verdict, deadline, config)


def _read_capped(
    read_fd: int, limit: int, deadline: float
) -> tuple[bytes | None, bool, bool]:
    """Read at most `limit` bytes before `deadline`. Oversize is discarded whole."""
    selector = selectors.DefaultSelector()
    selector.register(read_fd, selectors.EVENT_READ)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, False, True
            if not selector.select(remaining):
                return None, False, True
            try:
                chunk = os.read(read_fd, 4096)
            except OSError:
                return None, False, False
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return None, True, False
            chunks.append(chunk)
    finally:
        selector.close()
    return b"".join(chunks), False, False


def _reap(process: subprocess.Popen, deadline: float) -> bool:
    """Wait for the custody process; kill it at the deadline. True if it failed."""
    remaining = max(0.0, deadline - time.monotonic())
    try:
        code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return True
    return code != 0


def _hold(
    verdict: release.Verdict, deadline: float, config: ChannelConfig
) -> release.Verdict:
    if config.hold_release:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    return verdict
