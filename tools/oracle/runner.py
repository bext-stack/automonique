#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The custody-side entry point. This file runs on the side that holds legacy source.

It is deliberately standalone — it imports nothing from this repository — so it
can be copied to the custody host on its own. It is also, deliberately,
**untrusted**: it executes in the same process as the legacy plugin, so a
plugin can rebind anything in it. Nothing here is a security control.

What it does is stop *accidental* leaks at their source, which is where they
are cheapest to stop:

1. it seals file descriptors 1 and 2 onto the null device before the plugin is
   imported, so a `print`, a warning, a traceback or an interpreter crash
   message goes nowhere. It does this at the descriptor level, not by
   reassigning `sys.stdout`, because a C extension writing to fd 2 does not
   consult `sys`;
2. it converts every exception — including `BaseException` — into a typed
   record with no message, no exception class name and no traceback;
3. it refuses to emit a record larger than the wire limit.

The security control is `tools/oracle/release.py` on the other side, which
assumes this file is hostile.
"""

from __future__ import annotations

import json
import os
import sys
import types

# Kept in step with tools/oracle/vocabulary.py by tools/oracle/check_boundary.py.
# Duplicated rather than imported so this file can travel alone.
RELEASE_SCHEMA = "automonique.oracle-release/v1"
ERROR_OUTCOME = "oracle_error"
REJECTED_OUTCOME = "input_rejected"
RECORD_LIMIT = 4096

PLUGIN_VARIABLE = "AUTOMONIQUE_ORACLE_PLUGIN"


def seal_standard_streams() -> None:
    """Point fds 1 and 2 at the null device, irrevocably for this process."""
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, 1)
        os.dup2(null, 2)
    finally:
        if null > 2:
            os.close(null)
    sink = open(os.devnull, "w", encoding="ascii")
    sys.stdout = sink
    sys.stderr = sink


def encode(outcome: str, differences: object) -> bytes:
    record = {
        "schema": RELEASE_SCHEMA,
        "outcome": outcome,
        "differences": differences,
    }
    return json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def error_record() -> bytes:
    return encode(ERROR_OUTCOME, [])


def observation_record(observation: object) -> bytes:
    """Encode a plugin observation, or an error record if it is not encodable."""
    if not isinstance(observation, dict) or set(observation) != {
        "outcome",
        "differences",
    }:
        return encode(REJECTED_OUTCOME, [])
    try:
        record = encode(observation["outcome"], observation["differences"])
    except (TypeError, ValueError, RecursionError):
        return error_record()
    if len(record) > RECORD_LIMIT:
        return error_record()
    return record


def load_plugin(path: str) -> object:
    """Compile the plugin from source, deliberately bypassing `__pycache__`.

    Measured, not theorised: importing the entry point through
    `importlib` re-ran a cached `.pyc` whose source had already been edited,
    because bytecode validity is (source mtime in whole seconds, source size)
    and an edit of the same length inside the same second matches both. A
    parity oracle that reports a comparison produced by a stale compiled copy
    of the legacy implementation is wrong in the one way it must never be
    wrong, and silently. `tools/oracle/test_boundary.py` reproduces it.

    The guarantee covers the entry point. Whatever the plugin then imports
    uses the ordinary machinery; `sys.dont_write_bytecode` at least keeps this
    process from leaving compiled legacy code behind in the custody tree.
    """
    sys.dont_write_bytecode = True
    with open(path, "rb") as handle:
        source = handle.read()
    module = types.ModuleType("automonique_oracle_plugin")
    module.__file__ = path
    # exec, deliberately: this side runs arbitrary custody code by definition.
    # The control is that nothing this process produces is trusted.
    exec(compile(source, path, "exec"), module.__dict__)
    return module


def run(release_fd: int, request_json: str) -> int:
    try:
        plugin = load_plugin(os.environ[PLUGIN_VARIABLE])
        request = json.loads(request_json)
        record = observation_record(plugin.observe(request))
    except BaseException:
        record = error_record()
    try:
        os.write(release_fd, record)
    except OSError:
        return 1
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    try:
        release_fd = int(argv[1])
    except ValueError:
        return 2
    if release_fd <= 2:
        # Sealing would destroy the release descriptor. Refuse instead.
        return 2
    seal_standard_streams()
    return run(release_fd, argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
