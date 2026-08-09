#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Behavior probe for the local harness worker sandbox."""

from __future__ import annotations

import os
import pathlib
import socket
import sys


def main() -> int:
    packet = pathlib.Path(sys.argv[-1])
    if not packet.is_file():
        return 10
    if os.environ.get("HOME") != "/nonexistent":
        return 11
    if any(pathlib.Path(".git").iterdir()):
        return 12
    try:
        with pathlib.Path("README.md").open("a"):
            pass
    except OSError:
        pass
    else:
        return 13
    temporary = pathlib.Path("/tmp/automonique-harness-probe")
    temporary.write_text("isolated\n")
    if temporary.read_text() != "isolated\n":
        return 14
    connection = socket.socket()
    connection.settimeout(0.2)
    try:
        result = connection.connect_ex(("1.1.1.1", 53))
    finally:
        connection.close()
    return 0 if result != 0 else 15


if __name__ == "__main__":
    sys.exit(main())
