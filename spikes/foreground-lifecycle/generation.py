#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Synthetic foreground generation used only by the R0-03 fixture."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys

from protocol import Endpoint, ProtocolError, ProtocolTimeout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument(
        "--behavior",
        choices=("normal", "fail-before-ready", "fail-after-ready"),
        default="normal",
    )
    args = parser.parse_args()
    if not args.generation.startswith("fixture-"):
        parser.error("generation must use the synthetic fixture- prefix")

    connection = socket.socket(fileno=args.control_fd)
    endpoint = Endpoint(connection)
    state = "warming"
    epoch = 0
    terminate = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal terminate
        terminate = True

    signal.signal(signal.SIGTERM, request_termination)

    def emit(kind: str, **fields: object) -> None:
        endpoint.send(
            {
                "type": kind,
                "generation": args.generation,
                "pid": os.getpid(),
                "state": state,
                **fields,
            }
        )

    emit("started")
    try:
        while True:
            if terminate:
                state = "stopping"
                emit("stopping", reason="signal")
                state = "stopped"
                emit("stopped", reason="signal")
                return 0
            try:
                command = endpoint.receive(0.1)
            except ProtocolTimeout:
                continue
            kind = command["type"]
            if kind == "complete_warmup" and state == "warming":
                if args.behavior == "fail-before-ready":
                    state = "failed"
                    emit("failed", phase="before-ready")
                    return 20
                state = "ready"
                emit("ready")
            elif kind == "activate" and state in {"ready", "quiesced"}:
                requested_epoch = command.get("epoch")
                if not isinstance(requested_epoch, int) or requested_epoch <= epoch:
                    raise ProtocolError("activate requires a strictly newer integer epoch")
                if args.behavior == "fail-after-ready":
                    state = "failed"
                    emit("failed", phase="after-ready", epoch=requested_epoch)
                    return 21
                epoch = requested_epoch
                state = "active"
                emit("active", epoch=epoch)
            elif kind == "probe":
                emit("state", epoch=epoch)
            elif kind == "quiesce" and state == "active":
                state = "quiesced"
                emit("quiesced", epoch=epoch)
            elif kind == "drain" and state in {"quiesced", "ready"}:
                state = "draining"
                emit("draining", epoch=epoch)
                state = "drained"
                emit("drained", epoch=epoch)
                return 0
            elif kind == "shutdown":
                state = "stopping"
                emit("stopping", reason="command")
                state = "stopped"
                emit("stopped", reason="command")
                return 0
            else:
                raise ProtocolError(f"command {kind!r} is invalid while {state}")
    except ProtocolError as exc:
        state = "protocol-error"
        try:
            emit("protocol_error", reason=str(exc))
        except (OSError, ProtocolError):
            pass
        return 64
    finally:
        endpoint.close()


if __name__ == "__main__":
    sys.exit(main())
