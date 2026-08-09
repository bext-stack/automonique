# SPDX-License-Identifier: Elastic-2.0

"""Bounded JSON-line control protocol for the execution-host fixture."""

from __future__ import annotations

import json
import socket
from typing import Any

MAX_FRAME = 4096


class ProtocolError(Exception):
    pass


class Endpoint:
    def __init__(self, connection: socket.socket, timeout: float) -> None:
        self.connection = connection
        self.connection.settimeout(timeout)
        self.buffer = bytearray()

    def send(self, message: dict[str, Any]) -> None:
        if not isinstance(message.get("type"), str):
            raise ProtocolError("message type must be a string")
        frame = (json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(frame) > MAX_FRAME:
            raise ProtocolError(f"frame exceeds {MAX_FRAME} bytes")
        self.connection.sendall(frame)

    def receive(self) -> dict[str, Any]:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                try:
                    message = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProtocolError("invalid JSON frame") from exc
                if not isinstance(message, dict) or not isinstance(message.get("type"), str):
                    raise ProtocolError("frame must be an object with a string type")
                return message
            if len(self.buffer) > MAX_FRAME:
                raise ProtocolError(f"frame exceeds {MAX_FRAME} bytes")
            chunk = self.connection.recv(MAX_FRAME + 1)
            if not chunk:
                raise ProtocolError("control channel closed")
            self.buffer.extend(chunk)

    def close(self) -> None:
        self.connection.close()
