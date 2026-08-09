# SPDX-License-Identifier: Elastic-2.0

"""Small bounded JSON-line protocol over an already-open local socket."""

from __future__ import annotations

import json
import select
import socket
import time
from typing import Any

MAX_FRAME = 4096


class ProtocolError(Exception):
    pass


class ProtocolTimeout(ProtocolError):
    pass


class Endpoint:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.connection.setblocking(False)
        self.buffer = bytearray()

    def send(self, message: dict[str, Any]) -> None:
        if not isinstance(message.get("type"), str):
            raise ProtocolError("message type must be a string")
        frame = (json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(frame) > MAX_FRAME:
            raise ProtocolError(f"frame exceeds {MAX_FRAME} bytes")
        self.connection.setblocking(True)
        try:
            self.connection.sendall(frame)
        finally:
            self.connection.setblocking(False)

    def receive(self, timeout: float) -> dict[str, Any]:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        deadline = time.monotonic() + timeout
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolTimeout("timed out waiting for lifecycle frame")
            readable, _, _ = select.select([self.connection], [], [], remaining)
            if not readable:
                raise ProtocolTimeout("timed out waiting for lifecycle frame")
            chunk = self.connection.recv(MAX_FRAME + 1)
            if not chunk:
                raise ProtocolError("lifecycle channel closed")
            self.buffer.extend(chunk)

    def close(self) -> None:
        self.connection.close()
