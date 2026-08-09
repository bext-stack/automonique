#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Bounded same-user local protocol for the bootstrap lab controller."""

from __future__ import annotations

import json
import os
import pathlib
import re
import socket
import stat
import struct
import threading
from collections.abc import Callable
from typing import Any


SCHEMA = "automonique.lab-scenario/v1"
ERROR_SCHEMA = "automonique.lab-transport-error/v1"
HEADER = struct.Struct(">I")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
REQUEST_FIELDS = {
    "select": frozenset(
        {
            "protocol",
            "requestId",
            "op",
            "objectiveId",
            "expectedBase",
            "execution",
            "providerPolicy",
            "budget",
        }
    ),
    "observe": frozenset(
        {"protocol", "requestId", "op", "objectiveId", "unitId", "afterSequence", "limit"}
    ),
    "resume": frozenset(
        {
            "protocol",
            "requestId",
            "op",
            "objectiveId",
            "unitId",
            "checkpointId",
            "expectedRevision",
            "idempotencyKey",
        }
    ),
    "cancel": frozenset(
        {
            "protocol",
            "requestId",
            "op",
            "objectiveId",
            "unitId",
            "expectedRevision",
            "idempotencyKey",
            "reason",
        }
    ),
}


class LabApiError(Exception):
    """The local API cannot safely continue."""


class HostCapabilityMissing(LabApiError):
    """Required local peer authentication is unavailable."""


class ProtocolError(LabApiError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _reject_symlink_components(path: pathlib.Path) -> pathlib.Path:
    supplied = pathlib.Path(os.path.abspath(os.fspath(path)))
    current = pathlib.Path(supplied.anchor)
    for part in supplied.parts[1:]:
        current /= part
        if current.is_symlink():
            raise LabApiError("socket path must not contain a symlink")
    return supplied


def _validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise ProtocolError("invalid_json_value", "JSON nesting exceeds the protocol limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise ProtocolError("invalid_json_value", "floating-point values are not supported")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ProtocolError("invalid_json_value", "JSON object keys must be strings")
        for item in value.values():
            _validate_json_value(item, depth + 1)
        return
    raise ProtocolError("invalid_json_value", "unsupported JSON value")


def canonical_json(document: dict[str, Any]) -> bytes:
    _validate_json_value(document)
    try:
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid_json_value", "document is not canonical JSON") from exc


def encode_frame(document: dict[str, Any], max_frame_size: int) -> bytes:
    payload = canonical_json(document)
    if not payload or len(payload) > max_frame_size:
        raise ProtocolError("frame_too_large", "frame exceeds the configured maximum")
    return HEADER.pack(len(payload)) + payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ProtocolError("malformed_json", "duplicate JSON object key")
        document[key] = value
    return document


def decode_payload(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_unique_object)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed_json", "request is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ProtocolError("invalid_request", "request root must be an object")
    _validate_json_value(document)
    if canonical_json(document) != payload:
        raise ProtocolError("noncanonical_json", "request JSON is not canonical")
    return document


def validate_request(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("protocol") != SCHEMA:
        raise ProtocolError("unsupported_version", "request schema version is unsupported")
    request_id = document.get("requestId")
    operation = document.get("op")
    if not isinstance(request_id, str) or not IDENTIFIER.fullmatch(request_id):
        raise ProtocolError("invalid_request", "requestId is invalid")
    if not isinstance(operation, str) or operation not in REQUEST_FIELDS:
        raise ProtocolError("invalid_request", "request op is unknown")
    if set(document) != REQUEST_FIELDS[operation]:
        raise ProtocolError("invalid_request", "request fields differ from the closed schema")
    for field in ("objectiveId", "unitId", "checkpointId", "idempotencyKey"):
        if field in document and (
            not isinstance(document[field], str) or not IDENTIFIER.fullmatch(document[field])
        ):
            raise ProtocolError("invalid_request", f"{field} is invalid")
    for field in ("afterSequence", "limit", "expectedRevision"):
        if field in document and (
            not isinstance(document[field], int)
            or isinstance(document[field], bool)
            or document[field] < (1 if field == "limit" else 0)
        ):
            raise ProtocolError("invalid_request", f"{field} is invalid")
    if operation == "observe" and document["limit"] > 1000:
        raise ProtocolError("invalid_request", "limit exceeds 1000")
    if operation == "cancel" and document["reason"] not in {
        "operator_request",
        "budget_exhausted",
        "policy_denied",
    }:
        raise ProtocolError("invalid_request", "cancel reason is unknown")
    if operation == "select":
        if not isinstance(document["expectedBase"], str) or not SHA1.fullmatch(
            document["expectedBase"]
        ):
            raise ProtocolError("invalid_request", "expectedBase is invalid")
        if document["execution"] not in {"synthetic", "inventory"}:
            raise ProtocolError("invalid_request", "execution is unknown")
        if not isinstance(document["providerPolicy"], dict) or not isinstance(
            document["budget"], dict
        ):
            raise ProtocolError("invalid_request", "select policy and budget must be objects")
    return document


class LabApiServer:
    """Sequential local Unix-socket server with one exchange per connection."""

    def __init__(
        self,
        socket_path: pathlib.Path,
        handler: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        max_frame_size: int = 65536,
        accept_timeout: float = 0.1,
        io_timeout: float = 0.5,
    ) -> None:
        if not callable(handler):
            raise LabApiError("handler must be callable")
        if not isinstance(max_frame_size, int) or not 256 <= max_frame_size <= 16 * 1024 * 1024:
            raise LabApiError("max_frame_size is outside the bounded range")
        if accept_timeout <= 0 or io_timeout <= 0:
            raise LabApiError("socket timeouts must be positive")
        self.socket_path = _reject_symlink_components(socket_path)
        self.handler = handler
        self.max_frame_size = max_frame_size
        self.accept_timeout = accept_timeout
        self.io_timeout = io_timeout
        self._socket: socket.socket | None = None
        self._bound_identity: tuple[int, int] | None = None

    @staticmethod
    def _require_peer_credentials() -> None:
        if not hasattr(socket, "SO_PEERCRED") or not isinstance(socket.SO_PEERCRED, int):
            raise HostCapabilityMissing("Linux SO_PEERCRED is unavailable")

    def start(self) -> None:
        if self._socket is not None:
            raise LabApiError("server is already started")
        self._require_peer_credentials()
        parent = self.socket_path.parent
        _reject_symlink_components(parent)
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink():
            raise LabApiError("socket parent must not be a symlink")
        os.chmod(parent, 0o700)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise LabApiError("socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.settimeout(self.accept_timeout)
            listener.bind(os.fspath(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            listener.listen(8)
            metadata = self.socket_path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode):
                raise LabApiError("bound path is not a Unix socket")
            self._bound_identity = (metadata.st_dev, metadata.st_ino)
            self._socket = listener
        except Exception:
            listener.close()
            try:
                if self.socket_path.exists() and stat.S_ISSOCK(self.socket_path.lstat().st_mode):
                    self.socket_path.unlink()
            except OSError:
                pass
            raise

    def close(self) -> None:
        listener, self._socket = self._socket, None
        if listener is not None:
            listener.close()
        try:
            metadata = self.socket_path.lstat()
            identity = (metadata.st_dev, metadata.st_ino)
            if self._bound_identity == identity and stat.S_ISSOCK(metadata.st_mode):
                self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self._bound_identity = None

    def __enter__(self) -> "LabApiServer":
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _recv_exact(connection: socket.socket, size: int) -> bytes:
        body = bytearray()
        while len(body) < size:
            try:
                chunk = connection.recv(size - len(body))
            except socket.timeout as exc:
                raise ProtocolError("timeout", "request frame timed out") from exc
            if not chunk:
                raise ProtocolError("truncated_frame", "connection closed within a frame")
            body.extend(chunk)
        return bytes(body)

    def _send(self, connection: socket.socket, document: dict[str, Any]) -> None:
        try:
            connection.sendall(encode_frame(document, self.max_frame_size))
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return

    def _error(
        self, connection: socket.socket, code: str, message: str, request_id: str | None = None
    ) -> None:
        self._send(
            connection,
            {
                "code": code,
                "protocol": ERROR_SCHEMA,
                "reason": message,
            },
        )

    def _peer_is_same_user(self, connection: socket.socket) -> bool:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack("3i", credentials)
        return uid == os.getuid()

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(self.io_timeout)
        if not self._peer_is_same_user(connection):
            self._error(connection, "peer_denied", "peer uid is not authorized")
            return
        request_id: str | None = None
        try:
            size = HEADER.unpack(self._recv_exact(connection, HEADER.size))[0]
            if size == 0 or size > self.max_frame_size:
                raise ProtocolError("frame_too_large", "frame exceeds the configured maximum")
            document = decode_payload(self._recv_exact(connection, size))
            if isinstance(document.get("requestId"), str):
                request_id = document["requestId"]
            validate_request(document)
            previous_timeout = connection.gettimeout()
            connection.setblocking(False)
            try:
                extra = connection.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                extra = b""
            finally:
                connection.settimeout(previous_timeout)
            if extra:
                raise ProtocolError("extra_data", "connection contains more than one frame")
            try:
                result = self.handler(document)
            except Exception:
                self._error(connection, "handler_error", "request handler failed", request_id)
                return
            if not isinstance(result, dict):
                raise ProtocolError("invalid_handler_result", "handler result must be an object")
            _validate_json_value(result)
            if result.get("protocol") != SCHEMA or result.get("requestId") != request_id:
                raise ProtocolError(
                    "invalid_handler_result", "handler response coordinates differ from request"
                )
            self._send(connection, result)
        except ProtocolError as exc:
            self._error(connection, exc.code, exc.message, request_id)

    def serve_once(self) -> bool:
        if self._socket is None:
            raise LabApiError("server is not started")
        try:
            connection, _ = self._socket.accept()
        except socket.timeout:
            return False
        with connection:
            self._handle(connection)
        return True

    def serve(self, stop_event: threading.Event) -> None:
        if not isinstance(stop_event, threading.Event):
            raise LabApiError("serve requires an explicit threading.Event")
        while not stop_event.is_set():
            self.serve_once()


def receive_frame(connection: socket.socket, max_frame_size: int) -> dict[str, Any]:
    """Bounded client-side decoder used by local tests and future typed clients."""

    header = LabApiServer._recv_exact(connection, HEADER.size)
    size = HEADER.unpack(header)[0]
    if size == 0 or size > max_frame_size:
        raise ProtocolError("frame_too_large", "response frame exceeds the configured maximum")
    return decode_payload(LabApiServer._recv_exact(connection, size))
