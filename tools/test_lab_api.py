#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import os
import pathlib
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

from tools import lab_api


class LabApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.socket_path = self.root / "private" / "lab.sock"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def request(request_id: str = "request-1", **extra: object) -> dict[str, object]:
        document: dict[str, object] = {
            "protocol": lab_api.SCHEMA,
            "requestId": request_id,
            "op": "observe",
            "objectiveId": "objective-1",
            "unitId": "unit-1",
            "afterSequence": 0,
            "limit": 10,
        }
        document.update(extra)
        return document

    def exchange(
        self,
        server: lab_api.LabApiServer,
        chunks: list[bytes],
        *,
        pause: float = 0,
    ) -> dict[str, object]:
        errors: list[BaseException] = []

        def serve() -> None:
            try:
                server.serve_once()
            except BaseException as exc:  # test thread must return failures
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(os.fspath(self.socket_path))
            for chunk in chunks:
                client.sendall(chunk)
                if pause:
                    time.sleep(pause)
            response = lab_api.receive_frame(client, server.max_frame_size)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]
        return response

    def test_same_user_chunked_request_and_private_modes(self) -> None:
        server = lab_api.LabApiServer(
            self.socket_path,
            lambda request: {
                "protocol": lab_api.SCHEMA,
                "requestId": request["requestId"],
                "kind": "denied",
                "code": "fixture",
                "reason": "hello",
            },
            io_timeout=1,
        )
        with server:
            frame = lab_api.encode_frame(self.request(), server.max_frame_size)
            response = self.exchange(server, [frame[:2], frame[2:7], frame[7:]], pause=0.01)
            self.assertEqual(lab_api.SCHEMA, response["protocol"])
            self.assertEqual("request-1", response["requestId"])
            self.assertEqual("denied", response["kind"])
            self.assertNotIn("result", response)
            self.assertEqual(0o700, self.socket_path.parent.stat().st_mode & 0o777)
            self.assertEqual(0o600, self.socket_path.stat().st_mode & 0o777)

    def test_oversize_malformed_extra_field_and_extra_bytes_are_denied(self) -> None:
        server = lab_api.LabApiServer(self.socket_path, lambda _: {"unexpected": True})
        with server:
            oversize = lab_api.HEADER.pack(server.max_frame_size + 1)
            malformed_body = b"{"
            malformed = lab_api.HEADER.pack(len(malformed_body)) + malformed_body
            extra_field = lab_api.encode_frame(
                self.request(extra="denied"), server.max_frame_size
            )
            valid_plus_extra = lab_api.encode_frame(
                self.request(request_id="request-2"), server.max_frame_size
            ) + b"x"
            cases = (
                (oversize, "frame_too_large"),
                (malformed, "malformed_json"),
                (extra_field, "invalid_request"),
                (valid_plus_extra, "extra_data"),
            )
            for frame, code in cases:
                with self.subTest(code=code):
                    response = self.exchange(server, [frame])
                    self.assertEqual(lab_api.ERROR_SCHEMA, response["protocol"])
                    self.assertEqual(code, response["code"])

    def test_partial_frame_times_out_with_bounded_denial(self) -> None:
        server = lab_api.LabApiServer(
            self.socket_path, lambda _: {}, io_timeout=0.05, accept_timeout=0.05
        )
        with server:
            response = self.exchange(server, [b"\x00\x00"])
            self.assertEqual(lab_api.ERROR_SCHEMA, response["protocol"])
            self.assertEqual("timeout", response["code"])

    def test_symlink_socket_parent_is_rejected(self) -> None:
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)

        with self.assertRaisesRegex(lab_api.LabApiError, "symlink"):
            lab_api.LabApiServer(link / "lab.sock", lambda _: {})

    def test_missing_peer_credentials_fail_before_socket_creation(self) -> None:
        server = lab_api.LabApiServer(self.socket_path, lambda _: {})
        with mock.patch.object(socket, "SO_PEERCRED", None):
            with self.assertRaises(lab_api.HostCapabilityMissing):
                server.start()
        self.assertFalse(self.socket_path.exists())

    def test_restart_reuses_injected_durable_handler_state(self) -> None:
        state = self.root / "handler.json"

        def durable(request: dict[str, object]) -> dict[str, object]:
            current = json.loads(state.read_text()) if state.exists() else {"count": 0}
            if request["op"] == "observe":
                current["count"] += 1
                state.write_text(json.dumps(current))
            return {
                "protocol": lab_api.SCHEMA,
                "requestId": request["requestId"],
                "kind": "denied",
                "code": "durable_fixture",
                "reason": str(current["count"]),
            }

        first = lab_api.LabApiServer(self.socket_path, durable)
        with first:
            response = self.exchange(
                first, [lab_api.encode_frame(self.request("first"), first.max_frame_size)]
            )
            self.assertEqual("1", response["reason"])
        second = lab_api.LabApiServer(self.socket_path, durable)
        with second:
            response = self.exchange(
                second, [lab_api.encode_frame(self.request("second"), second.max_frame_size)]
            )
            self.assertEqual("2", response["reason"])

    def test_serve_loop_stops_on_explicit_event(self) -> None:
        stop = threading.Event()
        server = lab_api.LabApiServer(self.socket_path, lambda _: {}, accept_timeout=0.02)
        with server:
            thread = threading.Thread(target=server.serve, args=(stop,))
            thread.start()
            stop.set()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
