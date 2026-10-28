# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Managed container log isolation, Engine framing and Agent dispatch."""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sovagrid_agent import container_log_broker as broker
from sovagrid_agent import service_broker
from sovagrid_agent.agent import _command_plan, run_once
from sovagrid_agent.container_logs import MARKER, parse_command, request_broker


IDENT = "a" * 64
OTHER = "b" * 64
NOW = 1_800_000_000


def frame(stream: int, body: bytes) -> bytes:
    return bytes((stream, 0, 0, 0)) + len(body).to_bytes(4, "big") + body


def inventory(*, ident=IDENT, timestamp=NOW, truncated=False):
    return {"collected_at": timestamp, "engines": [
        {"engine": "docker", "source_status": "ok", "truncated": truncated,
         "containers": [{"id": ident}]},
        {"engine": "podman", "source_status": "unavailable", "truncated": False,
         "containers": []},
    ]}


def inspect(*, ident=IDENT, project="sovagrid", service="hub", image="sovagrid-hub:local",
            tty=False):
    return {"Id": ident, "Config": {"Tty": tty, "Image": image,
            "Labels": {"com.docker.compose.project": project,
                       "com.docker.compose.service": service}}}


class ContainerLogsTests(unittest.TestCase):
    def test_agent_rejects_boolean_exit_code_from_broker(self):
        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _seconds):
                pass

            def connect(self, _path):
                pass

            def sendall(self, _raw):
                pass

            def recv(self, _limit):
                return b'{"state":"succeeded","exit_code":false,"output":"ok"}\n'

        with mock.patch("sovagrid_agent.container_logs.socket.socket", return_value=Connection()):
            with self.assertRaisesRegex(ValueError, "Invalid container log response"):
                request_broker("docker", IDENT, 10)

    def test_engine_request_is_fixed_read_only_and_never_follows(self):
        seen = []

        class Engine:
            def __init__(self, path, timeout):
                seen.append((path, timeout))

            def request(self, method, endpoint, headers):
                seen.append((method, endpoint, headers))

            def getresponse(self):
                return SimpleNamespace(status=200, read=lambda _size: frame(1, b"ok\n"))

            def close(self):
                seen.append("closed")

        with mock.patch.object(broker, "UnixHTTPConnection", Engine):
            self.assertEqual(broker._raw_logs(Path("/run/docker.sock"), IDENT, 10),
                             frame(1, b"ok\n"))
        self.assertEqual(seen[1], ("GET", f"/v1.40/containers/{IDENT}/logs?follow=0&stdout=1&stderr=1"
                                  "&timestamps=0&tail=10", {"Accept": "application/octet-stream"}))
        self.assertEqual(seen[-1], "closed")

    def test_agent_intercepts_only_canonical_full_id_request(self):
        command = f"{MARKER} read docker {IDENT} 25"
        self.assertEqual(parse_command(command), ("docker", IDENT, 25))
        for malformed in (f"{MARKER} read docker {IDENT[:12]} 25",
                          f"{MARKER} read docker {IDENT.upper()} 25",
                          f"{MARKER} read docker {IDENT} 025",
                          command + "; id", "echo " + command,
                          f"{MARKER} read docker {IDENT} 101"):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_command(malformed)
        with self.assertRaisesRegex(ValueError, "dedicated broker"):
            _command_plan(command, 15)

    def test_docker_frames_and_tty_reject_binary_and_control_text(self):
        self.assertEqual(broker._decode(frame(1, "Привет\n".encode()) + frame(2, b"warning\n"), tty=False),
                         "Привет\nwarning\n")
        self.assertEqual(broker._decode(b"raw tty\n", tty=True), "raw tty\n")
        for bad, tty in ((frame(0, b"stdin"), False),
                         (frame(1, b"x")[:-1], False),
                         (frame(1, b"a\x00b"), False),
                         (frame(1, b"\x1b[31m"), False),
                         (frame(1, b"\xff"), False),
                         (b"a\rhidden", True)):
            with self.subTest(bad=bad), self.assertRaises((ValueError, UnicodeError)):
                broker._decode(bad, tty=tty)
        with self.assertRaises(OverflowError):
            broker._decode(frame(1, b"x" * 8193), tty=False)

    def test_broker_checks_fresh_inventory_exact_inspect_and_labels_before_logs(self):
        calls = []

        def getter(_path, endpoint, **_):
            calls.append("inspect")
            self.assertEqual(endpoint, f"/containers/{IDENT}/json")
            return inspect()

        def logs(_path, ident, lines):
            calls.append("logs")
            self.assertEqual((ident, lines), (IDENT, 10))
            return frame(1, b"health ok\n")

        with mock.patch.object(broker, "_enabled"), mock.patch.object(broker, "_socket"):
            result = broker.execute("docker", IDENT, 10, snapshot=inventory(),
                                    getter=getter, logs_getter=logs, now=NOW)
            self.assertEqual(result, {"state": "succeeded", "exit_code": 0,
                                      "output": "health ok\n"})
            self.assertEqual(calls, ["inspect", "logs"])
            for denied in (inventory(ident=OTHER), inventory(timestamp=NOW - 91),
                           inventory(truncated=True)):
                calls.clear()
                with self.subTest(denied=denied), self.assertRaises(PermissionError):
                    broker.execute("docker", IDENT, 10, snapshot=denied,
                                   getter=getter, logs_getter=logs, now=NOW)
                self.assertEqual(calls, [])
            for changed in (inspect(ident=OTHER), inspect(project="other"),
                            inspect(service="db"), inspect(image="other:latest"),
                            inspect(tty="false")):
                calls.clear()
                with self.subTest(changed=changed), self.assertRaises(PermissionError):
                    broker.execute("docker", IDENT, 10, snapshot=inventory(),
                                   getter=lambda *_a, **_k: changed,
                                   logs_getter=logs, now=NOW)
                self.assertEqual(calls, [])

    def test_broker_has_total_deadline_even_for_trickling_engine(self):
        with mock.patch.object(broker, "_enabled"), mock.patch.object(broker, "_socket"), mock.patch.object(
                broker, "MAX_OPERATION_SECONDS", 0.02):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                broker.execute("docker", IDENT, 10, snapshot=inventory(), now=NOW,
                               getter=lambda *_a, **_k: inspect(),
                               logs_getter=lambda *_a: (time.sleep(0.2), b"")[1])
            self.assertLess(time.monotonic() - started, 0.1)

    def test_root_socket_transport_and_agent_result_do_not_use_shell(self):
        request = json.dumps({"operation": "container_logs", "engine": "docker",
                              "id": IDENT, "lines": 10}, separators=(",", ":")).encode() + b"\n"
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            self.assertEqual(service_broker._request(server),
                             ("container_logs", "docker", IDENT, 10))
        finally:
            server.close()
            client.close()
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            with mock.patch.object(service_broker, "_peer_identity", return_value=(1234, 1000)), mock.patch.object(
                    service_broker, "_main_pid", return_value=1234), mock.patch.object(
                    service_broker, "read_container_logs",
                    return_value={"state": "succeeded", "exit_code": 0, "output": "bounded log\n"}) as read:
                service_broker.handle_connection(server, 1000, "sovagrid-agent.service")
                self.assertEqual(json.loads(client.recv(1024))["output"], "bounded log\n")
                read.assert_called_once_with("docker", IDENT, 10)
        finally:
            server.close()
            client.close()
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            with mock.patch.object(service_broker, "_peer_identity", return_value=(1234, 1000)), mock.patch.object(
                    service_broker, "_main_pid", return_value=1234), mock.patch.object(
                    service_broker, "read_container_logs",
                    side_effect=http.client.IncompleteRead(b"partial")):
                service_broker.handle_connection(server, 1000, "sovagrid-agent.service")
            self.assertEqual(client.recv(1024), b"")
        finally:
            server.close()
            client.close()
        sent = []
        fake_client = SimpleNamespace(
            push_metrics=lambda _report: None,
            next_job=lambda: {"id": "job-1", "command": f"{MARKER} read docker {IDENT} 10"},
            send_result=lambda job_id, value: sent.append((job_id, value)))
        with mock.patch("sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent._request_container_logs",
                return_value={"state": "succeeded", "exit_code": 0, "output": "ok\n"}) as read, mock.patch(
                "sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, fake_client)
        read.assert_called_once_with("docker", IDENT, 10)
        shell.assert_not_called()
        self.assertEqual(sent, [("job-1", {"state": "succeeded", "exit_code": 0,
                                            "output": "ok\n"})])


if __name__ == "__main__":
    unittest.main()
