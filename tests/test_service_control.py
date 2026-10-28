# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Service policy and broker tests; no system service is touched."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sovagrid_agent.agent import _command_plan, load_config, run_command, run_once
from sovagrid_agent.service_control import (MARKER, job_result, parse_command,
                                           request_broker, validate_response,
                                           SOCKET_PATH, LOCAL_SOCKET_PATH)
from sovagrid_agent import service_broker as broker


SHOW = "Id=nginx.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
IDENTITY = "Id=nginx.service\nNames=nginx.service\nLoadState=loaded\n"
POLICY = {"nginx.service": frozenset(("status", "restart"))}


class FakeSystemctl:
    def __init__(self, *, operation_rc=0, show=SHOW, identity=IDENTITY, timeout_action=None):
        self.calls = []
        self.operation_rc = operation_rc
        self.show = show
        self.identity = identity
        self.timeout_action = timeout_action

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        action = "show" if "show" in argv else argv[-2]
        if action == self.timeout_action:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if action == "show":
            return subprocess.CompletedProcess(argv, 0,
                                               self.identity if "--property=Id,Names,LoadState" in argv else self.show,
                                               "")
        return subprocess.CompletedProcess(argv, self.operation_rc, None, None)


class ServiceControlTests(unittest.TestCase):
    def test_socket_profiles_read_independent_root_policies(self):
        self.assertEqual(broker.policy_paths_for_socket(SOCKET_PATH),
                         (Path("/etc/sovagrid-service/units.json"),
                          Path("/etc/sovagrid-service/enabled")))
        self.assertEqual(broker.policy_paths_for_socket(LOCAL_SOCKET_PATH),
                         (Path("/etc/sovagrid-service-local/units.json"),
                          Path("/etc/sovagrid-service-local/enabled")))
        with self.assertRaises(ValueError):
            broker.policy_paths_for_socket("/tmp/control.sock")

    def test_command_marker_is_exact_and_never_reaches_shell(self):
        command = f"{MARKER} restart nginx.service"
        self.assertEqual(parse_command(command), ("restart", "nginx.service"))
        self.assertEqual(parse_command(f"{MARKER} status ssh.service"), ("status", "ssh.service"))
        with self.assertRaises(ValueError):
            parse_command(f"{MARKER} restart ssh.service")
        with self.assertRaisesRegex(ValueError, "isolated broker"):
            _command_plan(command, 15)
        bad = (f"{MARKER} restart ssh.service;id",
               f"{MARKER} restart nginx@.service",
               f"{MARKER}  restart nginx.service",
               f"echo {MARKER} restart nginx.service",
               f"{MARKER} restart ../nginx.service",
               f"{MARKER} enable nginx.service",
               f"{MARKER} restart nginx.service && id")
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as process:
            for value in bad:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    run_command(value)
            process.assert_not_called()

    def test_policy_requires_root_marker_and_per_unit_actions(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            marker, policy = folder / "enabled", folder / "units.json"
            marker.write_bytes(b"enabled\n")
            policy.write_bytes(b'{"version":1,"units":{"nginx.service":["status","restart"]}}')
            folder.chmod(0o755)
            marker.chmod(0o600)
            policy.chmod(0o600)
            actual_lstat, actual_fstat = Path.lstat, os.fstat

            def root_lstat(path):
                info = actual_lstat(path)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

            def root_fstat(fd):
                info = actual_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                                       st_nlink=info.st_nlink, st_size=info.st_size)

            with mock.patch("sovagrid_agent.service_broker.Path.lstat", root_lstat), mock.patch(
                    "sovagrid_agent.service_broker.os.fstat", side_effect=root_fstat):
                # tmp's ordinary mode is not an approved policy directory.
                with self.assertRaises(PermissionError):
                    broker.read_policy(policy, marker)
                folder.chmod(0o700)
                self.assertEqual(broker.read_policy(policy, marker), POLICY)
                for raw in (b'{"version":1,"units":{"nginx.service":["restart","restart"]}}',
                            b'{"version":1,"units":{"nginx.service":["status","enable"]}}',
                            b'{"version":1,"units":{"nginx.service":["status"]},"x":1}',
                            b'{"version":1,"units":{"nginx.service":["status"],"nginx.service":["restart"]}}',
                            b'{"version":1,"units":{"nginx@.service":["status"]}}'):
                    policy.write_bytes(raw)
                    with self.subTest(raw=raw), self.assertRaises(ValueError):
                        broker.read_policy(policy, marker)
                policy.write_bytes(b'{"version":1,"units":{"nginx.service":["status"]}}')
                marker.write_bytes(b"disabled")
                with self.assertRaises(PermissionError):
                    broker.read_policy(policy, marker)
                marker.write_bytes(b"enabled\n")
                policy.chmod(0o644)
                with self.assertRaises(PermissionError):
                    broker.read_policy(policy, marker)
                policy.unlink()
                policy.symlink_to(folder / "elsewhere")
                with self.assertRaises(OSError):
                    broker.read_policy(policy, marker)

    def test_fixed_argv_and_whitelisted_state(self):
        fake = FakeSystemctl()
        public = broker.execute("restart", "nginx.service", POLICY, fake)
        self.assertEqual(public["result"], "ok")
        self.assertEqual(public["active_state"], "active")
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(fake.calls[0][0][-2:], ["show", "nginx.service"])
        self.assertEqual(fake.calls[1][0][-2:], ["restart", "nginx.service"])
        self.assertEqual(fake.calls[2][0][-2:], ["show", "nginx.service"])
        self.assertNotIn("/bin/sh", str(fake.calls))
        with self.assertRaises(PermissionError):
            broker.execute("stop", "nginx.service", POLICY, fake)
        with self.assertRaises(ValueError):
            broker.execute("restart", "ssh.service", POLICY, fake)
        self.assertEqual(len(fake.calls), 3)

    def test_mutation_timeout_and_nonzero_are_uncertain(self):
        timed_out = FakeSystemctl(timeout_action="restart")
        value = broker.execute("restart", "nginx.service", POLICY, timed_out)
        self.assertEqual(value["result"], "uncertain")
        self.assertIsNone(value["active_state"])
        self.assertEqual(len(timed_out.calls), 2)
        nonzero = FakeSystemctl(operation_rc=1)
        value = broker.execute("restart", "nginx.service", POLICY, nonzero)
        self.assertEqual(value["result"], "uncertain")
        self.assertEqual(value["active_state"], "active")
        self.assertEqual(job_result(value, "restart", "nginx.service")["state"], "timed_out")

    def test_mutation_success_with_mismatched_observed_state_is_uncertain(self):
        failed = SHOW.replace("ActiveState=active", "ActiveState=failed")
        start_policy = {"nginx.service": frozenset(("start", "restart", "stop"))}
        for action in ("start", "restart"):
            with self.subTest(action=action):
                value = broker.execute(action, "nginx.service", start_policy,
                                       FakeSystemctl(show=failed))
                self.assertEqual(value["result"], "uncertain")
                self.assertEqual(value["active_state"], "failed")
        value = broker.execute("stop", "nginx.service", start_policy, FakeSystemctl())
        self.assertEqual(value["result"], "uncertain")
        self.assertEqual(value["active_state"], "active")

    def test_mutation_preflight_rejects_critical_alias_before_systemctl_action(self):
        for identity in (
                "Id=nginx.service\nNames=nginx.service sovagrid-agent.service\nLoadState=loaded\n",
                "Id=sovagrid-agent.service\nNames=nginx.service sovagrid-agent.service\nLoadState=loaded\n",
                "Id=nginx.service\nNames=nginx.service\nLoadState=masked\n",
                "Id=nginx.service\nLoadState=loaded\n"):
            fake = FakeSystemctl(identity=identity)
            with self.subTest(identity=identity):
                value = broker.execute("restart", "nginx.service", POLICY, fake)
                self.assertEqual(value["result"], "failed")
                self.assertEqual(len(fake.calls), 1)
                self.assertEqual(fake.calls[0][0][-2:], ["show", "nginx.service"])

    def test_agent_identity_is_rechecked_after_mutation_preflight(self):
        fake = FakeSystemctl()
        with self.assertRaises(PermissionError):
            broker.execute("restart", "nginx.service", POLICY, fake,
                           pre_action_check=lambda: False)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0][0][-2:], ["show", "nginx.service"])

    def test_protected_units_remain_readable_but_cannot_mutate(self):
        for unit in ("sovagrid-agent.service", "reverse-tunnel.service", "ssh.service",
                     "sshd@host.service", "docker.service", "systemd-networkd.service",
                     "awg-quick@awg0.service"):
            with self.subTest(unit=unit):
                show = SHOW.replace("nginx.service", unit)
                fake = FakeSystemctl(show=show)
                status = broker.execute("status", unit, {unit: frozenset(("status", "restart"))}, fake)
                self.assertEqual(status["result"], "ok")
                with self.assertRaises(ValueError):
                    broker.execute("restart", unit, {unit: frozenset(("status", "restart"))}, fake)
                self.assertEqual(len(fake.calls), 1)

    def test_status_rejects_extra_properties_and_wrong_unit(self):
        for output in (SHOW + "ExecStart=SECRET\n",
                       SHOW.replace("Id=nginx.service", "Id=ssh.service"),
                       SHOW + "ActiveState=inactive\n",
                       SHOW.replace("SubState=running", "SubState=secret/path")):
            fake = FakeSystemctl(show=output)
            result = broker.execute("status", "nginx.service", POLICY, fake)
            self.assertEqual(result["result"], "failed")
            self.assertIsNone(result["active_state"])
        with self.assertRaises(ValueError):
            validate_response({"action": "status", "unit": "nginx.service",
                               "result": "ok", "load_state": "loaded",
                               "active_state": "active", "sub_state": "running",
                               "private": "SECRET"}, "status", "nginx.service")

    def test_socket_peer_policy_and_canonical_request(self):
        good = b'{"action":"status","unit":"nginx.service"}\n'
        bad = (b'{"unit":"nginx.service","action":"status"}\n',
               b'{"action":"status", "unit":"nginx.service"}\n',
               b'{"action":"status","unit":"nginx.service","x":1}\n',
               b'{"action":"status","action":"restart","unit":"nginx.service"}\n')
        for raw in bad:
            server, client = socket.socketpair()
            try:
                client.sendall(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    broker._request(server)
            finally:
                server.close()
                client.close()
        for peer, main_pid, allow in ((1000, 1234, True), (1001, 1234, False),
                                      (1000, 5678, False)):
            server, client = socket.socketpair()
            try:
                client.sendall(good)
                with mock.patch.object(broker, "_peer_identity", return_value=(1234, peer)), mock.patch.object(
                        broker, "_main_pid", return_value=main_pid) as current_pid, mock.patch.object(
                        broker, "read_policy", return_value=POLICY) as policy, mock.patch.object(
                        broker, "execute", return_value={"action": "status", "unit": "nginx.service",
                                                         "result": "ok", "load_state": "loaded",
                                                         "active_state": "active", "sub_state": "running"}) as execute:
                    broker.handle_connection(server, 1000, "sovagrid-agent.service")
                    try:
                        output = client.recv(1024)
                    except ConnectionResetError:
                        output = b""
                if allow:
                    self.assertEqual(json.loads(output)["active_state"], "active")
                    execute.assert_called_once()
                    policy.assert_called_once()
                    self.assertEqual(current_pid.call_count, 3)
                else:
                    self.assertEqual(output, b"")
                    execute.assert_not_called()
                    policy.assert_not_called()
            finally:
                client.close()

    def test_main_pid_query_fails_closed_and_requires_exact_agent_unit(self):
        for unit in ("sovagrid-agent.service", "sovagrid-agent-local.service"):
            for answer in ("MainPID=0\n", "MainPID=\n", "MainPID=1234\nId=other\n",
                           "MainPID=99999999999\n", "MainPID=-1\n"):
                with self.subTest(unit=unit, answer=answer):
                    calls = []

                    def runner(argv, **_kwargs):
                        calls.append(argv)
                        return subprocess.CompletedProcess(argv, 0, answer, "")

                    self.assertIsNone(broker._main_pid(unit, runner))
                    self.assertEqual(calls[0][-2:], ["show", unit])
            self.assertEqual(broker._main_pid(unit, lambda argv, **kwargs:
                             subprocess.CompletedProcess(argv, 0, "MainPID=1234\n", "")), 1234)
        unknown = mock.Mock()
        self.assertIsNone(broker._main_pid("nginx.service", unknown))
        unknown.assert_not_called()

    def test_agent_pid_change_rejects_status_and_mutation_before_execution(self):
        for request in (b'{"action":"status","unit":"nginx.service"}\n',
                        b'{"action":"restart","unit":"nginx.service"}\n'):
            for pids in ((1234, 5678), (1234, 1234, 5678)):
                server, client = socket.socketpair()
                try:
                    client.sendall(request)
                    with self.subTest(request=request, pids=pids), mock.patch.object(
                            broker, "_peer_identity", return_value=(1234, 1000)), mock.patch.object(
                            broker, "_main_pid", side_effect=pids), mock.patch.object(
                            broker, "read_policy", return_value=POLICY), mock.patch.object(
                            broker, "execute") as execute:
                        broker.handle_connection(server, 1000, "sovagrid-agent.service")
                        self.assertEqual(client.recv(1024), b"")
                        execute.assert_not_called()
                finally:
                    client.close()

    @unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SO_PEERCRED"),
                         "Linux SO_PEERCRED required")
    def test_same_uid_child_process_cannot_use_agent_service_socket(self):
        """A generic shell child is the same UID but not the Agent MainPID."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "service.sock")
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)
                code = ("import socket,sys; s=socket.socket(socket.AF_UNIX); "
                        "s.settimeout(3); s.connect(sys.argv[1]); "
                        "s.sendall(b'{\"action\":\"restart\",\"unit\":\"nginx.service\"}\\n'); "
                        "sys.stdout.buffer.write(s.recv(1024))")
                child = subprocess.Popen([sys.executable, "-c", code, path],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    connection, _ = listener.accept()
                    self.assertEqual(broker._peer_identity(connection), (child.pid, os.getuid()))
                    with mock.patch.object(broker, "_main_pid", return_value=os.getpid()), mock.patch.object(
                            broker, "read_policy") as policy, mock.patch.object(
                            broker, "execute") as execute:
                        broker.handle_connection(connection, os.getuid(), "sovagrid-agent.service")
                    out, err = child.communicate(timeout=4)
                    self.assertEqual((child.returncode, out, err), (0, b"", b""))
                    policy.assert_not_called()
                    execute.assert_not_called()
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()

    def test_client_socket_roundtrip_and_target_validation(self):
        class SocketStub:
            def __init__(self, answer):
                self.answer = answer
                self.sent = None
                self.connected = None

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, seconds):
                self.timeout = seconds

            def connect(self, path):
                self.connected = path

            def sendall(self, raw):
                self.sent = raw

            def recv(self, maximum):
                answer, self.answer = self.answer, b""
                return answer

        public = {"action": "status", "unit": "nginx.service", "result": "ok",
                  "load_state": "loaded", "active_state": "active", "sub_state": "running"}
        stub = SocketStub(json.dumps(public, separators=(",", ":")).encode() + b"\n")
        with mock.patch("sovagrid_agent.service_control.socket.socket", return_value=stub):
            value = request_broker("status", "nginx.service", "/mock/socket")
        self.assertEqual(value["active_state"], "active")
        self.assertEqual(stub.sent, b'{"action":"status","unit":"nginx.service"}\n')
        self.assertEqual(stub.connected, "/mock/socket")
        with self.assertRaises(ValueError):
            validate_response(value, "status", "ssh.service")

    def test_agent_job_uses_socket_and_sanitized_result(self):
        class Client:
            def __init__(self):
                self.results = []

            def push_metrics(self, report):
                pass

            def next_job(self):
                return {"id": "job", "command": f"{MARKER} status nginx.service"}

            def send_result(self, identifier, result):
                self.results.append((identifier, result))

        client = Client()
        answer = {"action": "status", "unit": "nginx.service", "result": "ok",
                  "load_state": "loaded", "active_state": "active", "sub_state": "running"}
        with mock.patch("sovagrid_agent.agent.collect", return_value={"details": {}}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent._request_service_broker", return_value=answer) as request, mock.patch(
                "sovagrid_agent.agent.run_command") as generic:
            run_once({"allow_remote_commands": True}, client)
            request.assert_called_once_with("status", "nginx.service", SOCKET_PATH)
            generic.assert_not_called()
        self.assertEqual(client.results[0][1]["state"], "succeeded")
        self.assertEqual(json.loads(client.results[0][1]["output"])["sub_state"], "running")

    def test_lost_broker_reply_after_mutation_is_uncertain(self):
        class Client:
            def __init__(self, action):
                self.action = action
                self.results = []

            def push_metrics(self, report):
                pass

            def next_job(self):
                return {"id": "job", "command": f"{MARKER} {self.action} nginx.service"}

            def send_result(self, identifier, result):
                self.results.append(result)

        with mock.patch("sovagrid_agent.agent.collect", return_value={"details": {}}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent._request_service_broker", side_effect=TimeoutError):
            mutation = Client("restart")
            run_once({"allow_remote_commands": True}, mutation)
            status = Client("status")
            run_once({"allow_remote_commands": True}, status)
        self.assertEqual(mutation.results[0]["state"], "timed_out")
        self.assertIn("uncertain", mutation.results[0]["output"])
        self.assertEqual(status.results[0]["state"], "failed")

    def test_local_agent_uses_separate_socket_profile(self):
        base = {"hub_url": "https://hub.example", "server_id": "local",
                "token_file": "/tmp/token", "service_socket": LOCAL_SOCKET_PATH}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "agent.json"
            path.write_text(json.dumps(base))
            self.assertEqual(load_config(str(path))["service_socket"], LOCAL_SOCKET_PATH)
            for bad in ("/tmp/broker.sock", [LOCAL_SOCKET_PATH], None):
                path.write_text(json.dumps(base | {"service_socket": bad}))
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    load_config(str(path))


if __name__ == "__main__":
    unittest.main()
