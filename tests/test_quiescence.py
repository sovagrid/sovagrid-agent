# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The future external updater may stop Agent only after this local ACK."""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_agent import agent, files, terminal
from sovagrid_agent.checks import CheckWorkers


class StopLoop(BaseException):
    pass


def line(connection):
    value = bytearray()
    while not value.endswith(b"\n"):
        value.extend(connection.recv(1))
    return bytes(value)


class QuiescenceTests(unittest.TestCase):
    def test_standard_service_owns_private_control_runtime(self):
        unit = (Path(__file__).resolve().parents[1] / "deploy/sovagrid-agent.service").read_text()
        self.assertIn("--enable-quiescence", unit)
        self.assertIn("RuntimeDirectory=sovagrid-agent-control", unit)
        self.assertIn("RuntimeDirectoryMode=0700", unit)
        self.assertIn("ReadWritePaths=/var/lib/sovagrid-agent /run/sovagrid-agent-control", unit)

    def test_one_sample_does_not_claim_the_live_control_socket(self):
        from sovagrid_agent.__main__ import main
        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.load_config", return_value={"token_file": "/test/token"}), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient"), mock.patch(
                "sovagrid_agent.__main__.run_once") as once, mock.patch(
                "sovagrid_agent.__main__.AgentQuiescenceServer") as server:
            main(["--once"])
        once.assert_called_once()
        server.assert_not_called()

    def test_pause_waits_for_fetched_work_and_blocks_new_work(self):
        gate = agent.AgentQuiescence()
        working = threading.Event()
        release = threading.Event()
        paused = threading.Event()
        result = []

        def operation():
            with gate.operation("file"):
                working.set()
                release.wait(2)

        def request_pause():
            result.append(gate.pause_until_idle(timeout=2))
            paused.set()

        with mock.patch("sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread = threading.Thread(target=operation)
            thread.start()
            self.assertTrue(working.wait(1))
            pause = threading.Thread(target=request_pause)
            pause.start()
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                with gate._condition:
                    if gate._paused:
                        break
                time.sleep(0.001)
            else:
                self.fail("Pause did not start")
            self.assertFalse(paused.is_set())
            release.set()
            self.assertTrue(paused.wait(1))
            self.assertEqual(result, [True])
            self.assertEqual(gate.idle_snapshot(), {"jobs_inflight": 0, "file_operations": 0,
                                                     "terminal_sessions": 0, "network_checks": 0,
                                                     "upload_sessions": 0, "probe_helpers": 0})
            with gate.operation("job", block=False) as admitted:
                self.assertFalse(admitted)
            entered_after_pause = threading.Event()
            def new_operation():
                with gate.operation("file"):
                    entered_after_pause.set()
            next_thread = threading.Thread(target=new_operation)
            next_thread.start()
            self.assertFalse(entered_after_pause.wait(0.03))
            gate.resume()
            self.assertTrue(entered_after_pause.wait(1))
            thread.join(1)
            pause.join(1)
            next_thread.join(1)
            with gate.operation("job", block=False) as admitted:
                self.assertTrue(admitted)

    def test_upload_session_refuses_idle_ack_and_resumes(self):
        gate = agent.AgentQuiescence()
        with mock.patch("sovagrid_agent.binary_files.active_upload_sessions", return_value=1):
            self.assertFalse(gate.pause_until_idle(timeout=0.02))
        with gate.operation("file", block=False) as admitted:
            self.assertTrue(admitted)

    def test_unreaped_probe_helper_refuses_idle_ack(self):
        gate = agent.AgentQuiescence()
        with mock.patch("sovagrid_agent.agent._reserved_children", return_value={12345}), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            self.assertEqual(gate.idle_snapshot()["probe_helpers"], 1)
            self.assertFalse(gate.pause_until_idle(timeout=0.02))
        with gate.operation("check", block=False) as admitted:
            self.assertTrue(admitted)

    def test_check_worker_keeps_gate_active_through_result_and_pauses_new_claims(self):
        gate = agent.AgentQuiescence()
        running = threading.Event()
        release_run = threading.Event()
        sending = threading.Event()
        release_send = threading.Event()
        claimed_after_resume = threading.Event()

        class Client:
            calls = 0
            def claim(self):
                self.calls += 1
                return {"check": {"kind": "http"}}
            def send_check_result(self, _lease, _value):
                sending.set()
                release_send.wait(2)
                workers.stop_event.set()

        class Runner:
            def run(self, _check, _stop):
                running.set()
                release_run.wait(2)
                return {"status": "up"}
            def cancel(self):
                pass

        client = Client()
        runner = Runner()
        workers = CheckWorkers({}, "token", client_factory=lambda *_: client,
                               runner_factory=lambda: runner, quiescence=gate)
        thread = threading.Thread(target=workers._loop, args=(client, runner))
        with mock.patch("sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread.start()
            try:
                self.assertTrue(running.wait(1))
                self.assertEqual(gate.idle_snapshot()["network_checks"], 1)
                self.assertFalse(gate.pause_until_idle(timeout=0.02))
                release_run.set()
                self.assertTrue(sending.wait(1))
                self.assertFalse(gate.pause_until_idle(timeout=0.02))
                release_send.set()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertEqual(client.calls, 1)
                self.assertTrue(gate.pause_until_idle(timeout=0.1))

                class WakingStop:
                    def __init__(self):
                        self.stopped = threading.Event()
                    def is_set(self):
                        return self.stopped.is_set()
                    def wait(self, _delay):
                        self.stopped.wait(0.01)
                    def set(self):
                        self.stopped.set()

                next_client = mock.Mock()
                def claim_next():
                    claimed_after_resume.set()
                    next_workers.stop_event.set()
                    return None
                next_client.claim.side_effect = claim_next
                next_workers = CheckWorkers({}, "token", client_factory=lambda *_: next_client,
                                            runner_factory=lambda: runner, quiescence=gate)
                next_workers.stop_event = WakingStop()
                next_thread = threading.Thread(target=next_workers._loop,
                                               args=(next_client, runner))
                next_thread.start()
                try:
                    self.assertFalse(claimed_after_resume.wait(0.03))
                    next_client.claim.assert_not_called()
                    gate.resume()
                    self.assertTrue(claimed_after_resume.wait(1))
                    next_thread.join(1)
                    self.assertFalse(next_thread.is_alive())
                    next_client.claim.assert_called_once()
                finally:
                    next_workers.stop_event.set()
                    gate.resume()
                    next_thread.join(1)
            finally:
                workers.stop_event.set()
                release_run.set()
                release_send.set()
                gate.resume()
                thread.join(1)

    def test_metrics_continue_during_pause_without_fetching_jobs(self):
        gate = agent.AgentQuiescence()
        class Client:
            reports = []
            def push_metrics(self, report):
                self.reports.append(report)
            def next_job(self):
                raise AssertionError("Paused Agent fetched a job")
        client = Client()
        with mock.patch("sovagrid_agent.binary_files.active_upload_sessions", return_value=0), mock.patch(
                "sovagrid_agent.agent.collect", return_value={"cpu_percent": 1.0}):
            self.assertTrue(gate.pause_until_idle(timeout=0.1))
            agent.run_once({"allow_remote_commands": True}, client, gate)
            gate.resume()
        self.assertEqual(client.reports, [{"cpu_percent": 1.0}])

    def test_root_only_protocol_holds_and_releases_idle_ack(self):
        gate = agent.AgentQuiescence()
        server = agent.AgentQuiescenceServer(gate)
        left, right = socket.socketpair()
        left.settimeout(2)
        errors = []
        def serve():
            try:
                server._handle(right)
            except Exception as exc:
                errors.append(exc)
            finally:
                gate.resume()
                right.close()
        with mock.patch("sovagrid_agent.agent._quiesce_peer_uid", return_value=0), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread = threading.Thread(target=serve)
            thread.start()
            left.sendall(b"QUIESCE 1\n")
            reply = json.loads(line(left))
            self.assertEqual(reply["protocol"], 1)
            self.assertEqual(reply["state"], "idle")
            self.assertEqual(reply["pid"], os.getpid())
            self.assertRegex(reply["epoch"], r"\A[0-9a-f]{32}\Z")
            for field in ("jobs_inflight", "file_operations", "terminal_sessions",
                          "network_checks", "upload_sessions", "probe_helpers"):
                self.assertEqual(reply[field], 0)
            with gate.operation("job", block=False) as admitted:
                self.assertFalse(admitted)
            left.sendall(b"PING 1\n")
            self.assertEqual(line(left), b"PONG 1 " + reply["epoch"].encode("ascii") + b"\n")
            left.sendall(b"RELEASE 1\n")
            self.assertEqual(line(left), b"RELEASED 1\n")
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            with gate.operation("job", block=False) as admitted:
                self.assertTrue(admitted)
        left.close()

    def test_non_root_peer_gets_no_ack(self):
        gate = agent.AgentQuiescence()
        server = agent.AgentQuiescenceServer(gate)
        left, right = socket.socketpair()
        with mock.patch("sovagrid_agent.agent._quiesce_peer_uid", return_value=1000):
            server._handle(right)
        right.close()
        self.assertEqual(left.recv(1), b"")
        left.close()
        with gate.operation("job", block=False) as admitted:
            self.assertTrue(admitted)

    def test_missed_heartbeat_revokes_idle_ack(self):
        gate = agent.AgentQuiescence()
        server = agent.AgentQuiescenceServer(gate)
        left, right = socket.socketpair()
        left.settimeout(2)
        errors = []
        def serve():
            try:
                server._handle(right)
            except Exception as exc:
                errors.append(exc)
            finally:
                gate.resume()
                right.close()
        with mock.patch("sovagrid_agent.agent._quiesce_peer_uid", return_value=0), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0), mock.patch.object(
                agent, "QUIESCE_HEARTBEAT_SECONDS", 0.03):
            thread = threading.Thread(target=serve)
            thread.start()
            left.sendall(b"QUIESCE 1\n")
            self.assertEqual(json.loads(line(left))["state"], "idle")
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], TimeoutError)
            self.assertEqual(left.recv(1), b"")
            with gate.operation("job", block=False) as admitted:
                self.assertTrue(admitted)
        left.close()

    def test_disconnected_controller_cancels_pending_pause(self):
        gate = agent.AgentQuiescence()
        server = agent.AgentQuiescenceServer(gate)
        left, right = socket.socketpair()
        active = gate.operation("job")
        active.__enter__()
        errors = []
        def serve():
            try:
                server._handle(right)
            except Exception as exc:
                errors.append(exc)
        with mock.patch("sovagrid_agent.agent._quiesce_peer_uid", return_value=0), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread = threading.Thread(target=serve)
            thread.start()
            left.sendall(b"QUIESCE 1\n")
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                with gate._condition:
                    if gate._paused:
                        break
                time.sleep(0.001)
            else:
                self.fail("Pause did not start")
            left.close()
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            active.__exit__(None, None, None)
            right.close()
            with gate.operation("file", block=False) as admitted:
                self.assertTrue(admitted)

    def test_unsafe_control_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            server = agent.AgentQuiescenceServer(agent.AgentQuiescence(), str(parent / "agent.sock"))
            with mock.patch("sovagrid_agent.agent.sys.platform", "linux"), mock.patch(
                    "sovagrid_agent.agent.os.geteuid", return_value=12345):
                with self.assertRaisesRegex(RuntimeError, "Unsafe Agent quiescence directory"):
                    server.start()

    def test_file_relay_keeps_gate_active_through_result(self):
        gate = agent.AgentQuiescence()
        entered = threading.Event()
        release = threading.Event()
        class Client:
            server_id = "server"
            calls = 0
            def request(self, method, path, payload=None):
                self.calls += 1
                if self.calls == 1:
                    return {"operation": {"id": "op", "request": {"action": "roots"}}}
                if self.calls == 2:
                    return {}
                raise StopLoop()
        def operate(_config, _request):
            entered.set()
            release.wait(2)
            return {"roots": []}
        def work():
            try:
                files.file_loop({"allow_remote_commands": True, "allow_file_manager": True}, Client(), gate)
            except StopLoop:
                pass
        with mock.patch("sovagrid_agent.files.operate", side_effect=operate), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread = threading.Thread(target=work)
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertFalse(gate.pause_until_idle(timeout=0.02))
            release.set()
            thread.join(1)
            self.assertFalse(thread.is_alive())

    def test_terminal_session_keeps_gate_active_until_exit(self):
        gate = agent.AgentQuiescence()
        entered = threading.Event()
        release = threading.Event()
        class Client:
            server_id = "server"
            calls = 0
            def request(self, method, path):
                self.calls += 1
                if self.calls == 1:
                    return {"session": {"id": "session"}}
                raise StopLoop()
        def session(_client, _item, _socket_path):
            entered.set()
            release.wait(2)
        def work():
            try:
                terminal.terminal_loop({"allow_remote_commands": True,
                                        "allow_interactive_terminal": True}, Client(), gate)
            except StopLoop:
                pass
        with mock.patch("sovagrid_agent.terminal.run_session", side_effect=session), mock.patch(
                "sovagrid_agent.binary_files.active_upload_sessions", return_value=0):
            thread = threading.Thread(target=work)
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertFalse(gate.pause_until_idle(timeout=0.02))
            release.set()
            thread.join(1)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
