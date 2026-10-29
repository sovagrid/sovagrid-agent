# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A trial Agent must prove its root watchdog before contacting the Hub."""

import os
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sovagrid_agent import trial_gate


EPOCH = "a" * 32
NONCE = "b" * 32


def read_line(connection):
    data = bytearray()
    while not data.endswith(b"\n"):
        item = connection.recv(1)
        if not item:
            raise EOFError
        data.extend(item)
    return bytes(data)


class TrialGateTests(unittest.TestCase):
    def test_environment_is_strict_and_opt_in(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(trial_gate.from_environment())
        for variables in (
            {trial_gate.GATE_ENV: "1"},
            {trial_gate.EPOCH_ENV: EPOCH},
            {trial_gate.GATE_ENV: "0", trial_gate.EPOCH_ENV: EPOCH},
            {trial_gate.GATE_ENV: "1", trial_gate.EPOCH_ENV: "A" * 32},
        ):
            with self.subTest(variables=variables), mock.patch.dict(os.environ, variables, clear=True):
                with self.assertRaisesRegex(RuntimeError, "Incomplete"):
                    trial_gate.from_environment()
        with mock.patch.dict(os.environ, {trial_gate.GATE_ENV: "1",
                                          trial_gate.EPOCH_ENV: EPOCH}, clear=True):
            self.assertEqual(trial_gate.from_environment().epoch, EPOCH)

    def test_path_and_peer_require_exact_root_owned_socket(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o710, st_uid=0,
                                    st_gid=1001)
        endpoint = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0,
                                   st_gid=1001, st_nlink=1)
        with mock.patch.object(trial_gate.sys, "platform", "linux"), mock.patch.object(
                trial_gate.os, "geteuid", return_value=1001), mock.patch.object(
                trial_gate.os, "getegid", return_value=1001), mock.patch.object(
                Path, "lstat", side_effect=[directory, endpoint]):
            trial_gate._trusted_path(Path("/run/test/gate.sock"))
        bad = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o666, st_uid=0,
                              st_gid=1001, st_nlink=1)
        with mock.patch.object(trial_gate.sys, "platform", "linux"), mock.patch.object(
                trial_gate.os, "geteuid", return_value=1001), mock.patch.object(
                trial_gate.os, "getegid", return_value=1001), mock.patch.object(
                Path, "lstat", side_effect=[directory, bad]):
            with self.assertRaisesRegex(RuntimeError, "Unsafe external trial gate socket"):
                trial_gate._trusted_path(Path("/run/test/gate.sock"))
        peer = mock.Mock()
        with mock.patch.object(trial_gate.sys, "platform", "linux"), mock.patch.object(
                trial_gate.socket, "SO_PEERCRED", 17, create=True):
            peer.getsockopt.return_value = struct.pack("3i", 456, 0, 0)
            trial_gate._trusted_peer(peer)
            peer.getsockopt.return_value = struct.pack("3i", 456, 1001, 1001)
            with self.assertRaisesRegex(RuntimeError, "not root"):
                trial_gate._trusted_peer(peer)

    def test_initial_round_trip_precedes_work_and_eof_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "gate.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            fatal = threading.Event()
            seen = []

            def supervisor():
                with listener.accept()[0] as connection:
                    seen.append(read_line(connection))
                    connection.sendall(f"READY 1 {EPOCH}\n".encode())
                    seen.append(read_line(connection))
                    connection.sendall(b"PONG 0\n")
                    seen.append(read_line(connection))
                    # Closing the root end must stop the trial Agent.

            server = threading.Thread(target=supervisor)
            server.start()
            try:
                with mock.patch.object(trial_gate, "_trusted_path"), mock.patch.object(
                        trial_gate, "_trusted_peer"), mock.patch.object(
                        trial_gate, "HEARTBEAT_SECONDS", 0.02), mock.patch.object(
                        trial_gate, "ROUND_TRIP_SECONDS", 0.2):
                    gate = trial_gate.ExternalTrialGate(EPOCH, path=path,
                                                        fatal=lambda code: fatal.set())
                    self.assertIs(gate.start(), gate)
                    self.assertEqual(seen[:2], [f"HELLO 1 {EPOCH}\n".encode(), b"PING 0\n"])
                    self.assertTrue(fatal.wait(1), "EOF must trip the watchdog")
                    gate.stop()
            finally:
                server.join(1)
                listener.close()
            self.assertEqual(seen[2], b"PING 1\n")

    def test_epoch_mismatch_fails_before_any_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "gate.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)

            def supervisor():
                with listener.accept()[0] as connection:
                    self.assertEqual(read_line(connection), f"HELLO 1 {EPOCH}\n".encode())
                    connection.sendall(f"READY 1 {'b' * 32}\n".encode())

            server = threading.Thread(target=supervisor)
            server.start()
            try:
                with mock.patch.object(trial_gate, "_trusted_path"), mock.patch.object(
                        trial_gate, "_trusted_peer"):
                    with self.assertRaisesRegex(RuntimeError, "epoch mismatch"):
                        trial_gate.ExternalTrialGate(EPOCH, path=path).start()
            finally:
                server.join(1)
                listener.close()

    def test_nonce_bound_promotion_detaches_only_after_dispatch_is_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "gate.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            seen = []
            fatal = mock.Mock()
            ready_after_release = threading.Event()

            def supervisor():
                with listener.accept()[0] as connection:
                    seen.append(read_line(connection))
                    connection.sendall(f"READY 1 {EPOCH}\n".encode())
                    seen.append(read_line(connection))
                    connection.sendall(b"PONG 0\n")
                    while True:
                        request = read_line(connection)
                        seen.append(request)
                        parts = request.strip().split()
                        sequence = parts[1]
                        if sequence == b"1":
                            connection.sendall(b"PROMOTE 1 " + NONCE.encode() + b"\n")
                        elif len(parts) == 4 and parts[2:] == [b"READY", NONCE.encode()] and \
                                b"ACK RELEASE " + NONCE.encode() + b"\n" not in seen:
                            connection.sendall(b"RELEASE " + sequence + b" " + NONCE.encode() + b"\n")
                            seen.append(read_line(connection))
                        elif len(parts) == 4 and parts[2:] == [b"READY", NONCE.encode()]:
                            connection.sendall(b"PONG " + sequence + b"\n")
                            ready_after_release.set()
                        elif len(parts) == 4 and parts[2:] == [b"ACTIVE", NONCE.encode()]:
                            connection.sendall(b"DETACH " + sequence + b" " + NONCE.encode() + b"\n")
                            seen.append(read_line(connection))
                            return
                        else:
                            connection.sendall(b"PONG " + sequence + b"\n")

            server = threading.Thread(target=supervisor)
            server.start()
            try:
                with mock.patch.object(trial_gate, "_trusted_path"), mock.patch.object(
                        trial_gate, "_trusted_peer"), mock.patch.object(
                        trial_gate, "HEARTBEAT_SECONDS", 0.02), mock.patch.object(
                        trial_gate, "ROUND_TRIP_SECONDS", 0.3):
                    gate = trial_gate.ExternalTrialGate(EPOCH, path=path, fatal=fatal).start()
                    self.assertTrue(gate.promotion_requested.wait(1))
                    self.assertFalse(gate.promotion_ready.is_set())
                    self.assertFalse(gate.released.is_set())
                    gate.mark_ready()
                    self.assertTrue(gate.released.wait(1))
                    self.assertFalse(gate.detached.is_set())
                    self.assertTrue(ready_after_release.wait(1))
                    gate.mark_dispatch_ready()
                    self.assertTrue(gate.detached.wait(1))
                    gate.stop()
            finally:
                server.join(1)
                listener.close()
            self.assertEqual(seen[0], f"HELLO 1 {EPOCH}\n".encode())
            self.assertIn(b"PING 1\n", seen)
            self.assertTrue(any(item.endswith(b" READY " + NONCE.encode() + b"\n") for item in seen))
            self.assertIn(b"ACK RELEASE " + NONCE.encode() + b"\n", seen)
            self.assertTrue(any(item.endswith(b" ACTIVE " + NONCE.encode() + b"\n") for item in seen))
            self.assertEqual(seen[-1], b"ACK DETACH " + NONCE.encode() + b"\n")
            fatal.assert_not_called()

    def test_supervisor_loss_after_release_before_detach_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "gate.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            fatal = threading.Event()

            def supervisor():
                with listener.accept()[0] as connection:
                    self.assertEqual(read_line(connection), f"HELLO 1 {EPOCH}\n".encode())
                    connection.sendall(f"READY 1 {EPOCH}\n".encode())
                    self.assertEqual(read_line(connection), b"PING 0\n")
                    connection.sendall(b"PONG 0\n")
                    self.assertEqual(read_line(connection), b"PING 1\n")
                    connection.sendall(b"PROMOTE 1 " + NONCE.encode() + b"\n")
                    request = read_line(connection)
                    self.assertTrue(request.endswith(b" READY " + NONCE.encode() + b"\n"))
                    sequence = request.strip().split()[1]
                    connection.sendall(b"RELEASE " + sequence + b" " + NONCE.encode() + b"\n")
                    self.assertEqual(read_line(connection), b"ACK RELEASE " + NONCE.encode() + b"\n")
                    # Root disappears before ACTIVE or DETACH; the committed
                    # Agent must still be supervised at this point.

            server = threading.Thread(target=supervisor)
            server.start()
            try:
                with mock.patch.object(trial_gate, "_trusted_path"), mock.patch.object(
                        trial_gate, "_trusted_peer"), mock.patch.object(
                        trial_gate, "HEARTBEAT_SECONDS", 0.02), mock.patch.object(
                        trial_gate, "ROUND_TRIP_SECONDS", 0.3):
                    gate = trial_gate.ExternalTrialGate(EPOCH, path=path,
                                                        fatal=lambda _code: fatal.set()).start()
                    self.assertTrue(gate.promotion_requested.wait(1))
                    gate.mark_ready()
                    self.assertTrue(gate.released.wait(1))
                    self.assertTrue(fatal.wait(1), "EOF before DETACH must kill the Agent")
                    self.assertFalse(gate.detached.is_set())
                    gate.stop()
            finally:
                server.join(1)
                listener.close()

    def test_dispatch_ready_requires_release(self):
        gate = trial_gate.ExternalTrialGate(EPOCH)
        with self.assertRaisesRegex(RuntimeError, "dispatch is unavailable"):
            gate.mark_dispatch_ready()
        gate.promotion_requested.set()
        gate._promotion_nonce = NONCE
        gate.mark_ready()
        with self.assertRaisesRegex(RuntimeError, "dispatch is unavailable"):
            gate.mark_dispatch_ready()

    def test_detach_before_active_proof_is_refused(self):
        gate = trial_gate.ExternalTrialGate(EPOCH)
        gate._connection = mock.Mock()
        gate._promotion_nonce = NONCE
        gate.promotion_requested.set()
        gate.promotion_ready.set()
        gate.released.set()
        with mock.patch.object(trial_gate, "_line",
                               return_value=f"DETACH 7 {NONCE}\n".encode()):
            with self.assertRaisesRegex(RuntimeError, "challenge failed"):
                gate._challenge(7)
        gate._connection.sendall.assert_called_once_with(
            f"PING 7 READY {NONCE}\n".encode())
        self.assertFalse(gate.detached.is_set())

    def test_release_before_metrics_ready_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "gate.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            fatal = threading.Event()

            def supervisor():
                with listener.accept()[0] as connection:
                    self.assertEqual(read_line(connection), f"HELLO 1 {EPOCH}\n".encode())
                    connection.sendall(f"READY 1 {EPOCH}\n".encode())
                    self.assertEqual(read_line(connection), b"PING 0\n")
                    connection.sendall(b"PONG 0\n")
                    self.assertEqual(read_line(connection), b"PING 1\n")
                    connection.sendall(b"RELEASE 1 " + NONCE.encode() + b"\n")

            server = threading.Thread(target=supervisor)
            server.start()
            try:
                with mock.patch.object(trial_gate, "_trusted_path"), mock.patch.object(
                        trial_gate, "_trusted_peer"), mock.patch.object(
                        trial_gate, "HEARTBEAT_SECONDS", 0.02), mock.patch.object(
                        trial_gate, "ROUND_TRIP_SECONDS", 0.3):
                    gate = trial_gate.ExternalTrialGate(EPOCH, path=path,
                                                        fatal=lambda _code: fatal.set()).start()
                    self.assertTrue(fatal.wait(1))
                    self.assertFalse(gate.released.is_set())
                    gate.stop()
            finally:
                server.join(1)
                listener.close()

    def test_missing_or_failed_gate_never_constructs_hub_client(self):
        from sovagrid_agent.__main__ import main
        gate = mock.Mock()
        gate.start.side_effect = RuntimeError("gate unavailable")
        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.external_trial_gate_from_environment", return_value=gate), mock.patch(
                "sovagrid_agent.__main__.load_config") as load, mock.patch(
                "sovagrid_agent.__main__.HubClient") as client:
            with self.assertRaisesRegex(RuntimeError, "gate unavailable"):
                main([])
        load.assert_not_called()
        client.assert_not_called()

    def test_trial_lifetime_expires_even_if_supervisor_could_keep_replying(self):
        fatal = mock.Mock()
        gate = trial_gate.ExternalTrialGate(EPOCH, fatal=fatal)
        gate._started = time.monotonic() - trial_gate.MAX_TRIAL_SECONDS - 1
        with mock.patch.object(trial_gate, "HEARTBEAT_SECONDS", 0.01):
            thread = threading.Thread(target=gate._watch)
            thread.start()
            thread.join(1)
        self.assertFalse(thread.is_alive())
        fatal.assert_called_once_with(70)

    def test_trial_mode_starts_gate_first_and_only_reports_health(self):
        from sovagrid_agent.__main__ import main

        order = []
        config = {"token_file": "/test/token", "allow_remote_commands": True,
                  "allow_interactive_terminal": True, "allow_file_manager": True,
                  "allow_systemd_journal": True, "journal_units": ["ssh.service"],
                  "interval_seconds": 5}
        gate = mock.Mock()
        gate.start.side_effect = lambda: order.append("gate")
        gate.released.is_set.return_value = False
        gate.promotion_requested.is_set.return_value = False
        gate.promotion_ready.is_set.return_value = False
        def load(_path):
            order.append("config")
            return config
        def client(_config, _token):
            order.append("client")
            return mock.Mock()
        def once(effective, _client, _quiescence):
            self.assertFalse(effective["allow_remote_commands"])
            self.assertFalse(effective["allow_interactive_terminal"])
            self.assertFalse(effective["allow_file_manager"])
            self.assertFalse(effective["allow_systemd_journal"])
            raise KeyboardInterrupt
        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.external_trial_gate_from_environment", return_value=gate), mock.patch(
                "sovagrid_agent.__main__.load_config", side_effect=load), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient", side_effect=client), mock.patch(
                "sovagrid_agent.__main__.run_once", side_effect=once), mock.patch(
                "sovagrid_agent.__main__.CheckWorkers") as workers, mock.patch(
                "sovagrid_agent.__main__.terminal_loop") as terminal, mock.patch(
                "sovagrid_agent.__main__.file_loop") as files:
            main([])
        self.assertEqual(order, ["gate", "config", "client"])
        workers.assert_not_called()
        terminal.assert_not_called()
        files.assert_not_called()
        gate.stop.assert_called_once()

    def test_trial_metric_cycle_never_claims_a_job(self):
        from sovagrid_agent.agent import run_once
        client = mock.Mock()
        with mock.patch("sovagrid_agent.agent.collect", return_value={"cpu_percent": 1.0}):
            run_once({"allow_remote_commands": False}, client)
        client.push_metrics.assert_called_once()
        client.next_job.assert_not_called()

    def test_in_process_promotion_keeps_dispatch_off_until_release_ack(self):
        from sovagrid_agent.__main__ import main

        class Gate:
            promotion_requested = threading.Event()
            promotion_ready = threading.Event()
            released = threading.Event()
            dispatch_ready = threading.Event()

            def start(self):
                return self

            def mark_ready(self):
                self.promotion_ready.set()
                self.released.set()  # Simulates a later authenticated RELEASE ACK.

            def mark_dispatch_ready(self):
                activation.append("active")
                self.dispatch_ready.set()

            def wait(self, _seconds):
                self.promotion_requested.set()

            def stop(self):
                pass

        gate = Gate()
        normal = {"token_file": "/test/token", "allow_remote_commands": True,
                  "allow_interactive_terminal": True, "allow_file_manager": True,
                  "allow_systemd_journal": True, "interval_seconds": 5}
        cycles = []
        activation = []

        def once(effective, _client, _quiescence):
            cycles.append(effective.copy())
            if len(cycles) == 2:
                workers.assert_called_once()
                workers.return_value.start.assert_not_called()
                thread.return_value.start.assert_not_called()
            if len(cycles) == 3:
                raise KeyboardInterrupt

        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.external_trial_gate_from_environment", return_value=gate), mock.patch(
                "sovagrid_agent.__main__.load_config", return_value=normal), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient", return_value=mock.Mock(token="token")), mock.patch(
                "sovagrid_agent.__main__.run_once", side_effect=once), mock.patch(
                "sovagrid_agent.__main__.CheckWorkers") as workers, mock.patch(
                "sovagrid_agent.__main__.terminal_loop") as terminal, mock.patch(
                "sovagrid_agent.__main__.file_loop") as files, mock.patch(
                "sovagrid_agent.__main__.threading.Thread") as thread:
            thread.return_value.start.return_value = None
            thread.return_value.start.side_effect = lambda: activation.append("poller")
            workers.return_value.start.side_effect = lambda: (activation.append("checks"), workers.return_value)[1]
            main([])
        self.assertEqual(len(cycles), 3)
        self.assertFalse(cycles[0]["allow_remote_commands"])
        self.assertFalse(cycles[1]["allow_remote_commands"])
        self.assertTrue(cycles[2]["allow_remote_commands"])
        workers.assert_called_once()
        workers.return_value.start.assert_called_once()
        self.assertEqual(thread.call_count, 2)
        self.assertEqual(thread.return_value.start.call_count, 2)
        self.assertEqual(activation, ["poller", "poller", "checks", "active"])
        self.assertTrue(gate.dispatch_ready.is_set())
        terminal.assert_not_called()
        files.assert_not_called()

    def test_post_release_worker_start_failure_exits_for_systemd_restart(self):
        from sovagrid_agent.__main__ import main

        gate = mock.Mock()
        gate.released.is_set.return_value = True
        gate.promotion_requested.is_set.return_value = True
        gate.promotion_ready.is_set.return_value = True
        config = {"token_file": "/test/token", "allow_remote_commands": False,
                  "interval_seconds": 5}
        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.external_trial_gate_from_environment", return_value=gate), mock.patch(
                "sovagrid_agent.__main__.load_config", return_value=config), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient", return_value=mock.Mock(token="token")), mock.patch(
                "sovagrid_agent.__main__.CheckWorkers") as workers, mock.patch(
                "sovagrid_agent.__main__.run_once") as once:
            workers.return_value.start.side_effect = RuntimeError("worker could not start")
            with self.assertRaisesRegex(RuntimeError, "worker could not start"):
                main([])
        once.assert_not_called()
        gate.mark_dispatch_ready.assert_not_called()
        gate.stop.assert_called_once()

    def test_journal_enabled_host_can_report_metrics_during_trial(self):
        from sovagrid_agent.__main__ import main
        config = {"token_file": "/test/token", "allow_remote_commands": True,
                  "allow_systemd_journal": True, "journal_units": ["ssh.service"]}
        gate = mock.Mock()
        client = mock.Mock()
        with mock.patch("sovagrid_agent.__main__._protect_agent_process"), mock.patch(
                "sovagrid_agent.__main__.external_trial_gate_from_environment", return_value=gate), mock.patch(
                "sovagrid_agent.__main__.load_config", return_value=config), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient", return_value=client), mock.patch(
                "sovagrid_agent.agent.collect", return_value={"cpu_percent": 1.0}):
            main(["--once"])
        client.push_metrics.assert_called_once_with({"cpu_percent": 1.0})
        client.next_job.assert_not_called()
        gate.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
