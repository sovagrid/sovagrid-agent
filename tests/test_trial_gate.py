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
