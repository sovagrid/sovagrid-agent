# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sovagrid_agent.agent import _command_plan, load_config, run_command, run_once
from sovagrid_agent.journal import MARKER, configured_units, journal_argv, parse_journal_request, request_broker
from sovagrid_agent.journal_broker import _request, _send_result, handle_connection, read_policy


class JournalTests(unittest.TestCase):
    def test_default_off_and_exact_allowlist(self):
        self.assertEqual(configured_units({}), ())
        self.assertEqual(configured_units({"journal_units": ["nginx.service"]}), ())
        self.assertEqual(configured_units({"allow_remote_commands": True, "allow_systemd_journal": True,
                                           "journal_units": ["nginx.service", "ssh@blue.service"]}),
                         ("nginx.service", "ssh@blue.service"))
        for bad in (True, "nginx.service", ["nginx.service", "nginx.service"],
                    ["nginx"], ["../nginx.service"], ["-x.service;id"],
                    ["a.service\n"], ["a.service"] * 17):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                configured_units({"allow_remote_commands": True, "allow_systemd_journal": True, "journal_units": bad})
        with self.assertRaises(ValueError):
            configured_units({"allow_systemd_journal": True})
        with self.assertRaises(ValueError):
            configured_units({"allow_systemd_journal": True, "journal_units": ["nginx.service"]})

    def test_config_load_rejects_invalid_journal_permission(self):
        config = {"hub_url": "https://hub.example", "server_id": "a", "token_file": "/tmp/token"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.json"
            for extra in ({"allow_systemd_journal": "true"},
                          {"allow_systemd_journal": True},
                          {"allow_systemd_journal": True, "journal_units": ["x.service;id"]}):
                path.write_text(json.dumps(config | extra))
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    load_config(str(path))

    def test_marker_never_enters_generic_command_shell(self):
        command = f"{MARKER} read nginx.service 100"
        self.assertEqual(parse_journal_request(command, ("nginx.service",)), ("nginx.service", 100))
        with self.assertRaisesRegex(ValueError, "isolated broker"):
            _command_plan(command, 999, ("nginx.service",))
        argv = journal_argv("nginx.service", 100, ("nginx.service",))
        self.assertEqual(argv[0], "/usr/bin/journalctl")
        self.assertEqual(argv[-1], "--unit=nginx.service")
        self.assertEqual(argv[-3:-1], ["--lines", "100"])
        self.assertNotIn("/bin/sh", argv)
        for unit in ("ssh.service", "../nginx.service", "--help.service"):
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                journal_argv(unit, 20, ("nginx.service",))

    def test_denied_before_subprocess_for_unlisted_or_injected_unit(self):
        requests = (
            f"{MARKER} read ssh.service 20",
            f"{MARKER} read nginx.service 0",
            f"{MARKER} read nginx.service 101",
            f"{MARKER} read nginx.service 020",
            f"{MARKER} read nginx.service 20;id",
            f"{MARKER} read nginx.service 20 && id",
            f"echo {MARKER} read nginx.service 20",
            f"{MARKER} read 'nginx.service' 20",
            f"{MARKER} read nginx.service 20\nid",
            f"{MARKER}  read nginx.service 20",
        )
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as popen:
            for command in requests:
                with self.subTest(command=command), self.assertRaises(ValueError):
                    run_command(command, journal_units=("nginx.service",))
            with self.assertRaises(ValueError):
                run_command(f"{MARKER} read nginx.service 20")
            popen.assert_not_called()

    def test_agent_advertises_only_enabled_units_and_reports_denial(self):
        class Client:
            def __init__(self, job=None):
                self.reports = []
                self.job = job
                self.results = []

            def push_metrics(self, report):
                self.reports.append(report)

            def next_job(self):
                return self.job

            def send_result(self, job_id, result):
                self.results.append((job_id, result))

        metrics = {"details": {"services": {"failed_count": 0, "units": []}}}
        disabled = Client()
        with mock.patch("sovagrid_agent.agent.collect", return_value=metrics.copy()), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000):
            run_once({"allow_remote_commands": True}, disabled)
        self.assertNotIn("journal_units", disabled.reports[0]["details"])

        client = Client({"id": "job", "command": f"{MARKER} read ssh.service 20"})
        with mock.patch("sovagrid_agent.agent.collect", return_value={"details": {}}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as popen:
            run_once({"allow_remote_commands": True, "allow_systemd_journal": True,
                      "journal_units": ["nginx.service"]}, client)
            popen.assert_not_called()
        self.assertEqual(client.reports[0]["details"]["journal_units"], ["nginx.service"])
        self.assertEqual(client.results[0][1]["state"], "failed")
        self.assertIn("denied", client.results[0][1]["output"])

        allowed = Client({"id": "allowed", "command": f"{MARKER} read nginx.service 20"})
        with mock.patch("sovagrid_agent.agent.collect", return_value={"details": {}}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.request_broker", return_value={"state": "succeeded", "exit_code": 0,
                                                                     "output": "bounded line"}) as broker, mock.patch(
                "sovagrid_agent.agent.run_command") as generic:
            run_once({"allow_remote_commands": True, "allow_systemd_journal": True,
                      "journal_units": ["nginx.service"]}, allowed)
            broker.assert_called_once_with("nginx.service", 20)
            generic.assert_not_called()
        self.assertEqual(allowed.results[0][1]["output"], "bounded line")

    def test_broker_request_is_canonical_and_bounded(self):
        for payload in (b'{"unit":"nginx.service","lines":20}\n',
                        b'{"unit":"nginx.service", "lines":20}\n',
                        b'{"unit":"nginx.service","lines":20,"x":1}\n',
                        b'{"unit":"nginx.service","lines":20,"lines":20}\n',
                        b'{"unit":"nginx.service","lines":20}\ntrailing'):
            server, client = socket.socketpair()
            try:
                client.sendall(payload)
                if payload == b'{"unit":"nginx.service","lines":20}\n':
                    self.assertEqual(_request(server), ("nginx.service", 20))
                else:
                    with self.subTest(payload=payload), self.assertRaises(ValueError):
                        _request(server)
            finally:
                server.close()
                client.close()

    def test_root_owned_policy_rejects_unsafe_or_inexact_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "units.json"
            original_fstat = os.fstat

            def root_fstat(fd):
                info = original_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_uid=0, st_gid=1234, st_size=info.st_size)

            with mock.patch("sovagrid_agent.journal_broker.os.fstat", side_effect=root_fstat):
                for raw, good in ((b'{"units":["nginx.service"]}', True),
                                  (b'{"units":["nginx.service","nginx.service"]}', False),
                                  (b'{"units":["nginx.service"],"units":["ssh.service"]}', False),
                                  (b'{"units":["nginx.service;id"]}', False),
                                  (b'{"units":["nginx.service"],"extra":true}', False)):
                    path.write_bytes(raw)
                    path.chmod(0o640)
                    if good:
                        self.assertEqual(read_policy(str(path), 1234), ("nginx.service",))
                    else:
                        with self.subTest(raw=raw), self.assertRaises(ValueError):
                            read_policy(str(path), 1234)
                path.chmod(0o600)
                with self.assertRaises(PermissionError):
                    read_policy(str(path), 1234)
            path.unlink()
            path.symlink_to(Path(tmp) / "other")
            with self.assertRaises(OSError):
                read_policy(str(path), 1234)

    def test_socket_broker_checks_peer_and_policy_before_journalctl(self):
        canonical = b'{"unit":"nginx.service","lines":20}\n'
        for peer, policy, should_run in ((1000, ("nginx.service",), True),
                                         (1001, ("nginx.service",), False),
                                         (1000, ("ssh.service",), False)):
            server, client = socket.socketpair()
            try:
                client.sendall(canonical)
                with mock.patch("sovagrid_agent.journal_broker._peer_uid", return_value=peer), mock.patch(
                        "sovagrid_agent.journal_broker.read_policy", return_value=policy) as read, mock.patch(
                        "sovagrid_agent.journal_broker.run_command",
                        return_value={"state": "succeeded", "exit_code": 0, "output": "private"}) as run:
                    handle_connection(server, 1000, 1234)
                    try:
                        response = client.recv(12001)
                    except ConnectionResetError:
                        # Linux resets a socket closed with unread input.
                        # Unauthorized peers are rejected before their bytes
                        # are read; macOS instead reports EOF for this case.
                        if peer == 1000:
                            raise
                        response = b""
                if should_run:
                    self.assertEqual(json.loads(response)["output"], "private")
                    self.assertEqual(run.call_args.kwargs["argv_override"],
                                     journal_argv("nginx.service", 20, ("nginx.service",)))
                    self.assertNotIn("/bin/sh", run.call_args.kwargs["argv_override"])
                else:
                    run.assert_not_called()
                    if peer != 1000:
                        read.assert_not_called()
                        self.assertEqual(response, b"")
                    else:
                        self.assertEqual(json.loads(response)["output"], "Journal unavailable or denied")
            finally:
                client.close()

    def test_client_socket_roundtrip_and_encoded_output_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "control.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            def service():
                conn, _ = listener.accept()
                with mock.patch("sovagrid_agent.journal_broker._peer_uid", return_value=1000), mock.patch(
                        "sovagrid_agent.journal_broker.read_policy", return_value=("nginx.service",)), mock.patch(
                        "sovagrid_agent.journal_broker.run_command",
                        return_value={"state": "succeeded", "exit_code": 0, "output": "\"\\\\" * 4096}):
                    handle_connection(conn, 1000, 1234)
            worker = threading.Thread(target=service, daemon=True)
            worker.start()
            try:
                result = request_broker("nginx.service", 20, path)
                self.assertEqual(result["state"], "output_limited")
                self.assertLessEqual(len(result["output"].encode()), 8192)
            finally:
                listener.close()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
