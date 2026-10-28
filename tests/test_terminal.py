# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Terminal broker and outbound control channel checks."""

import array
import base64
import os
import re
import select
import signal
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

from sovagrid_agent.terminal import _control_loop, _decoded, _encoded
from sovagrid_agent.terminal_broker import (LOCAL_SOCKET_PATH, PROFILES, SOCKET_PATH,
                                           _descendants, _drop, _process_starttime,
                                           _request, handle_connection)
from sovagrid_agent.agent import load_config


class TerminalTests(unittest.TestCase):
    def test_promoted_hub_uses_a_distinct_fixed_broker_profile(self):
        self.assertEqual(PROFILES["standard"],
                         (SOCKET_PATH, "sovagrid", "sovagrid-shell", "/var/lib/sovagrid-shell"))
        self.assertEqual(PROFILES["local"],
                         (LOCAL_SOCKET_PATH, "sovagrid-local", "sovagrid-local-shell",
                          "/var/lib/sovagrid-local-shell"))
        self.assertEqual(len({value for row in PROFILES.values() for value in row[:1]}), 2)
        with tempfile.TemporaryDirectory() as directory:
            config = {"hub_url": "https://localhost:8767", "server_id": "local",
                      "token_file": "/tmp/sovagrid-test-token",
                      "terminal_socket": LOCAL_SOCKET_PATH,
                      "allow_remote_commands": True,
                      "allow_interactive_terminal": True}
            path = os.path.join(directory, "agent.json")
            import json
            with open(path, "w", encoding="utf-8") as output:
                json.dump(config, output)
            self.assertEqual(load_config(path)["terminal_socket"], LOCAL_SOCKET_PATH)
            for unsafe in ("/run/sovagrid-terminal-local/other.sock", "/tmp/control.sock", None):
                with self.subTest(unsafe=unsafe):
                    config["terminal_socket"] = unsafe
                    with open(path, "w", encoding="utf-8") as output:
                        json.dump(config, output)
                    with self.assertRaises(ValueError):
                        load_config(path)

    def test_broker_request_exact_size_and_peer_rejection(self):
        for value in (b'{"cols":80,"rows":24}\n',
                      b'{"cols":80,"rows":24,"command":"id"}\n',
                      b'{"cols":80,"cols":81,"rows":24}\n',
                      b'{"rows":24,"cols":80}\n',
                      b'{"cols":1,"rows":24}\n',
                      b'{"cols":true,"rows":24}\n',
                      b'{"cols":80,"rows":24}\nsecret'):
            left, right = socket.socketpair()
            try:
                left.sendall(value)
                if value == b'{"cols":80,"rows":24}\n':
                    self.assertEqual(_request(right), (80, 24))
                else:
                    with self.assertRaises(ValueError):
                        _request(right)
            finally:
                left.close()
                right.close()
        left, right = socket.socketpair()
        try:
            with mock.patch("sovagrid_agent.terminal_broker._peer_uid", return_value=999999), mock.patch(
                    "sovagrid_agent.terminal_broker.os.forkpty") as fork:
                handle_connection(right, os.getuid(), os.getuid(), os.getgid(), "/tmp")
            fork.assert_not_called()
        finally:
            left.close()

    def test_broker_refuses_root_or_agent_identity(self):
        with mock.patch("sovagrid_agent.terminal_broker.os.getuid", return_value=0), mock.patch(
                "sovagrid_agent.terminal_broker.os.geteuid", return_value=0):
            with self.assertRaises(PermissionError):
                _drop(10003, 10003)
        with mock.patch("sovagrid_agent.terminal_broker.os.getuid", return_value=10003), mock.patch(
                "sovagrid_agent.terminal_broker.os.geteuid", return_value=10003), mock.patch(
                "sovagrid_agent.terminal_broker.os.getgid", return_value=10003), mock.patch(
                "sovagrid_agent.terminal_broker.os.getegid", return_value=10003):
            _drop(10003, 10003)

    @unittest.skipUnless(hasattr(os, "forkpty") and hasattr(os, "fork"), "PTY fork required")
    def test_broker_passes_real_pty_and_shell_exits_on_disconnect(self):
        left, right = socket.socketpair()
        with tempfile.TemporaryDirectory() as home:
            pid = os.fork()
            if pid == 0:
                left.close()
                with mock.patch("sovagrid_agent.terminal_broker._peer_uid", return_value=os.getuid()):
                    try:
                        handle_connection(right, os.getuid(), os.getuid(), os.getgid(), home)
                    except Exception as exc:
                        import traceback
                        traceback.print_exc()
                        os._exit(2)
                os._exit(0)
            right.close()
            master = None
            try:
                left.sendall(b'{"cols":80,"rows":24}\n')
                response, ancillary, _flags, _addr = left.recvmsg(16, socket.CMSG_SPACE(4))
                self.assertEqual(response, b"OK\n")
                descriptors = array.array("i")
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(data[:4])
                self.assertEqual(len(descriptors), 1)
                master = descriptors[0]
                os.write(master, b"printf __SOVAGRID_PTY_TEST__; exit\n")
                found = bytearray()
                deadline = time.monotonic() + 5
                while b"__SOVAGRID_PTY_TEST__" not in found and time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.5)
                    if readable:
                        try:
                            found.extend(os.read(master, 4096))
                        except OSError:
                            break
                self.assertIn(b"__SOVAGRID_PTY_TEST__", found)
            finally:
                if master is not None:
                    os.close(master)
                left.close()
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_control_loop_checks_order_and_writes_bytes(self):
        master, slave = os.openpty()
        output = []

        class Client:
            calls = 0

            def request(self, method, path, payload=None):
                self.calls += 1
                if self.calls == 1:
                    return {"events": [{"seq": 1, "type": "input", "data": _encoded(b"abc\n")}],
                            "next_after": 1, "state": "active"}
                output.append(path)
                return {"events": [], "next_after": 1, "state": "closed"}

        try:
            import threading
            stop = threading.Event()
            _control_loop(Client(), "/terminal/test", master, stop)
            self.assertTrue(stop.is_set())
            self.assertEqual(os.read(slave, 4), b"abc\n")
            self.assertEqual(output, ["/terminal/test/controls?after=1"])
            self.assertEqual(_decoded(_encoded(b"\x00\xff")), b"\x00\xff")
            with self.assertRaises(ValueError):
                _decoded("not+base64")
        finally:
            os.close(master)
            os.close(slave)

    def test_descendant_scan_includes_reparented_and_new_session_children(self):
        snapshot = {12: (500, 11), 13: (12, 12), 14: (13, 13),
                    15: (500, 14), 16: (999, 15)}
        with mock.patch("sovagrid_agent.terminal_broker._proc_snapshot", return_value=snapshot), mock.patch(
                "sovagrid_agent.terminal_broker.os.getpid", return_value=500):
            self.assertEqual(_descendants(12), {12: 11, 13: 12, 14: 13, 15: 14})
            # A reused PID from another parent must never be signalled.
            self.assertEqual(_descendants(16), {12: 11, 13: 12, 14: 13, 15: 14})

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "forkpty"), "Linux PTY cleanup required")
    def test_detached_shell_child_dies_when_agent_disconnects(self):
        left, right = socket.socketpair()
        with tempfile.TemporaryDirectory() as home:
            handler = os.fork()
            if handler == 0:
                left.close()
                with mock.patch("sovagrid_agent.terminal_broker._peer_uid", return_value=os.getuid()):
                    try:
                        handle_connection(right, os.getuid(), os.getuid(), os.getgid(), home)
                    except Exception:
                        os._exit(2)
                os._exit(0)
            right.close()
            master = None
            detached_pid = None
            detached_start = None
            handler_reaped = False
            try:
                left.sendall(b'{"cols":80,"rows":24}\n')
                response, ancillary, _, _ = left.recvmsg(16, socket.CMSG_SPACE(4))
                self.assertEqual(response, b"OK\n")
                descriptors = array.array("i")
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(data[:4])
                self.assertEqual(len(descriptors), 1)
                master = descriptors[0]
                os.write(master, b"setsid sleep 30 </dev/null >/dev/null 2>&1 & echo CHILD:$!\n")
                output = bytearray()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.2)
                    if readable:
                        output.extend(os.read(master, 4096))
                    found = re.search(rb"CHILD:(\d+)", output)
                    if found:
                        detached_pid = int(found.group(1))
                        detached_start = _process_starttime(detached_pid)
                        if detached_start is not None:
                            break
                self.assertIsNotNone(detached_start)
                os.close(master)
                master = None
                left.close()
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline:
                    waited, status = os.waitpid(handler, os.WNOHANG)
                    if waited:
                        handler_reaped = True
                        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                        break
                    time.sleep(0.05)
                else:
                    self.fail("terminal handler survived Agent disconnect")
                self.assertNotEqual(_process_starttime(detached_pid), detached_start)
            finally:
                if master is not None:
                    os.close(master)
                left.close()
                if not handler_reaped:
                    try:
                        os.kill(handler, signal.SIGKILL)
                        os.waitpid(handler, 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass
                if detached_pid is not None and _process_starttime(detached_pid) == detached_start:
                    os.kill(detached_pid, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
