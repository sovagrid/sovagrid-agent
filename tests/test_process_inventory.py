# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""On-demand process pages cannot turn into shell commands or metric history."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_agent.agent import _command_plan, run_once
from sovagrid_agent.process_inventory import MARKER, job_result, parse_request, snapshot


class ProcessInventoryTests(unittest.TestCase):
    def test_exact_marker_and_bounded_filter(self):
        command = f"{MARKER} list 0 32 707974686f6e"
        self.assertEqual(parse_request(command), (0, 32, "python"))
        with self.assertRaises(ValueError):
            _command_plan(command, 15)
        for malformed in (f"{command}; id", f"{MARKER} list 00 32 -",
                          f"{MARKER} list 0 33 -", f"{MARKER} list 0 32 5",
                          f"echo {MARKER} list 0 1 -"):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_request(malformed)
            with self.subTest(shell=malformed), self.assertRaises(ValueError):
                _command_plan(malformed, 15)

    def test_pages_filter_and_disappearing_process(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            for pid in range(1, 71):
                entry = proc / str(pid)
                entry.mkdir()
                (entry / "comm").write_text("python\n" if pid % 2 else "[kworker/0:1]\n")
                (entry / "statm").write_text(f"100 {pid}\n")
            (proc / "71").mkdir()  # exited between directory discovery and reads
            first = snapshot(0, 32, "worker", proc_root=root, page_size=4096)
            self.assertEqual(len(first["processes"]), 32)
            self.assertEqual(first["processes"][0],
                             {"pid": 2, "name": "[kworker/0:1]", "rss_bytes": 8192})
            self.assertTrue(first["has_more"])
            second = snapshot(first["next_after_pid"], 32, "worker", proc_root=root,
                              page_size=4096)
            self.assertEqual([row["pid"] for row in second["processes"]], [66, 68, 70])
            self.assertFalse(second["has_more"])
            self.assertLess(len(json.dumps(first).encode()), 8192)
            self.assertEqual(job_result((0, 32, "worker"), collector=lambda *args: first)
                             ["state"], "succeeded")

    def test_job_intercept_does_not_invoke_shell(self):
        class Client:
            def __init__(self):
                self.metrics = []
                self.results = []

            def push_metrics(self, value):
                self.metrics.append(value)

            def next_job(self):
                return {"id": "job", "command": f"{MARKER} list 0 2 -"}

            def send_result(self, job_id, result):
                self.results.append((job_id, result))

        client = Client()
        page = {"observed_at": 1234, "after_pid": 0, "filter": "", "next_after_pid": 1,
                "has_more": False, "processes": [{"pid": 1, "name": "init", "rss_bytes": 4}]}
        with mock.patch("sovagrid_agent.agent.collect", return_value={"collected_at": 1234}), \
             mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), \
             mock.patch("sovagrid_agent.agent._process_job_result",
                        return_value={"state": "succeeded", "exit_code": 0,
                                      "output": json.dumps(page)}) as process, \
             mock.patch("sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, client)
        self.assertEqual(len(client.metrics), 1)
        self.assertEqual(client.results[0][0], "job")
        process.assert_called_once_with((0, 2, ""))
        shell.assert_not_called()


if __name__ == "__main__":
    unittest.main()
