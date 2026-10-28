# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""UTC clock diagnostics never alter the host and degrade safely."""

from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from sovagrid_agent.clock import snapshot


class ClockTests(unittest.TestCase):
    def fixture(self, *, rtc="1000165\n", status="Timezone=Etc/UTC\nLocalRTC=no\nNTPSynchronized=no\n"):
        folder = tempfile.TemporaryDirectory()
        root = Path(folder.name)
        path = root / "class/rtc/rtc0"
        path.mkdir(parents=True)
        (path / "since_epoch").write_text(rtc)
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=status)

        return folder, root, run, calls

    def test_unsynchronized_utc_rtc_reports_positive_offset(self):
        folder, root, run, calls = self.fixture()
        try:
            result = snapshot(sys_root=str(root), run=run, time_fn=lambda: 1000000)
        finally:
            folder.cleanup()
        self.assertEqual(result, {
            "system_utc_epoch": 1000000, "timezone": "Etc/UTC",
            "ntp_synchronized": False, "rtc_local_time": False,
            "rtc_utc_epoch": 1000165, "rtc_offset_seconds": 165,
        })
        self.assertEqual(calls[0][0][0], "timedatectl")
        self.assertLessEqual(calls[0][1]["timeout"], 2)

    def test_local_rtc_is_not_misreported_as_utc(self):
        folder, root, run, _ = self.fixture(status="Timezone=Europe/Moscow\nLocalRTC=yes\nNTPSynchronized=yes\n")
        try:
            result = snapshot(sys_root=str(root), run=run, time_fn=lambda: 1000000)
        finally:
            folder.cleanup()
        self.assertEqual(result["timezone"], "Europe/Moscow")
        self.assertTrue(result["ntp_synchronized"])
        self.assertTrue(result["rtc_local_time"])
        self.assertIsNone(result["rtc_utc_epoch"])
        self.assertIsNone(result["rtc_offset_seconds"])

    def test_missing_tools_or_rtc_are_unknown_not_unsynchronized(self):
        with tempfile.TemporaryDirectory() as folder:
            def unavailable(_argv, **_kwargs):
                raise subprocess.TimeoutExpired("timedatectl", 2)
            result = snapshot(sys_root=folder, run=unavailable, time_fn=lambda: 1000000)
        self.assertEqual(result["system_utc_epoch"], 1000000)
        self.assertIsNone(result["ntp_synchronized"])
        self.assertIsNone(result["rtc_offset_seconds"])

    def test_malformed_bounded_output_and_rtc_do_not_escape(self):
        folder, root, run, _ = self.fixture(rtc="not-an-epoch\n", status="Timezone=UTC\nLocalRTC=no\nNTPSynchronized=no\n")
        try:
            self.assertIsNone(snapshot(sys_root=str(root), run=run, time_fn=lambda: 1000000)["rtc_offset_seconds"])
            bad_run = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout="Timezone=UTC\n" * 200)
            self.assertIsNone(snapshot(sys_root=str(root), run=bad_run, time_fn=lambda: 1000000)["timezone"])
        finally:
            folder.cleanup()


if __name__ == "__main__":
    unittest.main()
