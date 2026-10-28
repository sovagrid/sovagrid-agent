# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
from types import SimpleNamespace
import unittest
from unittest import mock

from sovagrid_agent.metrics import _filesystem_inventory, _trim_details


STAT = SimpleNamespace(f_blocks=100, f_frsize=4096, f_bavail=50,
                       f_files=1000, f_favail=500)


class FilesystemCompletenessTests(unittest.TestCase):
    def test_mount_cap_marks_snapshot_incomplete(self):
        mounts = [(f"/mnt/volume-{index:02d}", "ext4") for index in range(17)]
        with mock.patch("sovagrid_agent.metrics.mounts", return_value=mounts), \
             mock.patch("sovagrid_agent.metrics.os.statvfs", return_value=STAT):
            rows, truncated = _filesystem_inventory()
        self.assertEqual(len(rows), 16)
        self.assertTrue(truncated)

    def test_failed_local_mount_does_not_claim_complete_coverage(self):
        mounts = [("/mnt/ok", "ext4"), ("/mnt/unreadable", "ext4")]
        def stat(path):
            if path == "/mnt/unreadable":
                raise OSError("unavailable")
            return STAT
        with mock.patch("sovagrid_agent.metrics.mounts", return_value=mounts), \
             mock.patch("sovagrid_agent.metrics.os.statvfs", side_effect=stat):
            rows, truncated = _filesystem_inventory()
        self.assertEqual([row["mountpoint"] for row in rows], ["/mnt/ok"])
        self.assertTrue(truncated)

    def test_payload_budget_trim_marks_removed_filesystems(self):
        details = {"filesystems": [{"mountpoint": "/" + "a" * 120} for _ in range(16)],
                   "filesystems_truncated": False,
                   "top_processes": [{"name": "x" * 11900}]}
        _trim_details(details)
        self.assertTrue(details["filesystems_truncated"])
        self.assertLess(len(details["filesystems"]), 16)
        self.assertLessEqual(len(json.dumps(details, separators=(",", ":")).encode()), 12000)


if __name__ == "__main__":
    unittest.main()
