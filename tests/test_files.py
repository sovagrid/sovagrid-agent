# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from sovagrid_agent.files import FileError, operate, validate_roots


def encoded(value: str):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


class FileOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        (self.root / "note.txt").write_text("initial\n", encoding="utf-8")
        self.config = {"allow_remote_commands": True, "allow_file_manager": True,
                       "file_roots": {"workspace": str(self.root)}}

    def tearDown(self):
        self.temp.cleanup()

    def test_roots_list_read_write_and_conflict(self):
        self.assertEqual(operate(self.config, {"action": "roots"}), {"roots": ["workspace"]})
        listed = operate(self.config, {"action": "list", "root": "workspace", "path": ""})
        self.assertEqual(listed["entries"][0]["name"], "note.txt")
        request = {"action": "read", "root": "workspace", "path": "note.txt"}
        old = operate(self.config, request)
        self.assertEqual(old["content"], encoded("initial\n"))
        replacement = {"action": "write", "root": "workspace", "path": "note.txt",
                       "etag": old["etag"], "content": encoded("new text\n")}
        changed = operate(self.config, replacement)
        self.assertNotEqual(changed["etag"], old["etag"])
        self.assertEqual((self.root / "note.txt").read_text(), "new text\n")
        with self.assertRaises(FileError) as error:
            operate(self.config, replacement)
        self.assertEqual(error.exception.code, "conflict")

    def test_path_escape_symlink_hardlink_and_fifo_are_rejected(self):
        outside = self.root.parent / "outside-file.txt"
        outside.write_text("outside")
        self.addCleanup(outside.unlink)
        (self.root / "link").symlink_to(outside)
        (self.root / "dir-link").symlink_to(self.root.parent, target_is_directory=True)
        os.link(outside, self.root / "hardlink")
        os.mkfifo(self.root / "pipe")
        for path in ("../outside-file.txt", "/etc/passwd", "sub/../note.txt"):
            with self.subTest(path=path), self.assertRaises(FileError):
                operate(self.config, {"action": "read", "root": "workspace", "path": path})
        for path in ("link", "hardlink", "pipe"):
            with self.subTest(path=path), self.assertRaises(FileError):
                operate(self.config, {"action": "read", "root": "workspace", "path": path})
        with self.assertRaises(FileError):
            operate(self.config, {"action": "list", "root": "workspace", "path": "dir-link"})
        names = [item["name"] for item in operate(
            self.config, {"action": "list", "root": "workspace", "path": ""})["entries"]]
        self.assertEqual(names, ["note.txt"])

    def test_large_or_binary_files_are_rejected(self):
        (self.root / "large.txt").write_bytes(b"a" * 8193)
        (self.root / "binary.txt").write_bytes(b"hello\0world")
        for path in ("large.txt", "binary.txt"):
            with self.subTest(path=path), self.assertRaises(FileError):
                operate(self.config, {"action": "read", "root": "workspace", "path": path})

    def test_listing_stays_within_hub_request_bound(self):
        for index in range(100):
            (self.root / (f"{index:03d}-" + "ф" * 40)).write_text("x")
        result = operate(self.config, {"action": "list", "root": "workspace", "path": ""})
        self.assertTrue(result["truncated"])
        self.assertLess(len(json.dumps(result).encode("utf-8")), 16384)

    def test_write_requires_private_agent_owned_parent(self):
        old = operate(self.config, {"action": "read", "root": "workspace", "path": "note.txt"})
        self.root.chmod(0o777)
        with self.assertRaises(FileError) as error:
            operate(self.config, {"action": "write", "root": "workspace", "path": "note.txt",
                                  "etag": old["etag"], "content": encoded("changed")})
        self.assertEqual(error.exception.code, "denied")
        self.assertEqual((self.root / "note.txt").read_text(), "initial\n")

    def test_disabled_and_invalid_roots(self):
        with self.assertRaises(FileError) as error:
            operate(self.config | {"allow_file_manager": False}, {"action": "roots"})
        self.assertEqual(error.exception.code, "disabled")
        with self.assertRaises(ValueError):
            validate_roots({"file_roots": {"anything": "/"}})


if __name__ == "__main__":
    unittest.main()
