# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import base64
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_agent.binary_files import CHUNK_BYTES, MAX_BINARY_BYTES, MAX_DOWNLOAD_BYTES, _sessions
from sovagrid_agent.files import FileError, operate


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class BinaryFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.config = {"allow_remote_commands": True, "allow_file_manager": True,
                       "file_roots": {"workspace": str(self.root)}}
        _sessions.clear()

    def tearDown(self):
        _sessions.clear()
        self.temp.cleanup()

    def request(self, action, path="file.bin", **fields):
        return operate(self.config, {"action": action, "root": "workspace", "path": path, **fields})

    def test_download_chunks_reassemble_and_detect_change(self):
        original = bytes(range(256)) * 600
        (self.root / "file.bin").write_bytes(original)
        info = self.request("binary_info")
        self.assertEqual(info["size"], len(original))
        self.assertEqual(info["sha256"], hashlib.sha256(original).hexdigest())
        chunks = [self.request("binary_chunk", etag=info["etag"], offset=offset)
                  for offset in range(0, len(original), CHUNK_BYTES)]
        self.assertEqual(b"".join(base64.urlsafe_b64decode(item["content"] + "=" * (-len(item["content"]) % 4))
                                  for item in chunks), original)
        (self.root / "file.bin").write_bytes(b"changed")
        with self.assertRaises(FileError) as error:
            self.request("binary_chunk", etag=info["etag"], offset=0)
        self.assertEqual(error.exception.code, "conflict")

    def test_download_over_upload_limit_keeps_bounded_chunks_and_etag(self):
        original = bytes(range(256)) * (MAX_BINARY_BYTES // 256 + 1)
        (self.root / "file.bin").write_bytes(original)
        info = self.request("binary_info")
        self.assertEqual(info["size"], MAX_BINARY_BYTES + 256)
        self.assertEqual(info["sha256"], hashlib.sha256(original).hexdigest())
        last = self.request("binary_chunk", etag=info["etag"], offset=MAX_BINARY_BYTES)
        self.assertEqual(last["size"], 256)
        self.assertEqual(base64.urlsafe_b64decode(last["content"] + "=" * (-len(last["content"]) % 4)),
                         original[MAX_BINARY_BYTES:])
        with self.assertRaises(FileError) as error:
            self.request("upload_begin", size=len(original), sha256=info["sha256"], etag=info["etag"])
        self.assertEqual(error.exception.code, "invalid_request")

    def test_upload_create_overwrite_conflict_and_cancel(self):
        data = bytes(range(256)) * 700
        digest = hashlib.sha256(data).hexdigest()
        beginning = self.request("upload_begin", size=len(data), sha256=digest, etag=None)
        upload_id = beginning["upload_id"]
        for offset in range(0, len(data), CHUNK_BYTES):
            result = self.request("upload_chunk", upload_id=upload_id, offset=offset,
                                  content=encoded(data[offset:offset + CHUNK_BYTES]))
        self.assertEqual(result["received"], len(data))
        saved = self.request("upload_commit", upload_id=upload_id)
        self.assertEqual((self.root / "file.bin").read_bytes(), data)
        self.assertEqual(stat.S_IMODE((self.root / "file.bin").stat().st_mode), 0o600)
        self.assertEqual(saved["sha256"], digest)
        with self.assertRaises(FileError) as error:
            self.request("upload_begin", size=0, sha256=hashlib.sha256(b"").hexdigest(), etag=None)
        self.assertEqual(error.exception.code, "conflict")
        replacing = self.request("upload_begin", size=0, sha256=hashlib.sha256(b"").hexdigest(),
                                 etag=saved["etag"])
        self.request("upload_commit", upload_id=replacing["upload_id"])
        self.assertEqual((self.root / "file.bin").read_bytes(), b"")
        cancelled = self.request("upload_begin", path="other.bin", size=0,
                                 sha256=hashlib.sha256(b"").hexdigest(), etag=None)
        self.assertEqual(self.request("upload_cancel", path="other.bin", upload_id=cancelled["upload_id"]),
                         {"cancelled": True})
        self.assertFalse((self.root / "other.bin").exists())
        self.assertEqual(list(self.root.glob(".sovagrid-upload-*")), [])

    def test_boundaries_symlinks_hardlinks_and_private_parent(self):
        with (self.root / "large.bin").open("wb") as stream:
            stream.truncate(MAX_DOWNLOAD_BYTES + 1)
        with self.assertRaises(FileError) as error:
            self.request("binary_info", path="large.bin")
        self.assertEqual(error.exception.code, "too_large")
        outside = self.root.parent / "outside-binary-test"
        outside.write_bytes(b"secret")
        self.addCleanup(outside.unlink)
        (self.root / "link.bin").symlink_to(outside)
        os.link(outside, self.root / "hard.bin")
        for name in ("link.bin", "hard.bin"):
            with self.subTest(name=name), self.assertRaises(FileError):
                self.request("binary_info", path=name)
        self.root.chmod(0o777)
        with self.assertRaises(FileError) as error:
            self.request("upload_begin", path="new.bin", size=0,
                         sha256=hashlib.sha256(b"").hexdigest(), etag=None)
        self.assertEqual(error.exception.code, "denied")

    def test_invalid_chunk_and_digest_cannot_publish_partial_file(self):
        data = b"safe"
        beginning = self.request("upload_begin", size=len(data), sha256="a" * 64, etag=None)
        upload_id = beginning["upload_id"]
        with self.assertRaises(FileError):
            self.request("upload_chunk", upload_id=upload_id, offset=1, content=encoded(data))
        with self.assertRaises(FileError):
            self.request("upload_chunk", upload_id=upload_id, offset=0, content=encoded(b"x" * (CHUNK_BYTES + 1)))
        self.request("upload_chunk", upload_id=upload_id, offset=0, content=encoded(data))
        with self.assertRaises(FileError) as error:
            self.request("upload_commit", upload_id=upload_id)
        self.assertEqual(error.exception.code, "conflict")
        self.assertFalse((self.root / "file.bin").exists())

    def test_stale_destination_and_session_cap_cannot_publish(self):
        empty_hash = hashlib.sha256(b"").hexdigest()
        active = [self.request("upload_begin", path=f"file-{index}.bin", size=0,
                               sha256=empty_hash, etag=None) for index in range(4)]
        with self.assertRaises(FileError) as error:
            self.request("upload_begin", path="fifth.bin", size=0, sha256=empty_hash, etag=None)
        self.assertEqual(error.exception.code, "busy")
        (self.root / "file-0.bin").write_bytes(b"created elsewhere")
        with self.assertRaises(FileError) as error:
            self.request("upload_commit", path="file-0.bin", upload_id=active[0]["upload_id"])
        self.assertEqual(error.exception.code, "conflict")
        self.assertEqual((self.root / "file-0.bin").read_bytes(), b"created elsewhere")

    def test_create_cannot_overwrite_target_appearing_at_publish(self):
        empty_hash = hashlib.sha256(b"").hexdigest()
        started = self.request("upload_begin", size=0, sha256=empty_hash, etag=None)
        original_link = os.link

        def racing_link(source, target, **kwargs):
            (self.root / target).write_bytes(b"appeared during commit")
            return original_link(source, target, **kwargs)

        with mock.patch("sovagrid_agent.binary_files.os.link", side_effect=racing_link):
            with self.assertRaises(FileError) as error:
                self.request("upload_commit", upload_id=started["upload_id"])
        self.assertEqual(error.exception.code, "conflict")
        self.assertEqual((self.root / "file.bin").read_bytes(), b"appeared during commit")
        self.assertEqual(list(self.root.glob(".sovagrid-upload-*")), [])


if __name__ == "__main__":
    unittest.main()
