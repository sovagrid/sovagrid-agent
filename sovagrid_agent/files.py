# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded file operations on explicitly configured local directories.

The Agent opens each path component relative to a directory descriptor with
O_NOFOLLOW. Nothing in this module needs a root identity or a shell.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import itertools
import json
import os
import re
import stat
import time
import uuid

MAX_TEXT_BYTES = 8192
MAX_ENTRIES = 200
MAX_LIST_JSON_BYTES = 12000
_ROOT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC


class FileError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _components(path: str) -> list[str]:
    if not isinstance(path, str) or "\x00" in path or "\\" in path:
        raise FileError("invalid_path")
    try:
        if len(path.encode("utf-8")) > 512:
            raise FileError("invalid_path")
    except UnicodeEncodeError as exc:
        raise FileError("invalid_path") from exc
    if path == "":
        return []
    parts = path.split("/")
    if (len(parts) > 20 or any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255
                               or not part.isprintable() for part in parts)):
        raise FileError("invalid_path")
    return parts


def validate_roots(config: dict) -> dict[str, str]:
    roots = config.get("file_roots", {})
    if not isinstance(roots, dict) or len(roots) > 8:
        raise ValueError("file_roots must map at most eight names to absolute paths")
    for name, path in roots.items():
        if (not isinstance(name, str) or not _ROOT.fullmatch(name)
                or not isinstance(path, str) or not path.startswith("/")
                or path == "/" or path.endswith("/") or len(path.encode("utf-8")) > 512
                or "\x00" in path or "\\" in path):
            raise ValueError("Invalid file root")
        try:
            _components(path[1:])
        except FileError as exc:
            raise ValueError("Invalid file root") from exc
    return roots


def _open_directory(root_path: str, relative_parts: list[str]):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in _components(root_path[1:]) + relative_parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _etag(info, content: bytes) -> str:
    marker = f"{info.st_dev}:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}:".encode("ascii")
    return hashlib.sha256(marker + content).hexdigest()


def _regular_content(parent_fd: int, name: str):
    fd = os.open(name, os.O_RDONLY | _NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FileError("unsupported")
        if before.st_size > MAX_TEXT_BYTES:
            raise FileError("too_large")
        data = bytearray()
        while len(data) <= MAX_TEXT_BYTES:
            chunk = os.read(fd, MAX_TEXT_BYTES + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (len(data) > MAX_TEXT_BYTES or after.st_size > MAX_TEXT_BYTES):
            raise FileError("too_large")
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) != (
                after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size):
            raise FileError("conflict")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileError("unsupported") from exc
        if "\x00" in text:
            raise FileError("unsupported")
        return bytes(data), before
    finally:
        os.close(fd)


def _decode_content(encoded: str) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > 10923 or not re.fullmatch(r"[A-Za-z0-9_-]*", encoded):
        raise FileError("invalid_content")
    try:
        data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise FileError("invalid_content") from exc
    if (len(data) > MAX_TEXT_BYTES
            or base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") != encoded):
        raise FileError("invalid_content")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FileError("invalid_content") from exc
    if "\x00" in text:
        raise FileError("invalid_content")
    return data


def operate(config: dict, request: dict) -> dict:
    """Run one validated operation; errors have fixed codes and no path text."""
    if os.geteuid() == 0:
        raise PermissionError("File operations may not execute as root")
    if not config.get("allow_remote_commands", False) or not config.get("allow_file_manager", False):
        raise FileError("disabled")
    roots = validate_roots(config)
    if not isinstance(request, dict):
        raise FileError("invalid_request")
    action = request.get("action")
    if action == "roots" and set(request) == {"action"}:
        return {"roots": sorted(roots)}
    if action in ("binary_info", "binary_chunk", "upload_begin", "upload_chunk",
                  "upload_commit", "upload_cancel"):
        from .binary_files import operate_binary
        return operate_binary(roots, request)
    if action not in ("list", "read", "write") or not isinstance(request.get("root"), str):
        raise FileError("invalid_request")
    expected = {"action", "root", "path"} | ({"etag", "content"} if action == "write" else set())
    if set(request) != expected:
        raise FileError("invalid_request")
    root = request["root"]
    if root not in roots:
        raise FileError("unknown_root")
    parts = _components(request["path"])
    if action in ("read", "write") and not parts:
        raise FileError("invalid_path")
    try:
        if action == "list":
            directory = _open_directory(roots[root], parts)
            try:
                entries = []
                # Cap scanning even when an attacker creates millions of names.
                with os.scandir(directory) as scan:
                    names = sorted(item.name for item in itertools.islice(scan, MAX_ENTRIES + 1))
                listed_bytes = 0
                truncated = len(names) > MAX_ENTRIES
                for name in names:
                    if len(entries) >= MAX_ENTRIES:
                        break
                    try:
                        name.encode("utf-8")
                        if name in (".", "..") or len(name.encode("utf-8")) > 255:
                            continue
                        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except (OSError, UnicodeEncodeError):
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        kind = "directory"
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        kind = "file"
                    else:
                        continue
                    entry = {"name": name, "kind": kind, "size": info.st_size if kind == "file" else None}
                    cost = len(json.dumps(entry, ensure_ascii=True, separators=(",", ":")).encode("ascii")) + 1
                    if listed_bytes + cost > MAX_LIST_JSON_BYTES:
                        truncated = True
                        break
                    entries.append(entry)
                    listed_bytes += cost
                return {"entries": entries, "truncated": truncated}
            finally:
                os.close(directory)
        parent = _open_directory(roots[root], parts[:-1])
        try:
            content, info = _regular_content(parent, parts[-1])
            current_etag = _etag(info, content)
            if action == "read":
                return {"content": base64.urlsafe_b64encode(content).decode("ascii").rstrip("="),
                        "etag": current_etag, "size": len(content)}
            if (not isinstance(request.get("etag"), str) or not _HEX.fullmatch(request["etag"])):
                raise FileError("invalid_etag")
            if request["etag"] != current_etag:
                raise FileError("conflict")
            parent_info = os.fstat(parent)
            if (info.st_uid != os.geteuid() or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
                    or parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022):
                raise FileError("denied")
            replacement = _decode_content(request["content"])
            temporary = f".sovagrid-{uuid.uuid4().hex}"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                os.fchmod(fd, stat.S_IMODE(info.st_mode))
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(replacement)
                    stream.flush()
                    os.fsync(fd)
                # Detect changes made while the temporary file was written.
                latest, latest_info = _regular_content(parent, parts[-1])
                if _etag(latest_info, latest) != current_etag:
                    raise FileError("conflict")
                os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                after = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                return {"etag": _etag(after, replacement), "size": len(replacement)}
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent)
    except FileError:
        raise
    except FileNotFoundError as exc:
        raise FileError("not_found") from exc
    except (PermissionError, IsADirectoryError, NotADirectoryError) as exc:
        raise FileError("denied") from exc
    except OSError as exc:
        raise FileError("unavailable") from exc


def file_loop(config: dict, client, quiescence=None):
    """Keep each fetched file action counted through its result POST."""
    if not config.get("allow_remote_commands", False) or not config.get("allow_file_manager", False):
        return
    if os.geteuid() == 0:
        raise PermissionError("File poller must not run as root")
    path = f"/api/v1/servers/{client.server_id}/files"
    while True:
        try:
            with (quiescence.operation("file") if quiescence is not None else contextlib.nullcontext()):
                item = client.request("GET", path + "/next").get("operation")
                if not item:
                    continue
                try:
                    value = operate(config, item["request"])
                    result = {"state": "succeeded", "value": value}
                except FileError as exc:
                    result = {"state": "failed", "code": exc.code}
                except Exception:
                    result = {"state": "failed", "code": "unavailable"}
                client.request("POST", path + f"/operations/{item['id']}/result", result)
        except Exception:
            # Never log request objects, paths, content, or urllib errors.
            time.sleep(3)
