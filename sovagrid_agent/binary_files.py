# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded binary transfers confined to Agent's explicitly allowed file roots.

Uploads exist only in this process's bounded memory until an atomic commit.
Agent restarts discard them. Neither file bytes nor names enter Agent logs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import threading
import time
import uuid

from .files import FileError, _components, _open_directory, _NOFOLLOW

MAX_BINARY_BYTES = 4 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
MAX_SESSIONS = 4
SESSION_TTL = 600
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_sessions: dict[str, dict] = {}
_lock = threading.RLock()


def _valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)


def _etag(info):
    return hashlib.sha256(":".join(map(str, _snapshot(info))).encode("ascii")).hexdigest()


def _file(root: str, parts: list[str]):
    parent = _open_directory(root, parts[:-1])
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise FileError("unsupported")
            if info.st_size > MAX_DOWNLOAD_BYTES:
                raise FileError("too_large")
            return parent, fd, info
        except BaseException:
            os.close(fd)
            raise
    except BaseException:
        os.close(parent)
        raise


def _close(parent: int, fd: int):
    os.close(fd)
    os.close(parent)


def _decode(value):
    if not isinstance(value, str) or len(value) > 87382 or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise FileError("invalid_content")
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise FileError("invalid_content") from exc
    if len(data) > CHUNK_BYTES or base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") != value:
        raise FileError("invalid_content")
    return data


def _encode(value: bytes):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _target_at(parent: int, name: str, expected_etag):
    parent_info = os.fstat(parent)
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
        raise FileError("denied")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        if expected_etag is not None:
            raise FileError("conflict")
        return 0o600
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise FileError("unsupported")
        if info.st_size > MAX_BINARY_BYTES:
            raise FileError("too_large")
        if info.st_uid != os.geteuid() or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise FileError("denied")
        if expected_etag is None or _etag(info) != expected_etag:
            raise FileError("conflict")
        return stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def _target(root: str, parts: list[str], expected_etag):
    parent = _open_directory(root, parts[:-1])
    try:
        return parent, _target_at(parent, parts[-1], expected_etag)
    except BaseException:
        os.close(parent)
        raise


def _purge():
    cutoff = time.monotonic() - SESSION_TTL
    for key, value in list(_sessions.items()):
        if value["touched"] < cutoff:
            del _sessions[key]


def active_upload_sessions() -> int:
    """Expose only the count needed by the local quiescence gate."""
    with _lock:
        _purge()
        return len(_sessions)


def operate_binary(roots: dict[str, str], request: dict) -> dict:
    action = request["action"]
    fields = {
        "binary_info": {"action", "root", "path"},
        "binary_chunk": {"action", "root", "path", "etag", "offset"},
        "upload_begin": {"action", "root", "path", "size", "sha256", "etag"},
        "upload_chunk": {"action", "root", "path", "upload_id", "offset", "content"},
        "upload_commit": {"action", "root", "path", "upload_id"},
        "upload_cancel": {"action", "root", "path", "upload_id"},
    }
    if (set(request) != fields[action] or not isinstance(request.get("root"), str)
            or request["root"] not in roots):
        raise FileError("invalid_request")
    parts = _components(request.get("path"))
    if not parts:
        raise FileError("invalid_path")
    root, path = request["root"], request["path"]
    try:
        if action == "binary_info":
            parent, fd, info = _file(roots[root], parts)
            try:
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(fd, CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise FileError("too_large")
                if total != info.st_size or _snapshot(os.fstat(fd)) != _snapshot(info):
                    raise FileError("conflict")
                return {"size": info.st_size, "etag": _etag(info), "sha256": digest.hexdigest()}
            finally:
                _close(parent, fd)
        if action == "binary_chunk":
            offset, etag = request["offset"], request["etag"]
            if (type(offset) is not int or offset < 0 or offset % CHUNK_BYTES != 0
                    or not isinstance(etag, str) or not _HEX.fullmatch(etag)):
                raise FileError("invalid_request")
            parent, fd, info = _file(roots[root], parts)
            try:
                if _etag(info) != etag or offset >= info.st_size:
                    raise FileError("conflict")
                chunk = os.pread(fd, min(CHUNK_BYTES, info.st_size - offset), offset)
                if len(chunk) != min(CHUNK_BYTES, info.st_size - offset) or _snapshot(os.fstat(fd)) != _snapshot(info):
                    raise FileError("conflict")
                return {"content": _encode(chunk), "offset": offset, "size": len(chunk), "etag": etag}
            finally:
                _close(parent, fd)
        if action == "upload_begin":
            size, digest, etag = request["size"], request["sha256"], request["etag"]
            if (type(size) is not int or not 0 <= size <= MAX_BINARY_BYTES or
                    not isinstance(digest, str) or not _HEX.fullmatch(digest) or
                    (etag is not None and (not isinstance(etag, str) or not _HEX.fullmatch(etag)))):
                raise FileError("invalid_request")
            parent, _ = _target(roots[root], parts, etag)
            os.close(parent)
            with _lock:
                _purge()
                if len(_sessions) >= MAX_SESSIONS:
                    raise FileError("busy")
                upload_id = str(uuid.uuid4())
                _sessions[upload_id] = {"root": root, "path": path, "size": size, "sha256": digest,
                                        "etag": etag, "data": bytearray(), "touched": time.monotonic()}
            return {"upload_id": upload_id, "size": size}
        upload_id = request.get("upload_id")
        if not _valid_uuid(upload_id):
            raise FileError("invalid_request")
        with _lock:
            _purge()
            session = _sessions.get(upload_id)
            if not session or (session["root"], session["path"]) != (root, path):
                raise FileError("not_found")
            session["touched"] = time.monotonic()
            if action == "upload_cancel":
                del _sessions[upload_id]
                return {"cancelled": True}
            if action == "upload_chunk":
                offset = request["offset"]
                data = _decode(request["content"])
                if (type(offset) is not int or offset != len(session["data"])
                        or not data or len(session["data"]) + len(data) > session["size"]):
                    raise FileError("conflict")
                session["data"].extend(data)
                return {"received": len(session["data"]), "size": session["size"]}
            if len(session["data"]) != session["size"] or hashlib.sha256(session["data"]).hexdigest() != session["sha256"]:
                raise FileError("conflict")
            parent, mode = _target(roots[root], parts, session["etag"])
            temporary = f".sovagrid-upload-{uuid.uuid4().hex}"
            fd = -1
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                             0o600, dir_fd=parent)
                os.fchmod(fd, mode)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(session["data"])
                    stream.flush()
                    os.fsync(fd)
                _target_at(parent, parts[-1], session["etag"])
                if session["etag"] is None:
                    # A new target must never replace a file created after
                    # upload_begin. The hard-link creation is atomic.
                    os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent,
                            follow_symlinks=False)
                    os.unlink(temporary, dir_fd=parent)
                else:
                    # Another Agent-user process can still race this final
                    # check; the parent directory is required to be private.
                    os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                del _sessions[upload_id]
                return {"size": session["size"], "sha256": session["sha256"], "etag": _etag(info)}
            finally:
                if fd != -1:
                    os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
                os.close(parent)
    except FileError:
        raise
    except FileExistsError as exc:
        raise FileError("conflict") from exc
    except FileNotFoundError as exc:
        raise FileError("not_found") from exc
    except (PermissionError, IsADirectoryError, NotADirectoryError) as exc:
        raise FileError("denied") from exc
    except OSError as exc:
        raise FileError("unavailable") from exc
