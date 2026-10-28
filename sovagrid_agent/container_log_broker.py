# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Restricted Engine log read used only by the root service socket broker.

The Engine socket is powerful. This module makes fixed GET requests for one
full ID after a fresh SovaGrid inventory and a second Compose label check.
No Engine JSON, environment, mount, or raw binary stream leaves this process.
"""

from __future__ import annotations

from contextlib import contextmanager
import grp
import http.client
from pathlib import Path
import signal
import stat
import time

from .container_collector import API_PREFIX, SOCKETS, UnixHTTPConnection, _get
from .container_logs import MAX_OUTPUT_BYTES, parameters, safe_text
from .containers import read_snapshot


MARKER = Path("/etc/sovagrid/.containers-managed-by-run-sh")
MAX_SNAPSHOT_AGE = 90
MAX_RAW_BYTES = 16384
COMPOSE_IMAGES = {"hub": "sovagrid-hub:local", "web": "sovagrid-web:local"}
MAX_OPERATION_SECONDS = 7


@contextmanager
def _time_limit():
    """Bound the complete single-threaded broker request, including trickling HTTP."""
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise TimeoutError("Container log broker deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, MAX_OPERATION_SECONDS)
    if previous_timer[0] > 0:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)
        raise PermissionError("Container log broker has a conflicting timer")
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _enabled(path: Path = MARKER) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 64):
        raise PermissionError("Container inventory opt-in is unsafe")


def _socket(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise PermissionError("Engine socket is unavailable")


def _inventory(engine: str, ident: str, *, now: int | None = None,
               snapshot: dict | None = None) -> None:
    now = int(time.time()) if now is None else now
    if snapshot is None:
        snapshot = read_snapshot(group_gid=grp.getgrnam("sovagrid").gr_gid, now=now)
    if (snapshot is None or type(snapshot.get("collected_at")) is not int or
            not 0 <= now - snapshot["collected_at"] <= MAX_SNAPSHOT_AGE):
        raise PermissionError("Fresh container inventory is unavailable")
    matches = [item for source in snapshot["engines"] if source["engine"] == engine
               and source["source_status"] == "ok" and not source["truncated"]
               for item in source["containers"] if item["id"] == ident]
    if len(matches) != 1:
        raise PermissionError("Container is not in the complete managed inventory")


def _identity(value: object, ident: str) -> bool:
    if not isinstance(value, dict) or value.get("Id") != ident:
        return False
    config = value.get("Config")
    if not isinstance(config, dict) or type(config.get("Tty")) is not bool:
        return False
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        return False
    service = labels.get("com.docker.compose.service")
    return (labels.get("com.docker.compose.project") == "sovagrid" and
            isinstance(service, str) and service in COMPOSE_IMAGES and
            config.get("Image") == COMPOSE_IMAGES[service])


def _raw_logs(path: Path, ident: str, lines: int) -> bytes:
    client = UnixHTTPConnection(path, timeout=5)
    try:
        endpoint = (f"{API_PREFIX}/containers/{ident}/logs?follow=0&stdout=1&stderr=1"
                    f"&timestamps=0&tail={lines}")
        client.request("GET", endpoint, headers={"Accept": "application/octet-stream"})
        response = client.getresponse()
        if response.status != 200:
            raise OSError("Container logs are unavailable")
        raw = response.read(MAX_RAW_BYTES + 1)
        if len(raw) > MAX_RAW_BYTES:
            raise OverflowError("Container logs exceed the bounded read")
        return raw
    finally:
        client.close()


def _decode(raw: bytes, *, tty: bool) -> str:
    if not tty:
        offset = 0
        chunks = []
        payload_bytes = 0
        while offset < len(raw):
            if len(raw) - offset < 8 or raw[offset] not in (1, 2) or raw[offset + 1:offset + 4] != b"\0\0\0":
                raise ValueError("Invalid Engine log frame")
            size = int.from_bytes(raw[offset + 4:offset + 8], "big")
            offset += 8
            if size > len(raw) - offset:
                raise ValueError("Incomplete Engine log frame")
            payload_bytes += size
            if payload_bytes > MAX_OUTPUT_BYTES:
                raise OverflowError("Container logs exceed output limit")
            chunks.append(raw[offset:offset + size])
            offset += size
        raw = b"".join(chunks)
    if len(raw) > MAX_OUTPUT_BYTES:
        raise OverflowError("Container logs exceed output limit")
    # TTY-backed applications commonly emit CRLF. A standalone carriage
    # return can repaint terminal content, so it remains forbidden below.
    raw = raw.replace(b"\r\n", b"\n")
    text = raw.decode("utf-8", "strict")
    if not safe_text(text):
        raise ValueError("Container logs contain control or binary content")
    return text


def execute(engine: str, ident: str, lines: int, *, snapshot: dict | None = None,
            getter=_get, logs_getter=_raw_logs, marker: Path = MARKER,
            now: int | None = None) -> dict:
    parameters(engine, ident, lines)
    with _time_limit():
        _enabled(marker)
        _inventory(engine, ident, now=now, snapshot=snapshot)
        path = SOCKETS[engine]
        _socket(path)
        value = getter(path, f"/containers/{ident}/json", limit=65536, timeout=2)
        if not _identity(value, ident):
            raise PermissionError("Container identity is not SovaGrid-managed")
        try:
            output = _decode(logs_getter(path, ident, lines), tty=value["Config"]["Tty"])
        except OverflowError:
            return {"state": "output_limited", "exit_code": None,
                    "output": "Container logs exceed the 8192-byte limit; request fewer lines"}
        return {"state": "succeeded", "exit_code": 0, "output": output}
