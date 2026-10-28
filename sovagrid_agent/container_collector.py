# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in, root-only collector for bounded Docker/Podman read-only inventory.

Only fixed GET endpoints are requested on local Unix sockets. The raw Engine
responses (which may contain configuration secrets) are never logged or saved.
"""

from __future__ import annotations

import grp
import http.client
import json
import os
import socket
import stat
import sys
import tempfile
import time
from pathlib import Path

from .containers import (CONTAINER_ID, LOCAL_SNAPSHOT, MAX_CONTAINERS,
                         MAX_SNAPSHOT_BYTES, SNAPSHOT, validate_snapshot)

SOCKETS = {"docker": Path("/run/docker.sock"), "podman": Path("/run/podman/podman.sock")}
API_PREFIX = "/v1.40"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: Path, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def _get(path: Path, endpoint: str, *, limit: int, timeout: float) -> object:
    client = UnixHTTPConnection(path, timeout)
    try:
        client.request("GET", API_PREFIX + endpoint, headers={"Accept": "application/json"})
        response = client.getresponse()
        if response.status != 200:
            raise OSError("Engine API request failed")
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise OSError("Engine API response exceeds limit")
        return json.loads(raw)
    finally:
        client.close()


def _valid_name(value, limit: int) -> str | None:
    return value if isinstance(value, str) and 1 <= len(value) <= limit and value.isprintable() else None


def _nonnegative_int(value, maximum: int) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def _inspect_fields(path: Path, ident: str, deadline: float) -> tuple[int | None, str | None]:
    if time.monotonic() >= deadline:
        return None, None
    try:
        value = _get(path, f"/containers/{ident}/json", limit=65536,
                     timeout=min(1.5, max(0.1, deadline - time.monotonic())))
    except (OSError, ValueError, http.client.HTTPException):
        return None, None
    if not isinstance(value, dict):
        return None, None
    restarts = _nonnegative_int(value.get("RestartCount"), 2**31 - 1)
    state = value.get("State")
    health = state.get("Health") if isinstance(state, dict) else None
    health = health.get("Status") if isinstance(health, dict) else None
    return restarts, health if health in ("starting", "healthy", "unhealthy") else None


def _stats_fields(path: Path, ident: str, deadline: float) -> tuple[float | None, int | None]:
    if time.monotonic() >= deadline:
        return None, None
    try:
        value = _get(path, f"/containers/{ident}/stats?stream=false&one-shot=true", limit=65536,
                     timeout=min(1.5, max(0.1, deadline - time.monotonic())))
    except (OSError, ValueError, http.client.HTTPException):
        return None, None
    if not isinstance(value, dict):
        return None, None
    memory = value.get("memory_stats") or {}
    used = _nonnegative_int(memory.get("usage"), 2**63 - 1) if isinstance(memory, dict) else None
    cached = memory.get("stats", {}) if isinstance(memory, dict) else {}
    if isinstance(cached, dict) and used is not None:
        cache = _nonnegative_int(cached.get("inactive_file", cached.get("total_inactive_file")), used)
        if cache is not None:
            used -= cache
    cpu, previous = value.get("cpu_stats") or {}, value.get("precpu_stats") or {}
    percent = None
    if isinstance(cpu, dict) and isinstance(previous, dict):
        current_usage = cpu.get("cpu_usage") or {}
        previous_usage = previous.get("cpu_usage") or {}
        if isinstance(current_usage, dict) and isinstance(previous_usage, dict):
            now_cpu = _nonnegative_int(current_usage.get("total_usage"), 2**63 - 1)
            old_cpu = _nonnegative_int(previous_usage.get("total_usage"), 2**63 - 1)
            now_system = _nonnegative_int(cpu.get("system_cpu_usage"), 2**63 - 1)
            old_system = _nonnegative_int(previous.get("system_cpu_usage"), 2**63 - 1)
            online = cpu.get("online_cpus")
            if online is None:
                per_cpu = current_usage.get("percpu_usage")
                online = len(per_cpu) if isinstance(per_cpu, list) else None
            if (None not in (now_cpu, old_cpu, now_system, old_system) and
                    type(online) is int and 1 <= online <= 1024 and
                    now_cpu >= old_cpu and now_system > old_system):
                estimate = round(100 * (now_cpu - old_cpu) * online / (now_system - old_system), 2)
                if 0 <= estimate <= 10000:
                    percent = estimate
    return percent, used


def _engine(name: str, path: Path, *, owner_uid: int = 0) -> dict:
    unavailable = lambda reason: {"engine": name, "source_status": "unavailable", "reason": reason,
                                  "truncated": False, "containers": []}
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return unavailable("no_socket")
    except PermissionError:
        return unavailable("no_access")
    except OSError:
        return unavailable("error")
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid:
        return unavailable("no_access")
    try:
        raw = _get(path, f"/containers/json?all=1&limit={MAX_CONTAINERS + 1}", limit=262144, timeout=2)
    except PermissionError:
        return unavailable("no_access")
    except (OSError, ValueError, http.client.HTTPException):
        return unavailable("error")
    if not isinstance(raw, list):
        return unavailable("error")
    deadline = time.monotonic() + 10
    items = []
    seen = set()
    complete = len(raw) <= MAX_CONTAINERS
    for entry in raw[:MAX_CONTAINERS]:
        if not isinstance(entry, dict):
            complete = False
            continue
        ident = entry.get("Id")
        names = entry.get("Names")
        name_value = names[0].lstrip("/") if isinstance(names, list) and names and isinstance(names[0], str) else None
        container_name = _valid_name(name_value, 96)
        image = _valid_name(entry.get("Image"), 160)
        state = entry.get("State")
        if (not isinstance(ident, str) or not CONTAINER_ID.fullmatch(ident) or ident in seen or
                container_name is None or image is None):
            complete = False
            continue
        seen.add(ident)
        if state not in ("created", "running", "paused", "restarting", "removing", "exited", "dead"):
            state = "unknown"
        restarts, health = _inspect_fields(path, ident, deadline)
        cpu, memory = _stats_fields(path, ident, deadline) if state == "running" else (None, None)
        items.append({"id": ident, "name": container_name, "image": image, "state": state,
                      "health": health, "restarts": restarts,
                      "cpu_percent": cpu, "memory_bytes": memory})
    # Missing-container alerts require a complete name set. A malformed or
    # duplicate Engine row is omitted from the public snapshot, so it must
    # also invalidate any claim that a container name is absent.
    return {"engine": name, "source_status": "ok", "reason": None,
            "truncated": not complete, "containers": items}


def collect() -> dict:
    engines = [_engine(name, path) for name, path in SOCKETS.items()]
    value = {"version": 1, "collected_at": int(time.time()), "engines": engines}
    # A long but valid image/name must not crowd out host metrics in the
    # Agent's 12 KiB detail envelope. Keep the shape and mark a clipped list.
    while len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) >= MAX_SNAPSHOT_BYTES:
        largest = max(engines, key=lambda item: len(item["containers"]))
        if not largest["containers"]:
            raise ValueError("container snapshot cannot fit")
        largest["containers"].pop()
        largest["truncated"] = True
    return validate_snapshot(value)


def save(value: dict, path: Path = SNAPSHOT, *, group_gid: int | None = None) -> None:
    if os.geteuid() != 0:
        raise PermissionError("container collector requires root")
    if group_gid is None:
        group_gid = grp.getgrnam("sovagrid").gr_gid
    directory = path.parent.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            directory.st_gid != group_gid or stat.S_IMODE(directory.st_mode) != 0o750):
        raise PermissionError("unsafe container snapshot directory")
    content = (json.dumps(validate_snapshot(value), ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(content) > MAX_SNAPSHOT_BYTES:
        raise ValueError("container snapshot too large")
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != 0 or info.st_gid != group_gid:
                raise PermissionError("collector identity cannot create the private snapshot")
            os.fchmod(stream.fileno(), 0o640)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> None:
    """Run only one of two fixed, isolated collector profiles."""
    if argv is None:
        argv = sys.argv[1:]
    if argv == []:
        save(collect())
        return
    if argv == ["--local"]:
        local_gid = grp.getgrnam("sovagrid-local").gr_gid
        if os.geteuid() != 0 or os.getegid() != local_gid:
            raise PermissionError("local collector requires root:sovagrid-local")
        save(collect(), path=LOCAL_SNAPSHOT, group_gid=local_gid)
        return
    raise SystemExit("usage: python3 -m sovagrid_agent.container_collector [--local]")


if __name__ == "__main__":
    main()
