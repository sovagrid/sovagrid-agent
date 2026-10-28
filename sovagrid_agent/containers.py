# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict schema and unprivileged reader for the optional container snapshot."""

from __future__ import annotations

import json
import os
import grp
import pwd
import re
import stat
import time
from pathlib import Path

SNAPSHOT = Path("/var/lib/sovagrid-containers/snapshot.json")
LOCAL_SNAPSHOT = Path("/var/lib/sovagrid-containers-local/snapshot.json")
MAX_SNAPSHOT_BYTES = 10000
MAX_CONTAINERS = 12
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
STATES = ("created", "running", "paused", "restarting", "removing", "exited", "dead", "unknown")
HEALTH = (None, "starting", "healthy", "unhealthy")
REASONS = (None, "no_socket", "no_access", "error")


def _number(value, *, maximum: int, integer: bool = False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= maximum:
        raise ValueError("invalid container number")
    if integer and (type(value) is not int):
        raise ValueError("invalid container integer")
    return value


def validate_snapshot(value: object) -> dict:
    """Discard arbitrary Engine response keys; only this allowlist leaves the host."""
    if not isinstance(value, dict) or set(value) != {"version", "collected_at", "engines"}:
        raise ValueError("invalid container snapshot")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("unsupported container snapshot")
    collected_at = _number(value["collected_at"], maximum=253402300799, integer=True)
    if collected_at < 1:
        raise ValueError("invalid container timestamp")
    engines = value["engines"]
    if not isinstance(engines, list) or len(engines) != 2:
        raise ValueError("invalid container engines")
    clean_engines = []
    for expected, engine in zip(("docker", "podman"), engines):
        if not isinstance(engine, dict) or set(engine) != {"engine", "source_status", "reason", "truncated", "containers"}:
            raise ValueError("invalid container engine")
        if engine["engine"] != expected or engine["source_status"] not in ("ok", "unavailable"):
            raise ValueError("invalid container engine state")
        if (engine["reason"] not in REASONS or type(engine["truncated"]) is not bool or
                not isinstance(engine["containers"], list) or len(engine["containers"]) > MAX_CONTAINERS or
                (engine["source_status"] == "ok") != (engine["reason"] is None) or
                (engine["source_status"] == "unavailable" and (engine["containers"] or engine["truncated"]))):
            raise ValueError("invalid container engine fields")
        clean_items = []
        seen = set()
        for item in engine["containers"]:
            if not isinstance(item, dict) or set(item) != {"id", "name", "image", "state", "health", "restarts", "cpu_percent", "memory_bytes"}:
                raise ValueError("invalid container fields")
            ident, name, image = item["id"], item["name"], item["image"]
            if (not isinstance(ident, str) or not CONTAINER_ID.fullmatch(ident) or ident in seen or
                    not isinstance(name, str) or not 1 <= len(name) <= 96 or not name.isprintable() or
                    not isinstance(image, str) or not 1 <= len(image) <= 160 or not image.isprintable() or
                    item["state"] not in STATES or item["health"] not in HEALTH):
                raise ValueError("invalid container identity")
            seen.add(ident)
            for field, maximum, integer in (("restarts", 2**31 - 1, True),
                                             ("cpu_percent", 10000, False),
                                             ("memory_bytes", 2**63 - 1, True)):
                if item[field] is not None:
                    _number(item[field], maximum=maximum, integer=integer)
            clean_items.append({key: item[key] for key in ("id", "name", "image", "state", "health", "restarts", "cpu_percent", "memory_bytes")})
        clean_engines.append({"engine": expected, "source_status": engine["source_status"], "reason": engine["reason"],
                              "truncated": engine["truncated"], "containers": clean_items})
    clean = {"version": 1, "collected_at": collected_at, "engines": clean_engines}
    if len(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("container snapshot too large")
    return clean


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate container snapshot key")
        result[key] = value
    return result


def read_snapshot(path: Path = SNAPSHOT, *, owner_uid: int = 0,
                  group_gid: int | None = None, now: int | None = None) -> dict | None:
    """Read only a root-written, group-readable regular file without following links."""
    if group_gid is None:
        group_gid = os.getgid()
    if now is None:
        now = int(time.time())
    try:
        directory = path.parent.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != owner_uid or
                directory.st_gid != group_gid or stat.S_IMODE(directory.st_mode) != 0o750):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_gid != group_gid or
                    stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1 or
                    info.st_size > MAX_SNAPSHOT_BYTES):
                return None
            value = json.loads(stream.read(MAX_SNAPSHOT_BYTES + 1), object_pairs_hook=_unique_pairs)
        clean = validate_snapshot(value)
        if clean["collected_at"] > now + 300:
            return None
        return clean
    except (OSError, ValueError, UnicodeError):
        return None


def read_agent_snapshot() -> dict | None:
    """Select one fixed private snapshot by the Agent's exact service identity.

    A supplementary group, writable config field, or caller-supplied path can
    never redirect the external Agent into the local Agent's inventory.
    """
    identity = (os.geteuid(), os.getegid())
    matches = []
    for name, path in (("sovagrid", SNAPSHOT), ("sovagrid-local", LOCAL_SNAPSHOT)):
        try:
            user = pwd.getpwnam(name)
            group = grp.getgrnam(name)
        except (KeyError, OSError):
            continue
        if identity == (user.pw_uid, group.gr_gid) and user.pw_gid == group.gr_gid:
            matches.append((path, group.gr_gid))
    if len(matches) != 1:
        return None
    path, group_gid = matches[0]
    return read_snapshot(path, group_gid=group_gid)
