# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read one root-produced, bounded VPN inventory without opening private VPN state."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time


SNAPSHOT = Path("/var/lib/sovagrid-vpn-inventory/status.json")
MAX_BYTES = 65536
MAX_AGE_SECONDS = 90
_TOP_LEVEL = ("schema_version", "collected_at", "source", "source_status",
              "services", "managed", "amnezia_details")
_SERVICE = ("name", "state", "health", "published_ports")
_PORT = ("port", "protocol")
_MANAGED = ("name", "interface", "port", "subnet", "client_count", "state")
_AMNEZIA = ("name", "status", "configured_clients", "runtime_clients", "awg3_fields",
            "active_last_3m", "latest_handshake_at", "received_bytes", "sent_bytes",
            "api_enabled", "stats_enabled")


def _fields(value: object, names: tuple[str, ...]) -> dict:
    if type(value) is not dict:
        raise ValueError("Invalid VPN inventory row")
    return {key: value[key] for key in names if key in value}


def _public_source(snapshot: dict) -> dict:
    public = _fields(snapshot, _TOP_LEVEL)
    services = snapshot["services"]
    if len(services) > 8:
        raise ValueError("Too many VPN services")
    public["services"] = []
    for row in services:
        item = _fields(row, _SERVICE)
        ports = row.get("published_ports", [])
        if type(ports) is not list or len(ports) > 16:
            raise ValueError("Invalid VPN ports")
        item["published_ports"] = [_fields(port, _PORT) for port in ports]
        public["services"].append(item)
    managed = snapshot.get("managed")
    if managed is not None:
        item = _fields(managed, ("source_status", "instances"))
        instances = managed.get("instances", [])
        if type(instances) is not list or len(instances) > 64:
            raise ValueError("Invalid managed VPN instances")
        item["instances"] = [_fields(row, _MANAGED) for row in instances]
        public["managed"] = item
    amnezia = snapshot.get("amnezia_details")
    if amnezia is not None:
        item = _fields(amnezia, ("schema_version", "collected_at", "source_status", "services"))
        rows = amnezia.get("services", [])
        if type(rows) is not list or len(rows) > 3:
            raise ValueError("Invalid Amnezia details")
        item["services"] = [_fields(row, _AMNEZIA) for row in rows]
        public["amnezia_details"] = item
    return public


def read_snapshot(path: Path = SNAPSHOT, *, now: int | None = None,
                  owner: int = 0, group: int | None = None) -> dict | None:
    """Return only the fixed source schema; missing, stale or unsafe is unknown.

    The installed status timer owns the file. Agent only has group read access
    to this public projection and never traverses private VPN configuration.
    Hub independently projects every nested field before persistence.
    """
    now = int(time.time()) if now is None else now
    group = os.getegid() if group is None else group
    path = Path(path)
    try:
        directory = path.parent.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != owner or
                directory.st_gid != group or stat.S_IMODE(directory.st_mode) != 0o750):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            named = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or
                    before.st_gid != group or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != 0o640 or
                    not 0 < before.st_size <= MAX_BYTES or
                    (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
                return None
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(fd)
            if (len(raw) > MAX_BYTES or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                     before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                     after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid)):
                return None
        finally:
            os.close(fd)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        def reject_constant(_value):
            raise ValueError("Nonfinite VPN value")
        snapshot = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
        if (type(snapshot) is not dict or type(snapshot.get("schema_version")) is not int or
                snapshot["schema_version"] != 1 or type(snapshot.get("collected_at")) is not int or
                not 0 <= now - snapshot["collected_at"] <= MAX_AGE_SECONDS or
                snapshot.get("source") != "docker_cli" or
                snapshot.get("source_status") not in ("ok", "error") or
                type(snapshot.get("services")) is not list):
            return None
        # A root producer can evolve, but newly added top-level fields must
        # never become part of the Agent request by accident.
        return _public_source(snapshot)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return None
