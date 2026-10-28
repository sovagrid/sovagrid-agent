# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Socket-activated, non-root journal reader with an independent root policy."""

from __future__ import annotations

import grp
import json
import logging
import os
import pwd
import socket
import stat
import struct

from .agent import run_command
from .journal import MARKER, SOCKET_PATH, configured_units, journal_argv


POLICY_PATH = "/etc/sovagrid-journal/units.json"
MAX_RESPONSE_BYTES = 12000


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_policy(path: str = POLICY_PATH, broker_gid: int | None = None) -> tuple[str, ...]:
    """Open one exact root-owned policy without following a symlink."""
    if broker_gid is None:
        broker_gid = grp.getgrnam("sovagrid-journal").gr_gid
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != 0 or info.st_gid != broker_gid or
                stat.S_IMODE(info.st_mode) != 0o640 or not 1 <= info.st_size <= 4096):
            raise PermissionError("Unsafe journal policy")
        raw = os.read(fd, 4097)
        if len(raw) != info.st_size:
            raise ValueError("Journal policy changed during read")
    finally:
        os.close(fd)
    value = json.loads(raw, object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict) or set(value) != {"units"}:
        raise ValueError("Invalid journal policy")
    return configured_units({"allow_remote_commands": True,
                             "allow_systemd_journal": True,
                             "journal_units": value["units"]})


def _peer_uid(conn: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Linux peer credentials are required")
    data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", data)
    return uid


def _request(conn: socket.socket) -> tuple[str, int]:
    conn.settimeout(3)
    data = bytearray()
    while b"\n" not in data and len(data) <= 256:
        chunk = conn.recv(257 - len(data))
        if not chunk:
            raise ValueError("Incomplete journal request")
        data.extend(chunk)
    if len(data) > 256 or not data.endswith(b"\n"):
        raise ValueError("Invalid journal request")
    value = json.loads(data, object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict) or set(value) != {"unit", "lines"}:
        raise ValueError("Invalid journal request")
    unit, lines = value["unit"], value["lines"]
    journal_argv(unit, lines, (unit,))
    canonical = json.dumps({"unit": unit, "lines": lines}, separators=(",", ":")).encode() + b"\n"
    if bytes(data) != canonical:
        raise ValueError("Noncanonical journal request")
    return unit, lines


def _send_result(conn: socket.socket, result: dict):
    state, output = result["state"], result["output"]
    exit_code = result["exit_code"]
    if state not in ("succeeded", "failed", "timed_out", "output_limited") or not isinstance(output, str):
        raise ValueError("Invalid journal result")
    # Bound the *encoded* response as well: log lines can contain many JSON
    # escapes, and the Agent forwards this output inside a 16 KiB Hub request.
    while True:
        encoded = json.dumps({"state": state, "exit_code": exit_code, "output": output},
                             ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        if len(encoded) <= MAX_RESPONSE_BYTES and len(output.encode()) <= 8192:
            conn.sendall(encoded)
            return
        state = "output_limited"
        output = output[:max(0, len(output) - 256)]


def handle_connection(conn: socket.socket, agent_uid: int, broker_gid: int,
                      policy_path: str = POLICY_PATH):
    try:
        if _peer_uid(conn) != agent_uid:
            return
        unit, lines = _request(conn)
        units = read_policy(policy_path, broker_gid)
        argv = journal_argv(unit, lines, units)
        result = run_command(f"{MARKER} read {unit} {lines}", 5, 8192, argv_override=argv)
        _send_result(conn, result)
    except (OSError, ValueError, PermissionError) as exc:
        logging.warning("Journal broker rejected request: %s", type(exc).__name__)
        try:
            _send_result(conn, {"state": "failed", "exit_code": None,
                                "output": "Journal unavailable or denied"})
        except OSError:
            pass
    finally:
        conn.close()


def serve_activated():
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("Journal broker requires one systemd socket")
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.getsockname() != SOCKET_PATH:
        raise RuntimeError("Unexpected journal broker socket")
    agent = pwd.getpwnam("sovagrid")
    broker = pwd.getpwnam("sovagrid-journal")
    journal_gid = grp.getgrnam("systemd-journal").gr_gid
    broad_reader_gids = {journal_gid}
    try:
        broad_reader_gids.add(grp.getgrnam("adm").gr_gid)
    except KeyError:
        pass
    if broad_reader_gids.intersection(os.getgrouplist(agent.pw_name, agent.pw_gid)):
        raise PermissionError("Agent account has broad journal group access")
    if (agent.pw_uid == broker.pw_uid or broker.pw_uid == 0 or
            (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) !=
            (broker.pw_uid, broker.pw_uid, broker.pw_gid, broker.pw_gid) or
            journal_gid not in os.getgroups()):
        raise PermissionError("Journal broker has the wrong identity or groups")
    read_policy(POLICY_PATH, broker.pw_gid)
    while True:
        conn, _ = listener.accept()
        handle_connection(conn, agent.pw_uid, broker.pw_gid)


if __name__ == "__main__":
    serve_activated()
