# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict, read-only systemd journal request understood by the Agent."""

from __future__ import annotations

import re
import json
import socket


MARKER = "/usr/local/bin/sovagrid-journal-read"
UNIT_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,96}[.]service\Z")
MAX_UNITS = 16
MAX_LINES = 100
SOCKET_PATH = "/run/sovagrid-journal/control.sock"


def configured_units(config: dict) -> tuple[str, ...]:
    """Validate the independent, default-off local journal permission."""
    enabled = config.get("allow_systemd_journal", False)
    units = config.get("journal_units", [])
    if type(enabled) is not bool:
        raise ValueError("allow_systemd_journal must be boolean")
    if (not isinstance(units, list) or len(units) > MAX_UNITS or
            any(not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit) for unit in units) or
            len(set(units)) != len(units)):
        raise ValueError("journal_units must contain up to 16 unique .service names")
    if enabled and not units:
        raise ValueError("journal_units must be nonempty when journal access is enabled")
    if enabled and config.get("allow_remote_commands") is not True:
        raise ValueError("allow_systemd_journal requires allow_remote_commands")
    return tuple(units) if enabled else ()


def parse_journal_request(command: str, units: tuple[str, ...] = ()) -> tuple[str, int] | None:
    """Reject every malformed marker request before any shell can see it."""
    if not isinstance(command, str) or MARKER not in command:
        return None
    parts = command.split(" ")
    if (len(parts) != 4 or parts[0] != MARKER or parts[1] != "read" or
            not UNIT_NAME.fullmatch(parts[2]) or parts[2] not in units or
            not parts[3].isascii() or not parts[3].isdecimal()):
        raise ValueError("Journal access denied or invalid request")
    lines = int(parts[3])
    if not 1 <= lines <= MAX_LINES or str(lines) != parts[3] or command != " ".join(parts):
        raise ValueError("Journal access denied or invalid request")
    return parts[2], lines


def journal_argv(unit: str, lines: int, units: tuple[str, ...]) -> list[str]:
    """The isolated broker's fixed argv; no user string becomes an option."""
    if not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit) or unit not in units:
        raise ValueError("Journal unit is not allowed")
    if type(lines) is not int or not 1 <= lines <= MAX_LINES:
        raise ValueError("Invalid journal line count")
    return ["/usr/bin/journalctl", "--no-pager", "--quiet", "--output=short-iso",
            "--since=-24h", "--lines", str(lines), "--unit=" + unit]


def request_broker(unit: str, lines: int, socket_path: str = SOCKET_PATH) -> dict:
    """Ask the socket-activated read-only broker; never launch journalctl here."""
    # Validate before connecting, even though the broker checks its own policy.
    journal_argv(unit, lines, (unit,))
    request = json.dumps({"unit": unit, "lines": lines}, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(socket_path)
        conn.sendall(request)
        data = bytearray()
        while b"\n" not in data and len(data) <= 12000:
            chunk = conn.recv(12001 - len(data))
            if not chunk:
                raise ValueError("Incomplete journal broker response")
            data.extend(chunk)
    if len(data) > 12000 or not data.endswith(b"\n"):
        raise ValueError("Invalid journal broker response")
    value = json.loads(data)
    if (not isinstance(value, dict) or set(value) != {"state", "exit_code", "output"} or
            value["state"] not in ("succeeded", "failed", "timed_out", "output_limited") or
            (value["exit_code"] is not None and
             (type(value["exit_code"]) is not int or not -255 <= value["exit_code"] <= 255)) or
            not isinstance(value["output"], str) or len(value["output"].encode()) > 8192):
        raise ValueError("Invalid journal broker response")
    return value
