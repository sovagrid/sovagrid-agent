# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Canonical Agent request for bounded, transient SovaGrid container logs."""

from __future__ import annotations

import json
import re
import socket

from .service_control import SOCKET_PATH


MARKER = "/usr/local/bin/sovagrid-container-log-read"
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
ENGINES = frozenset(("docker", "podman"))
MAX_LINES = 100
MAX_OUTPUT_BYTES = 8192
MAX_RESPONSE_BYTES = 12000


def parameters(engine: object, ident: object, lines: object) -> tuple[str, str, int]:
    if (not isinstance(engine, str) or engine not in ENGINES or
            not isinstance(ident, str) or IDENTITY.fullmatch(ident) is None or
            type(lines) is not int or not 1 <= lines <= MAX_LINES):
        raise ValueError("Invalid container log request")
    return engine, ident, lines


def parse_command(command: str) -> tuple[str, str, int] | None:
    if not isinstance(command, str) or MARKER not in command:
        return None
    parts = command.split(" ")
    if len(parts) != 5 or parts[:2] != [MARKER, "read"] or command != " ".join(parts):
        raise ValueError("Invalid container log command")
    if not parts[4].isascii() or not parts[4].isdecimal():
        raise ValueError("Invalid container log command")
    engine, ident, lines = parameters(parts[2], parts[3], int(parts[4]))
    if parts[4] != str(lines):
        raise ValueError("Invalid container log command")
    return engine, ident, lines


def safe_text(value: object) -> bool:
    return isinstance(value, str) and all(char.isprintable() or char in "\n\t" for char in value)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate container log response field")
        result[key] = value
    return result


def request_broker(engine: str, ident: str, lines: int, socket_path: str = SOCKET_PATH) -> dict:
    """Only the root service broker touches the Engine socket or log bytes."""
    parameters(engine, ident, lines)
    request = json.dumps({"operation": "container_logs", "engine": engine,
                          "id": ident, "lines": lines}, separators=(",", ":")).encode("ascii") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(socket_path)
        connection.sendall(request)
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_RESPONSE_BYTES:
            chunk = connection.recv(MAX_RESPONSE_BYTES + 1 - len(raw))
            if not chunk:
                raise ValueError("Incomplete container log response")
            raw.extend(chunk)
    if len(raw) > MAX_RESPONSE_BYTES or not raw.endswith(b"\n"):
        raise ValueError("Invalid container log response")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid container log response") from exc
    if (not isinstance(value, dict) or set(value) != {"state", "exit_code", "output"} or
            value["state"] not in ("succeeded", "failed", "output_limited") or
            (value["state"] == "succeeded" and
             (type(value["exit_code"]) is not int or value["exit_code"] != 0)) or
            (value["state"] != "succeeded" and value["exit_code"] is not None) or
            not safe_text(value["output"]) or
            len(value["output"].encode("utf-8")) > MAX_OUTPUT_BYTES):
        raise ValueError("Invalid container log response")
    return value
