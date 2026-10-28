# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact Agent job marker and typed reply for container lifecycle actions."""

from __future__ import annotations

import json
import socket
from typing import Any

from .containers import CONTAINER_ID
from .service_control import MAX_MESSAGE, SOCKET_PATH, SOCKET_PROFILES, unique_pairs


MARKER = "/usr/local/bin/sovagrid-container-action-ctl"
ACTIONS = frozenset(("status", "start", "stop", "restart"))
RESULTS = frozenset(("ok", "failed", "uncertain"))
STATES = frozenset(("created", "running", "paused", "restarting", "removing",
                    "exited", "dead"))
RESPONSE_FIELDS = frozenset(("action", "id", "result", "state"))


def parameters(action: object, ident: object) -> tuple[str, str]:
    if (not isinstance(action, str) or action not in ACTIONS or
            not isinstance(ident, str) or CONTAINER_ID.fullmatch(ident) is None):
        raise ValueError("Invalid container action")
    return action, ident


def parse_command(command: str) -> tuple[str, str] | None:
    """A marker anywhere in the command must never reach the shell."""
    if not isinstance(command, str) or MARKER not in command:
        return None
    parts = command.split(" ")
    if (len(parts) != 4 or parts[0] != MARKER or parts[2] != "docker" or
            command != " ".join(parts)):
        raise ValueError("Invalid container action command")
    return parameters(parts[1], parts[3])


def validate_response(value: Any, action: str, ident: str) -> dict:
    parameters(action, ident)
    if (not isinstance(value, dict) or set(value) != RESPONSE_FIELDS or
            value["action"] != action or value["id"] != ident or
            not isinstance(value["result"], str) or value["result"] not in RESULTS or
            (value["state"] is not None and
             (not isinstance(value["state"], str) or value["state"] not in STATES)) or
            (value["result"] == "ok" and value["state"] is None)):
        raise ValueError("Invalid container action response")
    return {key: value[key] for key in ("action", "id", "result", "state")}


def request_broker(action: str, ident: str, socket_path: str = SOCKET_PATH) -> dict:
    parameters(action, ident)
    if socket_path not in SOCKET_PROFILES:
        raise ValueError("Invalid container action socket")
    request = json.dumps({"operation": "container_action", "action": action, "id": ident},
                         separators=(",", ":")).encode("ascii") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(40)
        connection.connect(socket_path)
        connection.sendall(request)
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_MESSAGE:
            chunk = connection.recv(MAX_MESSAGE + 1 - len(raw))
            if not chunk:
                raise ValueError("Incomplete container action response")
            raw.extend(chunk)
    if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
        raise ValueError("Invalid container action response")
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid container action response") from exc
    return validate_response(value, action, ident)


def job_result(value: dict, action: str, ident: str) -> dict:
    public = validate_response(value, action, ident)
    result = public["result"]
    return {"state": "succeeded" if result == "ok" else
                     "timed_out" if result == "uncertain" else "failed",
            "exit_code": 0 if result == "ok" else None,
            "output": json.dumps(public, separators=(",", ":"))}
