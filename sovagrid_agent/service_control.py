# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Narrow Agent protocol for an independently enabled systemd broker."""

from __future__ import annotations

import json
import re
import socket
from typing import Any


MARKER = "/usr/local/bin/sovagrid-service-ctl"
SOCKET_PATH = "/run/sovagrid-service/control.sock"
LOCAL_SOCKET_PATH = "/run/sovagrid-service-local/control.sock"
SOCKET_PROFILES = {SOCKET_PATH: "sovagrid", LOCAL_SOCKET_PATH: "sovagrid-local"}
UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,87}[.]service\Z")
STATE_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
ACTIONS = frozenset(("status", "start", "stop", "restart"))
RESULTS = frozenset(("ok", "failed", "uncertain"))
RESPONSE_FIELDS = frozenset(("action", "unit", "result", "load_state",
                             "active_state", "sub_state"))
MAX_MESSAGE = 1024
_PROTECTED_BASES = frozenset((
    "ssh", "sshd", "dropbear", "dbus", "networking", "networkmanager",
    "network-manager", "docker", "containerd", "podman", "cri-o",
    "nftables", "ufw", "firewalld", "iptables", "netfilter-persistent",
    "caddy", "wg-quick", "awg-quick", "openvpn", "strongswan", "ipsec",
))


def protected_mutation_unit(unit: str) -> bool:
    """Reserve control-plane, network and tunnel units even in a root policy."""
    if not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit):
        return False
    stem = unit[:-len(".service")].casefold()
    base = stem.split("@", 1)[0]
    return (base in _PROTECTED_BASES or base.startswith(("sovagrid", "systemd-", "amnezia", "autossh"))
            or "tunnel" in base)


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate service control field")
        value[key] = item
    return value


def validate_action_unit(action: str, unit: str) -> None:
    if (not isinstance(action, str) or action not in ACTIONS or
            not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit)):
        raise ValueError("Invalid service control request")
    if unit.endswith("@.service"):
        raise ValueError("Service template is not an instance")
    if action != "status" and protected_mutation_unit(unit):
        raise ValueError("Protected service mutation is unavailable")


def parse_command(command: str) -> tuple[str, str] | None:
    """Intercept every marker occurrence before the general command shell."""
    if not isinstance(command, str) or MARKER not in command:
        return None
    parts = command.split(" ")
    if len(parts) != 3 or parts[0] != MARKER or command != " ".join(parts):
        raise ValueError("Invalid service control command")
    action, unit = parts[1:]
    validate_action_unit(action, unit)
    return action, unit


def validate_response(value: Any, action: str, unit: str) -> dict:
    validate_action_unit(action, unit)
    if (not isinstance(value, dict) or set(value) != RESPONSE_FIELDS or
            value["action"] != action or value["unit"] != unit or
            not isinstance(value["result"], str) or value["result"] not in RESULTS):
        raise ValueError("Invalid service control response")
    for field in ("load_state", "active_state", "sub_state"):
        state = value[field]
        if state is not None and (not isinstance(state, str) or
                                  not STATE_NAME.fullmatch(state)):
            raise ValueError("Invalid service control response")
    if value["result"] == "ok" and any(value[field] is None for field in
                                        ("load_state", "active_state", "sub_state")):
        raise ValueError("Incomplete service control response")
    return {key: value[key] for key in ("action", "unit", "result", "load_state",
                                        "active_state", "sub_state")}


def _read_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while b"\n" not in data and len(data) <= MAX_MESSAGE:
        chunk = connection.recv(MAX_MESSAGE + 1 - len(data))
        if not chunk:
            raise ValueError("Incomplete service control response")
        data.extend(chunk)
    if len(data) > MAX_MESSAGE or not data.endswith(b"\n"):
        raise ValueError("Invalid service control response")
    return bytes(data)


def request_broker(action: str, unit: str, socket_path: str = SOCKET_PATH) -> dict:
    """Ask the root broker over its Agent-only socket and validate its reply."""
    validate_action_unit(action, unit)
    request = json.dumps({"action": action, "unit": unit},
                         separators=(",", ":")).encode("ascii") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        # Four bounded MainPID checks plus preflight, operation and state read
        # can approach 50 seconds for a slow but still responsive systemd.
        connection.settimeout(55)
        connection.connect(socket_path)
        connection.sendall(request)
        raw = _read_line(connection)
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid service control response") from exc
    return validate_response(value, action, unit)


def job_result(value: dict, action: str, unit: str) -> dict:
    """Project a bounded, typed broker reply into the existing Hub job schema."""
    public = validate_response(value, action, unit)
    result = public["result"]
    return {"state": "succeeded" if result == "ok" else
                     "timed_out" if result == "uncertain" else "failed",
            "exit_code": 0 if result == "ok" else None,
            "output": json.dumps(public, separators=(",", ":"))}
