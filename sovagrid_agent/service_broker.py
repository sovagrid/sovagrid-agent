# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Default-off, root socket broker for narrowly allowed systemd operations."""

from __future__ import annotations

import http.client
import json
import logging
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess
from typing import Callable

from .container_logs import MAX_RESPONSE_BYTES as CONTAINER_LOG_RESPONSE_BYTES
from .container_logs import parameters as container_log_parameters
from .container_log_broker import execute as read_container_logs
from .container_action_broker import (execute as execute_container_action,
                                      ENABLE as CONTAINER_ENABLE_PATH,
                                      LOCAL_ENABLE as LOCAL_CONTAINER_ENABLE_PATH,
                                      LOCAL_POLICY as LOCAL_CONTAINER_POLICY_PATH,
                                      parameters as container_action_parameters,
                                      POLICY as CONTAINER_POLICY_PATH,
                                      read_policy as read_container_action_policy)
from .service_control import (ACTIONS, LOCAL_SOCKET_PATH, MAX_MESSAGE, SOCKET_PATH,
                              SOCKET_PROFILES, STATE_NAME, protected_mutation_unit,
                              UNIT_NAME, unique_pairs, validate_action_unit,
                              validate_response)


CONFIG_DIR = Path("/etc/sovagrid-service")
LOCAL_CONFIG_DIR = Path("/etc/sovagrid-service-local")
POLICY_PATH = CONFIG_DIR / "units.json"
ENABLE_PATH = CONFIG_DIR / "enabled"
SYSTEMCTL = "/usr/bin/systemctl"
MAX_UNITS = 16
MAX_POLICY_BYTES = 4096
AGENT_UNITS = {SOCKET_PATH: "sovagrid-agent.service",
               LOCAL_SOCKET_PATH: "sovagrid-agent-local.service"}


def policy_paths_for_socket(path: str) -> tuple[Path, Path]:
    if path == SOCKET_PATH:
        config = CONFIG_DIR
    elif path == LOCAL_SOCKET_PATH:
        config = LOCAL_CONFIG_DIR
    else:
        raise ValueError("Unexpected service broker socket")
    return config / "units.json", config / "enabled"


def container_action_policy_paths_for_agent(agent_unit: str) -> tuple[Path, Path]:
    if agent_unit == AGENT_UNITS[SOCKET_PATH]:
        return CONTAINER_POLICY_PATH, CONTAINER_ENABLE_PATH
    if agent_unit == AGENT_UNITS[LOCAL_SOCKET_PATH]:
        return LOCAL_CONTAINER_POLICY_PATH, LOCAL_CONTAINER_ENABLE_PATH
    raise ValueError("Unexpected Agent identity")


def _private_file(path: Path, *, maximum: int) -> bytes:
    directory = path.parent.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            stat.S_IMODE(directory.st_mode) != 0o700):
        raise PermissionError("Unsafe service policy directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_gid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or
                not 1 <= info.st_size <= maximum):
            raise PermissionError("Unsafe service policy file")
        raw = os.read(fd, maximum + 1)
        if len(raw) != info.st_size:
            raise ValueError("Service policy changed during read")
        return raw
    finally:
        os.close(fd)


def read_policy(policy_path: Path = POLICY_PATH,
                enable_path: Path = ENABLE_PATH) -> dict[str, frozenset[str]]:
    """Require exact root opt-in and a separate per-unit action allowlist."""
    if _private_file(enable_path, maximum=8) != b"enabled\n":
        raise PermissionError("Service control is disabled")
    return parse_policy(_private_file(policy_path, maximum=MAX_POLICY_BYTES))


def parse_policy(raw: bytes) -> dict[str, frozenset[str]]:
    """Validate the same strict policy before installation and at runtime."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_BYTES:
        raise ValueError("Invalid service policy")
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid service policy") from exc
    if (not isinstance(value, dict) or set(value) != {"version", "units"} or
            type(value["version"]) is not int or value["version"] != 1 or
            not isinstance(value["units"], dict) or
            not 1 <= len(value["units"]) <= MAX_UNITS):
        raise ValueError("Invalid service policy")
    policy = {}
    for unit, actions in value["units"].items():
        if (not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit) or
                unit.endswith("@.service") or
                not isinstance(actions, list) or not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS
                    for action in actions) or len(set(actions)) != len(actions)):
            raise ValueError("Invalid service policy")
        policy[unit] = frozenset(actions)
    return policy


def _peer_identity(connection: socket.socket) -> tuple[int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Linux peer credentials are required")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    return pid, uid


def _main_pid(agent_unit: str, runner: Callable) -> int | None:
    """Read the root-owned systemd identity, not an Agent-writable PID file."""
    if agent_unit not in AGENT_UNITS.values():
        return None
    argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password",
            "--property=MainPID", "show", agent_unit]
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        text=True, timeout=2,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    raw = result.stdout.strip()
    if not re.fullmatch(r"MainPID=[1-9][0-9]{0,9}", raw):
        return None
    pid = int(raw[8:])
    return pid if pid <= 2**31 - 1 else None


def _request(connection: socket.socket) -> tuple:
    connection.settimeout(3)
    data = bytearray()
    while b"\n" not in data and len(data) <= MAX_MESSAGE:
        chunk = connection.recv(MAX_MESSAGE + 1 - len(data))
        if not chunk:
            raise ValueError("Incomplete service request")
        data.extend(chunk)
    if len(data) > MAX_MESSAGE or not data.endswith(b"\n"):
        raise ValueError("Invalid service request")
    try:
        value = json.loads(data, object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid service request") from exc
    if not isinstance(value, dict):
        raise ValueError("Invalid service request")
    if set(value) == {"operation", "action", "id"}:
        if value["operation"] != "container_action":
            raise ValueError("Invalid container action operation")
        action, ident = container_action_parameters(value["action"], value["id"])
        canonical = json.dumps({"operation": "container_action", "action": action,
                                "id": ident}, separators=(",", ":")).encode("ascii") + b"\n"
        if bytes(data) != canonical:
            raise ValueError("Noncanonical container action request")
        return "container_action", action, ident
    if set(value) == {"operation", "engine", "id", "lines"}:
        if value["operation"] != "container_logs":
            raise ValueError("Invalid container log operation")
        engine, ident, lines = container_log_parameters(
            value["engine"], value["id"], value["lines"])
        canonical = json.dumps({"operation": "container_logs", "engine": engine,
                                "id": ident, "lines": lines},
                               separators=(",", ":")).encode("ascii") + b"\n"
        if bytes(data) != canonical:
            raise ValueError("Noncanonical container log request")
        return "container_logs", engine, ident, lines
    if set(value) != {"action", "unit"}:
        raise ValueError("Invalid service request")
    action, unit = value["action"], value["unit"]
    validate_action_unit(action, unit)
    canonical = json.dumps({"action": action, "unit": unit},
                           separators=(",", ":")).encode("ascii") + b"\n"
    if bytes(data) != canonical:
        raise ValueError("Noncanonical service request")
    return action, unit


def _show_state(unit: str, runner: Callable) -> dict | None:
    argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password", "--all",
            "--property=Id,LoadState,ActiveState,SubState", "show", unit]
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        text=True, timeout=5,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 512:
        return None
    values = {}
    for line in result.stdout.splitlines():
        if line.count("=") != 1:
            return None
        key, item = line.split("=", 1)
        if key in values or key not in {"Id", "LoadState", "ActiveState", "SubState"}:
            return None
        values[key] = item
    if (set(values) != {"Id", "LoadState", "ActiveState", "SubState"} or
            values["Id"] != unit or any(not STATE_NAME.fullmatch(values[key])
                                          for key in ("LoadState", "ActiveState", "SubState"))):
        return None
    return {"load_state": values["LoadState"], "active_state": values["ActiveState"],
            "sub_state": values["SubState"]}


def _mutation_identity_safe(unit: str, runner: Callable) -> bool:
    """Resolve systemd aliases before an action could reach a protected unit."""
    argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password", "--all",
            "--property=Id,Names,LoadState", "show", unit]
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        text=True, timeout=5,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 2048:
        return False
    values = {}
    for line in result.stdout.splitlines():
        if line.count("=") != 1:
            return False
        key, value = line.split("=", 1)
        if key in values or key not in {"Id", "Names", "LoadState"}:
            return False
        values[key] = value
    if set(values) != {"Id", "Names", "LoadState"} or values["Id"] != unit or values["LoadState"] != "loaded":
        return False
    aliases = values["Names"].split()
    if not 1 <= len(aliases) <= 32 or unit not in aliases:
        return False
    for alias in aliases:
        if (not UNIT_NAME.fullmatch(alias) or alias.endswith("@.service") or
                protected_mutation_unit(alias)):
            return False
    return True


def execute(action: str, unit: str, policy: dict[str, frozenset[str]],
            runner: Callable = subprocess.run,
            pre_action_check: Callable[[], bool] | None = None) -> dict:
    validate_action_unit(action, unit)
    if action not in policy.get(unit, frozenset()):
        raise PermissionError("Service action denied")
    result = "ok"
    if action != "status":
        if not _mutation_identity_safe(unit, runner):
            # Nothing was attempted. A changed or ambiguous alias is a hard
            # failure, not evidence that a previous service state is intact.
            return {"action": action, "unit": unit, "result": "failed",
                    "load_state": None, "active_state": None, "sub_state": None}
        # The identity lookup can block. Recheck the originating Agent just
        # before any systemctl mutation, with no shell or caller-owned PID file.
        if pre_action_check is not None and not pre_action_check():
            raise PermissionError("Agent process changed before service action")
        argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password",
                "--job-mode=fail", action, unit]
        try:
            operation = runner(argv, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except (OSError, subprocess.TimeoutExpired):
            return {"action": action, "unit": unit, "result": "uncertain",
                    "load_state": None, "active_state": None, "sub_state": None}
        # systemctl can report failure after the unit has changed. A nonzero
        # result therefore never means that the original state was preserved.
        if operation.returncode != 0:
            result = "uncertain"
    snapshot = _show_state(unit, runner)
    if snapshot is None:
        result = "failed" if action == "status" else "uncertain"
        snapshot = {"load_state": None, "active_state": None, "sub_state": None}
    elif (action in ("start", "restart") and
          snapshot["active_state"] not in ("active", "inactive")) or \
            (action == "stop" and snapshot["active_state"] not in ("inactive", "failed")):
        result = "uncertain"
    return {"action": action, "unit": unit, "result": result, **snapshot}


def handle_connection(connection: socket.socket, agent_uid: int, agent_unit: str,
                      policy_path: Path = POLICY_PATH,
                      enable_path: Path = ENABLE_PATH,
                      runner: Callable = subprocess.run) -> None:
    container_audit = None
    try:
        peer_pid, peer_uid = _peer_identity(connection)
        if peer_uid != agent_uid or peer_pid <= 0 or _main_pid(agent_unit, runner) != peer_pid:
            return
        request = _request(connection)
        # A restart while the request is read invalidates the old process.
        if _main_pid(agent_unit, runner) != peer_pid:
            return
        if len(request) == 4:
            if policy_path != POLICY_PATH or enable_path != ENABLE_PATH:
                raise PermissionError("Container logs require the host Agent socket")
            _operation, engine, ident, lines = request
            public = read_container_logs(engine, ident, lines)
            encoded = json.dumps(public, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8") + b"\n"
            if len(encoded) > CONTAINER_LOG_RESPONSE_BYTES:
                encoded = (b'{"state":"output_limited","exit_code":null,'
                           b'"output":"Container logs exceed the encoded response limit"}\n')
            connection.sendall(encoded)
        elif len(request) == 3:
            _operation, action, ident = request
            if action != "status":
                container_audit = (action, ident, peer_pid)
            container_policy_path, container_enable_path = container_action_policy_paths_for_agent(agent_unit)
            policy = read_container_action_policy(container_policy_path, container_enable_path)
            if _main_pid(agent_unit, runner) != peer_pid:
                return
            public = execute_container_action(
                action, ident, policy,
                pre_action_check=lambda: _main_pid(agent_unit, runner) == peer_pid)
            if container_audit is not None:
                logging.warning("Container action audit: action=%s id=%s peer_pid=%s result=%s",
                                action, ident, peer_pid, public["result"])
            connection.sendall(json.dumps(public, separators=(",", ":")).encode("ascii") + b"\n")
        else:
            action, unit = request
            policy = read_policy(policy_path, enable_path)
            # Policy I/O and the systemd preflight can outlive an Agent restart.
            # Never execute for a connection whose original peer has ceased to
            # be the current systemd MainPID.
            if _main_pid(agent_unit, runner) != peer_pid:
                return
            response = execute(action, unit, policy, runner,
                               pre_action_check=lambda: _main_pid(agent_unit, runner) == peer_pid)
            public = validate_response(response, action, unit)
            connection.sendall(json.dumps(public, separators=(",", ":")).encode("ascii") + b"\n")
    except (OSError, ValueError, PermissionError, TypeError,
            http.client.HTTPException) as exc:
        if container_audit is not None:
            logging.warning("Container action audit: action=%s id=%s peer_pid=%s result=rejected:%s",
                            *container_audit, type(exc).__name__)
        logging.warning("Service broker rejected request: %s", type(exc).__name__)
    finally:
        connection.close()


def serve_activated() -> None:
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("Service broker requires one systemd socket")
    listener = socket.socket(fileno=3)
    path = listener.getsockname()
    if listener.family != socket.AF_UNIX or path not in SOCKET_PROFILES:
        raise RuntimeError("Unexpected service broker socket")
    agent_uid = pwd.getpwnam(SOCKET_PROFILES[path]).pw_uid
    policy_path, enable_path = policy_paths_for_socket(path)
    if agent_uid == 0 or os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Service broker requires root separate from Agent")
    while True:
        connection, _ = listener.accept()
        handle_connection(connection, agent_uid, AGENT_UNITS[path], policy_path, enable_path)


if __name__ == "__main__":
    serve_activated()
