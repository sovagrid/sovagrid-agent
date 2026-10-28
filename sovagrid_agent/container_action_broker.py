# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Default-off root contract for exact Docker container lifecycle actions.

Only the already PID-bound service broker may call this module. A Hub route
never arms this independent root policy by itself.
"""

from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
from typing import Callable

from .container_actions import ACTIONS, STATES, parameters
from .container_collector import API_PREFIX, SOCKETS, UnixHTTPConnection, _get
from .containers import CONTAINER_ID


CONFIG = Path("/etc/sovagrid-container-actions")
POLICY = CONFIG / "policy.json"
ENABLE = CONFIG / "enabled"
LOCAL_CONFIG = Path("/etc/sovagrid-container-actions-local")
LOCAL_POLICY = LOCAL_CONFIG / "policy.json"
LOCAL_ENABLE = LOCAL_CONFIG / "enabled"
MAX_POLICY_BYTES = 8192
MAX_CONTAINERS = 16
MAX_SECONDS = 25
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate container policy field")
        result[key] = value
    return result


def protected_name(name: str) -> bool:
    """Keep control-plane, VPN and SSH infrastructure out of mutable policy."""
    lower = name.casefold()
    return (lower.startswith(("sovagrid", "amnezia", "docker", "containerd", "wireguard",
                              "openvpn", "tailscale", "xray", "sing-box")) or
            "tunnel" in lower or "ssh" in lower)


def _protected_image(reference: str) -> bool:
    # Registries and namespaces may precede a protected image basename.
    parts = reference.casefold().split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return any(protected_name(part.split(":", 1)[0].split("@", 1)[0]) for part in parts)


def parse_policy(raw: bytes) -> dict[str, dict]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_BYTES:
        raise ValueError("Invalid container action policy")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid container action policy") from exc
    if (not isinstance(value, dict) or set(value) != {"version", "containers"} or
            type(value["version"]) is not int or value["version"] != 1 or
            not isinstance(value["containers"], list) or
            not 1 <= len(value["containers"]) <= MAX_CONTAINERS):
        raise ValueError("Invalid container action policy")
    policy = {}
    for item in value["containers"]:
        if not isinstance(item, dict) or set(item) != {"id", "name", "image_id", "actions"}:
            raise ValueError("Invalid container action policy")
        ident, name, image = item["id"], item["name"], item["image_id"]
        actions = item["actions"]
        if (not isinstance(ident, str) or CONTAINER_ID.fullmatch(ident) is None or
                ident in policy or not isinstance(name, str) or NAME.fullmatch(name) is None or
                protected_name(name) or not isinstance(image, str) or
                IMAGE_ID.fullmatch(image) is None or not isinstance(actions, list) or
                not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS for action in actions) or
                len(set(actions)) != len(actions) or
                "status" not in actions):
            raise ValueError("Invalid container action policy")
        policy[ident] = {"name": name, "image_id": image,
                         "actions": frozenset(actions)}
    return policy


def _private_file(path: Path, maximum: int) -> bytes:
    folder = path.parent.lstat()
    if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != 0 or
            stat.S_IMODE(folder.st_mode) != 0o700):
        raise PermissionError("Unsafe container action policy directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                not 1 <= info.st_size <= maximum):
            raise PermissionError("Unsafe container action policy file")
        data = os.read(fd, maximum + 1)
        if len(data) != info.st_size:
            raise ValueError("Container action policy changed during read")
        return data
    finally:
        os.close(fd)


def read_policy(policy: Path = POLICY, enabled: Path = ENABLE) -> dict[str, dict]:
    """A separate root marker is mandatory even for read-only status."""
    if _private_file(enabled, 8) != b"enabled\n":
        raise PermissionError("Container actions are disabled")
    return parse_policy(_private_file(policy, MAX_POLICY_BYTES))


@contextmanager
def _deadline():
    previous = signal.getsignal(signal.SIGALRM)
    old_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    if old_timer[0] > 0:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        raise PermissionError("Container broker timer is already active")

    def expired(_signum, _frame):
        raise TimeoutError("Container action timed out")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, MAX_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _socket(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise PermissionError("Docker socket is unavailable")


def _unsafe_resources(value: dict, host: dict) -> None:
    """Do not operate containers sharing host files, devices or capabilities.

    A named volume can itself be backed by a host bind through a Docker volume
    driver. Until that provenance can be verified, every mount is excluded.
    """
    required = ("Binds", "VolumesFrom", "CapAdd", "Devices", "DeviceRequests",
                "DeviceCgroupRules", "SecurityOpt")
    if "Mounts" not in value or any(key not in host for key in required):
        raise PermissionError("Incomplete container isolation metadata")
    collections = (value["Mounts"], *(host[key] for key in required), host.get("Mounts"))
    for items in collections:
        if items is not None and (not isinstance(items, list) or items):
            raise PermissionError("Container shares host resources")
    for field in ("IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        mode = host.get(field, "")
        if not isinstance(mode, str) or mode not in ("", "private"):
            raise PermissionError("Container shares a host namespace")
    runtime = host.get("Runtime", "")
    if not isinstance(runtime, str) or runtime not in ("", "runc", "io.containerd.runc.v2"):
        raise PermissionError("Container uses an unreviewed runtime")


def _identity(value: object, ident: str, expected: dict) -> str:
    """Inspect live identity without forwarding Engine fields to the caller."""
    if (not isinstance(value, dict) or value.get("Id") != ident or
            value.get("Name") != "/" + expected["name"] or
            value.get("Image") != expected["image_id"]):
        raise PermissionError("Container identity changed")
    config, host, state = value.get("Config"), value.get("HostConfig"), value.get("State")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(state, dict):
        raise PermissionError("Container identity is incomplete")
    _unsafe_resources(value, host)
    image_ref = config.get("Image")
    labels = config.get("Labels")
    if labels is None:
        labels = {}
    if not isinstance(image_ref, str) or not isinstance(labels, dict):
        raise PermissionError("Container identity is incomplete")
    project = labels.get("com.docker.compose.project")
    service = labels.get("com.docker.compose.service")
    if (project is not None and not isinstance(project, str)) or \
            (service is not None and not isinstance(service, str)):
        raise PermissionError("Container identity is incomplete")
    exposed = config.get("ExposedPorts")
    bindings = host.get("PortBindings")
    if (exposed is not None and not isinstance(exposed, dict)) or \
            (bindings is not None and not isinstance(bindings, dict)):
        raise PermissionError("Container port identity is incomplete")
    if isinstance(exposed, dict) and any(not isinstance(port, str) or port.startswith("22/")
                                         for port in exposed):
        raise PermissionError("SSH infrastructure cannot be controlled")
    if isinstance(bindings, dict):
        for port, hosts in bindings.items():
            if not isinstance(port, str) or port.startswith("22/"):
                raise PermissionError("SSH infrastructure cannot be controlled")
            if hosts is None:
                continue
            if not isinstance(hosts, list):
                raise PermissionError("Container port identity is incomplete")
            for binding in hosts:
                if (not isinstance(binding, dict) or
                        not isinstance(binding.get("HostPort"), str) or
                        not isinstance(binding.get("HostIp", ""), str)):
                    raise PermissionError("Container port identity is incomplete")
                host_port = binding["HostPort"]
                if host_port and (len(host_port) > 5 or not host_port.isascii() or
                                  not host_port.isdecimal() or
                                  not 1 <= int(host_port) <= 65535):
                    raise PermissionError("Container port identity is incomplete")
                if host_port and int(host_port) == 22:
                    raise PermissionError("SSH infrastructure cannot be controlled")
    network_mode, pid_mode = host.get("NetworkMode"), host.get("PidMode")
    if (protected_name(expected["name"]) or _protected_image(image_ref) or
            isinstance(project, str) and protected_name(project) or
            isinstance(service, str) and protected_name(service) or
            host.get("Privileged") is not False or
            not isinstance(network_mode, str) or network_mode == "host" or
            network_mode.startswith("container:") or
            not isinstance(pid_mode, str) or pid_mode not in ("", "private")):
        raise PermissionError("Protected container cannot be controlled")
    status = state.get("Status")
    if not isinstance(status, str) or status not in STATES:
        raise PermissionError("Container state is unavailable")
    return status


def _post(path: Path, endpoint: str) -> int:
    client = UnixHTTPConnection(path, timeout=12)
    try:
        client.request("POST", API_PREFIX + endpoint, body=b"",
                       headers={"Content-Length": "0", "Accept": "application/json"})
        response = client.getresponse()
        response.read(513)
        return response.status
    finally:
        client.close()


def _result(action: str, ident: str, result: str, status: str | None) -> dict:
    return {"action": action, "id": ident, "result": result, "state": status}


def execute(action: str, ident: str, policy: dict[str, dict], *,
            getter: Callable = _get, poster: Callable = _post,
            pre_action_check: Callable[[], bool] | None = None) -> dict:
    """Never POST unless exact policy, inspect identity, and peer checks hold."""
    parameters(action, ident)
    entry = policy.get(ident)
    if entry is None or action not in entry["actions"]:
        raise PermissionError("Container action is not allowed")
    with _deadline():
        path = SOCKETS["docker"]
        _socket(path)
        before = _identity(getter(path, f"/containers/{ident}/json", limit=65536, timeout=3),
                           ident, entry)
        if action == "status":
            return _result(action, ident, "ok", before)
        if ((action == "start" and before not in ("created", "exited")) or
                (action in ("stop", "restart") and before != "running")):
            return _result(action, ident, "failed", before)
        if pre_action_check is None or not pre_action_check():
            raise PermissionError("Agent identity changed before container action")
        endpoint = f"/containers/{ident}/{action}" + ("?t=10" if action in ("stop", "restart") else "")
        try:
            code = poster(path, endpoint)
            if code != 204:
                return _result(action, ident, "uncertain", None)
            after = _identity(getter(path, f"/containers/{ident}/json", limit=65536, timeout=3),
                              ident, entry)
        except (OSError, ValueError, http.client.HTTPException):
            return _result(action, ident, "uncertain", None)
        expected_state = "exited" if action == "stop" else "running"
        return _result(action, ident, "ok" if after == expected_state else "uncertain", after)
