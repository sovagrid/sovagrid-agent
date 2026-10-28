# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Outbound HTTPS client and constrained command executor."""

from __future__ import annotations

import json
import base64
import contextlib
import logging
import os
import ctypes
import ipaddress
import re
import secrets
import select
import selectors
import shlex
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .metrics import collect
from .children import reserved as _reserved_children
from .files import validate_roots
from .amnezia import HELPER as _AMNEZIA_HELPER, command_argv as _amnezia_command_argv
from .amnezia import sanitize_result as _sanitize_amnezia_result
from .journal import MARKER as _JOURNAL_MARKER, configured_units, parse_journal_request, request_broker
from .service_control import MARKER as _SERVICE_MARKER
from .service_control import job_result as _service_job_result
from .service_control import parse_command as _parse_service_command
from .service_control import request_broker as _request_service_broker
from .service_control import SOCKET_PATH as _SERVICE_SOCKET_PATH
from .service_control import SOCKET_PROFILES as _SERVICE_SOCKET_PROFILES
from .process_inventory import MARKER as _PROCESS_MARKER
from .process_inventory import job_result as _process_job_result
from .process_inventory import parse_request as _parse_process_request
from .container_logs import MARKER as _CONTAINER_LOG_MARKER
from .container_logs import parse_command as _parse_container_log_command
from .container_logs import request_broker as _request_container_logs
from .container_actions import MARKER as _CONTAINER_ACTION_MARKER
from .container_actions import job_result as _container_action_job_result
from .container_actions import parse_command as _parse_container_action_command
from .container_actions import request_broker as _request_container_action_broker


_VPN_HELPER = "/usr/local/bin/sovagrid-vpn-ctl"
_VPN_TIMEOUT_SECONDS = 105
_AMNEZIA_TIMEOUT_SECONDS = 135
_VPN_SOCKET_PATH = "/run/sovagrid-vpn/control.sock"
_AMNEZIA_SOCKET_PATH = "/run/sovagrid-vpn/amnezia-control.sock"
_BROKER_REQUEST_LIMIT = 4096
_BROKER_RESPONSE_LIMIT = 8192
_VPN_NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
_VPN_CLIENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_VPN_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{87}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
_OPTIONAL_METRIC_DETAILS = frozenset(("pressure", "cpu_times"))
_LEGACY_RETRY_OMIT_DETAILS = _OPTIONAL_METRIC_DETAILS | frozenset(("filesystems_truncated",))
QUIESCE_SOCKET = "/run/sovagrid-agent-control/agent.sock"
QUIESCE_WAIT_SECONDS = 180
QUIESCE_HEARTBEAT_SECONDS = 45
QUIESCE_MAX_HOLD_SECONDS = 900


class AgentQuiescence:
    """Count every fetched action until its result is sent, then pause at zero.

    Metrics continue while paused. A fetched file or terminal operation stays
    counted even if the Hub response arrives during the pause request.
    """

    KINDS = ("job", "file", "terminal", "check")

    def __init__(self):
        self._condition = threading.Condition()
        self._paused = False
        self._active = {kind: 0 for kind in self.KINDS}

    @contextlib.contextmanager
    def operation(self, kind: str, *, block: bool = True):
        if kind not in self._active:
            raise ValueError("Invalid Agent operation kind")
        with self._condition:
            while self._paused and block:
                self._condition.wait()
            admitted = not self._paused
            if admitted:
                self._active[kind] += 1
        if not admitted:
            yield False
            return
        try:
            yield True
        finally:
            with self._condition:
                self._active[kind] -= 1
                self._condition.notify_all()

    def pause_until_idle(self, timeout: float = QUIESCE_WAIT_SECONDS,
                         cancelled=None) -> bool:
        from .binary_files import active_upload_sessions

        deadline = time.monotonic() + timeout
        with self._condition:
            if self._paused:
                return False
            self._paused = True
            while True:
                if cancelled is not None and cancelled():
                    self._paused = False
                    self._condition.notify_all()
                    return False
                # A probe helper whose cleanup failed remains reserved even if
                # its worker has left the check context. Never acknowledge an
                # idle Agent while that child can still be running.
                if (not any(self._active.values()) and
                        active_upload_sessions() == 0 and
                        not _reserved_children()):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._paused = False
                    self._condition.notify_all()
                    return False
                # Upload sessions can expire without a new file operation.
                self._condition.wait(min(remaining, 0.25))

    def resume(self) -> None:
        with self._condition:
            self._paused = False
            self._condition.notify_all()

    def idle_snapshot(self) -> dict[str, int]:
        from .binary_files import active_upload_sessions

        with self._condition:
            return {"jobs_inflight": self._active["job"],
                    "file_operations": self._active["file"],
                    "terminal_sessions": self._active["terminal"],
                    "network_checks": self._active["check"],
                    "upload_sessions": active_upload_sessions(),
                    "probe_helpers": len(_reserved_children())}


def _quiesce_peer_uid(connection: socket.socket) -> int:
    """SO_PEERCRED is required; non-Linux cannot issue a trusted ACK."""
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        return -1
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


def _quiesce_line(connection: socket.socket, deadline: float) -> bytes:
    line = bytearray()
    while len(line) < 64:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Quiescence control timeout")
        connection.settimeout(remaining)
        item = connection.recv(1)
        if not item:
            raise EOFError("Quiescence controller disconnected")
        line.extend(item)
        if item == b"\n":
            return bytes(line)
    raise ValueError("Quiescence control line too large")


def _quiesce_controller_gone(connection: socket.socket) -> bool:
    """No bytes may arrive before ACK; readability means EOF or bad input."""
    try:
        return bool(select.select([connection], [], [], 0)[0])
    except (OSError, ValueError):
        return True


class AgentQuiescenceServer:
    """Root-only local control channel; an ACK lives only with this socket.

    The future root updater must check this socket's SO_PEERCRED server PID and
    UID against systemd's Agent MainPID/User, keep it open through Agent stop,
    and fail if a PONG is lost, the epoch changes, or the socket closes before
    the stop is confirmed. This server alone never authorizes an update.
    """

    def __init__(self, gate: AgentQuiescence, path: str = QUIESCE_SOCKET):
        self.gate = gate
        self.path = Path(path)
        self.epoch = secrets.token_hex(16)
        self._listener: socket.socket | None = None
        self._connection: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._mutex = threading.Lock()
        self._inode: int | None = None

    def start(self) -> "AgentQuiescenceServer":
        if sys.platform != "linux" or os.geteuid() == 0:
            raise RuntimeError("Agent quiescence requires unprivileged Linux")
        parent = self.path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise RuntimeError("Unsafe Agent quiescence directory")
        try:
            previous = self.path.lstat()
        except FileNotFoundError:
            previous = None
        if previous is not None:
            if (not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.geteuid()
                    or previous.st_nlink != 1):
                raise RuntimeError("Unsafe Agent quiescence socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                try:
                    probe.connect(str(self.path))
                except ConnectionRefusedError:
                    self.path.unlink()
                else:
                    raise RuntimeError("Agent quiescence socket is already active")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            self._inode = self.path.lstat().st_ino
            listener.listen(1)
            listener.settimeout(0.5)
        except BaseException:
            listener.close()
            raise
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="sovagrid-agent-quiescence")
        self._thread.start()
        return self

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stopping.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                with self._mutex:
                    self._connection = connection
                try:
                    self._handle(connection)
                except (OSError, TimeoutError, EOFError, ValueError, RuntimeError):
                    pass
                finally:
                    self.gate.resume()
                    with self._mutex:
                        self._connection = None

    def _handle(self, connection: socket.socket) -> None:
        if _quiesce_peer_uid(connection) != 0:
            return
        if _quiesce_line(connection, time.monotonic() + 5) != b"QUIESCE 1\n":
            return
        if not self.gate.pause_until_idle(cancelled=lambda:
                                          self._stopping.is_set() or _quiesce_controller_gone(connection)):
            if not self._stopping.is_set() and not _quiesce_controller_gone(connection):
                connection.sendall(b"BUSY 1\n")
            return
        counts = self.gate.idle_snapshot()
        if any(counts.values()):
            raise RuntimeError("Agent quiescence counters changed")
        response = {"protocol": 1, "state": "idle", "pid": os.getpid(),
                    "epoch": self.epoch, **counts}
        raw = json.dumps(response, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(raw) > 512:
            raise RuntimeError("Agent quiescence response too large")
        connection.sendall(raw)
        expires = time.monotonic() + QUIESCE_MAX_HOLD_SECONDS
        while not self._stopping.is_set():
            deadline = min(expires, time.monotonic() + QUIESCE_HEARTBEAT_SECONDS)
            line = _quiesce_line(connection, deadline)
            if line == b"PING 1\n" and time.monotonic() < expires:
                connection.sendall(b"PONG 1 " + self.epoch.encode("ascii") + b"\n")
            elif line == b"RELEASE 1\n":
                connection.sendall(b"RELEASED 1\n")
                return
            else:
                return

    def stop(self) -> None:
        self._stopping.set()
        with self._mutex:
            connection = self._connection
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._listener is not None:
            self._listener.close()
        self.gate.resume()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        if (self._inode is not None and info.st_ino == self._inode
                and stat.S_ISSOCK(info.st_mode)):
            self.path.unlink()


def _vpn_command_argv(command: str) -> list[str] | None:
    """Accept only the Hub's canonical, single VPN broker invocation.

    A malformed command mentioning the broker fails closed instead of falling
    through to the general shell executor. A valid one is executed directly,
    so shell operators cannot accompany a privileged broker request.
    """
    if not isinstance(command, str) or _VPN_HELPER not in command:
        return None
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError("Invalid VPN broker command") from exc
    if (not argv or argv[0] != _VPN_HELPER or shlex.join(argv) != command
            or len(argv) < 3 or not _VPN_NAME.fullmatch(argv[2])):
        raise ValueError("Invalid VPN broker command")
    action, name = argv[1:3]
    if action == "create":
        if (len(argv) != 9 or argv[3] != "--port" or argv[5] != "--subnet"
                or argv[7] != "--endpoint"):
            raise ValueError("Invalid VPN broker command")
        port, subnet, endpoint = argv[4], argv[6], argv[8]
        if not port.isascii() or not port.isdecimal() or not 1024 <= int(port) <= 65535 or str(int(port)) != port:
            raise ValueError("Invalid VPN broker port")
        try:
            network = ipaddress.IPv4Network(subnet, strict=True)
        except ValueError as exc:
            raise ValueError("Invalid VPN broker subnet") from exc
        if (str(network) != subnet or not 24 <= network.prefixlen <= 30
                or not any(network.subnet_of(parent) for parent in _PRIVATE_NETWORKS)):
            raise ValueError("Invalid VPN broker subnet")
        if not endpoint or len(endpoint) > 253:
            raise ValueError("Invalid VPN broker endpoint")
        try:
            address = ipaddress.IPv4Address(endpoint)
        except ipaddress.AddressValueError:
            if (endpoint.lower() != endpoint or "." not in endpoint
                    or not all(_DNS_LABEL.fullmatch(label) for label in endpoint.split("."))):
                raise ValueError("Invalid VPN broker endpoint")
        else:
            if str(address) != endpoint:
                raise ValueError("Invalid VPN broker endpoint")
    elif action == "activate":
        if len(argv) != 3:
            raise ValueError("Invalid VPN broker command")
    elif action in ("add-client", "revoke-client"):
        if len(argv) != 4 or not _VPN_CLIENT.fullmatch(argv[3]):
            raise ValueError("Invalid VPN broker command")
    elif action == "sealed-export":
        if (len(argv) not in (5, 7) or not _VPN_CLIENT.fullmatch(argv[3])
                or not _VPN_PUBLIC_KEY.fullmatch(argv[4])):
            raise ValueError("Invalid VPN broker command")
        if len(argv) == 7 and argv[5:] != ["--route", "full"]:
            raise ValueError("Invalid VPN broker route")
        try:
            raw_key = base64.urlsafe_b64decode(argv[4] + "=")
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Invalid VPN broker key") from exc
        if (len(raw_key) != 65 or raw_key[0] != 4
                or base64.urlsafe_b64encode(raw_key).decode("ascii").rstrip("=") != argv[4]):
            raise ValueError("Invalid VPN broker key")
    elif action == "remove":
        if len(argv) != 5 or argv[3:] != ["--confirm-name", name]:
            raise ValueError("Invalid VPN broker command")
    else:
        raise ValueError("Invalid VPN broker action")
    return argv


def _command_plan(command: str, timeout_seconds: int,
                  journal_units: tuple[str, ...] = ()) -> tuple[list[str], int]:
    vpn_argv = _vpn_command_argv(command)
    if vpn_argv is not None:
        raise ValueError("VPN requests require the Agent broker path")
    amnezia_argv = _amnezia_command_argv(command)
    if amnezia_argv is not None:
        raise ValueError("Amnezia requests require the Agent broker path")
    if parse_journal_request(command, journal_units) is not None:
        raise ValueError("Journal requests require the isolated broker")
    if _parse_service_command(command) is not None:
        raise ValueError("Service requests require the isolated broker")
    if _parse_container_action_command(command) is not None:
        raise ValueError("Container actions require the isolated broker")
    if _parse_process_request(command) is not None:
        raise ValueError("Process inventory requests require the dedicated path")
    if _parse_container_log_command(command) is not None:
        raise ValueError("Container logs require the dedicated broker")
    return ["/bin/sh", "-c", command], min(max(int(timeout_seconds), 1), 15)


def _sealed_envelope(output: str) -> str | None:
    """Return a canonical ciphertext envelope, rejecting extra or duplicate fields."""
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate envelope field")
            result[key] = value
        return result

    try:
        value = json.loads(output, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError):
        return None
    fields = ("version", "ephemeral_public_key", "salt", "nonce", "ciphertext")
    if (not isinstance(value, dict) or set(value) != set(fields)
            or type(value["version"]) is not int or value["version"] != 1):
        return None
    for field, minimum, maximum in (("ephemeral_public_key", 65, 65),
                                    ("salt", 16, 16), ("nonce", 12, 12),
                                    ("ciphertext", 16, 4096)):
        encoded = value[field]
        if (not isinstance(encoded, str) or not encoded
                or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded)):
            return None
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, base64.binascii.Error):
            return None
        if (not minimum <= len(raw) <= maximum
                or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded
                or (field == "ephemeral_public_key" and raw[0] != 4)):
            return None
    return json.dumps({field: value[field] for field in fields}, separators=(",", ":"))


def _request_owned_vpn_broker(argv: list[str], *, amnezia: bool = False) -> dict:
    """Send a validated operation from the Agent MainPID, never a shell child."""
    helper = _AMNEZIA_HELPER if amnezia else _VPN_HELPER
    if (not isinstance(argv, list) or not argv or argv[0] != helper or
            any(not isinstance(part, str) for part in argv[1:])):
        raise ValueError("Invalid VPN broker arguments")
    validator = _amnezia_command_argv if amnezia else _vpn_command_argv
    if validator(shlex.join(argv)) != argv:
        raise ValueError("Invalid VPN broker arguments")
    socket_path = _AMNEZIA_SOCKET_PATH if amnezia else _VPN_SOCKET_PATH
    request = (json.dumps({"argv": argv[1:]}, separators=(",", ":")) + "\n").encode("utf-8")
    if len(request) > _BROKER_REQUEST_LIMIT:
        raise ValueError("VPN broker request is too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(socket_path)
        connection.sendall(request)
        connection.settimeout(_AMNEZIA_TIMEOUT_SECONDS - 5 if amnezia else
                              _VPN_TIMEOUT_SECONDS - 5)
        response = bytearray()
        while b"\n" not in response and len(response) <= _BROKER_RESPONSE_LIMIT:
            chunk = connection.recv(_BROKER_RESPONSE_LIMIT + 1 - len(response))
            if not chunk:
                raise ValueError("Incomplete VPN broker response")
            response.extend(chunk)
    if (len(response) > _BROKER_RESPONSE_LIMIT or not response.endswith(b"\n") or
            response.count(b"\n") != 1):
        raise ValueError("Invalid VPN broker response")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate VPN broker response field")
            result[key] = value
        return result

    try:
        value = json.loads(response[:-1], object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid VPN broker response") from exc
    if (not isinstance(value, dict) or
            set(value) != ({"ok", "result"} if value.get("ok") is True else {"ok", "error"})):
        raise ValueError("Invalid VPN broker response")
    if value["ok"] is not True:
        # Error messages can contain local details. Keep only a generic
        # failure in the Hub job result and its audit trail.
        raise ValueError("VPN broker denied or failed")
    output = json.dumps(value["result"], sort_keys=True, separators=(",", ":"))
    if len(output.encode("utf-8")) > _BROKER_RESPONSE_LIMIT:
        raise ValueError("VPN broker response is too large")
    if amnezia:
        action = argv[1]
        public = _sanitize_amnezia_result(
            action, output, argv[2], argv[3] if action in ("add-profile", "revoke") else None)
        if public is None:
            raise ValueError("Invalid Amnezia broker result")
        if action in ("settings-intent", "settings-apply"):
            checked = json.loads(public)
            if (checked.get("config_sha256") != (argv[3] if action == "settings-intent" else argv[5]) or
                    checked.get("generation") != (int(argv[4]) if action == "settings-intent" else int(argv[4]) + 1) or
                    (action == "settings-intent" and
                     (checked.get("proposed_config_sha256") != argv[5] or
                      not set(checked.get("changed_fields", ())).issubset(
                          json.loads(argv[6])) or
                      not int(time.time()) < checked.get("expires_at", 0) <= int(time.time()) + 310))):
                raise ValueError("Amnezia broker result changed proposal")
        output = public
    elif argv[1] == "sealed-export":
        public = _sealed_envelope(output)
        if public is None:
            raise ValueError("Invalid sealed VPN broker result")
        output = public
    return {"state": "succeeded", "exit_code": 0, "output": output}


def load_config(path: str) -> dict:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object")
    hub_url = config.get("hub_url")
    parsed = urlsplit(hub_url) if isinstance(hub_url, str) else None
    if parsed is None or parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("hub_url must be an HTTPS origin")
    if parsed.path not in ("", "/"):
        raise ValueError("hub_url must not include a path")
    server_id = config.get("server_id")
    token_file = config.get("token_file")
    interval = config.get("interval_seconds", 30)
    if not isinstance(server_id, str) or not server_id or "/" in server_id:
        raise ValueError("server_id is invalid")
    if not isinstance(token_file, str) or not token_file.startswith("/"):
        raise ValueError("token_file must be absolute")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 5 <= interval <= 3600:
        raise ValueError("interval_seconds must be between 5 and 3600")
    if not isinstance(config.get("allow_remote_commands", False), bool):
        raise ValueError("allow_remote_commands must be boolean")
    if not isinstance(config.get("allow_interactive_terminal", False), bool):
        raise ValueError("allow_interactive_terminal must be boolean")
    from .terminal_broker import PROFILES, SOCKET_PATH
    if config.get("terminal_socket", SOCKET_PATH) not in {row[0] for row in PROFILES.values()}:
        raise ValueError("terminal_socket must be a SovaGrid broker socket")
    if not isinstance(config.get("allow_file_manager", False), bool):
        raise ValueError("allow_file_manager must be boolean")
    service_socket = config.get("service_socket", _SERVICE_SOCKET_PATH)
    if not isinstance(service_socket, str) or service_socket not in _SERVICE_SOCKET_PROFILES:
        raise ValueError("service_socket must be a SovaGrid broker socket")
    configured_units(config)
    validate_roots(config)
    ca_file = config.get("ca_file")
    if ca_file is not None and (not isinstance(ca_file, str) or not ca_file.startswith("/")):
        raise ValueError("ca_file must be an absolute path")
    return config


def read_token(path: str) -> str:
    token_path = Path(path)
    mode = token_path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o007:
        raise ValueError("Agent token file must be regular and inaccessible to other users")
    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("Agent token file is empty")
    return token


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    """Fail closed on every 30x response instead of replaying a bearer token."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class HubClient:
    def __init__(self, config: dict, token: str, opener=None):
        self.base = config["hub_url"].rstrip("/")
        self.server_id = config["server_id"]
        self.token = token
        self.context = ssl.create_default_context(cafile=config.get("ca_file"))
        # urllib's default redirect handler forwards Authorization to the
        # redirected URL, even across origins. A Hub API response must never
        # redirect an Agent bearer token to another host or plain HTTP.
        self._network_opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context), _RejectRedirect())
        self.opener = opener or self._open_without_redirects
        self._metric_details = frozenset()

    def _open_without_redirects(self, request, *, timeout, context):
        return self._network_opener.open(request, timeout=timeout)

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            method=method,
        )
        with self.opener(request, timeout=20, context=self.context) as response:
            return json.load(response)

    def push_metrics(self, data: dict):
        path = f"/api/v1/servers/{self.server_id}/metrics"
        details = data.get("details")
        selected = _OPTIONAL_METRIC_DETAILS & self._metric_details
        wire = data
        if isinstance(details, dict) and (_OPTIONAL_METRIC_DETAILS - selected) & details.keys():
            wire = {**data, "details": {key: value for key, value in details.items()
                                        if key not in _OPTIONAL_METRIC_DETAILS or key in selected}}
        sent_legacy_extension = (isinstance(wire.get("details"), dict) and
                                 bool(wire["details"].keys() & _LEGACY_RETRY_OMIT_DETAILS))
        try:
            response = self.request("POST", path, wire)
        except urllib.error.HTTPError as error:
            if error.code != 422 or not sent_legacy_extension:
                raise
            # A Hub rollback can follow a successful capability negotiation.
            # Older Hubs also reject the newer filesystem-completeness flag.
            # Retry this sample once; do not keep omitting it after a Hub
            # upgrade, because partial inventory must remain distinguishable.
            error.close()
            self._metric_details = frozenset()
            legacy = {**data, "details": {key: value for key, value in details.items()
                                           if key not in _LEGACY_RETRY_OMIT_DETAILS}}
            response = self.request("POST", path, legacy)
        capabilities = response.get("metric_details") if isinstance(response, dict) and response.get("accepted") is True else None
        if (isinstance(capabilities, list)
                and all(type(item) is str and item in _OPTIONAL_METRIC_DETAILS for item in capabilities)
                and len(capabilities) == len(set(capabilities))):
            self._metric_details = frozenset(capabilities)
        else:
            self._metric_details = frozenset()
        return response

    def next_job(self) -> dict | None:
        return self.request("GET", f"/api/v1/servers/{self.server_id}/jobs/next")["job"]

    def send_result(self, job_id: str, result: dict):
        return self.request("POST", f"/api/v1/servers/{self.server_id}/jobs/{job_id}/result", result)


def _enable_subreaper() -> bool:
    if sys.platform != "linux":
        return False
    try:
        # Linux PR_SET_CHILD_SUBREAPER: orphaned descendants are reparented to
        # this agent process, where the scanner can still identify them.
        return ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    except (AttributeError, OSError):
        return False


def _proc_snapshot(proc_root: str = "/proc") -> dict[int, tuple[int, int]]:
    result = {}
    try:
        entries = Path(proc_root).iterdir()
        for path in entries:
            if not path.name.isdecimal():
                continue
            try:
                raw = (path / "stat").read_text()
                # comm may itself contain ')' or spaces; split after the last
                # closing parenthesis. Tail fields start with state (field 3).
                tail = raw.rsplit(")", 1)[1].split()
                result[int(path.name)] = (int(tail[1]), int(tail[19]))
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        return {}
    return result


def _command_processes(root_pid: int, baseline: set[int], subreaper: bool,
                       proc_root: str = "/proc") -> dict[int, int]:
    snapshot = _proc_snapshot(proc_root)
    seeds = {root_pid} if snapshot.get(root_pid, (None, None))[0] == os.getpid() else set()
    if subreaper:
        protected = _reserved_children()
        seeds.update(pid for pid, (ppid, _) in snapshot.items()
                     if ppid == os.getpid() and pid not in baseline and pid not in protected)
    descendants = {}
    frontier = seeds
    while frontier:
        next_frontier = set()
        for pid in frontier:
            if pid in snapshot:
                descendants[pid] = snapshot[pid][1]
        for pid, (ppid, _) in snapshot.items():
            if ppid in frontier and pid not in descendants:
                next_frontier.add(pid)
        frontier = next_frontier
    return descendants


def _kill_observed(observed: dict[int, int]):
    for pid, starttime in observed.items():
        current = _proc_snapshot_one(pid)
        if current == starttime:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def _proc_snapshot_one(pid: int) -> int | None:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text()
        return int(raw.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _stop_processes(proc, observed: dict[int, int], baseline: set[int], subreaper: bool):
    observed.update(_command_processes(proc.pid, baseline, subreaper))
    _kill_observed(observed)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _reap_children(wait_seconds: float = 0):
    deadline = time.monotonic() + wait_seconds
    while True:
        # waitpid(-1) could steal a concurrently running check helper from its
        # Popen owner. Reap only unreserved direct children, by exact PID.
        snapshot = _proc_snapshot()
        protected = _reserved_children()
        candidates = [pid for pid, (ppid, _) in snapshot.items()
                      if ppid == os.getpid() and pid not in protected]
        pending = False
        for pid in candidates:
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
                pending |= not bool(reaped)
            except ChildProcessError:
                pass
        remaining = deadline - time.monotonic()
        if not pending or remaining <= 0:
            return
        time.sleep(min(remaining, 0.02))


def run_command(command: str, timeout_seconds: int = 15, output_limit_bytes: int = 8192,
                *, journal_units: tuple[str, ...] = (), argv_override: list[str] | None = None) -> dict:
    if os.geteuid() == 0:
        raise PermissionError("Remote commands may not execute as root")
    if (not isinstance(command, str) or not command or "\x00" in command
            or len(command.encode("utf-8")) > 2048):
        raise ValueError("Invalid command")
    if argv_override is None:
        argv, timeout_seconds = _command_plan(command, timeout_seconds, journal_units)
    else:
        # Only the isolated local broker calls this with its fixed validated
        # journalctl argv. Hub job data never supplies this Python argument.
        argv = argv_override
        timeout_seconds = min(max(int(timeout_seconds), 1), 5)
    sealed_export = len(argv) >= 2 and argv[0] == _VPN_HELPER and argv[1] == "sealed-export"
    amnezia_action = argv[1] if len(argv) >= 2 and argv[0] == _AMNEZIA_HELPER else None
    output_limit_bytes = min(max(int(output_limit_bytes), 1), 8192)
    subreaper = _enable_subreaper()
    if subreaper:
        _reap_children()
    baseline = {pid for pid, (ppid, _) in _proc_snapshot().items() if ppid == os.getpid()}
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        start_new_session=True, close_fds=True,
    )
    selector = selectors.DefaultSelector()
    os.set_blocking(proc.stdout.fileno(), False)
    selector.register(proc.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    state = None
    observed = {}
    try:
        while selector.get_map():
            observed.update(_command_processes(proc.pid, baseline, subreaper))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state = "timed_out"
                _stop_processes(proc, observed, baseline, subreaper)
                break
            ready = selector.select(timeout=min(remaining, 0.25))
            for key, _ in ready:
                chunk = os.read(key.fd, output_limit_bytes - len(output) + 1)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > output_limit_bytes:
                    del output[output_limit_bytes:]
                    state = "output_limited"
                    _stop_processes(proc, observed, baseline, subreaper)
                    break
            if state:
                break
        if state is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state = "timed_out"
                _stop_processes(proc, observed, baseline, subreaper)
            else:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    state = "timed_out"
                    _stop_processes(proc, observed, baseline, subreaper)
        proc.wait(timeout=2)
    finally:
        selector.close()
        if proc.poll() is None:
            _stop_processes(proc, observed, baseline, subreaper)
            proc.wait(timeout=2)
        # A command is one bounded job; remaining children are never intended
        # to survive it, even if the shell already exited successfully.
        observed.update(_command_processes(proc.pid, baseline, subreaper))
        _kill_observed(observed)
        if subreaper:
            _reap_children(0.5)
        proc.stdout.close()
    if state is None:
        state = "succeeded" if proc.returncode == 0 else "failed"
    decoded = output.decode("utf-8", errors="replace")
    while len(decoded.encode("utf-8")) > output_limit_bytes:
        decoded = decoded[:-1]
    if sealed_export:
        envelope = _sealed_envelope(decoded) if state == "succeeded" else None
        if envelope is None:
            return {"state": "failed" if state == "succeeded" else state,
                    "exit_code": proc.returncode,
                    "output": "Sealed profile export failed"}
        decoded = envelope
    if amnezia_action is not None:
        public = (_sanitize_amnezia_result(
            amnezia_action, decoded, argv[2],
            argv[3] if amnezia_action in ("add-profile", "revoke") else None)
            if state == "succeeded" else None)
        if public is None:
            return {"state": "failed" if state == "succeeded" else state,
                    "exit_code": proc.returncode, "output": "Amnezia control failed"}
        decoded = public
    return {"state": state, "exit_code": proc.returncode, "output": decoded}


def run_once(config: dict, client: HubClient, quiescence: AgentQuiescence | None = None):
    report = collect()
    allowed_journals = configured_units(config)
    if allowed_journals:
        report.setdefault("details", {})["journal_units"] = list(allowed_journals)
    # The Hub caps details at 12 KiB even when no journal units are selected.
    # Preserve the journal allowlist, which controls later read-only requests,
    # and discard optional diagnostics before long inventories.
    if "details" in report:
        for key in ("pressure", "cpu_times", "top_processes", "disk_io",
                    "interfaces", "filesystems", "services", "processes", "swap"):
            if len(json.dumps(report["details"], ensure_ascii=False, separators=(",", ":")).encode()) <= 12000:
                break
            report["details"].pop(key, None)
    client.push_metrics(report)
    if config.get("allow_remote_commands", False):
        if os.geteuid() == 0:
            raise PermissionError("Agent must run without root privileges when commands are enabled")
        with (quiescence.operation("job", block=False) if quiescence is not None
              else contextlib.nullcontext(True)) as admitted:
            if not admitted:
                return
            job = client.next_job()
            if job:
                try:
                    vpn_argv = _vpn_command_argv(job["command"])
                    amnezia_argv = _amnezia_command_argv(job["command"])
                    journal_request = parse_journal_request(job["command"], allowed_journals)
                    service_request = _parse_service_command(job["command"])
                    container_action_request = _parse_container_action_command(job["command"])
                    process_request = _parse_process_request(job["command"])
                    container_log_request = _parse_container_log_command(job["command"])
                except ValueError:
                    # Report a bad broker request instead of leaving the fetched
                    # job indefinitely in Hub's delivered state.
                    result = {"state": "failed", "exit_code": None,
                              "output": ("Invalid VPN broker command" if _VPN_HELPER in job["command"]
                                         else "Journal access denied or invalid request" if _JOURNAL_MARKER in job["command"]
                                         else "Service control denied or invalid request" if _SERVICE_MARKER in job["command"]
                                         else "Container action denied or invalid request" if _CONTAINER_ACTION_MARKER in job["command"]
                                         else "Process inventory denied or invalid request" if _PROCESS_MARKER in job["command"]
                                         else "Container logs denied or invalid request" if _CONTAINER_LOG_MARKER in job["command"]
                                         else "Invalid Amnezia broker command")}
                    vpn_argv = None
                    amnezia_argv = None
                    journal_request = None
                    service_request = None
                    container_action_request = None
                    process_request = None
                    container_log_request = None
                else:
                    try:
                        if journal_request is not None:
                            result = request_broker(*journal_request)
                        elif service_request is not None:
                            result = _service_job_result(
                                _request_service_broker(*service_request,
                                                        config.get("service_socket", _SERVICE_SOCKET_PATH)),
                                *service_request)
                        elif container_action_request is not None:
                            result = _container_action_job_result(
                                _request_container_action_broker(
                                    *container_action_request,
                                    config.get("service_socket", _SERVICE_SOCKET_PATH)),
                                *container_action_request)
                        elif process_request is not None:
                            result = _process_job_result(process_request)
                        elif container_log_request is not None:
                            result = _request_container_logs(*container_log_request)
                        elif vpn_argv is not None:
                            result = _request_owned_vpn_broker(vpn_argv)
                        elif amnezia_argv is not None:
                            result = _request_owned_vpn_broker(amnezia_argv, amnezia=True)
                        else:
                            result = run_command(
                                job["command"], job.get("timeout_seconds", 15),
                                job.get("output_limit_bytes", 8192),
                            )
                    except (OSError, ValueError):
                        if (vpn_argv is None and amnezia_argv is None and
                                journal_request is None and service_request is None and
                                container_action_request is None and process_request is None and
                                container_log_request is None):
                            raise
                        # Missing helper/socket and invalid broker metadata must
                        # complete the job without leaking local error details.
                        service_mutation_uncertain = (service_request is not None and
                                                      service_request[0] != "status")
                        container_mutation_uncertain = (container_action_request is not None and
                                                        container_action_request[0] != "status")
                        vpn_mutation_uncertain = (vpn_argv is not None and
                                                  vpn_argv[1] in ("create", "activate", "add-client",
                                                                  "revoke-client", "remove"))
                        amnezia_mutation_uncertain = (amnezia_argv is not None and
                                                      amnezia_argv[1] in ("add-profile", "revoke",
                                                                          "settings-intent", "settings-apply"))
                        result = {"state": "timed_out" if (service_mutation_uncertain or
                                                             container_mutation_uncertain or
                                                             vpn_mutation_uncertain or
                                                             amnezia_mutation_uncertain) else "failed",
                                  "exit_code": None,
                                  "output": ("VPN action outcome uncertain; inspect state before retrying"
                                             if vpn_mutation_uncertain else
                                             "Amnezia action outcome uncertain; inspect state before retrying"
                                             if amnezia_mutation_uncertain else
                                             "Container action outcome uncertain; check status before retrying"
                                             if container_mutation_uncertain else
                                             "VPN broker unavailable or invalid request" if vpn_argv is not None
                                             else "Amnezia broker unavailable or invalid request" if amnezia_argv is not None
                                             else "Service action outcome uncertain; check status before retrying"
                                             if service_mutation_uncertain else
                                             "Service control unavailable or denied" if service_request is not None
                                             else "Container action unavailable or denied" if container_action_request is not None
                                             else "Process inventory unavailable" if process_request is not None
                                             else "Container logs unavailable or denied" if container_log_request is not None
                                             else "Journal unavailable or invalid request")}
                if vpn_argv is not None or amnezia_argv is not None:
                    # A broker operation can run close to Hub's 120-second offline
                    # threshold. Refresh liveness before reporting its result;
                    # failure to refresh must never suppress that job result.
                    try:
                        client.push_metrics(collect())
                    except Exception:
                        logging.warning("VPN job finished; metric refresh failed" if vpn_argv is not None
                                        else "Amnezia job finished; metric refresh failed")
                client.send_result(job["id"], result)
