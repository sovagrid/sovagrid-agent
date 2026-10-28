# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-only, compare-and-swap installer for optional service control."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterator
import uuid

from .service_broker import parse_policy
from .service_control import LOCAL_SOCKET_PATH, protected_mutation_unit, unique_pairs


PROFILES = {
    "default": ("sovagrid-service-control", "/run/sovagrid-service/control.sock", "sovagrid"),
    "local": ("sovagrid-service-local-control", "/run/sovagrid-service-local/control.sock",
              "sovagrid-local"),
}
HEX = re.compile(r"[0-9a-f]{64}\Z")
SYSTEMCTL = "/usr/bin/systemctl"


class SetupError(RuntimeError):
    """A fixed, credential-free administrative error code."""


@dataclass(frozen=True)
class Paths:
    config: Path = Path("/etc/sovagrid-service")
    local_policy: Path = Path("/etc/sovagrid-service-local")
    units: Path = Path("/etc/systemd/system")
    lock: Path = Path("/etc/sovagrid-service-setup.lock")
    code: Path = Path("/opt/sovagrid-agent")
    local_code: Path = Path("/opt/sovagrid-agent-local")
    local_config: Path = Path("/etc/sovagrid-local/agent.json")


@dataclass(frozen=True)
class FileState:
    content: bytes
    mode: int
    group: int


def unit_content(profile: str) -> dict[str, bytes]:
    if profile not in PROFILES:
        raise SetupError("INVALID_PROFILE")
    name, socket_path, user = PROFILES[profile]
    title = ("SovaGrid allowed systemd service control" if profile == "default"
             else "SovaGrid local Agent allowed systemd service control")
    description = ("SovaGrid restricted systemd service controller" if profile == "default"
                   else "SovaGrid local Agent restricted systemd service controller")
    socket = (f"[Unit]\nDescription={title} socket\n\n[Socket]\n"
              f"ListenStream={socket_path}\nSocketUser={user}\nSocketMode=0600\n"
              f"DirectoryMode=0755\nRemoveOnStop=true\nService={name}.service\n\n"
              "[Install]\nWantedBy=sockets.target\n").encode("ascii")
    working = "/opt/sovagrid-agent" if profile == "default" else "/opt/sovagrid-agent-local"
    service = (f"[Unit]\nDescription={description}\nRequires={name}.socket\n"
               f"After={name}.socket\n\n[Service]\nType=simple\nUser=root\nGroup=root\n"
               f"WorkingDirectory={working}\n"
               "ExecStart=/usr/bin/python3 -B -E -S -m sovagrid_agent.service_broker\n"
               "Restart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n"
               "PrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\n"
               "ProtectHome=true\nProtectKernelTunables=true\nProtectControlGroups=true\n"
               "RestrictAddressFamilies=AF_UNIX\nCapabilityBoundingSet=\n"
               "AmbientCapabilities=\nTasksMax=16\nMemoryMax=128M\n"
               "KillMode=control-group\n").encode("ascii")
    return {f"{name}.socket": socket, f"{name}.service": service}


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _canonical_policy(raw: bytes) -> tuple[dict[str, frozenset[str]], bytes]:
    try:
        policy = parse_policy(raw)
    except ValueError as exc:
        raise SetupError("INVALID_POLICY") from exc
    if any(protected_mutation_unit(unit) and actions - {"status"}
           for unit, actions in policy.items()):
        raise SetupError("INVALID_POLICY")
    canonical = (json.dumps({"version": 1, "units":
                            {unit: sorted(actions) for unit, actions in sorted(policy.items())}},
                            separators=(",", ":")) + "\n").encode("ascii")
    return policy, canonical


def _local_agent_config(raw: bytes) -> bytes:
    """Accept only canonical promoted-Agent config and add the fixed broker socket."""
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise SetupError("LOCAL_CONFIG_CHANGED") from exc
    required = {"hub_url", "server_id", "token_file", "ca_file", "interval_seconds",
                "allow_remote_commands", "allow_interactive_terminal", "allow_file_manager"}
    optional = {"terminal_socket", "file_roots", "service_socket"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        raise SetupError("LOCAL_CONFIG_CHANGED")
    try:
        valid_id = str(uuid.UUID(value["server_id"])) == value["server_id"]
    except (ValueError, TypeError, AttributeError):
        valid_id = False
    if (not valid_id or value["hub_url"] != "https://localhost:8767" or
            value["token_file"] != "/etc/sovagrid-local/agent.token" or
            value["ca_file"] != "/etc/sovagrid-local/hub-ca.pem" or
            type(value["interval_seconds"]) is not int or value["interval_seconds"] != 30 or
            any(type(value[name]) is not bool for name in
                ("allow_remote_commands", "allow_interactive_terminal", "allow_file_manager")) or
            not value["allow_remote_commands"] or
            ("terminal_socket" in value) != value["allow_interactive_terminal"] or
            ("file_roots" in value) != value["allow_file_manager"] or
            ("terminal_socket" in value and
             value["terminal_socket"] != "/run/sovagrid-terminal-local/control.sock") or
            ("file_roots" in value and
             value["file_roots"] != {"workspace": "/var/lib/sovagrid-agent-local/files"}) or
            ("service_socket" in value and value["service_socket"] != LOCAL_SOCKET_PATH)):
        raise SetupError("LOCAL_CONFIG_CHANGED")
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise SetupError("LOCAL_CONFIG_CHANGED")
    value["service_socket"] = LOCAL_SOCKET_PATH
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class ServiceSetup:
    def __init__(self, *, paths: Paths = Paths(), runner: Callable = subprocess.run,
                 require_root: bool = True, local_gid: int | None = None):
        self.paths = paths
        self.runner = runner
        self.owner = 0 if require_root else os.geteuid()
        self.group = 0 if require_root else os.getegid()
        self.local_gid = local_gid
        self.require_root = require_root
        if require_root and (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
            raise SetupError("ROOT_REQUIRED")
        if not all(path.is_absolute() for path in (paths.config, paths.local_policy,
                                                  paths.units, paths.lock,
                                                  paths.code, paths.local_code,
                                                  paths.local_config)):
            raise SetupError("INVALID_PATHS")
        if require_root and (paths != Paths() or
                             Path(__file__).resolve() not in
                             (paths.code / "sovagrid_agent/service_setup.py",
                              paths.local_code / "sovagrid_agent/service_setup.py")):
            raise SetupError("INVALID_PATHS")

    def _local_gid(self) -> int:
        if self.local_gid is not None:
            return self.local_gid
        if not self.require_root:
            return os.getegid()
        try:
            return grp.getgrnam("sovagrid-local").gr_gid
        except KeyError as exc:
            raise SetupError("LOCAL_AGENT_MISSING") from exc

    def _dir(self, path: Path, *, private: bool, missing_ok: bool = False) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            if missing_ok:
                return False
            raise SetupError("INSTALLATION_MISSING")
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or
                (private and mode != 0o700) or
                (not private and mode & 0o022)):
            raise SetupError("UNSAFE_DIRECTORY")
        return True

    def _file(self, path: Path, mode: int, *, group: int | None = None,
              maximum: int = 4096) -> FileState | None:
        group = self.group if group is None else group
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_gid != group or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum):
                raise SetupError("UNSAFE_FILE")
            raw = os.read(fd, maximum + 1)
            if len(raw) != info.st_size:
                raise SetupError("STATE_CHANGED")
            return FileState(raw, mode, group)
        finally:
            os.close(fd)

    def _atomic(self, path: Path, content: bytes, mode: int,
                *, group: int | None = None) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".sovagrid-service-", dir=path.parent)
        try:
            os.fchmod(fd, mode)
            if self.owner == 0:
                os.fchown(fd, 0, self.group if group is None else group)
            with os.fdopen(fd, "wb") as output:
                fd = -1
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            temporary = ""
            _fsync_dir(path.parent)
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def _remove(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
        _fsync_dir(path.parent)

    def _systemctl(self, *args: str, status: bool = False) -> str | None:
        argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password", *args]
        try:
            result = self.runner(argv, stdout=subprocess.PIPE if status else subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, text=True, timeout=8 if status else 35,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SetupError("SYSTEMD_UNCERTAIN") from exc
        if status:
            value = result.stdout.strip() if isinstance(result.stdout, str) else ""
            if len(value) > 64 or not re.fullmatch(r"[a-z-]{1,32}", value):
                return None
            return value
        if result.returncode != 0:
            raise SetupError("SYSTEMD_UNCERTAIN")
        return None

    def _socket_status(self, profile: str) -> tuple[str, str]:
        unit = PROFILES[profile][0] + ".socket"
        enabled = self._systemctl("is-enabled", unit, status=True)
        active = self._systemctl("is-active", unit, status=True)
        return enabled or "unavailable", active or "unavailable"

    def _snapshot(self) -> dict:
        self._dir(self.paths.units, private=False)
        config_exists = {"default": self._dir(self.paths.config, private=True, missing_ok=True),
                         "local": self._dir(self.paths.local_policy, private=True, missing_ok=True)}
        files = {}
        for profile in PROFILES:
            for unit in unit_content(profile):
                files[unit] = self._file(self.paths.units / unit, 0o644)
            folder = self.paths.config if profile == "default" else self.paths.local_policy
            prefix = "" if profile == "default" else "local_"
            files[prefix + "policy"] = (self._file(folder / "units.json", 0o600)
                                         if config_exists[profile] else None)
            files[prefix + "marker"] = (self._file(folder / "enabled", 0o600)
                                         if config_exists[profile] else None)
        local_dir = self.paths.local_config.parent
        if self._dir(local_dir, private=False, missing_ok=True):
            info = local_dir.lstat()
            if (info.st_gid != self._local_gid() or
                    stat.S_IMODE(info.st_mode) != 0o750):
                raise SetupError("UNSAFE_LOCAL_AGENT")
            files["local_agent_config"] = self._file(self.paths.local_config, 0o640,
                                                     group=self._local_gid(), maximum=8192)
        else:
            files["local_agent_config"] = None
        sockets = {profile: self._socket_status(profile) for profile in PROFILES}
        serial = {name: None if state is None else hashlib.sha256(state.content).hexdigest()
                  for name, state in files.items()}
        revision = hashlib.sha256(json.dumps({"files": serial, "sockets": sockets,
                                               "config_exists": config_exists},
                                              sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        armed = {profile: files[("" if profile == "default" else "local_") + "marker"] is not None and
                 files[("" if profile == "default" else "local_") + "marker"].content == b"enabled\n"
                 for profile in PROFILES}
        return {"state_revision": revision, "armed": armed, "config_exists": config_exists,
                "sockets": sockets, "files": files}

    def preview(self, profile: str | None = None, policy_raw: bytes | None = None) -> dict:
        if profile is not None and profile not in PROFILES:
            raise SetupError("INVALID_PROFILE")
        state = self._snapshot()
        profiles = {}
        for name in PROFILES:
            current = state["files"][("" if name == "default" else "local_") + "policy"]
            try:
                policy = parse_policy(current.content) if current is not None else None
            except ValueError:
                policy = None
                status = "invalid"
            else:
                status = "present" if policy is not None else "absent"
            profiles[name] = {"armed": state["armed"][name], "policy_status": status,
                              "policy": ({unit: sorted(actions) for unit, actions in sorted(policy.items())}
                                         if policy is not None else None),
                              "socket": state["sockets"][name]}
        selected = profile or "default"
        public = {"state_revision": state["state_revision"], "armed": state["armed"][selected],
                  "sockets": state["sockets"], "profiles": profiles,
                  "policy_status": profiles[selected]["policy_status"],
                  "policy": profiles[selected]["policy"]}
        if policy_raw is not None:
            if profile is None:
                raise SetupError("INVALID_PROFILE")
            _, canonical = _canonical_policy(policy_raw)
            self._arm_precheck(state, profile)
            current = state["files"][("" if profile == "default" else "local_") + "policy"]
            public["plan"] = {"profile": profile,
                              "install_units": [unit for unit in unit_content(profile)
                                                if state["files"][unit] is None],
                              "change_policy": current is None or current.content != canonical,
                              "enable_socket": state["sockets"][profile] != ("enabled", "active"),
                              "configure_local_agent": profile == "local" and
                              state["files"]["local_agent_config"] is not None and
                              _local_agent_config(state["files"]["local_agent_config"].content) !=
                              state["files"]["local_agent_config"].content}
        return public

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._dir(self.paths.lock.parent, private=False)
        fd = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_gid != self.group or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise SetupError("UNSAFE_LOCK")
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SetupError("SETUP_BUSY")
                    time.sleep(0.1)
            yield
        finally:
            os.close(fd)

    def _expect(self, expected: str) -> dict:
        if not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise SetupError("INVALID_EXPECTED_STATE")
        state = self._snapshot()
        if state["state_revision"] != expected:
            raise SetupError("STATE_CHANGED")
        return state

    def _policy_dir(self, profile: str) -> Path:
        return self.paths.config if profile == "default" else self.paths.local_policy

    def _policy_key(self, profile: str, kind: str) -> str:
        return ("" if profile == "default" else "local_") + kind

    def _ensure_config_dir(self, profile: str) -> None:
        path = self._policy_dir(profile)
        if not self._dir(path, private=True, missing_ok=True):
            path.mkdir(mode=0o700)
            self._dir(path, private=True)
            _fsync_dir(path.parent)

    def _code_tree(self, profile: str) -> None:
        """The root service must never import code writable by Agent users."""
        code = self.paths.code if profile == "default" else self.paths.local_code
        required = ("sovagrid_agent/__init__.py", "sovagrid_agent/service_broker.py",
                    "sovagrid_agent/service_control.py")
        try:
            for path in (code.parent, code):
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or
                        stat.S_IMODE(info.st_mode) & 0o022):
                    raise SetupError("UNSAFE_CODE_TREE")
            count = 0
            pending = [code]
            while pending:
                directory = pending.pop()
                for child in directory.iterdir():
                    count += 1
                    if count > 1024:
                        raise SetupError("UNSAFE_CODE_TREE")
                    info = child.lstat()
                    if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) & 0o022:
                        raise SetupError("UNSAFE_CODE_TREE")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(child)
                    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise SetupError("UNSAFE_CODE_TREE")
            for name in required:
                info = (code / name).lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner:
                    raise SetupError("UNSAFE_CODE_TREE")
        except OSError as exc:
            raise SetupError("UNSAFE_CODE_TREE") from exc

    def _arm_precheck(self, before: dict, profile: str) -> None:
        self._code_tree(profile)
        for unit, content in unit_content(profile).items():
            old = before["files"][unit]
            if old is not None and old.content != content:
                raise SetupError("UNIT_DRIFT")
        if before["sockets"][profile][0] not in ("enabled", "disabled", "not-found") or \
                before["sockets"][profile][1] not in ("active", "inactive", "failed", "unknown"):
            raise SetupError("SYSTEMD_STATE_UNAVAILABLE")
        if profile == "local":
            config = before["files"]["local_agent_config"]
            if config is None:
                raise SetupError("LOCAL_AGENT_MISSING")
            _local_agent_config(config.content)
            if self._systemctl("is-active", "sovagrid-agent-local.service", status=True) != "active":
                raise SetupError("LOCAL_AGENT_INACTIVE")

    def _restore_files(self, before: dict, profiles: set[str]) -> None:
        for profile in profiles:
            self._ensure_config_dir(profile)
            path = self._policy_dir(profile)
            self._remove(path / "enabled")
            unit = PROFILES[profile][0] + ".socket"
            current = self._socket_status(profile)
            if current[0] == "enabled" or current[1] == "active":
                self._systemctl("disable", "--now", unit)
            for name in unit_content(profile):
                old = before["files"][name]
                target = self.paths.units / name
                if old is None:
                    self._remove(target)
                else:
                    self._atomic(target, old.content, old.mode, group=old.group)
            policy = before["files"][self._policy_key(profile, "policy")]
            if policy is None:
                self._remove(path / "units.json")
            else:
                self._atomic(path / "units.json", policy.content, policy.mode,
                             group=policy.group)
        if "local" in profiles:
            old = before["files"]["local_agent_config"]
            if old is not None:
                current = self._file(self.paths.local_config, 0o640,
                                     group=self._local_gid(), maximum=8192)
                if current is None or current.content != old.content:
                    self._atomic(self.paths.local_config, old.content, old.mode,
                                 group=old.group)
                    self._systemctl("restart", "sovagrid-agent-local.service")
                    if self._systemctl("is-active", "sovagrid-agent-local.service",
                                       status=True) != "active":
                        raise SetupError("ROLLBACK_INCOMPLETE")
        self._systemctl("daemon-reload")
        for profile in profiles:
            enabled, active = before["sockets"][profile]
            unit = PROFILES[profile][0] + ".socket"
            if any(before["files"][name] is not None for name in unit_content(profile)):
                if enabled == "enabled":
                    self._systemctl("enable", unit)
                elif enabled == "disabled":
                    self._systemctl("disable", unit)
                if active == "active":
                    self._systemctl("start", unit)
                elif active == "inactive":
                    self._systemctl("stop", unit)
            if self._socket_status(profile) != (enabled, active):
                raise SetupError("ROLLBACK_INCOMPLETE")
            marker = before["files"][self._policy_key(profile, "marker")]
            path = self._policy_dir(profile)
            if marker is not None:
                self._atomic(path / "enabled", marker.content, marker.mode,
                             group=marker.group)
            if not before["config_exists"][profile]:
                path.rmdir()
                _fsync_dir(path.parent)

    def arm(self, profile: str, policy_raw: bytes, expected: str) -> dict:
        if profile not in PROFILES:
            raise SetupError("INVALID_PROFILE")
        _, canonical = _canonical_policy(policy_raw)
        with self._locked():
            before = self._expect(expected)
            self._arm_precheck(before, profile)
            try:
                self._ensure_config_dir(profile)
                path = self._policy_dir(profile)
                self._remove(path / "enabled")
                self._atomic(path / "units.json", canonical, 0o600)
                for unit, content in unit_content(profile).items():
                    if before["files"][unit] is None:
                        self._atomic(self.paths.units / unit, content, 0o644)
                self._systemctl("daemon-reload")
                if profile == "local":
                    old_config = before["files"]["local_agent_config"]
                    desired = _local_agent_config(old_config.content)
                    if desired != old_config.content:
                        need_current = self._file(self.paths.local_config, 0o640,
                                                  group=self._local_gid(), maximum=8192)
                        if need_current != old_config:
                            raise SetupError("STATE_CHANGED")
                        self._atomic(self.paths.local_config, desired, 0o640,
                                     group=self._local_gid())
                        self._systemctl("restart", "sovagrid-agent-local.service")
                        if self._systemctl("is-active", "sovagrid-agent-local.service",
                                           status=True) != "active":
                            raise SetupError("LOCAL_AGENT_INACTIVE")
                self._systemctl("enable", "--now", PROFILES[profile][0] + ".socket")
                if self._socket_status(profile) != ("enabled", "active"):
                    raise SetupError("SYSTEMD_UNCERTAIN")
                self._atomic(path / "enabled", b"enabled\n", 0o600)
                return self.preview(profile)
            except Exception as exc:
                self._remove(self._policy_dir(profile) / "enabled")
                try:
                    self._restore_files(before, {profile})
                except Exception as rollback:
                    raise SetupError("ROLLBACK_INCOMPLETE") from rollback
                raise SetupError("ARM_FAILED") from exc

    def disarm(self, expected: str, profile: str = "default") -> dict:
        if profile not in (*PROFILES, "all"):
            raise SetupError("INVALID_PROFILE")
        targets = set(PROFILES) if profile == "all" else {profile}
        with self._locked():
            before = self._expect(expected)
            try:
                for target in targets:
                    if before["config_exists"][target]:
                        self._remove(self._policy_dir(target) / "enabled")
                    unit = PROFILES[target][0] + ".socket"
                    if before["sockets"][target][0] == "enabled" or \
                            before["sockets"][target][1] == "active":
                        self._systemctl("disable", "--now", unit)
                after = self._snapshot()
                if any(after["armed"][target] or
                       after["sockets"][target][0] == "enabled" or
                       after["sockets"][target][1] == "active" for target in targets):
                    raise SetupError("SYSTEMD_UNCERTAIN")
                return self.preview(None if profile == "all" else profile)
            except Exception as exc:
                for target in targets:
                    if before["config_exists"][target]:
                        self._remove(self._policy_dir(target) / "enabled")
                try:
                    self._restore_files(before, targets)
                except Exception as rollback:
                    raise SetupError("ROLLBACK_INCOMPLETE") from rollback
                raise SetupError("DISARM_FAILED") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SovaGrid root-only service control setup")
    sub = parser.add_subparsers(dest="command", required=True)
    preview = sub.add_parser("preview")
    preview.add_argument("--profile", choices=PROFILES)
    arm = sub.add_parser("arm")
    arm.add_argument("--profile", choices=PROFILES, required=True)
    arm.add_argument("--expected-state", required=True)
    disarm = sub.add_parser("disarm")
    disarm.add_argument("--profile", choices=(*PROFILES, "all"), default="default")
    disarm.add_argument("--expected-state", required=True)
    args = parser.parse_args(argv)
    try:
        setup = ServiceSetup()
        if args.command == "preview":
            if args.profile is not None:
                raw = sys.stdin.buffer.read(4097)
                if len(raw) > 4096:
                    raise SetupError("INVALID_POLICY")
                result = setup.preview(args.profile, raw)
            else:
                result = setup.preview()
        elif args.command == "arm":
            raw = sys.stdin.buffer.read(4097)
            if len(raw) > 4096:
                raise SetupError("INVALID_POLICY")
            result = setup.arm(args.profile, raw, args.expected_state)
        else:
            result = setup.disarm(args.expected_state, args.profile)
    except SetupError as exc:
        json.dump({"ok": False, "error": str(exc)}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 2
    except Exception:
        json.dump({"ok": False, "error": "SETUP_FAILED"}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 3
    json.dump({"ok": True, **result}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
