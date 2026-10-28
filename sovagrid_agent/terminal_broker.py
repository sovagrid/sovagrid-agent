# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Socket-activated PTY creator running as the isolated shell user.

The broker only creates a shell as sovagrid-shell and passes its PTY master
to the authenticated sovagrid Agent via SCM_RIGHTS.
"""

from __future__ import annotations

import array
import ctypes
import fcntl
import json
import logging
import os
import pwd
import select
import signal
import socket
import struct
import sys
import termios
import time
from pathlib import Path


SOCKET_PATH = "/run/sovagrid-terminal/control.sock"
LOCAL_SOCKET_PATH = "/run/sovagrid-terminal-local/control.sock"
MAX_HANDLERS = 4

# A promoted host has two independent Agents. The local Hub's Agent must never
# use the external Agent's socket, identity or shell home.
PROFILES = {
    "standard": (SOCKET_PATH, "sovagrid", "sovagrid-shell", "/var/lib/sovagrid-shell"),
    "local": (LOCAL_SOCKET_PATH, "sovagrid-local", "sovagrid-local-shell",
              "/var/lib/sovagrid-local-shell"),
}


def _request(conn: socket.socket) -> tuple[int, int]:
    conn.settimeout(5)
    data = bytearray()
    while b"\n" not in data and len(data) <= 128:
        chunk = conn.recv(129 - len(data))
        if not chunk:
            raise ValueError("Incomplete PTY request")
        data.extend(chunk)
    if len(data) > 128 or not data.endswith(b"\n"):
        raise ValueError("Invalid PTY request")
    value = json.loads(data)
    if not isinstance(value, dict) or set(value) != {"cols", "rows"}:
        raise ValueError("Invalid PTY request")
    cols, rows = value["cols"], value["rows"]
    if (type(cols) is not int or not 20 <= cols <= 300
            or type(rows) is not int or not 10 <= rows <= 120):
        raise ValueError("Invalid PTY size")
    if f'{{"cols":{cols},"rows":{rows}}}\n'.encode() != bytes(data):
        raise ValueError("Noncanonical PTY request")
    return cols, rows


def _peer_uid(conn: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Linux peer credentials are required")
    credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def _set_size(fd: int, cols: int, rows: int):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _drop(uid: int, gid: int):
    # The broker starts as this identity; no root/capability transition is
    # needed in the child or the handler after handing over the PTY.
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
        raise PermissionError("PTY broker has the wrong identity")


def _enable_subreaper() -> bool:
    try:
        # Escaped background children are reparented to this session handler.
        return ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    except (AttributeError, OSError):
        return False


def _proc_snapshot() -> dict[int, tuple[int, int]]:
    snapshot = {}
    try:
        paths = list(Path("/proc").iterdir())
    except OSError:
        return snapshot
    for path in paths:
        if not path.name.isdecimal():
            continue
        try:
            tail = (path / "stat").read_text().rsplit(")", 1)[1].split()
            snapshot[int(path.name)] = int(tail[1]), int(tail[19])
        except (OSError, ValueError, IndexError):
            continue
    return snapshot


def _descendants(shell_pid: int) -> dict[int, int]:
    snapshot = _proc_snapshot()
    handler_pid = os.getpid()
    # With PR_SET_CHILD_SUBREAPER, detached children join the direct set after
    # their parent exits. A handler owns exactly one terminal session.
    frontier = {pid for pid, (ppid, _) in snapshot.items() if ppid == handler_pid}
    if snapshot.get(shell_pid, (None, None))[0] == handler_pid:
        frontier.add(shell_pid)
    result = {}
    while frontier:
        result.update({pid: snapshot[pid][1] for pid in frontier if pid in snapshot})
        frontier = {pid for pid, (ppid, _) in snapshot.items()
                    if ppid in frontier and pid not in result}
    return result


def _process_starttime(pid: int) -> int | None:
    try:
        tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return int(tail[19])
    except (OSError, ValueError, IndexError):
        return None


def _signal_observed(observed: dict[int, int], signum: int):
    for pid, starttime in observed.items():
        if _process_starttime(pid) != starttime:
            continue
        try:
            os.kill(pid, signum)
        except (ProcessLookupError, PermissionError):
            pass


def _terminate_shell(pid: int, observed: dict[int, int], reaped: bool):
    observed.update(_descendants(pid))
    if not reaped:
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
    _signal_observed(observed, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        observed.update(_descendants(pid))
        current = _proc_snapshot()
        if not any(current.get(child, (None, None))[1] == start
                   for child, start in observed.items()):
            break
        time.sleep(0.05)
    observed.update(_descendants(pid))
    if not reaped:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    _signal_observed(observed, signal.SIGKILL)
    # Never block the broker handler on an uninterruptible task.
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if not child:
            break


def handle_connection(conn: socket.socket, expected_uid: int, shell_uid: int,
                      shell_gid: int, shell_home: str,
                      shell_name: str = "sovagrid-shell"):
    """Serve one connection in a forked handler process."""
    if _peer_uid(conn) != expected_uid:
        conn.close()
        return
    try:
        cols, rows = _request(conn)
    except (OSError, ValueError):
        conn.close()
        return
    pid = None
    master = None
    observed = {}
    reaped = False
    try:
        if sys.platform == "linux" and not _enable_subreaper():
            raise RuntimeError("PTY handler cannot track descendants")
        pid, master = os.forkpty()
        if pid == 0:
            stage = "close"
            try:
                conn.close()
                stage = "drop"
                _drop(shell_uid, shell_gid)
                stage = "chdir"
                os.chdir(shell_home)
                stage = "exec"
                os.execve("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "-i"],
                          {"HOME": shell_home, "USER": shell_name,
                           "LOGNAME": shell_name, "SHELL": "/bin/bash",
                           "TERM": "xterm-256color", "PATH": "/usr/local/bin:/usr/bin:/bin",
                           "LANG": "C.UTF-8"})
            except Exception as exc:
                try:
                    os.write(2, ("SovaGrid PTY shell startup failed: "
                                 + stage + "/" + type(exc).__name__ + "\r\n").encode("ascii"))
                except OSError:
                    pass
                os._exit(127)
        _set_size(master, cols, rows)
        conn.sendmsg([b"OK\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array("i", [master]))])
        os.close(master)
        master = None
        _drop(shell_uid, shell_gid)
        conn.settimeout(None)
        deadline = time.monotonic() + 30 * 60
        while True:
            observed.update(_descendants(pid))
            try:
                waited, _status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True
                break
            if waited:
                reaped = True
                break
            if time.monotonic() >= deadline:
                break
            readable, _, _ = select.select([conn], [], [], 0.5)
            if readable:
                # The fd handoff is the entire protocol; any further bytes or
                # EOF mean that the Agent has closed the terminal.
                break
    finally:
        if master is not None:
            os.close(master)
        if pid and pid > 0:
            _terminate_shell(pid, observed, reaped)
        conn.close()


def serve_activated(profile: str = "standard"):
    if profile not in PROFILES:
        raise RuntimeError("Unknown PTY broker profile")
    socket_path, agent_name, shell_name, shell_home = PROFILES[profile]
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("PTY broker requires one systemd socket")
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.getsockname() != socket_path:
        raise RuntimeError("Unexpected PTY broker socket")
    agent = pwd.getpwnam(agent_name)
    shell = pwd.getpwnam(shell_name)
    if agent.pw_uid == shell.pw_uid or agent.pw_gid == shell.pw_gid or shell.pw_uid == 0:
        raise RuntimeError("PTY shell identity must be separate from Agent")
    _drop(shell.pw_uid, shell.pw_gid)
    if any(group != shell.pw_gid for group in os.getgroups()):
        raise PermissionError("PTY broker has an unexpected supplementary group")
    if not os.path.isdir(shell_home):
        raise RuntimeError("PTY shell home is missing")
    children: set[int] = set()

    def reap(_signum, _frame):
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break
            children.discard(pid)

    signal.signal(signal.SIGCHLD, reap)
    while True:
        conn, _ = listener.accept()
        reap(None, None)
        if len(children) >= MAX_HANDLERS:
            conn.close()
            continue
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
        pid = os.fork()
        if pid == 0:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            listener.close()
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            try:
                handle_connection(conn, agent.pw_uid, shell.pw_uid, shell.pw_gid,
                                  shell_home, shell_name)
            except Exception as exc:
                # The class alone helps diagnose sandbox failures. Never log
                # shell input, PTY output, paths, or credentials.
                logging.error("PTY broker handler failed: %s", type(exc).__name__)
            os._exit(0)
        children.add(pid)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        conn.close()


if __name__ == "__main__":
    if sys.argv == [sys.argv[0]]:
        serve_activated("standard")
    elif sys.argv == [sys.argv[0], "--local"]:
        serve_activated("local")
    else:
        raise SystemExit("Usage: terminal_broker [--local]")
