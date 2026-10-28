# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Outbound HTTPS relay between Hub terminal sessions and the local PTY broker."""

from __future__ import annotations

import array
import base64
import contextlib
import fcntl
import json
import logging
import os
import select
import socket
import struct
import termios
import threading
import time
import urllib.error
import uuid

from .terminal_broker import SOCKET_PATH


def _encoded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decoded(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 5462:
        raise ValueError("Invalid terminal frame")
    if any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        raise ValueError("Invalid terminal frame")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if (not 1 <= len(raw) <= 4096
            or _encoded(raw) != value):
        raise ValueError("Invalid terminal frame")
    return raw


def open_local_pty(cols: int, rows: int, socket_path: str = SOCKET_PATH) -> tuple[socket.socket, int]:
    if (type(cols) is not int or not 20 <= cols <= 300
            or type(rows) is not int or not 10 <= rows <= 120):
        raise ValueError("Invalid terminal size")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(5)
        conn.connect(socket_path)
        conn.sendall(json.dumps({"cols": cols, "rows": rows},
                                separators=(",", ":")).encode() + b"\n")
        response, ancillary, flags, _address = conn.recvmsg(16, socket.CMSG_SPACE(array.array("i").itemsize))
        descriptors = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
        if (response != b"OK\n" or len(descriptors) != 1
                or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)):
            for descriptor in descriptors:
                os.close(descriptor)
            raise OSError("PTY broker rejected the request")
        conn.settimeout(None)
        return conn, descriptors[0]
    except Exception:
        conn.close()
        raise


def _request_with_retry(client, method: str, path: str, payload: dict | None = None):
    deadline = time.monotonic() + 15
    while True:
        try:
            return client.request(method, path, payload)
        except urllib.error.HTTPError:
            raise
        except (OSError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def _control_loop(client, base: str, master: int, stop: threading.Event):
    after = 0
    while not stop.is_set():
        try:
            result = _request_with_retry(client, "GET", f"{base}/controls?after={after}")
            if result.get("state") == "closed":
                break
            for event in result.get("events", []):
                seq = event.get("seq")
                if type(seq) is not int or seq != after + 1:
                    raise ValueError("Invalid terminal control sequence")
                if event.get("type") == "input" and set(event) == {"seq", "type", "data"}:
                    data = _decoded(event["data"])
                    while data:
                        data = data[os.write(master, data):]
                elif event.get("type") == "resize" and set(event) == {"seq", "type", "cols", "rows"}:
                    cols, rows = event["cols"], event["rows"]
                    if (type(cols) is not int or not 20 <= cols <= 300
                            or type(rows) is not int or not 10 <= rows <= 120):
                        raise ValueError("Invalid terminal size")
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                else:
                    raise ValueError("Invalid terminal control event")
                after = seq
            if result.get("next_after") != after or result.get("state") not in ("active", "closed"):
                raise ValueError("Invalid terminal control response")
            if result["state"] == "closed":
                break
        except (OSError, ValueError, urllib.error.HTTPError):
            # An unavailable or untrusted Hub must not leave an unattended
            # remote shell running. The broker kills it when we close the fd.
            logging.warning("Terminal control channel ended")
            break
    stop.set()


def run_session(client, session: dict, socket_path: str = SOCKET_PATH):
    session_id = session.get("id")
    try:
        if not isinstance(session_id, str) or str(uuid.UUID(session_id)) != session_id:
            return
    except ValueError:
        return
    base = f"/api/v1/servers/{client.server_id}/terminal/sessions/{session_id}"
    conn = None
    master = None
    stop = threading.Event()
    control = None
    try:
        conn, master = open_local_pty(session["cols"], session["rows"], socket_path)
        client.request("POST", base + "/ready", {})
        control = threading.Thread(target=_control_loop, args=(client, base, master, stop),
                                   daemon=True, name="sovagrid-terminal-controls")
        control.start()
        sequence = 0
        broker_closed_at = None
        while not stop.is_set():
            readable, _, _ = select.select([master, conn], [], [], 0.5)
            if master in readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                sequence += 1
                _request_with_retry(client, "POST", base + "/output",
                                    {"seq": sequence, "data": _encoded(chunk)})
            if conn in readable:
                # The broker closes this socket when the shell exits. Drain
                # the PTY for a brief grace period before reporting exit.
                if broker_closed_at is None:
                    broker_closed_at = time.monotonic()
                if time.monotonic() - broker_closed_at >= 1:
                    break
    except (OSError, ValueError, KeyError, urllib.error.HTTPError):
        logging.warning("Terminal session ended")
    finally:
        stop.set()
        if master is not None:
            os.close(master)
        if conn is not None:
            conn.close()
        if control is not None:
            control.join(timeout=1)
        try:
            client.request("POST", base + "/exit", {"exit_code": None})
        except (OSError, urllib.error.HTTPError):
            pass


def terminal_loop(config: dict, client, quiescence=None):
    """A dedicated poller counts a fetched PTY until its session exits."""
    if not config.get("allow_remote_commands", False) or not config.get("allow_interactive_terminal", False):
        return
    while True:
        try:
            with (quiescence.operation("terminal") if quiescence is not None else contextlib.nullcontext()):
                response = client.request("GET", f"/api/v1/servers/{client.server_id}/terminal/next")
                session = response.get("session")
                if session is not None:
                    run_session(client, session, config.get("terminal_socket", SOCKET_PATH))
        except (OSError, ValueError, urllib.error.HTTPError):
            logging.warning("Terminal poll failed; retrying")
            time.sleep(5)
