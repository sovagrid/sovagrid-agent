# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fail-closed Agent-side guard for an external-Agent update trial.

The root updater owns the server socket and trial epoch. A systemd drop-in
opts the new Agent into this guard. The Agent itself completes a live round
trip before it can create a Hub client, closing the ExecStartPre/ExecStart
handoff gap. The ordinary service has no trial environment and is unaffected.
"""

from __future__ import annotations

import os
import re
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Callable


SOCKET_PATH = "/run/sovagrid-external-agent-trial/gate.sock"
GATE_ENV = "SOVAGRID_EXTERNAL_TRIAL_GATE"
EPOCH_ENV = "SOVAGRID_EXTERNAL_TRIAL_EPOCH"
EPOCH = re.compile(r"[0-9a-f]{32}\Z")
ROUND_TRIP_SECONDS = 3.0
HEARTBEAT_SECONDS = 2.0
MAX_TRIAL_SECONDS = 900.0
MAX_LINE_BYTES = 96


def _line(connection: socket.socket, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < MAX_LINE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("External trial gate timed out")
        connection.settimeout(remaining)
        item = connection.recv(1)
        if not item:
            raise EOFError("External trial gate closed")
        result.extend(item)
        if item == b"\n":
            return bytes(result)
    raise ValueError("External trial gate line too large")


def _trusted_path(path: Path) -> None:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("External trial gate requires an unprivileged Linux Agent")
    directory = path.parent.lstat()
    endpoint = path.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            directory.st_gid != os.getegid() or stat.S_IMODE(directory.st_mode) != 0o710):
        raise RuntimeError("Unsafe external trial gate directory")
    if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or
            endpoint.st_gid != os.getegid() or endpoint.st_nlink != 1 or
            stat.S_IMODE(endpoint.st_mode) != 0o660):
        raise RuntimeError("Unsafe external trial gate socket")


def _trusted_peer(connection: socket.socket) -> None:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("External trial gate cannot authenticate its peer")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    if uid != 0 or pid <= 1:
        raise RuntimeError("External trial gate peer is not root")


class ExternalTrialGate:
    """Require a root supervisor until post-release dispatch is acknowledged.

    The supervisor must reply to each challenge within three seconds and must
    terminate its own lease at or before 900 seconds. The Agent independently
    exits after 900 seconds even if a faulty supervisor keeps replying. PROMOTE
    permits only another read-only Hub cycle. RELEASE after READY permits the
    same process to start normal dispatch; the watchdog remains fatal until
    the root supervisor acknowledges ACTIVE with DETACH.
    """

    def __init__(self, epoch: str, *, path: str = SOCKET_PATH,
                 fatal: Callable[[int], None] = os._exit) -> None:
        if EPOCH.fullmatch(epoch) is None:
            raise RuntimeError("Invalid external trial epoch")
        self.epoch = epoch
        self.path = Path(path)
        self._fatal = fatal
        self._connection: socket.socket | None = None
        self._watcher: threading.Thread | None = None
        self._stopping = threading.Event()
        self._started: float | None = None
        self.promotion_requested = threading.Event()
        self.promotion_ready = threading.Event()
        self.released = threading.Event()
        self.dispatch_ready = threading.Event()
        self.detached = threading.Event()
        self._transition = threading.Event()
        self._promotion_nonce: str | None = None

    def _challenge(self, sequence: int) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("External trial gate connection is unavailable")
        suffix = ""
        if self._promotion_nonce is not None:
            if self.dispatch_ready.is_set():
                suffix = f" ACTIVE {self._promotion_nonce}"
            elif self.promotion_ready.is_set():
                suffix = f" READY {self._promotion_nonce}"
        connection.sendall(f"PING {sequence}{suffix}\n".encode("ascii"))
        expected = f"PONG {sequence}\n".encode("ascii")
        response = _line(connection, time.monotonic() + ROUND_TRIP_SECONDS)
        if response == expected:
            return
        try:
            command, received_sequence, nonce = response.decode("ascii").strip().split(" ")
        except (UnicodeDecodeError, ValueError):
            raise RuntimeError("External trial gate challenge failed") from None
        if received_sequence != str(sequence) or EPOCH.fullmatch(nonce) is None:
            raise RuntimeError("External trial gate challenge failed")
        if command == "PROMOTE" and self._promotion_nonce is None and not self.released.is_set():
            self._promotion_nonce = nonce
            self.promotion_requested.set()
            self._transition.set()
            return
        if (command == "RELEASE" and self.promotion_ready.is_set() and
                not self.released.is_set() and nonce == self._promotion_nonce):
            connection.sendall(f"ACK RELEASE {nonce}\n".encode("ascii"))
            self.released.set()
            self._transition.set()
            return
        if (command == "DETACH" and self.released.is_set() and
                self.dispatch_ready.is_set() and not self.detached.is_set() and
                nonce == self._promotion_nonce):
            connection.sendall(f"ACK DETACH {nonce}\n".encode("ascii"))
            self.detached.set()
            self._stopping.set()
            self._transition.set()
            connection.close()
            self._connection = None
            return
        raise RuntimeError("External trial gate challenge failed")

    def mark_ready(self) -> None:
        """Report a successful post-PROMOTE, metrics-only Hub cycle."""
        if not self.promotion_requested.is_set() or self._promotion_nonce is None or \
                self.released.is_set() or self._stopping.is_set():
            raise RuntimeError("External trial promotion is unavailable")
        self.promotion_ready.set()
        self._transition.set()

    def mark_dispatch_ready(self) -> None:
        """Report that the same process started normal dispatch after RELEASE."""
        if (not self.released.is_set() or not self.promotion_ready.is_set() or
                self._promotion_nonce is None or self.detached.is_set() or
                self._stopping.is_set()):
            raise RuntimeError("External trial dispatch is unavailable")
        self.dispatch_ready.set()
        self._transition.set()

    def wait(self, timeout: float) -> None:
        """Wake the Agent's normal interval on a promotion or release."""
        self._transition.wait(timeout)
        self._transition.clear()

    def start(self) -> "ExternalTrialGate":
        _trusted_path(self.path)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(ROUND_TRIP_SECONDS)
            connection.connect(str(self.path))
            _trusted_peer(connection)
            connection.sendall(f"HELLO 1 {self.epoch}\n".encode("ascii"))
            expected = f"READY 1 {self.epoch}\n".encode("ascii")
            if _line(connection, time.monotonic() + ROUND_TRIP_SECONDS) != expected:
                raise RuntimeError("External trial gate epoch mismatch")
            self._connection = connection
            # A successful initial challenge is required before HubClient or
            # any network worker is created by the entry point.
            self._challenge(0)
        except BaseException:
            connection.close()
            self._connection = None
            raise
        self._started = time.monotonic()
        self._watcher = threading.Thread(target=self._watch, daemon=True,
                                         name="sovagrid-external-trial-watchdog")
        self._watcher.start()
        return self

    def _watch(self) -> None:
        sequence = 1
        while not self._stopping.wait(HEARTBEAT_SECONDS):
            try:
                if self._started is None or time.monotonic() - self._started >= MAX_TRIAL_SECONDS:
                    raise TimeoutError("External trial gate lifetime ended")
                self._challenge(sequence)
            except (OSError, TimeoutError, EOFError, ValueError, RuntimeError):
                if not self._stopping.is_set():
                    # systemd's default control-group kill policy then tears
                    # down helper children. A normal Python exception in this
                    # daemon thread would leave the Agent running unguarded.
                    self._stopping.set()
                    self._fatal(70)
                return
            sequence += 1

    def stop(self) -> None:
        self._stopping.set()
        connection = self._connection
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
            self._connection = None
        watcher = self._watcher
        if watcher is not None and watcher is not threading.current_thread():
            watcher.join(timeout=ROUND_TRIP_SECONDS + 0.5)


def from_environment() -> ExternalTrialGate | None:
    flag = os.environ.get(GATE_ENV)
    epoch = os.environ.get(EPOCH_ENV)
    if flag is None and epoch is None:
        return None
    if flag != "1" or epoch is None or EPOCH.fullmatch(epoch) is None:
        raise RuntimeError("Incomplete external Agent trial gate configuration")
    return ExternalTrialGate(epoch)
