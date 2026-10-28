# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SovaGrid Agent command line."""

from __future__ import annotations

import argparse
import ctypes
import logging
import os
import sys
import threading
import time

from .agent import (AgentQuiescence, AgentQuiescenceServer, HubClient,
                    load_config, read_token, run_once)
from .terminal import terminal_loop
from .files import file_loop
from .checks import CheckWorkers
from .trial_gate import from_environment as external_trial_gate_from_environment


def _protect_agent_process() -> None:
    """Keep same-UID command children out of Agent memory and file descriptors."""
    if sys.platform != "linux":
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # Linux prctl(PR_SET_DUMPABLE, 0) blocks same-UID ptrace and procfs
        # memory/fd access. Verify it instead of trusting a zero return alone.
        if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
            raise OSError("Agent process is still dumpable")
    except (AttributeError, OSError) as exc:
        raise RuntimeError("Agent process hardening failed") from exc


def _run(args, *, trial_mode: bool = False) -> None:
    config = load_config(args.config)
    if trial_mode:
        # A trial Agent proves health only. In particular it must never claim
        # work during the short heartbeat gap after a root supervisor dies.
        config = {**config, "allow_remote_commands": False,
                  "allow_interactive_terminal": False,
                  "allow_file_manager": False,
                  "allow_systemd_journal": False}
    client = HubClient(config, read_token(config["token_file"]))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.once:
        run_once(config, client)
        return
    quiescence = AgentQuiescence()
    control = AgentQuiescenceServer(quiescence).start() if args.enable_quiescence else None
    if config.get("allow_remote_commands", False) and config.get("allow_interactive_terminal", False):
        if os.geteuid() == 0:
            raise PermissionError("Terminal poller must not run as root")
        threading.Thread(target=terminal_loop, args=(config, client, quiescence), daemon=True,
                         name="sovagrid-terminal-poller").start()
    if config.get("allow_remote_commands", False) and config.get("allow_file_manager", False):
        if os.geteuid() == 0:
            raise PermissionError("File poller must not run as root")
        threading.Thread(target=file_loop, args=(config, client, quiescence), daemon=True,
                         name="sovagrid-file-poller").start()
    checks = None if trial_mode else CheckWorkers(config, client.token,
                                                  quiescence=quiescence).start()
    try:
        failures = 0
        while True:
            started = time.monotonic()
            try:
                run_once(config, client, quiescence)
                failures = 0
            except KeyboardInterrupt:
                return
            except Exception:
                # Never log urllib errors: their repr may disclose request details.
                logging.error("Agent cycle failed; retrying")
                failures += 1
            interval = float(config.get("interval_seconds", 30))
            delay = min(300, interval * 2 ** min(failures, 4)) if failures else interval
            try:
                time.sleep(max(0, delay - (time.monotonic() - started)))
            except KeyboardInterrupt:
                return
    finally:
        if checks is not None:
            checks.stop()
        if control is not None:
            control.stop()


def main(argv=None):
    _protect_agent_process()
    parser = argparse.ArgumentParser(description="SovaGrid Ubuntu agent")
    parser.add_argument("--config", default="/etc/sovagrid/agent.json")
    parser.add_argument("--once", action="store_true", help="Collect and send one sample")
    parser.add_argument("--enable-quiescence", action="store_true",
                        help="Enable the local root-only update-idle channel")
    args = parser.parse_args(argv)
    gate = external_trial_gate_from_environment()
    if gate is not None:
        gate.start()
    try:
        _run(args, trial_mode=gate is not None)
    finally:
        if gate is not None:
            gate.stop()


if __name__ == "__main__":
    main()
