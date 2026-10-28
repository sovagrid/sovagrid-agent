# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only, bounded UTC and time synchronization diagnostics on Linux."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import time


TIME_ZONE = re.compile(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+){0,4}\Z")
MAX_EPOCH = 253402300799  # 9999-12-31 UTC; protects JSON clients.
MAX_OFFSET = 2**31 - 1


def _time_status(run) -> tuple[bool | None, str | None, bool | None]:
    try:
        result = run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone",
                      "-p", "LocalRTC", "--no-pager"], capture_output=True, text=True,
                     timeout=2, env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None, None, None
    if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 512:
        return None, None, None
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator != "=" or key not in {"NTPSynchronized", "Timezone", "LocalRTC"} or key in fields:
            return None, None, None
        fields[key] = value
    sync = fields.get("NTPSynchronized")
    local_rtc = fields.get("LocalRTC")
    timezone = fields.get("Timezone")
    return (sync == "yes" if sync in {"yes", "no"} else None,
            timezone if isinstance(timezone, str) and len(timezone) <= 64 and TIME_ZONE.fullmatch(timezone) else None,
            local_rtc == "yes" if local_rtc in {"yes", "no"} else None)


def _rtc_utc_epoch(sys_root: str) -> int | None:
    try:
        with (Path(sys_root) / "class/rtc/rtc0/since_epoch").open("r", encoding="ascii") as stream:
            raw = stream.read(64).strip()
    except (OSError, UnicodeError):
        return None
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 12:
        return None
    value = int(raw)
    return value if 1 <= value <= MAX_EPOCH else None


def snapshot(*, sys_root: str = "/sys", run=subprocess.run, time_fn=time.time) -> dict:
    """Never change host time; unknown NTP/RTC values stay null, not false."""
    synchronized, timezone, rtc_local = _time_status(run)
    rtc = _rtc_utc_epoch(sys_root) if rtc_local is False else None
    system_epoch = int(time_fn())
    offset = rtc - system_epoch if rtc is not None else None
    if offset is not None and abs(offset) > MAX_OFFSET:
        rtc, offset = None, None
    return {"system_utc_epoch": system_epoch, "timezone": timezone,
            "ntp_synchronized": synchronized, "rtc_local_time": rtc_local,
            "rtc_utc_epoch": rtc, "rtc_offset_seconds": offset}
