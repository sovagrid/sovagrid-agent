# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Small, on-demand procfs pages. Never read argv, environment, or paths."""

from __future__ import annotations

import heapq
import json
import os
import time
from pathlib import Path

MARKER = "/usr/local/bin/sovagrid-process-inventory"
MAX_PAGE = 32
SCAN_WINDOW = 2048
MAX_PID = 2**31 - 1
MAX_RSS = 2**63 - 1


def _number(value: str, low: int, high: int) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ValueError("Invalid process inventory request")
    number = int(value)
    if not low <= number <= high or str(number) != value:
        raise ValueError("Invalid process inventory request")
    return number


def _filter(value: str) -> str:
    if value == "-":
        return ""
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid process inventory request") from exc
    if (not decoded or len(decoded) > 16 or len(decoded.encode("utf-8")) > 64
            or not decoded.isprintable() or decoded != decoded.strip()
            or decoded.encode("utf-8").hex() != value):
        raise ValueError("Invalid process inventory request")
    return decoded


def parse_request(command: str) -> tuple[int, int, str] | None:
    """Reject malformed marker requests so the shell cannot interpret them."""
    if not isinstance(command, str) or MARKER not in command:
        return None
    parts = command.split(" ")
    if len(parts) != 5 or parts[:2] != [MARKER, "list"] or command != " ".join(parts):
        raise ValueError("Invalid process inventory request")
    return _number(parts[2], 0, MAX_PID), _number(parts[3], 1, MAX_PAGE), _filter(parts[4])


def _read_process(path: Path, pid: int, page_size: int) -> dict | None:
    try:
        if path.is_symlink():
            return None
        with (path / "comm").open(encoding="utf-8", errors="replace") as stream:
            name = stream.read(65).rstrip("\n")
        if (not 1 <= len(name) <= 16 or len(name.encode("utf-8")) > 64
                or not name.isprintable()):
            return None
        with (path / "statm").open(encoding="ascii", errors="replace") as stream:
            fields = stream.read(128).split()
        if len(fields) < 2 or not fields[1].isascii() or not fields[1].isdecimal():
            return None
        rss = int(fields[1]) * page_size
        if not 0 <= rss <= MAX_RSS:
            return None
        return {"pid": pid, "name": name, "rss_bytes": rss}
    except (OSError, ValueError, UnicodeError):
        # /proc is live: a PID may exit or become inaccessible while scanned.
        return None


def snapshot(after_pid: int, limit: int, name_filter: str, *, proc_root: str = "/proc",
             page_size: int | None = None, monotonic=time.monotonic, clock=time.time) -> dict:
    if (type(after_pid) is not int or not 0 <= after_pid <= MAX_PID
            or type(limit) is not int or not 1 <= limit <= MAX_PAGE
            or not isinstance(name_filter, str) or len(name_filter) > 16
            or len(name_filter.encode("utf-8")) > 64 or
            (name_filter and (not name_filter.isprintable() or name_filter != name_filter.strip()))):
        raise ValueError("Invalid process inventory request")
    page_size = os.sysconf("SC_PAGE_SIZE") if page_size is None else page_size
    if type(page_size) is not int or not 1 <= page_size <= 2**20:
        raise ValueError("Invalid page size")
    deadline = monotonic() + 5

    def candidates():
        with os.scandir(proc_root) as entries:
            for entry in entries:
                if monotonic() >= deadline:
                    raise TimeoutError("Process inventory timed out")
                name = entry.name
                if not name.isascii() or not name.isdecimal():
                    continue
                pid = int(name)
                if after_pid < pid <= MAX_PID:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            yield pid, entry.path
                    except OSError:
                        continue

    # A bounded heap keeps memory fixed even when a host has many processes.
    selected = heapq.nsmallest(SCAN_WINDOW + 1, candidates(), key=lambda item: item[0])
    more_outside_window = len(selected) > SCAN_WINDOW
    rows = []
    cursor = after_pid
    consumed = 0
    for pid, raw_path in selected[:SCAN_WINDOW]:
        if monotonic() >= deadline:
            raise TimeoutError("Process inventory timed out")
        consumed += 1
        cursor = pid
        item = _read_process(Path(raw_path), pid, page_size)
        if item is not None and name_filter.casefold() in item["name"].casefold():
            rows.append(item)
            if len(rows) >= limit:
                break
    return {"observed_at": int(clock()), "after_pid": after_pid, "filter": name_filter,
            "next_after_pid": cursor,
            "has_more": consumed < min(len(selected), SCAN_WINDOW) or more_outside_window,
            "processes": rows}


def job_result(request: tuple[int, int, str], *, collector=snapshot) -> dict:
    try:
        output = json.dumps(collector(*request), ensure_ascii=False, separators=(",", ":"))
        if len(output.encode("utf-8")) > 8192:
            raise ValueError("Inventory output exceeds job limit")
    except TimeoutError:
        return {"state": "timed_out", "exit_code": None, "output": "Process inventory timed out"}
    except (OSError, ValueError, UnicodeError):
        return {"state": "failed", "exit_code": None, "output": "Process inventory unavailable"}
    return {"state": "succeeded", "exit_code": 0, "output": output}
