# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Unprivileged Linux host metrics from procfs and statvfs."""

from __future__ import annotations

import os
import json
import math
import re
import subprocess
import time
from pathlib import Path

from .clock import snapshot as clock_snapshot
from .containers import read_agent_snapshot as container_snapshot

# Only call statvfs on filesystem types normally backed by local block or
# memory storage. Network and FUSE mounts can block the entire polling loop.
LOCAL_FS_TYPES = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs",
                  "vfat", "exfat", "ntfs3", "tmpfs"}
WATCHED_SERVICES = {"ssh.service", "sshd.service", "docker.service", "containerd.service",
                    "sovagrid-agent.service", "sovagrid-vpn-status.service",
                    "sovagrid-terminal-control.service"}
SERVICE_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,96}[.]service\Z")
PROCESS_NAME = re.compile(r"[A-Za-z0-9_.:+@-]{1,16}\Z")

def cpu_snapshot(proc_root: str = "/proc") -> tuple[int, int, int, int]:
    values = (Path(proc_root) / "stat").read_text().splitlines()[0].split()
    if values[0] != "cpu":
        raise ValueError("Unexpected /proc/stat format")
    ticks = [int(value) for value in values[1:]]
    if len(ticks) < 4 or any(value < 0 for value in ticks):
        raise ValueError("Unexpected /proc/stat CPU counters")
    idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
    # guest and guest_nice are already included in user and nice.
    return sum(ticks[:8]), idle, ticks[4] if len(ticks) > 4 else 0, ticks[7] if len(ticks) > 7 else 0


def cpu_percent(before: tuple[int, ...], after: tuple[int, ...]) -> float:
    total = after[0] - before[0]
    idle = after[1] - before[1]
    return round(max(0.0, min(100.0, 100.0 * (total - idle) / total)), 2) if total > 0 else 0.0


def cpu_times_percent(before: tuple[int, ...], after: tuple[int, ...]) -> dict | None:
    """Share of CPU time spent waiting for I/O or taken by the hypervisor."""
    if len(before) < 4 or len(after) < 4:
        return None
    total = after[0] - before[0]
    iowait = after[2] - before[2]
    steal = after[3] - before[3]
    if total <= 0 or iowait < 0 or steal < 0:
        return None
    return {"iowait_percent": round(min(100.0, 100.0 * iowait / total), 2),
            "steal_percent": round(min(100.0, 100.0 * steal / total), 2)}


_PRESSURE_MODES = {"cpu": ("some",), "memory": ("some", "full"), "io": ("some", "full")}
_PRESSURE_AVERAGES = ("avg10", "avg60", "avg300")


def pressure(proc_root: str = "/proc") -> dict | None:
    """Read a fixed set of PSI counters; malformed or absent files are omitted."""
    result = {}
    for resource, modes in _PRESSURE_MODES.items():
        try:
            with (Path(proc_root) / "pressure" / resource).open(encoding="ascii") as stream:
                raw = stream.read(513)
        except (OSError, UnicodeError):
            continue
        if len(raw) > 512:
            continue
        parsed = {}
        for line in raw.splitlines():
            parts = line.split()
            if not parts or parts[0] not in modes or parts[0] in parsed or len(parts) != 5:
                continue
            fields = dict(part.split("=", 1) for part in parts[1:] if part.count("=") == 1)
            if set(fields) != {*_PRESSURE_AVERAGES, "total"}:
                continue
            try:
                averages = {key: float(fields[key]) for key in _PRESSURE_AVERAGES}
                total = fields["total"]
                if (any(not math.isfinite(value) or not 0 <= value <= 100 for value in averages.values())
                        or not total.isascii() or not total.isdecimal() or int(total) > 2**63 - 1):
                    continue
                parsed[parts[0]] = {**averages, "total_us": int(total)}
            except ValueError:
                continue
        if set(parsed) == set(modes):
            result[resource] = {mode: parsed[mode] for mode in modes}
    return result or None


def memory_info(proc_root: str = "/proc") -> dict[str, int]:
    values = {}
    for line in (Path(proc_root) / "meminfo").read_text().splitlines():
        key, _, rest = line.partition(":")
        if rest:
            values[key] = int(rest.strip().split()[0]) * 1024
    return values


def memory(proc_root: str = "/proc") -> tuple[int, int, float]:
    values = memory_info(proc_root)
    total = values["MemTotal"]
    available = min(total, max(0, values.get("MemAvailable", values.get("MemFree", 0))))
    used_percent = round(100 * (1 - available / total), 2) if total else 0.0
    return total, available, max(0.0, min(100.0, used_percent))


def swap(proc_root: str = "/proc") -> dict | None:
    values = memory_info(proc_root)
    if "SwapTotal" not in values or "SwapFree" not in values:
        return None
    total = values["SwapTotal"]
    free = min(total, max(0, values["SwapFree"]))
    return {"total_bytes": total, "free_bytes": free,
            "used_percent": round(100 * (1 - free / total), 2) if total else 0.0}


def disk(path: str = "/") -> tuple[int, int, float]:
    stats = os.statvfs(path)
    total = stats.f_blocks * stats.f_frsize
    available = min(total, max(0, stats.f_bavail * stats.f_frsize))
    used_percent = round(100 * (1 - available / total), 2) if total else 0.0
    return total, available, max(0.0, min(100.0, used_percent))


def network_interfaces(proc_root: str = "/proc") -> list[dict]:
    items = []
    for line in (Path(proc_root) / "net" / "dev").read_text().splitlines()[2:]:
        if ":" not in line:
            continue
        interface, numbers = line.split(":", 1)
        name = interface.strip()
        if name == "lo" or not 1 <= len(name) <= 64 or not name.isprintable():
            continue
        fields = numbers.split()
        if len(fields) < 16:
            continue
        items.append({"name": name, "rx_bytes": int(fields[0]), "tx_bytes": int(fields[8]),
                      "rx_errors": int(fields[2]), "tx_errors": int(fields[10])})
        if len(items) >= 16:
            break
    return sorted(items, key=lambda item: item["name"])


def network(proc_root: str = "/proc") -> tuple[int, int]:
    items = network_interfaces(proc_root)
    return sum(item["rx_bytes"] for item in items), sum(item["tx_bytes"] for item in items)


def _unescape_mountpoint(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def mounts(proc_root: str = "/proc") -> list[tuple[str, str]]:
    mountinfo = Path(proc_root) / "self" / "mountinfo"
    if not mountinfo.exists():
        return []
    result = []
    for line in mountinfo.read_text(errors="replace").splitlines():
        left, divider, right = line.partition(" - ")
        if not divider:
            continue
        fields, rest = left.split(), right.split()
        if len(fields) < 5 or not rest:
            continue
        mountpoint = _unescape_mountpoint(fields[4])
        fstype = rest[0]
        result.append((mountpoint, fstype))
    return result


def local_mount_type(path: str, proc_root: str = "/proc") -> str | None:
    path = os.path.abspath(path)
    match = None
    for mountpoint, fstype in mounts(proc_root):
        if (path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")) and (match is None or len(mountpoint) >= len(match[0])):
            match = (mountpoint, fstype)
    if match is None:
        return None
    fstype = match[1]
    return fstype if fstype in LOCAL_FS_TYPES else None


def _filesystem_inventory(proc_root: str = "/proc") -> tuple[list[dict], bool]:
    items = []
    seen = set()
    truncated = False
    # Later mountinfo entries can cover earlier mounts at the same path.
    for mountpoint, fstype in reversed(mounts(proc_root)):
        if mountpoint in seen:
            continue
        seen.add(mountpoint)
        if fstype not in LOCAL_FS_TYPES or (fstype == "tmpfs" and mountpoint != "/"):
            continue
        if len(items) >= 16 and mountpoint != "/":
            truncated = True
            continue
        if not 1 <= len(mountpoint) <= 128 or not 1 <= len(fstype) <= 32 or not mountpoint.isprintable() or not fstype.isprintable():
            truncated = True
            continue
        try:
            stat = os.statvfs(mountpoint)
        except OSError:
            truncated = True
            continue
        total = stat.f_blocks * stat.f_frsize
        available = min(total, max(0, stat.f_bavail * stat.f_frsize))
        inodes_total = max(0, stat.f_files)
        inodes_available = min(inodes_total, max(0, stat.f_favail))
        items.append({
            "mountpoint": mountpoint, "fstype": fstype,
            "total_bytes": total, "available_bytes": available,
            "used_percent": round(100 * (1 - available / total), 2) if total else 0.0,
            "inodes_total": inodes_total, "inodes_available": inodes_available,
            "inodes_used_percent": round(100 * (1 - inodes_available / inodes_total), 2) if inodes_total else 0.0,
        })
    if len(items) > 16:
        truncated = True
    return sorted(items, key=lambda item: (item["mountpoint"] != "/", item["mountpoint"]))[:16], truncated


def filesystems(proc_root: str = "/proc") -> list[dict]:
    return _filesystem_inventory(proc_root)[0]


def processes(proc_root: str = "/proc") -> dict | None:
    values = {}
    for line in (Path(proc_root) / "stat").read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in ("procs_running", "procs_blocked"):
            values[fields[0]] = int(fields[1])
    if "procs_running" not in values or "procs_blocked" not in values:
        return None
    return {"running": values["procs_running"], "blocked": values["procs_blocked"]}


def top_processes(proc_root: str = "/proc", page_size: int | None = None) -> list[dict] | None:
    """Return a small RSS snapshot without reading cmdline, environ, or paths."""
    if page_size is None:
        page_size = os.sysconf("SC_PAGE_SIZE")
    try:
        entries = (Path(proc_root)).iterdir()
        items = []
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            if not 1 <= pid <= 2**31 - 1:
                continue
            try:
                if entry.is_symlink():
                    continue
                # Both procfs files are short, but bound reads for fixture or
                # unusual proc implementations as well.
                with (entry / "comm").open(encoding="utf-8", errors="replace") as stream:
                    name = stream.read(64).strip()
                if not PROCESS_NAME.fullmatch(name):
                    continue
                with (entry / "statm").open(encoding="ascii", errors="replace") as stream:
                    fields = stream.read(128).split()
                if len(fields) < 2 or not fields[1].isascii() or not fields[1].isdecimal():
                    continue
                resident_pages = int(fields[1])
                rss_bytes = resident_pages * page_size
                if not 0 < rss_bytes <= 2**63 - 1:
                    continue
            except (OSError, ValueError):
                # Processes may disappear or deny reads while /proc is scanned.
                continue
            items.append({"pid": pid, "name": name, "rss_bytes": rss_bytes})
    except OSError:
        return None
    return sorted(items, key=lambda item: (-item["rss_bytes"], item["pid"]))[:10]


def disk_io(sys_root: str = "/sys") -> list[dict]:
    block = Path(sys_root) / "block"
    if not block.exists():
        return []
    items = []
    for path in sorted(block.iterdir(), key=lambda item: item.name):
        if path.name.startswith(("loop", "ram", "fd", "sr")) or not 1 <= len(path.name) <= 64 or not path.name.isprintable():
            continue
        try:
            fields = [int(value) for value in (path / "stat").read_text().split()]
        except (OSError, ValueError):
            continue
        if len(fields) < 7:
            continue
        # Linux block stat sectors are expressed in 512-byte units.
        items.append({"device": path.name, "read_bytes": fields[2] * 512, "write_bytes": fields[6] * 512})
        if len(items) >= 16:
            break
    return items


def services(run=subprocess.run) -> dict | None:
    """Small, read-only systemd inventory; never block metric delivery on D-Bus."""
    try:
        result = run(["systemctl", "list-units", "--type=service", "--all", "--plain",
                      "--no-legend", "--no-pager"], capture_output=True, text=True,
                     timeout=3, env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or len(result.stdout) > 131072:
        return None
    selected = []
    failed_count = 0
    seen = set()
    for line in result.stdout.splitlines():
        fields = line.split(None, 4)
        if len(fields) < 4:
            continue
        name, load, active, sub = fields[:4]
        if not SERVICE_NAME.fullmatch(name) or name in seen:
            continue
        seen.add(name)
        if active == "failed":
            failed_count += 1
        if load != "loaded" or (active != "failed" and name not in WATCHED_SERVICES):
            continue
        if active not in {"active", "inactive", "failed", "activating", "deactivating"}:
            continue
        if not re.fullmatch(r"[a-z-]{1,32}", sub):
            continue
        selected.append({"name": name, "active": active, "sub": sub})
    selected.sort(key=lambda item: (item["active"] != "failed", item["name"]))
    return {"failed_count": failed_count, "units": selected[:16]}


def _trim_details(details: dict) -> None:
    """Keep Hub's bounded metrics payload while retaining completeness evidence."""
    while len(json.dumps(details, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 12000:
        for key in ("filesystems", "interfaces", "disk_io", "top_processes"):
            if details.get(key):
                details[key].pop()
                if key == "filesystems":
                    details["filesystems_truncated"] = True
                break
        else:
            engines = details.get("containers", {}).get("engines", [])
            fullest = max(engines, key=lambda item: len(item["containers"]), default=None)
            if fullest is not None and fullest["containers"]:
                fullest["containers"].pop()
                fullest["truncated"] = True
            else:
                details.pop("containers", None)
                break


def collect(sample_seconds: float = 0.25, proc_root: str = "/proc", disk_path: str = "/", sys_root: str = "/sys") -> dict:
    before = cpu_snapshot(proc_root)
    time.sleep(sample_seconds)
    after = cpu_snapshot(proc_root)
    memory_total, memory_available, memory_percent = memory(proc_root)
    disk_total, disk_available, disk_percent = disk(disk_path) if local_mount_type(disk_path, proc_root) else (0, 0, 0.0)
    interfaces = network_interfaces(proc_root)
    rx = sum(item["rx_bytes"] for item in interfaces)
    tx = sum(item["tx_bytes"] for item in interfaces)
    uptime = float((Path(proc_root) / "uptime").read_text().split()[0])
    load1, load5, load15 = os.getloadavg()
    filesystem_items, filesystems_truncated = _filesystem_inventory(proc_root)
    details = {"interfaces": interfaces, "filesystems": filesystem_items,
               "filesystems_truncated": filesystems_truncated,
               "load5": round(load5, 3), "load15": round(load15, 3),
               "clock": clock_snapshot(sys_root=sys_root)}
    cpu_times = cpu_times_percent(before, after)
    if cpu_times is not None:
        details["cpu_times"] = cpu_times
    pressure_info = pressure(proc_root)
    if pressure_info is not None:
        details["pressure"] = pressure_info
    swap_info = swap(proc_root)
    if swap_info is not None:
        details["swap"] = swap_info
    process_info = processes(proc_root)
    if process_info is not None:
        details["processes"] = process_info
    top = top_processes(proc_root)
    if top is not None:
        details["top_processes"] = top
    io_items = disk_io(sys_root)
    if io_items:
        details["disk_io"] = io_items
    service_info = services()
    if service_info is not None:
        details["services"] = service_info
    container_info = container_snapshot()
    if container_info is not None:
        details["containers"] = container_info
    _trim_details(details)
    return {
        "collected_at": int(time.time()),
        "cpu_percent": cpu_percent(before, after),
        "memory_percent": memory_percent,
        "disk_percent": disk_percent,
        "network_rx_bytes": rx,
        "network_tx_bytes": tx,
        "load1": round(load1, 3),
        "uptime_seconds": int(uptime),
        "memory_total_bytes": memory_total,
        "memory_available_bytes": memory_available,
        "disk_total_bytes": disk_total,
        "disk_available_bytes": disk_available,
        "details": details,
    }
