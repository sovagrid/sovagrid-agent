# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reserve fixed helper children from the command subreaper's cleanup scans."""
import subprocess
import threading

_lock = threading.RLock()
_reserved = set()


def spawn(*args, **kwargs):
    # The scanner takes the same lock when obtaining exclusions; no child can
    # appear as a newly adopted command descendant before its registration.
    with _lock:
        proc = subprocess.Popen(*args, **kwargs)
        _reserved.add(proc.pid)
        return proc


def reserved():
    with _lock:
        return set(_reserved)


def release(proc):
    # Caller must wait/reap its own Popen before releasing ownership.
    with _lock:
        _reserved.discard(proc.pid)
