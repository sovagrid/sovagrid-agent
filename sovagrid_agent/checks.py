# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Two independent, bounded outbound network-check workers."""
from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from .agent import HubClient
from . import children
from .check_probe import (MAX_INPUT, _integer, canonical_uuid, http_target, result, unique_object,
                          validate_definition, validate_result)

MAX_OUTPUT = 4096
_PROCESS_SLOTS = threading.BoundedSemaphore(2)
_LEASE_FIELDS = {"id", "check_id", "config_revision", "expires_at", "check"}


def validate_lease(response):
    if not isinstance(response, dict) or set(response) != {"lease"}:
        raise ValueError("Invalid claim")
    lease = response["lease"]
    if lease is None:
        return None
    if not isinstance(lease, dict) or set(lease) != _LEASE_FIELDS:
        raise ValueError("Invalid lease")
    canonical_uuid(lease["id"])
    canonical_uuid(lease["check_id"])
    check = validate_definition(lease["check"])
    now = int(time.time())
    if (check["id"] != lease["check_id"] or not check["enabled"]
            or not _integer(lease["config_revision"], 1, 2**63 - 1)
            or not _integer(lease["expires_at"], 1, 253402300799)
            # Lease expiry belongs to the Hub clock. Match its permitted
            # five-minute observation skew; target lifetime is independently
            # bounded by ProbeRunner's monotonic deadline. The Hub still
            # rejects expired leases transactionally when a result arrives.
            or not now - 300 <= lease["expires_at"] <= now + 390):
        raise ValueError("Invalid lease metadata")
    return dict(lease, check=check)


class ChecksHubClient(HubClient):
    """Dedicated opener, short network waits, and a hard response-body cap."""
    def request(self, method, path, payload=None):
        data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                        headers={"Authorization": f"Bearer {self.token}",
                                                 "Content-Type": "application/json"})
        with self.opener(request, timeout=5, context=self.context) as response:
            raw = response.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("Response limit")
        return json.loads(raw, object_pairs_hook=unique_object)

    def claim(self):
        return validate_lease(self.request("POST", f"/api/v1/servers/{self.server_id}/checks/claim", {"protocol": 1}))

    def send_check_result(self, lease, value):
        value = validate_result(value, lease["check"]["kind"])
        payload = dict(value, lease_id=lease["id"], config_revision=lease["config_revision"])
        return self.request("POST", f"/api/v1/servers/{self.server_id}/checks/{lease['check_id']}/result", payload)


class ProbeRunner:
    def __init__(self):
        self._lock = threading.Lock()
        self._process = None
        self._closed = False

    def cancel(self):
        with self._lock:
            self._closed = True
            if self._process is not None and self._process.poll() is None:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass

    def run(self, definition, stop=None):
        definition = validate_definition(definition)
        if not definition["enabled"]:
            raise ValueError("Disabled check")
        stop = stop or threading.Event()
        started = time.monotonic()
        deadline = started + definition["timeout_seconds"]
        with self._lock:
            if self._closed or stop.is_set():
                return None
        acquired = False
        while not stop.is_set() and time.monotonic() < deadline:
            if _PROCESS_SLOTS.acquire(timeout=min(0.05, max(0, deadline - time.monotonic()))):
                acquired = True
                break
        if not acquired:
            return None if stop.is_set() else result(started, "timeout")
        proc = selector = None
        output = bytearray()
        error = None
        try:
            public = json.dumps(definition, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(public) > MAX_INPUT:
                raise ValueError("Definition limit")
            # -I ignores Python environment/site customisations. No Hub URL,
            # bearer, config path, CA override or inherited proxy reaches the
            # fixed standard-library helper. Parent PID is public lifecycle data.
            proc = children.spawn(
                [sys.executable, "-I", str(Path(__file__).with_name("check_probe.py").resolve()), str(os.getpid())],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, close_fds=True, bufsize=0,
            )
            with self._lock:
                self._process = proc
                cancelled = self._closed or stop.is_set()
            if cancelled:
                return None
            # <=4 KiB fits an empty pipe without waiting for the child reader.
            proc.stdin.write(public)
            proc.stdin.close()
            os.set_blocking(proc.stdout.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                if stop.is_set():
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = "timeout"
                    break
                if selector.get_map():
                    for key, _ in selector.select(min(remaining, 0.05)):
                        chunk = os.read(key.fd, MAX_OUTPUT - len(output) + 1)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif len(output) + len(chunk) > MAX_OUTPUT:
                            error = "internal_error"
                            break
                        else:
                            output.extend(chunk)
                    if error:
                        break
                else:
                    if proc.poll() is not None:
                        break
                    stop.wait(min(remaining, 0.05))
            if error:
                return result(started, error)
            if proc.returncode != 0:
                return result(started, "internal_error")
            value = validate_result(json.loads(output, object_pairs_hook=unique_object), definition["kind"])
            if (definition["kind"] == "dns" and value["error_code"] == "dns_mismatch"
                    and definition["expected_ip"] is None):
                raise ValueError("Unexpected DNS mismatch")
            if definition["kind"] == "http":
                scheme, _, _, _ = http_target(definition["url"])
                if ((scheme != "https" and value["tls_expires_at"] is not None)
                        or (value["status"] == "up" and value["http_status"] is None)
                        or (scheme == "https" and value["status"] == "up" and value["tls_expires_at"] is None)):
                    raise ValueError("Wrong result kind")
            return value
        except (OSError, ValueError, TypeError):
            return result(started, "internal_error")
        finally:
            reaped = proc is None
            try:
                if selector is not None:
                    selector.close()
                if proc is not None:
                    try:
                        if proc.poll() is None:
                            with contextlib.suppress(ProcessLookupError):
                                proc.kill()
                        proc.wait(timeout=2)
                        reaped = True
                    except (OSError, subprocess.TimeoutExpired):
                        # A kernel-stalled child must not release a process
                        # slot and allow a third probe. Quarantine this runner
                        # and stop both workers; the service can be restarted.
                        stop.set()
                        logging.error("Network check helper cleanup failed; workers stopped")
                    finally:
                        if reaped:
                            children.release(proc)
                        for stream in (proc.stdin, proc.stdout):
                            if stream is not None:
                                with contextlib.suppress(OSError):
                                    stream.close()
            finally:
                with self._lock:
                    self._process = None if reaped else proc
                    if not reaped:
                        self._closed = True
                if reaped:
                    _PROCESS_SLOTS.release()



class CheckWorkers:
    """A fixed pair: no per-lease threads, queue, shell or metrics changes."""
    def __init__(self, config, token, *, client_factory=ChecksHubClient, runner_factory=ProbeRunner,
                 quiescence=None):
        self.stop_event = threading.Event()
        self.quiescence = quiescence
        self.clients = [client_factory(config, token) for _ in range(2)]
        self.runners = [runner_factory() for _ in range(2)]
        self.threads = [threading.Thread(target=self._loop, args=(client, runner), daemon=True,
                                         name=f"sovagrid-check-{i + 1}")
                        for i, (client, runner) in enumerate(zip(self.clients, self.runners))]

    def start(self):
        for thread in self.threads:
            thread.start()
        return self

    def stop(self):
        self.stop_event.set()
        for runner in self.runners:
            runner.cancel()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(timeout=6)

    def _loop(self, client, runner):
        failures = 0
        while not self.stop_event.is_set():
            delay = 15
            try:
                # Enter before the claim so an idle ACK cannot race a newly
                # acquired Hub lease. Hold through result delivery.
                admission = (self.quiescence.operation("check", block=False)
                             if self.quiescence is not None else contextlib.nullcontext(True))
                with admission as admitted:
                    if not admitted:
                        delay = 1
                    else:
                        lease = client.claim()
                        if self.stop_event.is_set():
                            return
                        if lease is not None:
                            value = runner.run(lease["check"], self.stop_event)
                            if value is not None and not self.stop_event.is_set():
                                client.send_check_result(lease, value)
                            # Keep polling even after work bounded and interruptible.
                            delay = 1
                failures = 0
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                if code in (404, 405):
                    delay = 300
                elif code == 409:
                    # An edit, token rotation or expired lease invalidates work.
                    delay = 15
                else:
                    failures += 1
                    delay = min(300, 15 * 2 ** min(failures - 1, 5))
            except Exception:
                # Never log exceptions containing a target or bearer/header.
                logging.warning("Network check cycle failed; retrying")
                failures += 1
                delay = min(300, 15 * 2 ** min(failures - 1, 5))
            self.stop_event.wait(delay)
