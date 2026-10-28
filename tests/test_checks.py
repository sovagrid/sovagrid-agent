# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local sockets only; generated test CA never enters the production helper."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import uuid
from unittest import mock

from sovagrid_agent.check_probe import (MAX_CA_DER, MAX_HEADERS, _read_status, probe, result,
                                       validate_definition, validate_result)
from sovagrid_agent.checks import (CheckWorkers, ChecksHubClient, ProbeRunner,
                                  validate_lease)


def definition(kind="http", **changes):
    value = {"id": str(uuid.uuid4()), "name": "Local test", "kind": kind,
             "enabled": True, "interval_seconds": 60, "timeout_seconds": 1}
    value.update({"url": "http://127.0.0.1/"} if kind == "http" else
                 {"host": "127.0.0.1", "port": 1} if kind == "tcp" else
                 {"host": "example.test", "record_type": "A", "expected_ip": None})
    value.update(changes)
    return value


def lease(check=None):
    check = check or definition()
    return {"id": str(uuid.uuid4()), "check_id": check["id"], "config_revision": 1,
            "expires_at": int(time.time()) + 90, "check": check}


class LocalServer:
    def __init__(self, handler, context=None):
        self.handler = handler
        self.context = context
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(4)
        self.listener.settimeout(0.05)
        self.requests = []
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.settimeout(2)
                if self.context:
                    conn = self.context.wrap_socket(conn, server_side=True)
                self.handler(self, conn)
            except (OSError, ssl.SSLError):
                pass  # Client intentionally closes untrusted/oversized responses.
            finally:
                conn.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stopped.set()
        self.listener.close()
        self.thread.join(3)
        if self.thread.is_alive():
            raise AssertionError("Fixture thread leaked")


def http_handler(status=200, headers=b"", body=b""):
    def handle(server, conn):
        raw = bytearray()
        while b"\r\n\r\n" not in raw and len(raw) < 4096:
            part = conn.recv(4096)
            if not part:
                return
            raw.extend(part)
        server.requests.append(bytes(raw))
        conn.sendall(f"HTTP/1.1 {status} Private reason\r\n".encode() + headers + b"\r\n" + body)
    return handle


class CheckValidationTests(unittest.TestCase):
    def test_tagged_definition_and_lease_fail_closed(self):
        for target in ("http://user:secret@localhost/", "http://localhost/?secret", "http://localhost/#x",
                       "file:///etc/passwd", "http://localhost/\r\nInjected:secret", "http://[::%25eth0]/",
                       "http://224.0.0.1/", "http://0.0.0.0/", "http://127.00.0.1/", "http://localhost:0/", "http://localhost:/",
                       "http://0x7f000001/", "http://0x7f.0.0.1/", "http://localhost../",
                       "http://[::1]trailing/", "http://[::1]trailing:80/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_definition(definition(url=target))
        for change in ({"timeout_seconds": True}, {"interval_seconds": 59}, {"enabled": 1},
                       {"extra": "secret"}, {"id": str(uuid.uuid4()).upper()}, {"name": "a\x00b"}, {"name": "\ud800"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_definition(definition(**change))
        for host in ("10.0.0.1", "127.0.0.1", "::1", "localhost", "home.lan"):
            validate_definition(definition("tcp", host=host))
        for change in ({"host": "127.0.0.1"}, {"record_type": "TXT"},
                       {"expected_ip": "2001:db8::1"}, {"expected_ip": "bad"},
                       {"expected_ip": "0.0.0.0"}, {"expected_ip": "224.0.0.1"}, {"port": 53}):
            with self.subTest(dns=change), self.assertRaises(ValueError):
                validate_definition(definition("dns", **change))
        valid = lease()
        self.assertEqual(validate_lease({"lease": valid}), valid)
        self.assertIsNone(validate_lease({"lease": None}))
        for change in ({"config_revision": True}, {"expires_at": 0}, {"expires_at": int(time.time()) - 301},
                       {"check_id": str(uuid.uuid4())}, {"extra": 1}, {"id": "bad"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_lease({"lease": dict(valid, **change)})

    def test_lease_uses_hub_time_with_bounded_local_clock_skew(self):
        hub_now = 1792926000
        item = lease()
        item["expires_at"] = hub_now + 90
        for skew in (-300, -120, 0, 120, 300):
            with self.subTest(skew=skew), mock.patch("sovagrid_agent.checks.time.time", return_value=hub_now + skew):
                self.assertEqual(validate_lease({"lease": item}), item)
        with mock.patch("sovagrid_agent.checks.time.time", return_value=hub_now):
            # A recently expired local timestamp may be current on the Hub;
            # the result transaction, not this wall clock, enforces its lease.
            self.assertEqual(validate_lease({"lease": dict(item, expires_at=hub_now - 1)})["expires_at"], hub_now - 1)
            for stamp in (hub_now - 301, hub_now + 391):
                with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                    validate_lease({"lease": dict(item, expires_at=stamp)})

    def test_result_types_and_semantics(self):
        good = result(time.monotonic(), http_status=200)
        validate_result(good, "http")
        for change in ({"observed_at": True}, {"latency_ms": float("nan")}, {"http_status": True},
                       {"tls_expires_at": "tomorrow"}, {"error_code": ["secret"]},
                       {"status": "down"}, {"http_status": 503}, {"extra": "remote text"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_result(dict(good, **change))
        with self.assertRaises(ValueError):
            validate_result(good, "tcp")
        with self.assertRaises(ValueError):
            validate_result(dict(good, status="down", error_code="connect_error", http_status=None), "dns")

    def test_dns_probe_uses_selected_family_and_returns_no_addresses(self):
        calls = []
        def resolver(host, port, **options):
            calls.append((host, port, options))
            family = options["family"]
            address = "203.0.113.7" if family == socket.AF_INET else "2001:db8::7"
            endpoint = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", endpoint)]
        for kind, expected, family in (("A", "203.0.113.7", socket.AF_INET),
                                       ("AAAA", "2001:db8::7", socket.AF_INET6)):
            check = definition("dns", record_type=kind, expected_ip=expected)
            self.assertEqual(probe(check, resolver=resolver)["status"], "up")
            self.assertEqual(calls[-1][2]["family"], family)
            mismatch = probe(dict(check, expected_ip="203.0.113.8" if kind == "A" else "2001:db8::8"), resolver=resolver)
            self.assertEqual(mismatch["error_code"], "dns_mismatch")
            self.assertNotIn(expected, json.dumps(mismatch))
        self.assertEqual(probe(definition("dns"), resolver=resolver)["status"], "up")
        self.assertEqual(probe(definition("dns"), resolver=lambda *a, **k: [])["error_code"], "dns_error")
        self.assertEqual(probe(definition("dns"), resolver=lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("224.0.0.1", 0))])["error_code"], "dns_error")

    def test_dns_subprocess_with_system_resolver_has_no_answer_in_output(self):
        answer = ProbeRunner().run(definition("dns", host="localhost", expected_ip="127.0.0.1"))
        self.assertEqual(answer["status"], "up")
        self.assertNotIn("127.0.0.1", json.dumps(answer))

    def test_checks_hub_client_bounds_response_and_types_protocol(self):
        calls = []
        def opener(request, **kwargs):
            calls.append((request, kwargs))
            return contextlib.closing(io.BytesIO(b'{"lease":null}'))
        client = ChecksHubClient({"hub_url": "https://hub.example", "server_id": "server-A"}, "private-token", opener=opener)
        self.assertIsNone(client.claim())
        req, options = calls[0]
        self.assertEqual(req.full_url, "https://hub.example/api/v1/servers/server-A/checks/claim")
        self.assertEqual(json.loads(req.data), {"protocol": 1})
        self.assertEqual(options["timeout"], 5)
        for raw in (b"x" * 4097, b'{"lease":null,"lease":null}'):
            client.opener = lambda *a, **k: contextlib.closing(io.BytesIO(raw))
            with self.assertRaises(ValueError):
                client.claim()
        sent = []
        client.request = lambda method, path, payload: sent.append((method, path, payload))
        item = lease()
        client.send_check_result(item, result(time.monotonic(), http_status=200))
        self.assertEqual(sent[0][2]["lease_id"], item["id"])
        self.assertEqual(sent[0][2]["config_revision"], 1)
        self.assertEqual(set(sent[0][2]), {"lease_id", "config_revision", "observed_at", "status", "latency_ms", "http_status", "tls_expires_at", "error_code"})


class ProbeTests(unittest.TestCase):
    def test_real_http_success_failure_redirect_and_no_sensitive_text(self):
        for status in (200, 204, 302, 503):
            with self.subTest(status=status), LocalServer(http_handler(status, b"Location: http://secret.example/\r\nSet-Cookie: secret\r\n")) as server:
                check = definition(url=f"http://127.0.0.1:{server.port}/check")
                answer = ProbeRunner().run(check)
                self.assertEqual(answer["http_status"], status)
                self.assertEqual(answer["status"], "up" if status < 300 else "down")
                self.assertEqual(answer["error_code"], None if status < 300 else "http_error")
                self.assertEqual(len(server.requests), 1)
                self.assertNotIn("secret", json.dumps(answer))
                request = server.requests[0]
                self.assertIn(b"GET /check HTTP/1.1\r\n", request)
                for forbidden in (b"Authorization", b"Cookie", b"private-token"):
                    self.assertNotIn(forbidden, request)

    def test_never_waits_for_body_and_parser_never_reads_a_body_byte(self):
        def handle(server, conn):
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n")
            server.stopped.wait(2)
        with LocalServer(handle) as server:
            started = time.monotonic()
            answer = ProbeRunner().run(definition(url=f"http://127.0.0.1:{server.port}/"))
            self.assertEqual(answer["status"], "up")
            self.assertLess(time.monotonic() - started, 0.9)
        class Trap:
            def __init__(self):
                self.data = bytearray(b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n")
            def settimeout(self, seconds):
                pass
            def recv(self, size):
                self.assert_size = size
                if not self.data:
                    raise AssertionError("Body read")
                value = bytes(self.data[:size]); del self.data[:size]
                return value
        trap = Trap()
        self.assertEqual(_read_status(trap, time.monotonic() + 1), 200)
        self.assertEqual(trap.assert_size, 1)
        self.assertFalse(trap.data)

    def test_header_total_limit_includes_all_headers_and_interim_responses(self):
        headers = b"X-Remote-Secret: " + b"s" * (MAX_HEADERS + 100) + b"\r\n"
        with LocalServer(http_handler(200, headers)) as server:
            answer = ProbeRunner().run(definition(url=f"http://127.0.0.1:{server.port}/"))
            self.assertEqual(answer["error_code"], "invalid_response")
            self.assertNotIn("ssss", json.dumps(answer))
        raw = (b"HTTP/1.1 100 Continue\r\nX: " + b"s" * 4000 + b"\r\n\r\n") * 9
        fake = mock.Mock()
        stream = io.BytesIO(raw)
        fake.recv.side_effect = lambda size: stream.read(size)
        with self.assertRaises(ValueError):
            _read_status(fake, time.monotonic() + 2)

    def test_real_tcp_connect_only_open_and_refused(self):
        received = []
        def handler(server, conn):
            received.append(conn.recv(1))
        with LocalServer(handler) as server:
            answer = ProbeRunner().run(definition("tcp", port=server.port))
            self.assertEqual(answer["status"], "up")
            limit = time.monotonic() + 1
            while not received and time.monotonic() < limit:
                time.sleep(0.01)
            self.assertEqual(received, [b""])
            port = server.port
        answer = ProbeRunner().run(definition("tcp", port=port))
        self.assertEqual(answer["error_code"], "connect_error")
        self.assertIsNone(answer["http_status"])

    def test_dns_errors_and_disallowed_answers_do_not_leak_or_connect(self):
        for addresses in ([(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", 80))],
                          [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("ff02::1", 80, 0, 0))]):
            with mock.patch("sovagrid_agent.check_probe.socket.socket") as sock:
                answer = probe(definition(), resolver=lambda *a, **k: addresses)
            sock.assert_not_called()
            self.assertEqual(answer["error_code"], "dns_error")
        def bad_dns(*a, **k):
            raise socket.gaierror("private resolver response")
        answer = probe(definition(), resolver=bad_dns)
        self.assertEqual(answer["error_code"], "dns_error")
        self.assertNotIn("private", json.dumps(answer))

    def test_stalled_headers_total_deadline_and_cancel_cleanup(self):
        def stalled(server, conn):
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            server.stopped.wait(3)
        with LocalServer(stalled) as server:
            check = definition(url=f"http://127.0.0.1:{server.port}/")
            started = time.monotonic()
            runner = ProbeRunner()
            answer = runner.run(check)
            self.assertEqual(answer["error_code"], "timeout")
            self.assertLess(time.monotonic() - started, 1.8)
            self.assertIsNone(runner._process)
            runner = ProbeRunner()
            output = []
            thread = threading.Thread(target=lambda: output.append(runner.run(check)))
            thread.start()
            limit = time.monotonic() + 1
            while runner._process is None and time.monotonic() < limit:
                time.sleep(0.01)
            proc = runner._process
            self.assertIsNotNone(proc)
            runner.cancel()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertIsNotNone(proc.poll())

    def test_child_deadline_covers_stalled_dns_and_caps_stdout_during_read(self):
        real_popen = subprocess.Popen
        procs = []
        for script, error in (("import time;time.sleep(30)", "timeout"),
                              ("import os,time;os.write(1,b'x'*1000000);time.sleep(30)", "internal_error")):
            def popen(argv, **options):
                # Production invocation remains fixed and token/environment free.
                self.assertEqual(argv[1], "-I")
                self.assertTrue(argv[2].endswith("/check_probe.py"))
                self.assertEqual(set(options["env"]), {"PATH", "LANG"})
                proc = real_popen([sys.executable, "-I", "-c", script], **options)
                procs.append(proc)
                return proc
            started = time.monotonic()
            with mock.patch("sovagrid_agent.checks.subprocess.Popen", side_effect=popen):
                answer = ProbeRunner().run(definition())
            self.assertEqual(answer["error_code"], error)
            self.assertLess(time.monotonic() - started, 1.8)
            self.assertIsNotNone(procs[-1].poll())

    def test_failed_reap_quarantines_slot_and_stops_workers(self):
        from sovagrid_agent import children
        from sovagrid_agent import checks
        real_spawn = children.spawn
        processes = []
        def spawn(*args, **kwargs):
            proc = real_spawn(*args, **kwargs)
            original_wait = proc.wait
            proc.wait = mock.Mock(side_effect=subprocess.TimeoutExpired("fixed-helper", 2))
            processes.append((proc, original_wait))
            return proc
        slots = mock.Mock()
        stop = threading.Event()
        runner = ProbeRunner()
        try:
            with mock.patch.object(checks, "_PROCESS_SLOTS", slots), mock.patch.object(children, "spawn", side_effect=spawn):
                with self.assertLogs(level="ERROR") as logs:
                    runner.run(definition("tcp"), stop)
                slots.release.assert_not_called()
            self.assertTrue(stop.is_set())
            self.assertTrue(runner._closed)
            self.assertIn("workers stopped", logs.output[0])
        finally:
            for proc, wait in processes:
                if proc.poll() is None:
                    proc.kill()
                wait(timeout=2)
                children.release(proc)

    def test_real_helper_dns_call_is_inside_process_deadline(self):
        real_popen = subprocess.Popen
        path = str(Path(__file__).resolve().parents[1])
        def popen(argv, **options):
            script = ("import sys,time;sys.path.insert(0," + repr(path) + ");"
                      "import sovagrid_agent.check_probe as p;"
                      "p.probe.__kwdefaults__['resolver']=lambda *a,**k:time.sleep(30);"
                      "sys.argv=['probe'," + repr(str(os.getpid())) + "];sys.exit(p.main())")
            return real_popen([sys.executable, "-I", "-c", script], **options)
        started = time.monotonic()
        with mock.patch("sovagrid_agent.checks.subprocess.Popen", side_effect=popen):
            answer = ProbeRunner().run(definition())
        self.assertEqual(answer["error_code"], "timeout")
        self.assertLess(time.monotonic() - started, 1.8)


class TLSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SovaGrid Local Test CA", "-keyout", "ca.key", "-out", "ca.pem",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der")
        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SovaGrid Unrelated CA", "-keyout", "other.key", "-out", "other.pem",
                "-addext", "basicConstraints=critical,CA:TRUE")
        openssl("x509", "-in", "other.pem", "-outform", "DER", "-out", "other.der")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "leaf.key", "-out", "leaf.csr")
        (cls.root / "ext.cnf").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
        openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", "1", "-days", "2", "-extfile", "ext.cnf", "-out", "good.pem")
        (cls.root / "index").touch()
        (cls.root / "serial").write_text("02\n")
        (cls.root / "ca.cnf").write_text("[ca]\ndefault_ca=test\n[test]\ndatabase=index\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\nserial=serial\ndefault_md=sha256\npolicy=policy\nx509_extensions=server\n[policy]\ncommonName=supplied\n[server]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
        openssl("ca", "-batch", "-config", "ca.cnf", "-in", "leaf.csr", "-out", "expired.pem",
                "-startdate", "20000101000000Z", "-enddate", "20010101000000Z")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def ca_b64(self, name="ca.der"):
        return base64.b64encode((self.root / name).read_bytes()).decode("ascii")

    def test_custom_ca_is_verified_by_real_helper_and_wrong_host_or_ca_fails(self):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(self.root / "good.pem"), str(self.root / "leaf.key"))
        with LocalServer(http_handler(200), server_context) as server:
            base = definition(url=f"https://localhost:{server.port}/", timeout_seconds=2,
                              ca_cert_der_b64=self.ca_b64())
            self.assertEqual(validate_lease({"lease": lease(base)})["check"], base)
            trusted = ProbeRunner().run(base)
            self.assertEqual(trusted["status"], "up")
            self.assertEqual(trusted["http_status"], 200)
            self.assertGreater(trusted["tls_expires_at"], int(time.time()))
            for check in (dict(base, ca_cert_der_b64=self.ca_b64("other.der")),
                          dict(base, url=f"https://127.0.0.1:{server.port}/"),
                          {key: value for key, value in base.items() if key != "ca_cert_der_b64"}):
                with self.subTest(check=check["url"], has_ca="ca_cert_der_b64" in check):
                    failed = ProbeRunner().run(check)
                    self.assertEqual(failed["error_code"], "tls_error")
                    self.assertIsNone(failed["tls_expires_at"])
                    self.assertNotIn("SovaGrid Local Test CA", json.dumps(failed))

    def test_custom_ca_rejects_malformed_noncanonical_and_wrong_kind(self):
        valid = self.ca_b64()
        self.assertLessEqual(len(base64.b64decode(valid)), MAX_CA_DER)
        rejected = (None, 1, "", "not base64!", valid + "\n", valid.rstrip("="),
                    base64.b64encode((self.root / "ca.der").read_bytes() + b"extra").decode(),
                    base64.b64encode(b"x" * (MAX_CA_DER + 1)).decode(),
                    base64.b64encode((self.root / "ca.key").read_bytes()).decode())
        for cert in rejected:
            with self.subTest(cert_type=type(cert).__name__, cert_len=len(cert) if isinstance(cert, str) else None):
                with self.assertRaises(ValueError):
                    validate_definition(definition(url="https://localhost/", ca_cert_der_b64=cert))
        for check in (definition(url="http://localhost/", ca_cert_der_b64=valid),
                      definition("tcp", ca_cert_der_b64=valid),
                      definition("dns", ca_cert_der_b64=valid)):
            with self.assertRaises(ValueError):
                validate_definition(check)

    def test_verified_tls_expiry_only_for_trusted_correct_hostname(self):
        for cert, host, trusted in (("good.pem", "localhost", True), ("good.pem", "127.0.0.1", True),
                                    ("expired.pem", "localhost", True), ("good.pem", "localhost", False)):
            with self.subTest(cert=cert, host=host, trusted=trusted):
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(str(self.root / cert), str(self.root / "leaf.key"))
                with LocalServer(http_handler(200), server_context) as server:
                    factory = (lambda: ssl.create_default_context(cafile=str(self.root / "ca.pem"))) if trusted else ssl.create_default_context
                    answer = probe(definition(url=f"https://{host}:{server.port}/", timeout_seconds=2), context_factory=factory)
                    good = trusted and host == "localhost" and cert == "good.pem"
                    self.assertEqual(answer["status"], "up" if good else "down")
                    if good:
                        self.assertGreater(answer["tls_expires_at"], int(time.time()))
                    else:
                        self.assertEqual(answer["error_code"], "tls_error")
                        self.assertIsNone(answer["tls_expires_at"])

    def test_tls_record_failure_after_verified_handshake_preserves_expiry(self):
        conn = mock.Mock()
        conn.getpeercert.return_value = {"notAfter": time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 86400))}
        conn.sendall.side_effect = ssl.SSLError("private remote failure")
        context = mock.Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        context.wrap_socket.return_value = conn
        with mock.patch("sovagrid_agent.check_probe._connect", return_value=conn):
            answer = probe(definition(url="https://localhost/"), context_factory=lambda: context)
        self.assertEqual(answer["error_code"], "invalid_response")
        self.assertGreater(answer["tls_expires_at"], int(time.time()))
        validate_result(answer, "http")
        self.assertNotIn("private", json.dumps(answer))

    def test_insecure_test_context_rejected(self):
        context = ssl._create_unverified_context()
        with LocalServer(http_handler()) as server:
            answer = probe(definition(url=f"https://localhost:{server.port}/"), context_factory=lambda: context)
        self.assertEqual(answer["error_code"], "tls_error")
        self.assertIsNone(answer["tls_expires_at"])


class WorkerTests(unittest.TestCase):
    def test_old_hub_backoff_and_empty_poll_do_not_spin(self):
        class Stop:
            def __init__(self):
                self.delay = None
            def is_set(self):
                return self.delay is not None
            def wait(self, delay):
                self.delay = delay
        for code, expected in ((404, 300), (405, 300), (401, 15), (409, 15), (503, 15), (None, 15)):
            with self.subTest(code=code):
                client = mock.Mock()
                if code:
                    client.claim.side_effect = urllib.error.HTTPError("https://secret.example", code, "private", {}, None)
                else:
                    client.claim.return_value = None
                workers = CheckWorkers({}, "token", client_factory=lambda *a: client)
                workers.stop_event = Stop()
                workers._loop(client, mock.Mock())
                self.assertEqual(workers.stop_event.delay, expected)
                self.assertEqual(client.claim.call_count, 1)

    def test_two_stalled_workers_do_not_block_metric_cycle_or_spawn_more(self):
        claimed = threading.Barrier(3)
        clients = []
        class Client:
            def __init__(self, *args):
                self.calls = 0
                clients.append(self)
            def claim(self):
                self.calls += 1
                return lease()
            def send_check_result(self, *args):
                raise AssertionError("Cancelled work must not publish")
        class Runner:
            def run(self, value, stop):
                claimed.wait(2)
                stop.wait(3)
                return None
            def cancel(self):
                pass
        workers = CheckWorkers({}, "token", client_factory=Client, runner_factory=Runner).start()
        try:
            claimed.wait(2)
            self.assertEqual(len(clients), 2)
            self.assertIsNot(clients[0], clients[1])
            self.assertEqual(len(workers.threads), 2)
            self.assertTrue(all(t.daemon for t in workers.threads))
            from sovagrid_agent.agent import run_once
            with mock.patch("sovagrid_agent.agent.collect", return_value={"collected_at": 1}):
                metric_client = mock.Mock()
                run_once({"allow_remote_commands": False}, metric_client)
                metric_client.push_metrics.assert_called_once_with({"collected_at": 1})
        finally:
            workers.stop()
        self.assertTrue(all(not t.is_alive() for t in workers.threads))
        self.assertTrue(all(c.calls == 1 for c in clients))

    def test_command_subreaper_never_kills_or_reaps_reserved_probe(self):
        from sovagrid_agent.agent import _command_processes, _reap_children
        parent = os.getpid()
        snapshot = {101: (parent, 1000), 102: (parent, 1001), 103: (101, 1002)}
        with mock.patch("sovagrid_agent.agent._proc_snapshot", return_value=snapshot), mock.patch(
                "sovagrid_agent.agent._reserved_children", return_value={102}), mock.patch(
                "sovagrid_agent.agent.os.waitpid", return_value=(101, 0)) as wait:
            tracked = _command_processes(101, set(), True)
            self.assertEqual(set(tracked), {101, 103})
            _reap_children()
            self.assertEqual(wait.call_args_list, [mock.call(101, os.WNOHANG)])

    def test_once_never_starts_workers_and_long_mode_stops_on_interrupt(self):
        from sovagrid_agent.__main__ import main
        config = {"token_file": "/test/token", "interval_seconds": 5}
        with mock.patch("sovagrid_agent.__main__.load_config", return_value=config), mock.patch(
                "sovagrid_agent.__main__.read_token", return_value="token"), mock.patch(
                "sovagrid_agent.__main__.HubClient"), mock.patch(
                "sovagrid_agent.__main__.CheckWorkers") as workers, mock.patch(
                "sovagrid_agent.__main__.run_once") as once:
            main(["--once"])
            workers.assert_not_called()
            once.assert_called_once()
            once.side_effect = KeyboardInterrupt
            main([])
            workers.return_value.start.return_value.stop.assert_called_once()

    @unittest.skipUnless(sys.platform == "linux", "Linux parent-death signal required")
    def test_linux_helper_dies_when_its_agent_parent_is_killed(self):
        package_root = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as temp:
            pidfile = Path(temp) / "pid"
            ready = Path(temp) / "dns-started"
            # The helper enters its real main/parent-death setup and then a
            # deliberately stalled resolver. No arbitrary fixture shell.
            child = (
                "import sys,time,os\nfrom pathlib import Path\n"
                f"sys.path.insert(0,{package_root!r})\n"
                "import sovagrid_agent.check_probe as p\n"
                "def stalled(*a,**k):\n"
                f" Path({str(ready)!r}).write_text('ready')\n"
                " time.sleep(30)\n"
                "p.probe.__kwdefaults__['resolver']=stalled\n"
                "sys.argv=['probe',str(os.getppid())]\n"
                "sys.exit(p.main())\n"
            )
            script = (
                "import sys,time,subprocess,json\nfrom pathlib import Path\n"
                f"c=subprocess.Popen([sys.executable,'-I','-c',{child!r}],stdin=subprocess.PIPE)\n"
                f"c.stdin.write({json.dumps(definition()).encode()!r});c.stdin.close()\n"
                f"Path({str(pidfile)!r}).write_text(str(c.pid))\n"
                "time.sleep(30)\n"
            )
            parent = subprocess.Popen([sys.executable, "-I", "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_pid = None
            try:
                until = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "Helper never entered DNS")
                child_pid = int(pidfile.read_text())
                parent.kill(); parent.wait(timeout=2)
                until = time.monotonic() + 3
                while time.monotonic() < until:
                    stat = Path(f"/proc/{child_pid}/stat")
                    if not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                        break
                    time.sleep(0.02)
                else:
                    self.fail("Helper survived Agent death")
            finally:
                if parent.poll() is None:
                    parent.kill(); parent.wait(timeout=2)
                if child_pid:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(child_pid, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
