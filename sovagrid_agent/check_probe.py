# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed, credential-free one-shot network probe (also imported for validation).

The parent, not socket timeouts, bounds DNS and the entire subprocess lifetime.
This module never imports Agent configuration, sends application credentials,
reads a response body, follows redirects, or returns remote text.
"""
from __future__ import annotations

import base64
import binascii
import ctypes
import ipaddress
import json
import math
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import quote, urlsplit

MAX_INPUT = 4096
MAX_HEADERS = 32768
MAX_CA_DER = 1536
ERROR_CODES = frozenset(("dns_error", "connect_error", "tls_error", "timeout",
                         "http_error", "invalid_response", "internal_error", "dns_mismatch"))
_RESULT_FIELDS = frozenset(("observed_at", "status", "latency_ms", "http_status",
                            "tls_expires_at", "error_code"))
_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate field")
        value[key] = item
    return value


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid ID")
    return value


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate_host(value):
    if (not isinstance(value, str) or not value or len(value) > 253
            or not value.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value)
            or any(c in value for c in "/\\@%[]")):
        raise ValueError("Invalid host")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Do not let libc reinterpret noncanonical numeric IPv4 forms as DNS.
        if (":" in value or re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+))*", value)
                or not all(_DNS_LABEL.fullmatch(label) for label in value.removesuffix(".").split("."))):
            raise ValueError("Invalid host") from None
    else:
        if not _allowed_address(address):
            raise ValueError("Invalid address")
    return value


def validate_dns_target(host, record_type, expected_ip):
    validate_host(host)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("DNS target must be a hostname")
    if record_type not in ("A", "AAAA"):
        raise ValueError("Invalid DNS record type")
    if expected_ip is not None:
        if not isinstance(expected_ip, str):
            raise ValueError("Invalid expected DNS address")
        try:
            address = ipaddress.ip_address(expected_ip)
        except ValueError:
            raise ValueError("Invalid expected DNS address") from None
        if (address.version != (4 if record_type == "A" else 6) or "%" in expected_ip
                or not _allowed_address(address)):
            raise ValueError("Wrong expected DNS address family")
    return host


def _allowed_address(address):
    mapped = getattr(address, "ipv4_mapped", None)
    return not (address.is_unspecified or address.is_multicast
                or (mapped is not None and (mapped.is_unspecified or mapped.is_multicast)))


def http_target(url):
    if (not isinstance(url, str) or len(url.encode("utf-8")) > 1024
            or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in url)
            or any(c in url for c in "\\?#")):
        raise ValueError("Invalid URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid URL") from None
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or parsed.username is not None or parsed.password is not None or host is None
            or parsed.netloc.endswith(":")):
        raise ValueError("Invalid URL")
    validate_host(host)
    authority = f"[{host}]" if ":" in host else host
    if not re.fullmatch(re.escape(authority) + r"(?::[0-9]+)?", parsed.netloc, re.IGNORECASE):
        raise ValueError("Invalid authority")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return parsed.scheme, host, port or (443 if parsed.scheme == "https" else 80), parsed.path or "/"


def decode_ca_der(value):
    """Accept one canonical, bounded X.509 DER certificate as a trust anchor."""
    if not isinstance(value, str) or not value or len(value) > 4 * ((MAX_CA_DER + 2) // 3):
        raise ValueError("Invalid CA certificate")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid CA certificate") from None
    if not raw or len(raw) > MAX_CA_DER or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Invalid CA certificate")
    # Reject appended DER objects and nonminimal/indefinite lengths before
    # OpenSSL parses the trust anchor. A certificate is one outer SEQUENCE.
    if len(raw) < 4 or raw[0] != 0x30:
        raise ValueError("Invalid CA certificate")
    first = raw[1]
    if first < 0x80:
        header, length = 2, first
    elif 0x81 <= first <= 0x84:
        count = first - 0x80
        if len(raw) < 2 + count or raw[2] == 0 or (count == 1 and raw[2] < 0x80):
            raise ValueError("Invalid CA certificate")
        header, length = 2 + count, int.from_bytes(raw[2:2 + count], "big")
        if length < 0x80 or length.bit_length() <= 8 * (count - 1):
            raise ValueError("Invalid CA certificate")
    else:
        raise ValueError("Invalid CA certificate")
    if header + length != len(raw):
        raise ValueError("Invalid CA certificate")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(raw))
    except (ssl.SSLError, ValueError):
        raise ValueError("Invalid CA certificate") from None
    return raw


def validate_definition(value):
    common = {"id", "name", "kind", "enabled", "interval_seconds", "timeout_seconds"}
    if not isinstance(value, dict) or value.get("kind") not in ("http", "tcp", "dns"):
        raise ValueError("Invalid definition")
    expected = common | ({"url"} if value["kind"] == "http" else
                         {"host", "port"} if value["kind"] == "tcp" else
                         {"host", "record_type", "expected_ip"})
    if value["kind"] == "http" and "ca_cert_der_b64" in value:
        expected.add("ca_cert_der_b64")
    if set(value) != expected:
        raise ValueError("Invalid fields")
    canonical_uuid(value["id"])
    name = value["name"]
    if (not isinstance(name, str) or not 1 <= len(name) <= 80 or name != name.strip()
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in name)):
        raise ValueError("Invalid name")
    if (type(value["enabled"]) is not bool
            or not _integer(value["interval_seconds"], 60, 3600)
            or not _integer(value["timeout_seconds"], 1, 10)):
        raise ValueError("Invalid schedule")
    if value["kind"] == "http":
        scheme, _, _, _ = http_target(value["url"])
        if "ca_cert_der_b64" in value:
            if scheme != "https":
                raise ValueError("CA requires HTTPS")
            decode_ca_der(value["ca_cert_der_b64"])
    elif value["kind"] == "tcp":
        validate_host(value["host"])
        if not _integer(value["port"], 1, 65535):
            raise ValueError("Invalid port")
    else:
        validate_dns_target(value["host"], value["record_type"], value["expected_ip"])
    return dict(value)


def validate_result(value, kind=None):
    if not isinstance(value, dict) or set(value) != _RESULT_FIELDS:
        raise ValueError("Invalid result")
    if (not _integer(value["observed_at"], 1, 253402300799)
            or not _integer(value["latency_ms"], 0, 10000)
            or value["status"] not in ("up", "down")
            or (value["http_status"] is not None and not _integer(value["http_status"], 100, 599))
            or (value["tls_expires_at"] is not None and not _integer(value["tls_expires_at"], 1, 253402300799))
            or (value["error_code"] is not None and (not isinstance(value["error_code"], str) or value["error_code"] not in ERROR_CODES))):
        raise ValueError("Invalid result types")
    code = value["error_code"]
    if ((value["status"] == "up") != (code is None)
            or (code == "http_error" and (value["http_status"] is None or 200 <= value["http_status"] < 300))
            or (value["status"] == "up" and value["http_status"] is not None
                and not 200 <= value["http_status"] < 300)
            or (code in ("dns_error", "connect_error", "tls_error") and value["http_status"] is not None)
            or (code == "tls_error" and value["tls_expires_at"] is not None)
            or (kind in ("tcp", "dns") and (value["http_status"] is not None or value["tls_expires_at"] is not None))
            or (kind == "dns" and code in ("http_error", "tls_error", "connect_error"))
            or (kind != "dns" and code == "dns_mismatch")):
        raise ValueError("Inconsistent result")
    return dict(value)


def result(started, error=None, http_status=None, tls_expires_at=None):
    return {"observed_at": int(time.time()), "status": "down" if error else "up",
            "latency_ms": min(10000, max(0, int((time.monotonic() - started) * 1000))),
            "http_status": http_status, "tls_expires_at": tls_expires_at, "error_code": error}


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _connect(host, port, deadline, resolver):
    addresses = resolver(host, port, family=socket.AF_UNSPEC,
                         type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not addresses:
        raise socket.gaierror
    # Validate the complete answer before connecting; local/private are opt-in
    # valid targets, but unspecified/multicast are never connectivity checks.
    for family, _, _, _, endpoint in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6) or not _allowed_address(ipaddress.ip_address(endpoint[0])):
            raise socket.gaierror
    last_timeout = False
    for family, socktype, proto, _, endpoint in addresses:
        conn = socket.socket(family, socktype, proto)
        try:
            conn.settimeout(_remaining(deadline))
            conn.connect(endpoint)
            return conn
        except (TimeoutError, OSError) as exc:
            conn.close()
            last_timeout = isinstance(exc, TimeoutError)
    if last_timeout or time.monotonic() >= deadline:
        raise TimeoutError
    raise ConnectionError


def _resolve_dns(value, resolver):
    family = socket.AF_INET if value["record_type"] == "A" else socket.AF_INET6
    addresses = resolver(value["host"], None, family=family,
                         type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not addresses:
        raise socket.gaierror
    answer = set()
    for returned_family, _, _, _, endpoint in addresses:
        if returned_family != family or not isinstance(endpoint, tuple) or not endpoint:
            raise socket.gaierror
        try:
            address = ipaddress.ip_address(endpoint[0])
        except ValueError:
            raise socket.gaierror from None
        if address.version != (4 if family == socket.AF_INET else 6) or not _allowed_address(address):
            raise socket.gaierror
        answer.add(address)
    if not answer:
        raise socket.gaierror
    expected = value["expected_ip"]
    return expected is None or ipaddress.ip_address(expected) in answer


def _read_status(conn, deadline):
    # One byte per recv prevents even a single response-body byte being read.
    # Total includes status line, every interim response, and the final CRLF.
    total = 0
    interim = 0
    while True:
        lines = []
        line = bytearray()
        while True:
            if total >= MAX_HEADERS:
                raise ValueError("Headers limit")
            conn.settimeout(_remaining(deadline))
            byte = conn.recv(1)
            if not byte:
                raise ValueError("Incomplete headers")
            total += 1
            line.extend(byte)
            if byte == b"\n":
                if not line.endswith(b"\r\n"):
                    raise ValueError("Invalid newline")
                raw = bytes(line[:-2]); line.clear()
                if not raw:
                    break
                lines.append(raw)
        if not lines or not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e\x80-\xff]*)?", lines[0]):
            raise ValueError("Invalid status")
        for header in lines[1:]:
            if (not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*", header)):
                raise ValueError("Invalid header")
        status = int(lines[0][9:12])
        if status >= 200 or status == 101:
            return status
        interim += 1
        if interim > 8:
            raise ValueError("Interim limit")


def probe(value, *, resolver=socket.getaddrinfo, context_factory=ssl.create_default_context):
    value = validate_definition(value)
    started = time.monotonic()
    deadline = started + value["timeout_seconds"]
    http_status = tls_expires_at = None
    conn = None
    stage = "dns"
    try:
        if value["kind"] == "dns":
            # The parent process bounds libc resolver time, including a
            # blocked resolver. No answer addresses leave this child.
            return result(started, None if _resolve_dns(value, resolver) else "dns_mismatch")
        if value["kind"] == "http":
            scheme, host, port, path = http_target(value["url"])
        else:
            host, port = value["host"], value["port"]
        # The parent deadline includes getaddrinfo even when libc blocks here.
        conn = _connect(host, port, deadline, resolver)
        stage = "connect"
        if value["kind"] == "http":
            if scheme == "https":
                stage = "tls"
                context = context_factory()
                if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                    raise ssl.SSLError("Unverified context")
                if "ca_cert_der_b64" in value:
                    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(
                        decode_ca_der(value["ca_cert_der_b64"])))
                conn.settimeout(_remaining(deadline))
                conn = context.wrap_socket(conn, server_hostname=host)
                expiry = conn.getpeercert().get("notAfter")
                if not expiry:
                    raise ssl.SSLError("Missing verified expiry")
                stamp = ssl.cert_time_to_seconds(expiry)
                if not math.isfinite(stamp) or not 1 <= stamp <= 253402300799:
                    raise ssl.SSLError("Invalid verified expiry")
                tls_expires_at = int(stamp)
            stage = "http"
            host_header = f"[{host}]" if ":" in host else host
            if port != (443 if scheme == "https" else 80):
                host_header += f":{port}"
            target = quote(path, safe="/%:@!$&'()*+,;=-._~")
            request = f"GET {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nUser-Agent: SovaGrid-Check/1\r\n\r\n"
            conn.settimeout(_remaining(deadline))
            conn.sendall(request.encode("ascii"))
            http_status = _read_status(conn, deadline)
            if not 200 <= http_status < 300:
                return result(started, "http_error", http_status, tls_expires_at)
        return result(started, http_status=http_status, tls_expires_at=tls_expires_at)
    except (TimeoutError, socket.timeout):
        error = "timeout"
    except socket.gaierror:
        error = "dns_error"
    except ssl.SSLError:
        # A TLS record failure after a verified handshake is an incomplete
        # HTTP response; retain its verified certificate expiry consistently.
        error = "invalid_response" if stage == "http" else "tls_error"
        if error == "tls_error":
            tls_expires_at = None
    except (ValueError, UnicodeError):
        error = "invalid_response"
    except OSError:
        error = "connect_error" if stage in ("dns", "connect") else "tls_error" if stage == "tls" else "invalid_response"
    except Exception:
        error = "internal_error"
    finally:
        if conn is not None:
            conn.close()
    return result(started, error, http_status, tls_expires_at)


def _arm_parent_death(expected_pid):
    if sys.platform == "linux":
        # Called inside the freshly exec'd process, never preexec_fn in a
        # multithreaded Agent. Checking again closes the prctl setup race.
        if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError("Parent death setup failed")
    if os.getppid() != expected_pid:
        raise OSError("Parent unavailable")


def main():
    try:
        if len(sys.argv) != 2 or not sys.argv[1].isascii() or not sys.argv[1].isdecimal():
            return 1
        _arm_parent_death(int(sys.argv[1]))
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            return 1
        value = validate_definition(json.loads(raw, object_pairs_hook=unique_object))
        if not value["enabled"]:
            return 1
        output = probe(value)
        sys.stdout.write(json.dumps(validate_result(output, value["kind"]), separators=(",", ":")))
        return 0
    except Exception:
        # No exception text, remote status phrase, URL, headers or IP escapes.
        return 1


if __name__ == "__main__":
    sys.exit(main())
