# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import io
import base64
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.response import addinfourl

from sovagrid_agent.agent import (HubClient, _RejectRedirect, _command_plan,
                                 _command_processes, _request_owned_vpn_broker,
                                 _sealed_envelope, _vpn_command_argv, load_config,
                                 run_command, run_once)
from sovagrid_agent.metrics import collect, cpu_percent, filesystems, local_mount_type, memory, network, services, top_processes


class AgentTests(unittest.TestCase):
    def test_metric_details_fit_hub_limit_without_journal_access(self):
        sent = []
        client = SimpleNamespace(push_metrics=lambda report: sent.append(report))
        report = {"details": {"top_processes": "x" * 13000,
                              "pressure": {"cpu": {"some": {"avg10": 1}}},
                              "cpu_times": {"iowait_percent": 1, "steal_percent": 2},
                              "load5": 0.1}}
        with mock.patch("sovagrid_agent.agent.collect", return_value=report):
            run_once({"allow_remote_commands": False}, client)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["details"], {"load5": 0.1})
        self.assertLessEqual(len(json.dumps(sent[0]["details"], separators=(",", ":")).encode()),
                             12000)

    def test_hub_redirect_cannot_forward_agent_bearer_to_malicious_location(self):
        calls = []

        class RedirectingHTTPS(urllib.request.BaseHandler):
            handler_order = 100

            def https_open(self, request):
                calls.append((request.full_url, request.get_header("Authorization")))
                headers = Message()
                headers["Location"] = "http://attacker.example/collect"
                response = addinfourl(io.BytesIO(b""), headers, request.full_url, code=302)
                response.msg = "Found"
                return response

        client = HubClient({"hub_url": "https://hub.example", "server_id": "server-A"}, "secret-agent-token")
        self.assertTrue(any(isinstance(handler, _RejectRedirect)
                            for handler in client._network_opener.handlers))
        client._network_opener = urllib.request.build_opener(RedirectingHTTPS(), _RejectRedirect())
        with self.assertRaises(urllib.error.HTTPError) as caught:
            client.request("GET", "/api/v1/servers/server-A/jobs/next")
        self.assertEqual(caught.exception.code, 302)
        caught.exception.close()
        self.assertEqual(calls, [("https://hub.example/api/v1/servers/server-A/jobs/next",
                                  "Bearer secret-agent-token")])

    def test_only_canonical_vpn_commands_use_agent_broker_path(self):
        helper = "/usr/local/bin/sovagrid-vpn-ctl"
        public_key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        commands = (
            f"{helper} create personal --port 51821 --subnet 10.49.0.0/24 --endpoint vpn.example.com",
            f"{helper} activate personal",
            f"{helper} add-client personal phone_1",
            f"{helper} revoke-client personal phone_1",
            f"{helper} sealed-export personal phone_1 {public_key}",
            f"{helper} sealed-export personal phone_1 {public_key} --route full",
            f"{helper} remove personal --confirm-name personal",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(_vpn_command_argv(command)[0], helper)
                with self.assertRaisesRegex(ValueError, "Agent broker path"):
                    _command_plan(command, 999)

    def test_ordinary_commands_keep_fifteen_second_cap(self):
        for requested in (-1, 1, 15, 60, 999):
            with self.subTest(requested=requested):
                argv, seconds = _command_plan("sleep 100", requested)
                self.assertEqual(argv, ["/bin/sh", "-c", "sleep 100"])
                self.assertEqual(seconds, min(max(requested, 1), 15))

    def test_broker_shell_injection_and_noncanonical_args_rejected(self):
        helper = "/usr/local/bin/sovagrid-vpn-ctl"
        public_key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        invalid = (
            f"{helper} activate personal; id",
            f"{helper} activate personal && id",
            f"{helper} activate personal\nid",
            f"{helper} activate personal $(id)",
            f"{helper} activate personal `id`",
            f"{helper} activate 'personal'",
            f"{helper}  activate personal",
            f"{helper} create personal --port 51821 --subnet 10.49.0.0/24 --endpoint bad.example.com; id",
            f"{helper} create personal --port 51821 --subnet 8.8.8.0/24 --endpoint vpn.example.com",
            f"{helper} create personal --port 051821 --subnet 10.49.0.0/24 --endpoint vpn.example.com",
            f"{helper} remove personal --confirm-name other",
            f"{helper} export-client personal phone_1",
            f"{helper} sealed-export personal phone_1 bad",
            f"{helper} sealed-export personal phone_1 {public_key}; id",
            f"{helper} sealed-export personal phone_1 {public_key} extra",
            f"{helper} sealed-export personal phone_1 {public_key} --route split",
            f"{helper} sealed-export personal phone_1 {public_key} --route full; id",
            f"echo {helper} activate personal",
        )
        for command in invalid:
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _command_plan(command, 999)
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as popen:
            with self.assertRaises(ValueError):
                run_command(f"{helper} activate personal; id", timeout_seconds=999)
            popen.assert_not_called()

    def test_sealed_export_never_persists_raw_broker_output(self):
        key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        salt = base64.urlsafe_b64encode(b"s" * 16).decode().rstrip("=")
        nonce = base64.urlsafe_b64encode(b"n" * 12).decode().rstrip("=")
        ciphertext = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
        envelope = {"version": 1, "ephemeral_public_key": key, "salt": salt,
                    "nonce": nonce, "ciphertext": ciphertext}
        self.assertEqual(json.loads(_sealed_envelope(json.dumps(envelope))), envelope)
        for output in ("PrivateKey = secret", json.dumps({**envelope, "profile": "PrivateKey = secret"}),
                       json.dumps({**envelope, "ciphertext": "bad="}),
                       json.dumps({**envelope, "version": True}),
                       json.dumps(envelope) + "\nPrivateKey = secret",
                       '{"version":1,"version":1}'):
            with self.subTest(output=output):
                self.assertIsNone(_sealed_envelope(output))
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "fake-broker"
            with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                    "sovagrid_agent.agent._VPN_HELPER", str(script)), mock.patch(
                    "sovagrid_agent.agent._command_plan", return_value=([str(script), "sealed-export"], 105)):
                for body, expected_state, expected_output in (
                    ("printf 'PrivateKey = secret\\n'", "failed", "Sealed profile export failed"),
                    ("printf 'PrivateKey = secret\\n'; exit 1", "failed", "Sealed profile export failed"),
                    (f"printf '%s\\n' '{json.dumps(envelope)}'", "succeeded",
                     json.dumps(envelope, separators=(",", ":"))),
                ):
                    with self.subTest(body=body):
                        script.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
                        script.chmod(0o700)
                        result = run_command("ignored")
                        self.assertEqual(result["state"], expected_state)
                        self.assertEqual(result["output"], expected_output)
                        self.assertNotIn("PrivateKey", json.dumps(result))

    def test_vpn_job_refreshes_liveness_and_still_reports_if_refresh_fails(self):
        command = "/usr/local/bin/sovagrid-vpn-ctl activate personal"
        for refresh_fails in (False, True):
            with self.subTest(refresh_fails=refresh_fails):
                events = []

                def push_metrics(_sample):
                    events.append("metrics")
                    if refresh_fails and events.count("metrics") == 2:
                        raise OSError("private connection detail")

                def next_job():
                    events.append("job")
                    return {"id": "job-1", "command": command, "timeout_seconds": 15}

                def send_result(job_id, result):
                    self.assertEqual(job_id, "job-1")
                    self.assertEqual(result["state"], "succeeded")
                    events.append("result")

                def execute(*_args, **_kwargs):
                    events.append("exec")
                    return {"state": "succeeded", "exit_code": 0, "output": ""}

                client = SimpleNamespace(push_metrics=push_metrics, next_job=next_job,
                                         send_result=send_result)
                with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                        "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                        "sovagrid_agent.agent._request_owned_vpn_broker", side_effect=execute), mock.patch(
                        "sovagrid_agent.agent.logging.warning") as warning:
                    run_once({"allow_remote_commands": True}, client)
                self.assertEqual(events, ["metrics", "job", "exec", "metrics", "result"])
                if refresh_fails:
                    warning.assert_called_once_with("VPN job finished; metric refresh failed")
                else:
                    warning.assert_not_called()

    def test_vpn_socket_request_is_sent_by_agent_and_sealed_result_is_bounded(self):
        public_key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        envelope = {"version": 1, "ephemeral_public_key": public_key,
                    "salt": base64.urlsafe_b64encode(b"s" * 16).decode().rstrip("="),
                    "nonce": base64.urlsafe_b64encode(b"n" * 12).decode().rstrip("="),
                    "ciphertext": base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")}
        argv = _vpn_command_argv(
            f"/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone {public_key}")

        class FakeSocket:
            def __init__(self, answer):
                self.answer = answer
                self.sent = None
                self.path = None
                self.timeouts = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, value):
                self.timeouts.append(value)

            def connect(self, path):
                self.path = path

            def sendall(self, request):
                self.sent = request

            def recv(self, _size):
                answer, self.answer = self.answer, b""
                return answer

        response = (json.dumps({"ok": True, "result": envelope}, separators=(",", ":")) + "\n").encode()
        fake = FakeSocket(response)
        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=fake), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as process:
            result = _request_owned_vpn_broker(argv)
        self.assertEqual(fake.path, "/run/sovagrid-vpn/control.sock")
        self.assertEqual(fake.sent, (json.dumps({"argv": argv[1:]}, separators=(",", ":")) + "\n").encode())
        self.assertEqual(fake.timeouts, [5, 100])
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(json.loads(result["output"]), envelope)
        process.assert_not_called()

        for invalid in ({"ok": True, "result": {"PrivateKey": "secret"}},
                        {"ok": False, "error": "token=secret"}):
            with self.subTest(invalid=invalid), mock.patch(
                    "sovagrid_agent.agent.socket.socket",
                    return_value=FakeSocket((json.dumps(invalid) + "\n").encode())):
                with self.assertRaises(ValueError) as error:
                    _request_owned_vpn_broker(argv)
                self.assertNotIn("secret", str(error.exception))

    def test_ordinary_job_does_not_trigger_extra_metric_push(self):
        events = []
        client = SimpleNamespace(
            push_metrics=lambda _: events.append("metrics"),
            next_job=lambda: {"id": "job-2", "command": "uptime", "timeout_seconds": 999},
            send_result=lambda *_: events.append("result"),
        )
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.run_command", return_value={"state": "succeeded", "exit_code": 0, "output": ""}):
            run_once({"allow_remote_commands": True}, client)
        self.assertEqual(events, ["metrics", "result"])

    def test_rejected_broker_job_reports_failure_without_execution(self):
        results = []
        client = SimpleNamespace(
            push_metrics=lambda _: None,
            next_job=lambda: {"id": "job-3", "command": "/usr/local/bin/sovagrid-vpn-ctl activate personal; id"},
            send_result=lambda job_id, result: results.append((job_id, result)),
        )
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.run_command") as execute:
            run_once({"allow_remote_commands": True}, client)
        execute.assert_not_called()
        self.assertEqual(results, [("job-3", {
            "state": "failed", "exit_code": None, "output": "Invalid VPN broker command",
        })])

    def test_missing_broker_reports_sanitized_failure_and_completes_job(self):
        for error in (FileNotFoundError("/private/path/sovagrid-vpn-ctl"),
                      PermissionError("socket token=secret"), ValueError("malformed secret")):
            with self.subTest(error=type(error).__name__):
                results = []
                pushes = []
                client = SimpleNamespace(
                    push_metrics=lambda _: pushes.append(True),
                    next_job=lambda: {"id": "job-4", "command": "/usr/local/bin/sovagrid-vpn-ctl activate personal"},
                    send_result=lambda job_id, result: results.append((job_id, result)),
                )
                with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                        "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                        "sovagrid_agent.agent._request_owned_vpn_broker", side_effect=error):
                    run_once({"allow_remote_commands": True}, client)
                self.assertEqual(len(pushes), 2)
                self.assertEqual(results, [("job-4", {
                    "state": "timed_out", "exit_code": None,
                    "output": "VPN action outcome uncertain; inspect state before retrying",
                })])

    def test_vpn_read_only_broker_failure_is_failed_without_retry_warning(self):
        key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        results = []
        client = SimpleNamespace(
            push_metrics=lambda _: None,
            next_job=lambda: {"id": "job-read", "command":
                              f"/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone {key}"},
            send_result=lambda _id, result: results.append(result))
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent._request_owned_vpn_broker",
                side_effect=TimeoutError("private path")):
            run_once({"allow_remote_commands": True}, client)
        self.assertEqual(results, [{"state": "failed", "exit_code": None,
                                    "output": "VPN broker unavailable or invalid request"}])

    def test_ordinary_job_startup_error_still_propagates(self):
        client = SimpleNamespace(
            push_metrics=lambda _: None,
            next_job=lambda: {"id": "job-5", "command": "uptime"},
            send_result=lambda *_: self.fail("Unexpected result"),
        )
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.run_command", side_effect=FileNotFoundError("/bin/sh")):
            with self.assertRaises(FileNotFoundError):
                run_once({"allow_remote_commands": True}, client)

    def test_proc_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "net").mkdir()
            (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
            (proc / "net" / "dev").write_text("header\nheader\nlo: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\neth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n")
            self.assertEqual(memory(directory), (1024000, 256000, 75.0))
            self.assertEqual(network(directory), (10, 20))
            self.assertEqual(cpu_percent((100, 20), (200, 50)), 70.0)

    def test_detailed_collection_from_synthetic_procfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            sys = root / "sys"
            (proc / "net").mkdir(parents=True)
            (proc / "self").mkdir()
            (proc / "pressure").mkdir()
            (sys / "block" / "sda").mkdir(parents=True)
            (proc / "stat").write_text("cpu 10 0 10 80 0 0 0 0\nprocs_running 3\nprocs_blocked 1\n")
            (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 500 kB\nSwapFree: 100 kB\n")
            (proc / "net" / "dev").write_text("header\nheader\neth0: 10 0 1 0 0 0 0 0 20 0 2 0 0 0 0 0\n")
            (proc / "uptime").write_text("1234.5 999.0\n")
            (proc / "pressure" / "cpu").write_text("some avg10=1.25 avg60=2.50 avg300=3.75 total=12345\n")
            (proc / "pressure" / "memory").write_text("some avg10=0.10 avg60=0.20 avg300=0.30 total=10\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            (proc / "pressure" / "io").write_text("some avg10=4.00 avg60=5.00 avg300=6.00 total=40\nfull avg10=1.00 avg60=2.00 avg300=3.00 total=20\n")
            (proc / "self" / "mountinfo").write_text("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
            (proc / "42").mkdir()
            (proc / "42" / "comm").write_text("python3\n")
            (proc / "42" / "statm").write_text("100 20 0 0 0 0 0\n")
            (sys / "block" / "sda" / "stat").write_text("1 0 2 0 3 0 4 0 0 0 0\n")
            with mock.patch("sovagrid_agent.metrics.time.sleep"), mock.patch("sovagrid_agent.metrics.cpu_snapshot", side_effect=[(100, 20, 5, 2), (200, 50, 15, 7)]):
                sample = collect(sample_seconds=0, proc_root=str(proc), sys_root=str(sys))
            details = sample["details"]
            self.assertEqual(sample["cpu_percent"], 70.0)
            self.assertEqual(details["swap"]["used_percent"], 80.0)
            self.assertEqual(details["interfaces"][0]["rx_errors"], 1)
            self.assertEqual(details["interfaces"][0]["tx_errors"], 2)
            self.assertEqual(details["filesystems"][0]["mountpoint"], "/")
            self.assertEqual(details["processes"], {"running": 3, "blocked": 1})
            self.assertEqual(details["top_processes"][0]["name"], "python3")
            self.assertEqual(details["top_processes"][0]["rss_bytes"], 20 * os.sysconf("SC_PAGE_SIZE"))
            self.assertEqual(details["disk_io"][0]["read_bytes"], 1024)
            self.assertEqual(details["disk_io"][0]["write_bytes"], 2048)
            self.assertEqual(details["cpu_times"], {"iowait_percent": 10.0, "steal_percent": 5.0})
            self.assertEqual(details["pressure"]["cpu"]["some"]["avg10"], 1.25)
            self.assertEqual(details["pressure"]["io"]["full"]["total_us"], 20)

    def test_top_processes_use_only_short_comm_and_rss(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid in range(1, 15):
                entry = proc / str(pid)
                entry.mkdir()
                (entry / "comm").write_text(f"worker{pid}\n")
                (entry / "statm").write_text(f"100 {pid} 0 0 0 0 0\n")
                (entry / "cmdline").write_text("--secret-password=never-send")
                (entry / "environ").write_text("TOKEN=never-send")
            (proc / "15").mkdir()
            (proc / "15" / "comm").write_text("../../secret\n")
            (proc / "15" / "statm").write_text("100 999\n")
            (proc / "16").mkdir()  # Process exited while being sampled.
            (proc / "17").mkdir()
            (proc / "17" / "comm").write_text("bad\n")
            (proc / "17" / "statm").write_text("100 not-a-number\n")
            result = top_processes(str(proc), page_size=4096)
            self.assertEqual([item["pid"] for item in result], list(range(14, 4, -1)))
            self.assertEqual(result[0], {"pid": 14, "name": "worker14", "rss_bytes": 14 * 4096})
            self.assertNotIn("never-send", json.dumps(result))
            self.assertIsNone(top_processes(str(proc / "missing"), page_size=4096))

    def test_service_inventory_keeps_failed_and_watched_units(self):
        output = ("ssh.service loaded active running OpenSSH server\n"
                  "docker.service loaded failed failed Docker engine\n"
                  "irrelevant.service loaded active running Other\n"
                  "broken.service loaded failed failed Broken\n"
                  "missing.service not-found inactive dead Missing\n")
        def run(argv, **kwargs):
            self.assertEqual(argv[:2], ["systemctl", "list-units"])
            self.assertEqual(kwargs["timeout"], 3)
            return SimpleNamespace(returncode=0, stdout=output)
        self.assertEqual(services(run), {"failed_count": 2, "units": [
            {"name": "broken.service", "active": "failed", "sub": "failed"},
            {"name": "docker.service", "active": "failed", "sub": "failed"},
            {"name": "ssh.service", "active": "active", "sub": "running"},
        ]})

    def test_network_and_fuse_mounts_never_reach_statvfs(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "self").mkdir()
            (proc / "self" / "mountinfo").write_text(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
                "4 1 0:1 / / rw - nfs server:/root rw\n"
                "2 1 0:2 / /mnt/fuse rw - fuse.sshfs remote rw\n"
                "3 1 8:1 / /mnt/local rw - ext4 /dev/sda1 rw\n")
            self.assertIsNone(local_mount_type("/", directory))
            with mock.patch("sovagrid_agent.metrics.os.statvfs") as statvfs:
                statvfs.return_value = SimpleNamespace(f_blocks=100, f_frsize=4096, f_bavail=50,
                                                       f_files=1000, f_favail=500)
                items = filesystems(directory)
            self.assertEqual([item["mountpoint"] for item in items], ["/mnt/local"])
            statvfs.assert_called_once_with("/mnt/local")

    def test_linux_process_tracking_includes_new_session_child(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid, ppid, start in ((101, 100, 1), (102, 101, 2), (103, 100, 3), (104, 100, 4)):
                entry = proc / str(pid)
                entry.mkdir()
                (entry / "stat").write_text(f"{pid} (name with ) spaces) S {ppid} " + "0 " * 17 + f"{start}\n")
            with mock.patch("sovagrid_agent.agent.os.getpid", return_value=100):
                tracked = _command_processes(101, {104}, True, directory)
            self.assertEqual(tracked, {101: 1, 102: 2, 103: 3})

    def test_config_requires_https_and_client_bearer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = {"hub_url": "http://example.com", "server_id": "abc", "token_file": "/tmp/token"}
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                load_config(str(path))
            config["hub_url"] = "https://example.com"
            path.write_text(json.dumps(config))
            loaded = load_config(str(path))
        seen = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        def opener(request, **kwargs):
            seen.append(request)
            return Response(b'{"accepted":true}')

        client = HubClient(loaded, "secret-token", opener=opener)
        client.push_metrics({"cpu_percent": 5})
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(seen[0].full_url, "https://example.com/api/v1/servers/abc/metrics")

    @unittest.skipIf(os.geteuid() == 0, "Cannot test subprocess execution as root")
    def test_command_exit_and_output_limit(self):
        self.assertEqual(run_command("printf hello")["output"], "hello")
        for invalid in ("", "a\x00b", "я" * 1025):
            with self.assertRaises(ValueError):
                run_command(invalid)
        limited = run_command("yes x", timeout_seconds=2, output_limit_bytes=100)
        self.assertEqual(limited["state"], "output_limited")
        self.assertLessEqual(len(limited["output"].encode()), 100)
        timed = run_command("sleep 2", timeout_seconds=1)
        self.assertEqual(timed["state"], "timed_out")


if __name__ == "__main__":
    unittest.main()
