# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The privileged collector never exports raw Engine configuration."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_agent import container_collector, containers
from sovagrid_agent.container_collector import _engine
from sovagrid_agent.containers import read_agent_snapshot, read_snapshot, validate_snapshot
from sovagrid_agent.metrics import collect

IDENT = "a" * 64


class ContainerTests(unittest.TestCase):
    def test_agent_snapshot_is_bound_to_exact_primary_user_and_group(self):
        users = {
            "sovagrid": SimpleNamespace(pw_uid=101, pw_gid=201),
            "sovagrid-local": SimpleNamespace(pw_uid=102, pw_gid=202),
        }
        groups = {
            "sovagrid": SimpleNamespace(gr_gid=201),
            "sovagrid-local": SimpleNamespace(gr_gid=202),
        }
        with mock.patch.object(containers.pwd, "getpwnam", side_effect=users.__getitem__), \
             mock.patch.object(containers.grp, "getgrnam", side_effect=groups.__getitem__), \
             mock.patch.object(containers, "read_snapshot", return_value={"safe": True}) as reader:
            for uid, gid, path in ((101, 201, containers.SNAPSHOT),
                                   (102, 202, containers.LOCAL_SNAPSHOT)):
                with mock.patch.object(containers.os, "geteuid", return_value=uid), \
                     mock.patch.object(containers.os, "getegid", return_value=gid):
                    self.assertEqual(read_agent_snapshot(), {"safe": True})
                    reader.assert_called_with(path, group_gid=gid)
            reader.reset_mock()
            for uid, gid in ((0, 201), (102, 201), (101, 202), (999, 999)):
                with mock.patch.object(containers.os, "geteuid", return_value=uid), \
                     mock.patch.object(containers.os, "getegid", return_value=gid):
                    self.assertIsNone(read_agent_snapshot())
            reader.assert_not_called()
            users["sovagrid-local"] = SimpleNamespace(pw_uid=102, pw_gid=999)
            with mock.patch.object(containers.os, "geteuid", return_value=102), \
                 mock.patch.object(containers.os, "getegid", return_value=202):
                self.assertIsNone(read_agent_snapshot())
            reader.assert_not_called()

    def test_collector_local_mode_has_fixed_path_group_and_exact_arguments(self):
        with mock.patch.object(container_collector.grp, "getgrnam",
                               return_value=SimpleNamespace(gr_gid=202)), \
             mock.patch.object(container_collector.os, "geteuid", return_value=0), \
             mock.patch.object(container_collector.os, "getegid", return_value=202), \
             mock.patch.object(container_collector, "collect", return_value={"safe": True}) as collector, \
             mock.patch.object(container_collector, "save") as saver:
            container_collector.main(["--local"])
            saver.assert_called_once_with({"safe": True}, path=containers.LOCAL_SNAPSHOT,
                                          group_gid=202)
            saver.reset_mock()
            collector.reset_mock()
            for argv in (["--local", "../other"], ["--path", "/etc/passwd"], ["--standard"]):
                with self.assertRaises(SystemExit):
                    container_collector.main(argv)
            saver.assert_not_called()
            collector.assert_not_called()
            with mock.patch.object(container_collector.os, "getegid", return_value=201):
                with self.assertRaises(PermissionError):
                    container_collector.main(["--local"])
            saver.assert_not_called()
            collector.assert_not_called()
            container_collector.main([])
            saver.assert_called_once_with({"safe": True})

    def test_agent_includes_only_valid_snapshot_without_blocking_host_metrics(self):
        snapshot = {"version": 1, "collected_at": int(time.time()), "engines": [
            {"engine": name, "source_status": "unavailable", "reason": "no_socket", "truncated": False, "containers": []}
            for name in ("docker", "podman")]}
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "uptime").write_text("10 5\n")
            with mock.patch("sovagrid_agent.metrics.cpu_snapshot", side_effect=[(100, 20), (200, 40)]), \
                 mock.patch("sovagrid_agent.metrics.time.sleep"), \
                 mock.patch("sovagrid_agent.metrics.memory", return_value=(1000, 500, 50.0)), \
                 mock.patch("sovagrid_agent.metrics.local_mount_type", return_value=None), \
                 mock.patch("sovagrid_agent.metrics.network_interfaces", return_value=[]), \
                 mock.patch("sovagrid_agent.metrics._filesystem_inventory", return_value=([], False)), \
                 mock.patch("sovagrid_agent.metrics.swap", return_value=None), \
                 mock.patch("sovagrid_agent.metrics.processes", return_value=None), \
                 mock.patch("sovagrid_agent.metrics.top_processes", return_value=None), \
                 mock.patch("sovagrid_agent.metrics.disk_io", return_value=[]), \
                 mock.patch("sovagrid_agent.metrics.services", return_value=None), \
                 mock.patch("sovagrid_agent.metrics.clock_snapshot", return_value={}), \
                 mock.patch("sovagrid_agent.metrics.os.getloadavg", return_value=(0.1, 0.2, 0.3)), \
                 mock.patch("sovagrid_agent.metrics.container_snapshot", return_value=snapshot):
                report = collect(sample_seconds=0, proc_root=str(proc))
            self.assertEqual(report["cpu_percent"], 80.0)
            self.assertEqual(report["details"]["containers"], snapshot)

    def test_fixed_read_only_requests_export_only_bounded_fields(self):
        requests = []
        def fake_get(_path, endpoint, **_kwargs):
            requests.append(endpoint)
            if endpoint.endswith("/containers/json?all=1&limit=13"):
                return [{"Id": IDENT, "Names": ["/private-api"], "Image": "registry.example/api:1",
                         "State": "running", "Labels": {"password": "DO_NOT_LEAK"},
                         "Mounts": [{"Source": "/secret/private"}]}]
            if endpoint.endswith("/containers/" + IDENT + "/json"):
                return {"RestartCount": 3, "State": {"Health": {"Status": "healthy"}},
                        "Config": {"Env": ["API_KEY=DO_NOT_LEAK"]}}
            if endpoint.endswith("/containers/" + IDENT + "/stats?stream=false&one-shot=true"):
                return {"memory_stats": {"usage": 2000, "stats": {"inactive_file": 500}},
                        "cpu_stats": {"cpu_usage": {"total_usage": 400}, "system_cpu_usage": 2000, "online_cpus": 2},
                        "precpu_stats": {"cpu_usage": {"total_usage": 300}, "system_cpu_usage": 1000}}
            raise AssertionError("unexpected Engine request")
        engine_socket = mock.Mock()
        engine_socket.stat.return_value = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=os.getuid())
        with mock.patch("sovagrid_agent.container_collector._get", side_effect=fake_get):
            result = _engine("docker", engine_socket, owner_uid=os.getuid())
            self.assertEqual(result["source_status"], "ok")
            self.assertEqual(len(result["containers"]), 1)
            item = result["containers"][0]
            self.assertEqual(item["restarts"], 3)
            self.assertEqual(item["health"], "healthy")
            self.assertEqual(item["cpu_percent"], 20.0)
            self.assertEqual(item["memory_bytes"], 1500)
            self.assertNotIn("DO_NOT_LEAK", json.dumps(result))
            self.assertNotIn("secret", json.dumps(result))
            self.assertTrue(all(path.startswith("/containers/") for path in requests))
            self.assertEqual(len(requests), 3)

    def test_missing_or_symlink_socket_does_not_grant_access(self):
        with tempfile.TemporaryDirectory() as directory:
            sock = Path(directory) / "missing.sock"
            self.assertEqual(_engine("docker", sock)["reason"], "no_socket")
            sock.symlink_to("/run/docker.sock")
            self.assertEqual(_engine("docker", sock)["reason"], "no_access")

    def test_omitted_engine_rows_mark_inventory_incomplete(self):
        valid = {"Id": IDENT, "Names": ["/api"], "Image": "api:1", "State": "running"}
        socket_path = mock.Mock()
        socket_path.stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o660, st_uid=os.getuid())
        for omitted in (None,
                        {"Id": "bad", "Names": ["/other"], "Image": "other:1"},
                        {"Id": "b" * 64, "Names": [], "Image": "other:1"},
                        {"Id": "b" * 64, "Names": ["/other"], "Image": ""},
                        valid):
            with self.subTest(omitted=omitted), mock.patch(
                    "sovagrid_agent.container_collector._get", return_value=[valid, omitted]):
                result = _engine("docker", socket_path, owner_uid=os.getuid())
                self.assertEqual(result["source_status"], "ok")
                self.assertTrue(result["truncated"])
                self.assertEqual([item["name"] for item in result["containers"]], ["api"])

    def test_reader_requires_owned_regular_snapshot_and_rejects_extra_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "inventory"
            folder.mkdir(mode=0o750)
            folder.chmod(0o750)
            path = folder / "snapshot.json"
            value = {"version": 1, "collected_at": int(time.time()), "engines": [
                {"engine": name, "source_status": "unavailable", "reason": "no_socket", "truncated": False, "containers": []}
                for name in ("docker", "podman")]}
            path.write_text(json.dumps(value))
            path.chmod(0o640)
            self.assertEqual(read_snapshot(path, owner_uid=os.getuid(), group_gid=os.getgid()), value)
            path.chmod(0o666)
            self.assertIsNone(read_snapshot(path, owner_uid=os.getuid(), group_gid=os.getgid()))
            path.chmod(0o640)
            path.write_text(json.dumps(value | {"Config": {"Env": ["SECRET=x"]}}))
            self.assertIsNone(read_snapshot(path, owner_uid=os.getuid(), group_gid=os.getgid()))
            path.unlink()
            path.symlink_to("/etc/passwd")
            self.assertIsNone(read_snapshot(path, owner_uid=os.getuid(), group_gid=os.getgid()))

    def test_schema_rejects_unbounded_or_secret_fields(self):
        base = {"version": 1, "collected_at": 1800000000, "engines": [
            {"engine": name, "source_status": "ok", "reason": None, "truncated": False, "containers": []}
            for name in ("docker", "podman")]}
        item = {"id": IDENT, "name": "api", "image": "api:1", "state": "running", "health": None,
                "restarts": None, "cpu_percent": None, "memory_bytes": None}
        validate_snapshot(base)
        for corrupt in (item | {"env": "SECRET=x"}, item | {"name": "bad\nname"},
                        item | {"cpu_percent": 10001}, item | {"health": {"Status": "healthy"}}):
            base["engines"][0]["containers"] = [corrupt]
            with self.assertRaises(ValueError):
                validate_snapshot(base)
        base["engines"][0]["containers"] = []
        base["engines"][0]["reason"] = {"secret": "x"}
        with self.assertRaises(ValueError):
            validate_snapshot(base)


if __name__ == "__main__":
    unittest.main()
