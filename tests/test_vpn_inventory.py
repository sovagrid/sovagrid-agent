# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""The optional root-owned VPN inventory cannot become an Agent secret source."""

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from types import SimpleNamespace
from unittest import mock

from sovagrid_agent.agent import HubClient, run_once
from sovagrid_agent.vpn_inventory import read_snapshot


class VpnInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "inventory"
        self.directory.mkdir(mode=0o750)
        self.directory.chmod(0o750)
        self.path = self.directory / "status.json"
        self.snapshot = {
            "schema_version": 1, "collected_at": 1000, "source": "docker_cli",
            "source_status": "ok", "services": [{"name": "amnezia-awg", "state": "running",
                 "health": "healthy", "published_ports": [{"port": 51820, "protocol": "udp",
                 "peer_address": "NEVER-SEND-PEER"}], "private_key": "NEVER-SEND-KEY"}],
            "managed": {"source_status": "ok", "instances": [], "token": "NEVER-SEND-TOKEN"},
            "private_key": "NEVER-SEND-ROOT",
        }

    def write(self, value=None):
        self.path.write_text(json.dumps(self.snapshot if value is None else value))
        self.path.chmod(0o640)

    def read(self, now=1001):
        return read_snapshot(self.path, now=now, owner=os.getuid(), group=os.getgid())

    def test_reads_fresh_snapshot_but_strips_unknown_nested_fields(self):
        self.write()
        result = self.read()
        self.assertEqual(result["services"][0]["published_ports"], [{"port": 51820, "protocol": "udp"}])
        self.assertNotIn("NEVER-SEND", json.dumps(result))
        self.assertIsNone(self.read(now=1091))
        self.assertIsNone(self.read(now=999))

    def test_rejects_unsafe_file_or_directory_and_duplicate_json(self):
        self.write()
        self.path.chmod(0o644)
        self.assertIsNone(self.read())
        self.path.chmod(0o640)
        self.directory.chmod(0o755)
        self.assertIsNone(self.read())
        self.directory.chmod(0o750)
        self.path.unlink()
        target = self.directory / "real.json"
        target.write_text(json.dumps(self.snapshot))
        target.chmod(0o640)
        self.path.symlink_to(target)
        self.assertIsNone(self.read())
        self.path.unlink()
        self.path.write_text('{"schema_version":1,"schema_version":1}')
        self.path.chmod(0o640)
        self.assertIsNone(self.read())
        self.path.write_bytes(b"x" * 65537)
        self.assertIsNone(self.read())

    def test_old_hub_404_does_not_fail_inventory_refresh(self):
        client = HubClient({"hub_url": "https://hub.example", "server_id": "server-a"}, "agent-secret")
        error = urllib.error.HTTPError("https://hub.example/api/v1/servers/server-a/vpn",
                                       404, "Not found", {}, io.BytesIO(b"{}"))
        with mock.patch.object(client, "request", side_effect=error):
            self.assertFalse(client.push_vpn_inventory(self.snapshot))
        with mock.patch.object(client, "request", return_value={"accepted": True}) as request:
            self.assertTrue(client.push_vpn_inventory(self.snapshot))
            self.assertEqual(request.call_args.args[:2], ("POST", "/api/v1/servers/server-a/vpn"))

    def test_inventory_failure_does_not_block_agent_cycle(self):
        sent = []
        client = SimpleNamespace(push_metrics=lambda report: sent.append(report),
                                 push_vpn_inventory=mock.Mock(side_effect=RuntimeError("down")))
        with (mock.patch("sovagrid_agent.agent.collect", return_value={"details": {}}),
              mock.patch("sovagrid_agent.agent.read_vpn_inventory", return_value=self.snapshot)):
            run_once({"allow_remote_commands": False}, client)
        self.assertEqual(len(sent), 1)
        client.push_vpn_inventory.assert_called_once_with(self.snapshot)


if __name__ == "__main__":
    unittest.main()
