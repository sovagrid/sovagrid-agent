# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Rootless transaction tests for the service-control setup backend."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from sovagrid_agent.service_setup import (PROFILES, Paths, ServiceSetup, SetupError,
                                          unit_content)


POLICY = b'{"version":1,"units":{"nginx.service":["status","restart"]}}'
LOCAL_CONFIG = (json.dumps({
    "hub_url": "https://localhost:8767",
    "server_id": "00000000-0000-4000-8000-000000000001",
    "token_file": "/etc/sovagrid-local/agent.token",
    "ca_file": "/etc/sovagrid-local/hub-ca.pem",
    "interval_seconds": 30,
    "allow_remote_commands": True,
    "allow_interactive_terminal": False,
    "allow_file_manager": False,
}, sort_keys=True, separators=(",", ":")) + "\n").encode()


class FakeSystemd:
    def __init__(self, units: Path):
        self.units = units
        self.state = {profile: ("not-found", "unknown") for profile in PROFILES}
        self.calls = []
        self.fail_once = None
        self.fail_always = set()
        self.markers = {}
        self.missing_active_state = "unknown"

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        action = argv[4]
        unit = argv[-1] if action != "daemon-reload" else None
        profile = next((name for name in PROFILES
                        if PROFILES[name][0] + ".socket" == unit), None)
        if action == "daemon-reload":
            for name in PROFILES:
                socket_name = PROFILES[name][0] + ".socket"
                if (self.units / socket_name).exists():
                    if self.state[name] == ("not-found", "unknown"):
                        self.state[name] = ("disabled", "inactive")
                else:
                    self.state[name] = ("not-found", self.missing_active_state)
            return subprocess.CompletedProcess(argv, 0, None, None)
        if profile is None:
            if unit == "sovagrid-agent-local.service":
                if action == "is-active":
                    return subprocess.CompletedProcess(argv, 0, "active\n", "")
                if action == "restart":
                    failed = action == self.fail_once or action in self.fail_always
                    if action == self.fail_once:
                        self.fail_once = None
                    return subprocess.CompletedProcess(argv, 1 if failed else 0, None, None)
            raise AssertionError("Unknown setup systemctl unit")
        enabled, active = self.state[profile]
        if action in ("is-enabled", "is-active"):
            return subprocess.CompletedProcess(argv, 0,
                                               (enabled if action == "is-enabled" else active) + "\n", "")
        if profile in self.markers and action == "enable":
            # The privilege marker must be absent until the socket works.
            assert not self.markers[profile].exists()
        if action == "enable":
            enabled = "enabled"
            if "--now" in argv:
                active = "active"
        elif action == "disable":
            enabled = "disabled"
            if "--now" in argv:
                active = "inactive"
        elif action == "start":
            active = "active"
        elif action == "stop":
            active = "inactive"
        else:
            raise AssertionError("Unexpected systemctl action")
        self.state[profile] = (enabled, active)
        failed = action == self.fail_once or action in self.fail_always
        if action == self.fail_once:
            self.fail_once = None
        return subprocess.CompletedProcess(argv, 1 if failed else 0, None, None)


class SetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        units = root / "systemd"
        units.mkdir(mode=0o755)
        code_parent = root / "opt"
        code_parent.mkdir(mode=0o755)
        code = code_parent / "sovagrid-agent"
        local_code = code_parent / "sovagrid-agent-local"
        for target in (code, local_code):
            package = target / "sovagrid_agent"
            package.mkdir(parents=True, mode=0o755)
            for name in ("__init__.py", "service_broker.py", "service_control.py"):
                (package / name).write_text("# root-owned package placeholder\n")
        local_etc = root / "sovagrid-local"
        local_etc.mkdir(mode=0o750)
        local_config = local_etc / "agent.json"
        local_config.write_bytes(LOCAL_CONFIG)
        local_config.chmod(0o640)
        self.paths = Paths(config=root / "service-policy", local_policy=root / "service-local",
                           units=units, lock=root / "service.lock", code=code,
                           local_code=local_code, local_config=local_config)
        self.systemd = FakeSystemd(units)
        self.systemd.markers = {"default": self.paths.config / "enabled",
                                "local": self.paths.local_policy / "enabled"}
        self.setup = ServiceSetup(paths=self.paths, runner=self.systemd, require_root=False)

    def test_generated_units_match_reviewed_deployment_files(self):
        root = Path(__file__).resolve().parents[1]
        for profile in PROFILES:
            for name, content in unit_content(profile).items():
                with self.subTest(unit=name):
                    self.assertEqual(content, (root / "deploy" / name).read_bytes())

    def test_preview_arm_disarm_and_stale_cas(self):
        initial = self.setup.preview()
        self.assertFalse(initial["armed"])
        self.assertFalse(self.paths.lock.exists())
        self.assertFalse(self.paths.config.exists())
        plan = self.setup.preview("default", POLICY)
        self.assertEqual(plan["state_revision"], initial["state_revision"])
        self.assertEqual(len(plan["plan"]["install_units"]), 2)
        self.assertTrue(plan["plan"]["change_policy"])
        self.assertFalse(self.paths.lock.exists())
        armed = self.setup.arm("default", POLICY, initial["state_revision"])
        self.assertTrue(armed["armed"])
        self.assertEqual(armed["policy_status"], "present")
        self.assertEqual(armed["policy"], {"nginx.service": ["restart", "status"]})
        self.assertEqual(armed["sockets"]["default"], ("enabled", "active"))
        self.assertEqual(self.paths.config.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.paths.config / "enabled").read_bytes(), b"enabled\n")
        self.assertEqual((self.paths.config / "units.json").stat().st_mode & 0o777, 0o600)
        self.assertIn(b"nginx.service", (self.paths.config / "units.json").read_bytes())
        for name, content in unit_content("default").items():
            self.assertEqual((self.paths.units / name).read_bytes(), content)
            self.assertEqual((self.paths.units / name).stat().st_mode & 0o777, 0o644)
        with self.assertRaisesRegex(SetupError, "STATE_CHANGED"):
            self.setup.disarm(initial["state_revision"])
        disabled = self.setup.disarm(armed["state_revision"])
        self.assertFalse(disabled["armed"])
        self.assertEqual(disabled["sockets"]["default"], ("disabled", "inactive"))
        self.assertTrue((self.paths.config / "units.json").exists())

    def test_local_profile_and_policy_revision_are_distinct(self):
        initial = self.setup.preview()
        armed = self.setup.arm("local", POLICY, initial["state_revision"])
        self.assertEqual(armed["sockets"]["local"], ("enabled", "active"))
        self.assertEqual(armed["sockets"]["default"], ("not-found", "unknown"))
        self.assertTrue(armed["profiles"]["local"]["armed"])
        self.assertEqual((self.paths.local_policy / "enabled").read_bytes(), b"enabled\n")
        self.assertFalse(self.paths.config.exists())
        self.assertEqual(json.loads(self.paths.local_config.read_bytes())["service_socket"],
                         "/run/sovagrid-service-local/control.sock")
        self.assertTrue((self.paths.units / "sovagrid-service-local-control.socket").exists())
        self.assertFalse((self.paths.units / "sovagrid-service-control.socket").exists())
        self.systemd.state["local"] = ("enabled", "inactive")
        with self.assertRaisesRegex(SetupError, "STATE_CHANGED"):
            self.setup.disarm(armed["state_revision"])

    def test_profiles_are_independent_and_local_disarm_keeps_default_armed(self):
        initial = self.setup.preview()
        armed = self.setup.arm("default", POLICY, initial["state_revision"])
        both = self.setup.arm("local", POLICY, armed["state_revision"])
        self.assertTrue(both["profiles"]["default"]["armed"])
        self.assertTrue(both["profiles"]["local"]["armed"])
        local_off = self.setup.disarm(both["state_revision"], "local")
        self.assertFalse(local_off["profiles"]["local"]["armed"])
        self.assertTrue(local_off["profiles"]["default"]["armed"])
        self.assertTrue((self.paths.config / "enabled").exists())
        self.assertFalse((self.paths.local_policy / "enabled").exists())
        self.assertEqual(self.systemd.state["default"], ("enabled", "active"))

    def test_local_arm_restart_failure_restores_original_config_and_policy(self):
        initial = self.setup.preview()
        self.systemd.fail_once = "restart"
        with self.assertRaisesRegex(SetupError, "ARM_FAILED"):
            self.setup.arm("local", POLICY, initial["state_revision"])
        self.assertEqual(self.paths.local_config.read_bytes(), LOCAL_CONFIG)
        self.assertFalse(self.paths.local_policy.exists())
        self.assertEqual(self.systemd.state["local"], ("not-found", "unknown"))

    def test_local_socket_failure_restores_agent_config_after_restart(self):
        initial = self.setup.preview()
        self.systemd.fail_once = "enable"
        with self.assertRaisesRegex(SetupError, "ARM_FAILED"):
            self.setup.arm("local", POLICY, initial["state_revision"])
        self.assertEqual(self.paths.local_config.read_bytes(), LOCAL_CONFIG)
        self.assertFalse(self.paths.local_policy.exists())
        self.assertFalse((self.paths.units / "sovagrid-service-local-control.socket").exists())
        self.assertEqual(self.systemd.state["local"], ("not-found", "unknown"))

    def test_invalid_policy_or_unit_drift_fails_before_change(self):
        initial = self.setup.preview()
        for policy in (b"{}", b'{"version":1,"units":{"bad/path.service":["status"]}}',
                       b'{"version":1,"units":{"x.service":["start","start"]}}',
                       b'{"version":1,"units":{"sovagrid-agent.service":["status","restart"]}}',
                       b'{"version":1,"units":{"reverse-tunnel.service":["stop"]}}',
                       b'{"version":1,"units":{"ssh.service":["status","stop"]}}'):
            with self.subTest(policy=policy), self.assertRaisesRegex(SetupError, "INVALID_POLICY"):
                self.setup.arm("default", policy, initial["state_revision"])
        self.assertFalse(self.paths.config.exists())
        name = "sovagrid-service-control.socket"
        (self.paths.units / name).write_text("changed")
        (self.paths.units / name).chmod(0o644)
        observed = self.setup.preview()
        with self.assertRaisesRegex(SetupError, "UNIT_DRIFT"):
            self.setup.arm("default", POLICY, observed["state_revision"])
        self.assertFalse(self.paths.config.exists())

    def test_arm_systemd_failure_rolls_back_files_and_socket_state(self):
        initial = self.setup.preview()
        self.systemd.fail_once = "enable"
        with self.assertRaisesRegex(SetupError, "ARM_FAILED"):
            self.setup.arm("default", POLICY, initial["state_revision"])
        self.assertFalse(self.paths.config.exists())
        self.assertFalse(any(self.paths.units.iterdir()))
        self.assertEqual(self.systemd.state["default"], ("not-found", "unknown"))
        self.assertFalse(self.setup.preview()["armed"])

    def test_rollback_on_missing_unit_with_inactive_status_skips_stop(self):
        self.systemd.missing_active_state = "inactive"
        self.systemd.state["default"] = ("not-found", "inactive")
        self.systemd.state["local"] = ("not-found", "inactive")
        initial = self.setup.preview()
        self.systemd.fail_once = "enable"
        with self.assertRaisesRegex(SetupError, "ARM_FAILED"):
            self.setup.arm("default", POLICY, initial["state_revision"])
        self.assertFalse(self.paths.config.exists())
        self.assertFalse(any(self.paths.units.iterdir()))
        self.assertNotIn(("stop", PROFILES["default"][0] + ".socket"),
                         [(call[4], call[-1]) for call in self.systemd.calls])

    def test_arm_existing_policy_failure_restores_previous_exact_bytes(self):
        initial = self.setup.preview()
        armed = self.setup.arm("default", POLICY, initial["state_revision"])
        before = (self.paths.config / "units.json").read_bytes()
        self.systemd.fail_once = "enable"
        new_policy = b'{"version":1,"units":{"ssh.service":["status"]}}'
        with self.assertRaisesRegex(SetupError, "ARM_FAILED"):
            self.setup.arm("default", new_policy, armed["state_revision"])
        self.assertEqual((self.paths.config / "units.json").read_bytes(), before)
        self.assertTrue((self.paths.config / "enabled").exists())
        self.assertEqual(self.systemd.state["default"], ("enabled", "active"))

    def test_disarm_error_rolls_back_or_leaves_marker_disabled(self):
        initial = self.setup.preview()
        armed = self.setup.arm("default", POLICY, initial["state_revision"])
        self.systemd.fail_once = "disable"
        with self.assertRaisesRegex(SetupError, "DISARM_FAILED"):
            self.setup.disarm(armed["state_revision"])
        self.assertTrue((self.paths.config / "enabled").exists())
        self.assertEqual(self.systemd.state["default"], ("enabled", "active"))
        observed = self.setup.preview()
        self.systemd.fail_always = {"disable", "enable"}
        with self.assertRaisesRegex(SetupError, "ROLLBACK_INCOMPLETE"):
            self.setup.disarm(observed["state_revision"])
        self.assertFalse((self.paths.config / "enabled").exists())

    def test_preview_rejects_symlink_and_unsafe_policy(self):
        initial = self.setup.preview()
        armed = self.setup.arm("default", POLICY, initial["state_revision"])
        marker = self.paths.config / "enabled"
        marker.unlink()
        marker.symlink_to(self.paths.config / "units.json")
        with self.assertRaises(OSError):
            self.setup.preview()
        marker.unlink()
        marker.write_bytes(b"enabled\n")
        marker.chmod(0o644)
        with self.assertRaisesRegex(SetupError, "UNSAFE_FILE"):
            self.setup.disarm(armed["state_revision"])

    def test_root_broker_code_tree_must_not_be_agent_writable(self):
        initial = self.setup.preview()
        package = self.paths.code / "sovagrid_agent"
        package.chmod(0o775)
        with self.assertRaisesRegex(SetupError, "UNSAFE_CODE_TREE"):
            self.setup.arm("default", POLICY, initial["state_revision"])
        package.chmod(0o755)
        (package / "__pycache__").mkdir(mode=0o777)
        (package / "__pycache__").chmod(0o777)
        with self.assertRaisesRegex(SetupError, "UNSAFE_CODE_TREE"):
            self.setup.arm("default", POLICY, initial["state_revision"])
        self.assertFalse(self.paths.config.exists())


if __name__ == "__main__":
    unittest.main()
