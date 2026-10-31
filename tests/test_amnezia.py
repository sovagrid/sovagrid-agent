# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import base64
import json
import os
import shlex
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_agent.agent import _command_plan, _request_owned_vpn_broker, run_command, run_once
from sovagrid_agent.amnezia import HELPER, command_argv, sanitize_result


PUBLIC = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).rstrip(b"=").decode()
ENVELOPE = {
    "version": 1,
    "ephemeral_public_key": PUBLIC,
    "salt": base64.urlsafe_b64encode(b"s" * 16).rstrip(b"=").decode(),
    "nonce": base64.urlsafe_b64encode(b"n" * 12).rstrip(b"=").decode(),
    "ciphertext": base64.urlsafe_b64encode(b"c" * 32).rstrip(b"=").decode(),
}
PREVIEW = {
    "target": "awg2", "container_id": "a" * 64, "image_id": "sha256:" + "b" * 64,
    "config_sha256": "c" * 64, "table_sha256": "d" * 64, "generation": 2,
    "protocol": "amneziawg", "interface": "awg0", "listen_port": 49289,
    "server_address": "10.44.0.1", "server_subnet": "10.44.0.0/24",
    "configured_clients": 3, "managed_clients": 1, "external_clients": 2,
    "awg_parameters": {"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "24", "S2": "24",
                       "S3": "24", "S4": "24", "H1": "1", "H2": "2", "H3": "3", "H4": "4"},
    "awg_parameters_runtime_verified": False, "header_protection_key_present": True,
    "awg3_required_parameters_present": True, "apply_supported": False,
    "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE",
                       "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"],
}
CONFIRMATION = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode()


class AmneziaAgentTests(unittest.TestCase):
    def test_settings_plan_accepts_only_canonical_bounded_awg_proposal(self):
        patch = '{"Jc":"5"}'
        argv = [HELPER, "settings-plan", "awg2", "c" * 64, "2", patch]
        command = shlex.join(argv)
        self.assertEqual(command_argv(command), argv)
        with self.assertRaisesRegex(ValueError, "Agent broker path"):
            _command_plan(command, 999)
        for invalid in (
                [HELPER, "settings-plan", "wireguard", "c" * 64, "2", patch],
                [HELPER, "settings-plan", "awg2", "c" * 64, "2", '{"Jc":"65536"}'],
                [HELPER, "settings-plan", "awg2", "c" * 64, "2", '{"Jc":"5","Jc":"6"}'],
                [HELPER, "settings-plan", "awg2", "c" * 64, "2", '{"PrivateKey":"secret"}'],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                _command_plan(shlex.join(invalid), 999)

    def test_settings_plan_result_is_secret_free_and_cannot_claim_apply(self):
        parameters = PREVIEW["awg_parameters"]
        result = {"target": "awg2", "container_id": "a" * 64,
                  "image_id": "sha256:" + "b" * 64, "generation": 2,
                  "config_sha256": "c" * 64, "table_sha256": "d" * 64,
                  "proposed_config_sha256": "e" * 64,
                  "current_awg_parameters": parameters,
                  "proposed_awg_parameters": {**parameters, "Jc": "5"},
                  "changed_fields": ["Jc"], "configured_clients": 3,
                  "apply_supported": False,
                  "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE"]}
        self.assertEqual(json.loads(sanitize_result("settings-plan", json.dumps(result), "awg2")),
                         result)
        eligible = result | {"configured_clients": 0, "apply_supported": True,
                             "apply_blockers": []}
        self.assertEqual(json.loads(sanitize_result("settings-plan", json.dumps(eligible), "awg2")),
                         eligible)
        for altered in (result | {"PrivateKey": "secret"},
                        result | {"apply_supported": True},
                        result | {"changed_fields": ["H1"]},
                        result | {"target": "wireguard"},
                        eligible | {"apply_blockers": ["RUNTIME_PARAMETERS_UNVERIFIED"]}):
            self.assertIsNone(sanitize_result("settings-plan", json.dumps(altered), "awg2"))

    def test_settings_intent_and_apply_are_exact_broker_actions(self):
        patch = '{"Jc":"5"}'
        prefix = [HELPER, "settings-intent", "awg2", "c" * 64, "2", "e" * 64, patch]
        apply = prefix[:1] + ["settings-apply"] + prefix[2:] + [CONFIRMATION]
        for argv in (prefix, apply):
            with self.subTest(argv=argv):
                command = shlex.join(argv)
                self.assertEqual(command_argv(command), argv)
                with self.assertRaisesRegex(ValueError, "Agent broker path"):
                    _command_plan(command, 999)
        for argv in (prefix[:2] + ["wireguard"] + prefix[3:],
                     prefix[:5] + ["F" * 64, patch],
                     prefix[:6] + ['{"Jc":"5","Jc":"6"}'],
                     apply[:-1] + ["not-a-confirmation"],
                     apply[:-2] + ['{"PrivateKey":"secret"}', CONFIRMATION]):
            with self.subTest(invalid=argv), self.assertRaises(ValueError):
                command_argv(shlex.join(argv))

    def test_settings_intent_and_apply_result_whitelists(self):
        intent = {"target": "awg2", "action": "settings_intent",
                  "confirmation_id": CONFIRMATION, "expires_at": 253402300700,
                  "generation": 2, "config_sha256": "c" * 64,
                  "proposed_config_sha256": "e" * 64, "changed_fields": ["Jc"],
                  "configured_clients": 0}
        applied = {"target": "awg2", "action": "settings_updated",
                   "generation": 3, "config_sha256": "e" * 64,
                   "cleanup_required": False}
        for action, value in (("settings-intent", intent), ("settings-apply", applied)):
            self.assertEqual(json.loads(sanitize_result(action, json.dumps(value), "awg2")), value)
            for altered in (value | {"PrivateKey": "secret"}, value | {"target": "wireguard"},
                            value | {"generation": True}):
                self.assertIsNone(sanitize_result(action, json.dumps(altered), "awg2"))
        self.assertIsNone(sanitize_result("settings-intent", json.dumps(intent | {
            "changed_fields": ["Jc", "Jc"]}), "awg2"))
        self.assertIsNone(sanitize_result("settings-apply", json.dumps(applied | {
            "cleanup_required": "false"}), "awg2"))

    def test_settings_broker_result_must_match_command_pins(self):
        command = shlex.join([HELPER, "settings-intent", "awg2", "c" * 64, "2",
                              "e" * 64, '{"Jc":"5"}'])
        argv = command_argv(command)
        result = {"target": "awg2", "action": "settings_intent",
                  "confirmation_id": CONFIRMATION, "expires_at": int(time.time()) + 300,
                  "generation": 2, "config_sha256": "c" * 64,
                  "proposed_config_sha256": "e" * 64,
                  "changed_fields": ["Jc"], "configured_clients": 0}

        class FakeSocket:
            def __init__(self, value):
                self.payload = (json.dumps({"ok": True, "result": value}) + "\n").encode()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, _seconds):
                pass

            def connect(self, _path):
                pass

            def sendall(self, _request):
                pass

            def recv(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=FakeSocket(result)):
            self.assertEqual(json.loads(_request_owned_vpn_broker(argv, amnezia=True)["output"]),
                             result)
        for altered in (result | {"config_sha256": "a" * 64},
                        result | {"proposed_config_sha256": "f" * 64},
                        result | {"changed_fields": ["S1"]},
                        result | {"expires_at": int(time.time()) + 3600}):
            with self.subTest(altered=altered), mock.patch(
                    "sovagrid_agent.agent.socket.socket", return_value=FakeSocket(altered)):
                with self.assertRaisesRegex(ValueError, "changed proposal"):
                    _request_owned_vpn_broker(argv, amnezia=True)
        apply_argv = command_argv(shlex.join([HELPER, "settings-apply", "awg2",
                                              "c" * 64, "2", "e" * 64,
                                              '{"Jc":"5"}', CONFIRMATION]))
        applied = {"target": "awg2", "action": "settings_updated", "generation": 3,
                   "config_sha256": "e" * 64, "cleanup_required": False}
        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=FakeSocket(applied)):
            self.assertEqual(json.loads(_request_owned_vpn_broker(apply_argv, amnezia=True)["output"]),
                             applied)
        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=FakeSocket(
                applied | {"config_sha256": "f" * 64})):
            with self.assertRaisesRegex(ValueError, "changed proposal"):
                _request_owned_vpn_broker(apply_argv, amnezia=True)

    def test_exact_argv_uses_agent_broker_path(self):
        for target in ("awg2", "wireguard"):
            cases = (
                f"{HELPER} status {target}",
                f"{HELPER} settings-preview {target}",
                f"{HELPER} add-profile {target} phone 10.1.2.3 vpn.example.com {PUBLIC} --route split",
                f"{HELPER} add-profile {target} phone auto vpn.example.com {PUBLIC} --route split",
                f"{HELPER} sealed-export {target} phone {PUBLIC}",
                f"{HELPER} revoke {target} phone",
            )
            for command in cases:
                with self.subTest(command=command):
                    self.assertEqual(command_argv(command)[0], HELPER)
                    with self.assertRaisesRegex(ValueError, "Agent broker path"):
                        _command_plan(command, 999)
        for command in (
            f"{HELPER} status awg2; id", f"{HELPER} status awg2 && id",
            f"{HELPER} settings-preview awg2 --read-secret",
            f"{HELPER} settings-preview awg2; id",
            f"{HELPER} status wireguardx", f"{HELPER} enroll wireguard secret",
            f"{HELPER} add-profile awg2 phone 10.1.2.3 vpn.example.com {PUBLIC} --route evil",
            f"{HELPER} add-profile awg2 phone AUTO vpn.example.com {PUBLIC} --route split",
            f"{HELPER} add-profile wireguard phone 10.1.2.3 vpn.example.com {PUBLIC} --route evil",
            f"{HELPER} add-profile awg2 phone 10.1.2.3 vpn.example.com {PUBLIC} --route full extra",
            f"{HELPER} sealed-export wireguard phone bad", f"echo {HELPER} status awg2",
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                _command_plan(command, 999)

    def test_result_whitelist_never_forwards_plaintext(self):
        for target, profile_format in (("awg2", "awg3-conf"), ("wireguard", "wg-conf")):
            status = {"target": target, "enrolled": True, "recovery_required": False,
                      "owned_clients": ["phone"]}
            added = {"target": target, "action": "added", "client": "phone",
                     "configured_clients": 2, "cleanup_required": False,
                     "profile_format": profile_format, "sealed_profile": ENVELOPE}
            revoked = {"target": target, "action": "revoked", "client": "phone",
                       "configured_clients": 1, "cleanup_required": False}
            for action, value in (("status", status), ("add-profile", added),
                                  ("sealed-export", ENVELOPE), ("revoke", revoked)):
                with self.subTest(target=target, action=action):
                    self.assertEqual(json.loads(sanitize_result(action, json.dumps(value), target)),
                                     value)
                    self.assertIsNone(sanitize_result(
                        action, json.dumps(value | {"PrivateKey": "secret"}), target))
                    self.assertIsNone(sanitize_result(
                        action, '{"target":"awg2","target":"other"}', target))
                    self.assertIsNone(sanitize_result(action, "PrivateKey = secret", target))
            other_target = "wireguard" if target == "awg2" else "awg2"
            for action, value in (("status", status), ("add-profile", added), ("revoke", revoked)):
                self.assertIsNone(sanitize_result(action, json.dumps(value), other_target))
            self.assertIsNone(sanitize_result("add-profile", json.dumps(added), target, "other"))
            self.assertIsNone(sanitize_result("revoke", json.dumps(revoked), target, "other"))
            self.assertIsNone(sanitize_result(
                "add-profile", json.dumps(added | {"profile_format": "wg-conf" if target == "awg2"
                                               else "awg3-conf"}), target))
        self.assertIsNone(sanitize_result("status", json.dumps(status), "unknown"))

    def test_amnezia_request_uses_agent_socket_and_public_result_schema(self):
        argv = command_argv(f"{HELPER} status awg2")
        public = {"target": "awg2", "enrolled": True,
                  "recovery_required": False, "owned_clients": []}

        class FakeSocket:
            def __init__(self, payload):
                self.payload = payload
                self.path = None
                self.request = None
                self.timeouts = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, seconds):
                self.timeouts.append(seconds)

            def connect(self, path):
                self.path = path

            def sendall(self, request):
                self.request = request

            def recv(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        fake = FakeSocket((json.dumps({"ok": True, "result": public}) + "\n").encode())
        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=fake), mock.patch(
                "sovagrid_agent.agent.subprocess.Popen") as process:
            result = _request_owned_vpn_broker(argv, amnezia=True)
        self.assertEqual(fake.path, "/run/sovagrid-vpn/amnezia-control.sock")
        self.assertEqual(fake.request, b'{"argv":["status","awg2"]}\n')
        self.assertEqual(fake.timeouts, [5, 130])
        self.assertEqual(json.loads(result["output"]), public)
        process.assert_not_called()

        fake = FakeSocket((json.dumps({"ok": True, "result": public | {"PrivateKey": "secret"}}) + "\n").encode())
        with mock.patch("sovagrid_agent.agent.socket.socket", return_value=fake):
            with self.assertRaises(ValueError) as error:
                _request_owned_vpn_broker(argv, amnezia=True)
            self.assertNotIn("secret", str(error.exception))

    def test_mutating_amnezia_socket_failure_is_uncertain(self):
        results = []
        client = type("Client", (), {
            "push_metrics": lambda _self, _sample: None,
            "next_job": lambda _self: {"id": "job-amnezia", "command":
                                       f"{HELPER} revoke awg2 phone"},
            "send_result": lambda _self, _id, value: results.append(value),
        })()
        with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent._request_owned_vpn_broker",
                side_effect=OSError("private socket detail")), mock.patch(
                "sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, client)
            shell.assert_not_called()
        self.assertEqual(results, [{"state": "timed_out", "exit_code": None,
                                    "output": "Amnezia action outcome uncertain; inspect state before retrying"}])

    def test_settings_preview_exact_schema_and_size_limit(self):
        wireguard = PREVIEW | {"target": "wireguard", "protocol": "wireguard", "interface": "wg0",
                               "awg_parameters": {}, "header_protection_key_present": False,
                               "awg3_required_parameters_present": False}
        for target, value in (("awg2", PREVIEW), ("wireguard", wireguard)):
            with self.subTest(target=target):
                self.assertEqual(json.loads(sanitize_result("settings-preview", json.dumps(value), target)), value)
                self.assertIsNone(sanitize_result("settings-preview", json.dumps(value),
                                                  "wireguard" if target == "awg2" else "awg2"))
                for altered in (value | {"private_key": "secret"},
                                value | {"awg_parameters": {"PrivateKey": "secret"}},
                                value | {"listen_port": True},
                                value | {"apply_supported": True},
                                value | {"external_clients": 100},
                                value | {"image_id": "secret"},
                                value | {"server_subnet": "10.45.0.0/24"}):
                    self.assertIsNone(sanitize_result("settings-preview", json.dumps(altered), target))
        self.assertIsNone(sanitize_result("settings-preview", json.dumps(PREVIEW) + " " * 4096, "awg2"))
        self.assertIsNone(sanitize_result("settings-preview", '{"target":"awg2","target":"awg2"}', "awg2"))
        self.assertIsNone(sanitize_result("settings-preview", "PrivateKey = secret", "awg2"))

    def test_failed_broker_output_is_replaced_and_success_is_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "broker"
            with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                    "sovagrid_agent.agent._AMNEZIA_HELPER", str(script)):
                for target in ("awg2", "wireguard"):
                    with mock.patch("sovagrid_agent.agent._command_plan",
                                    return_value=([str(script), "status", target], 3)):
                        status = {"target": target, "enrolled": True,
                                  "recovery_required": False, "owned_clients": []}
                        other = {**status, "target": "wireguard" if target == "awg2" else "awg2"}
                        for body, expected_state in (
                            ("printf 'PrivateKey = secret\\n'; exit 1", "failed"),
                            ("printf 'PrivateKey = secret\\n'", "failed"),
                            (f"printf '%s\\n' '{json.dumps(other)}'", "failed"),
                            (f"printf '%s\\n' '{json.dumps(status)}'", "succeeded"),
                        ):
                            script.write_text("#!/bin/sh\n" + body + "\n")
                            script.chmod(0o700)
                            result = run_command("ignored")
                            self.assertEqual(result["state"], expected_state)
                            self.assertNotIn("PrivateKey", json.dumps(result))
                            if expected_state == "failed":
                                self.assertEqual(result["output"], "Amnezia control failed")

    def test_settings_preview_broker_failure_never_forwards_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "broker"
            script.write_text("#!/bin/sh\nprintf 'PrivateKey = secret\\n'\n")
            script.chmod(0o700)
            with mock.patch("sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                    "sovagrid_agent.agent._AMNEZIA_HELPER", str(script)), mock.patch(
                    "sovagrid_agent.agent._command_plan",
                    return_value=([str(script), "settings-preview", "awg2"], 3)):
                result = run_command("ignored")
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["output"], "Amnezia control failed")


if __name__ == "__main__":
    unittest.main()
