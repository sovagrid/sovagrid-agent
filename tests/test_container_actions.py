# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root broker contract: exact identity, opt-in policy, bounded Engine calls."""

from __future__ import annotations

import copy
import json
import socket
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from sovagrid_agent import container_action_broker as action
from sovagrid_agent import container_actions as protocol
from sovagrid_agent import service_broker
from sovagrid_agent.agent import _command_plan, run_once
from sovagrid_agent.service_control import LOCAL_SOCKET_PATH, SOCKET_PATH


IDENT = "a" * 64
IMAGE = "sha256:" + "b" * 64
POLICY = {"version": 1, "containers": [{"id": IDENT, "name": "workload-1",
          "image_id": IMAGE, "actions": ["status", "start", "stop", "restart"]}]}


def inspected(state="running", *, name="workload-1", ident=IDENT, image=IMAGE,
              project="workload", service="worker", image_ref="docker.io/library/workload:stable",
              privileged=False, network="bridge", pid_mode="", exposed=None):
    return {"Id": ident, "Name": "/" + name, "Image": image,
            "Config": {"Image": image_ref, "Labels": {"com.docker.compose.project": project,
                                                      "com.docker.compose.service": service},
                       "ExposedPorts": exposed},
            "HostConfig": {"Privileged": privileged, "NetworkMode": network, "PidMode": pid_mode,
                           "Binds": None, "Mounts": None, "VolumesFrom": None,
                           "CapAdd": None, "Devices": [], "DeviceRequests": [],
                           "DeviceCgroupRules": None, "SecurityOpt": []},
            "Mounts": [], "State": {"Status": state}}


class ContainerActionTests(unittest.TestCase):
    def setUp(self):
        self.policy = action.parse_policy(json.dumps(POLICY).encode())

    def test_policy_exact_identity_and_separate_opt_in(self):
        for invalid in (
            {**POLICY, "containers": []},
            {**POLICY, "containers": [POLICY["containers"][0]] * 2},
            {**POLICY, "containers": [{**POLICY["containers"][0], "name": "sovagrid-hub"}]},
            {**POLICY, "containers": [{**POLICY["containers"][0], "actions": ["start"]}]},
            {**POLICY, "containers": [{**POLICY["containers"][0], "actions": ["status", "stop", "stop"]}]},
            {**POLICY, "containers": [{**POLICY["containers"][0], "actions": ["status", []]}]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                action.parse_policy(json.dumps(invalid).encode())
        with self.assertRaises(ValueError):
            action.parse_policy(b'{"version":1,"version":1,"containers":[]}')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises((OSError, PermissionError)):
                action.read_policy(Path(directory) / "policy.json", Path(directory) / "enabled")

    def test_status_is_read_only_and_mutations_use_fixed_endpoints(self):
        with mock.patch.object(action, "_socket"):
            called = []
            getter = lambda _path, endpoint, **kw: (called.append(("get", endpoint)), inspected())[1]
            poster = lambda _path, endpoint: (called.append(("post", endpoint)), 204)[1]
            result = action.execute("status", IDENT, self.policy, getter=getter, poster=poster)
            self.assertEqual(result, {"action": "status", "id": IDENT,
                                      "result": "ok", "state": "running"})
            self.assertEqual([kind for kind, _ in called], ["get"])
            for verb, before, after, suffix in (
                    ("start", "exited", "running", "start"),
                    ("stop", "running", "exited", "stop?t=10"),
                    ("restart", "running", "running", "restart?t=10")):
                calls = []
                inspections = iter((inspected(before), inspected(after)))
                getter = lambda _path, endpoint, **kw: (calls.append(("get", endpoint)), next(inspections))[1]
                poster = lambda _path, endpoint: (calls.append(("post", endpoint)), 204)[1]
                result = action.execute(verb, IDENT, self.policy, getter=getter,
                                        poster=poster, pre_action_check=lambda: True)
                self.assertEqual(result["result"], "ok")
                self.assertEqual(calls[1], ("post", f"/containers/{IDENT}/{suffix}"))
                self.assertEqual([kind for kind, _ in calls], ["get", "post", "get"])

    def test_no_mutation_on_identity_drift_protected_container_or_peer_change(self):
        with mock.patch.object(action, "_socket"):
            for current in (inspected(name="other"), inspected(image="sha256:" + "c" * 64),
                            inspected(project="sovagrid"), inspected(project="amneziawg"),
                            inspected(service="ssh-gateway"),
                            inspected(image_ref="ghcr.io/sovagrid/agent:latest"),
                            inspected(image_ref="ghcr.io/amneziavpn/awg:latest"),
                            inspected(exposed={"22/tcp": {}}),
                            inspected(privileged=True), inspected(network="host"),
                            inspected(pid_mode="host")):
                with self.subTest(current=current), mock.patch.object(action, "_post") as post:
                    with self.assertRaises(PermissionError):
                        action.execute("stop", IDENT, self.policy, getter=lambda *_args, **_kw: current,
                                       poster=post)
                    post.assert_not_called()
            poster = mock.Mock()
            with self.assertRaises(PermissionError):
                action.execute("stop", IDENT, self.policy,
                               getter=lambda *_args, **_kw: inspected(), poster=poster,
                               pre_action_check=lambda: False)
            with self.assertRaises(PermissionError):
                action.execute("stop", IDENT, self.policy,
                               getter=lambda *_args, **_kw: inspected(), poster=poster)
            poster.assert_not_called()
            self.assertEqual(action.execute("start", IDENT, self.policy,
                             getter=lambda *_args, **_kw: inspected(), poster=poster)["result"], "failed")
            poster.assert_not_called()
        with self.assertRaises(PermissionError):
            action.execute("stop", "c" * 64, self.policy)

    def test_shared_host_resources_and_malformed_inspect_fail_before_post(self):
        baseline = inspected()
        cases = []
        for key, payload in (
                ("Binds", ["/run/docker.sock:/run/docker.sock"]),
                ("Binds", ["/etc/ssh:/data:ro"]),
                ("Binds", ["/opt/sovagrid:/data:ro"]),
                ("Binds", ["/var/lib/amnezia:/data:ro"]),
                ("Mounts", [{"Type": "bind", "Source": "/etc/ssh", "Target": "/data"}]),
                ("VolumesFrom", ["sovagrid-hub:ro"]),
                ("CapAdd", ["NET_ADMIN"]),
                ("CapAdd", ["SYS_ADMIN"]),
                ("Devices", [{"PathOnHost": "/dev/net/tun"}]),
                ("DeviceRequests", [{"Driver": "nvidia"}]),
                ("DeviceCgroupRules", ["c 10:200 rwm"]),
                ("SecurityOpt", ["seccomp=unconfined"]),
                ("Binds", "/etc/ssh"), ("CapAdd", {"NET_ADMIN": True}),
                ("Devices", "device")):
            value = copy.deepcopy(baseline)
            value["HostConfig"][key] = payload
            cases.append((key, value))
        for key, payload in (
                ("Mounts", [{"Type": "bind", "Source": "/run/docker.sock",
                             "Destination": "/run/docker.sock"}]),
                ("Mounts", [{"Type": "volume", "Name": "ordinary-data"}]),
                ("Mounts", {"Source": "/etc/ssh"})):
            value = copy.deepcopy(baseline)
            value[key] = payload
            cases.append((key, value))
        for key, mode in (("IpcMode", "host"), ("UTSMode", "host"),
                          ("UsernsMode", "host"), ("CgroupnsMode", "host"),
                          ("Runtime", "custom-runtime")):
            value = copy.deepcopy(baseline)
            value["HostConfig"][key] = mode
            cases.append((key, value))
        port = copy.deepcopy(baseline)
        port["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostIp": "", "HostPort": "22"}]}
        cases.append(("host SSH port", port))
        missing = copy.deepcopy(baseline)
        missing.pop("Mounts")
        cases.append(("missing Mounts", missing))
        missing = copy.deepcopy(baseline)
        missing["HostConfig"].pop("CapAdd")
        cases.append(("missing CapAdd", missing))
        for field, value in cases:
            with self.subTest(field=field, value=value), mock.patch.object(action, "_socket"), \
                 mock.patch.object(action, "_post") as post:
                with self.assertRaises(PermissionError):
                    action.execute("stop", IDENT, self.policy,
                                   getter=lambda *_args, **_kw: value, poster=post,
                                   pre_action_check=lambda: True)
                post.assert_not_called()

    def test_post_or_reinspect_failure_is_uncertain_never_reported_failed(self):
        with mock.patch.object(action, "_socket"):
            for failure in (TimeoutError("secret"), OSError("secret")):
                with self.subTest(failure=failure):
                    result = action.execute("stop", IDENT, self.policy,
                                            getter=lambda *_args, **_kw: inspected(),
                                            poster=lambda *_args: (_ for _ in ()).throw(failure),
                                            pre_action_check=lambda: True)
                    self.assertEqual(result["result"], "uncertain")
                    self.assertIsNone(result["state"])
            snapshots = iter((inspected(), inspected(name="replaced")))
            result = action.execute("stop", IDENT, self.policy,
                                    getter=lambda *_args, **_kw: next(snapshots),
                                    poster=lambda *_args: 204,
                                    pre_action_check=lambda: True)
            self.assertEqual(result["result"], "uncertain")

    def test_service_broker_wire_requires_canonical_request_and_agent_pid(self):
        request = (json.dumps({"operation": "container_action", "action": "status", "id": IDENT},
                              separators=(",", ":")) + "\n").encode()
        for raw in (request, b'{"action":"status","id":"' + IDENT.encode() +
                    b'","operation":"container_action"}\n'):
            server, client = socket.socketpair()
            try:
                client.sendall(raw)
                if raw == request:
                    self.assertEqual(service_broker._request(server), ("container_action", "status", IDENT))
                else:
                    with self.assertRaises(ValueError):
                        service_broker._request(server)
            finally:
                server.close(); client.close()
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            with mock.patch.object(service_broker, "_peer_identity", return_value=(1234, 1000)), \
                 mock.patch.object(service_broker, "_main_pid", return_value=1234), \
                 mock.patch.object(service_broker, "read_container_action_policy",
                                   return_value=self.policy) as policy_read, \
                 mock.patch.object(service_broker, "execute_container_action",
                                   return_value={"action": "status", "id": IDENT,
                                                 "result": "ok", "state": "running"}) as execute:
                service_broker.handle_connection(server, 1000, "sovagrid-agent.service")
                self.assertEqual(json.loads(client.recv(1024))["state"], "running")
                execute.assert_called_once()
                policy_read.assert_called_once_with(action.POLICY, action.ENABLE)
        finally:
            client.close()
        self.assertEqual(
            service_broker.container_action_policy_paths_for_agent("sovagrid-agent.service"),
            (action.POLICY, action.ENABLE))
        self.assertEqual(
            service_broker.container_action_policy_paths_for_agent("sovagrid-agent-local.service"),
            (action.LOCAL_POLICY, action.LOCAL_ENABLE))
        with self.assertRaises(ValueError):
            service_broker.container_action_policy_paths_for_agent("other.service")
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            with mock.patch.object(service_broker, "_peer_identity", return_value=(1234, 1000)), \
                 mock.patch.object(service_broker, "_main_pid", return_value=1234), \
                 mock.patch.object(service_broker, "read_container_action_policy",
                                   return_value=self.policy) as policy_read, \
                 mock.patch.object(service_broker, "execute_container_action",
                                   return_value={"action": "status", "id": IDENT,
                                                 "result": "ok", "state": "running"}):
                service_broker.handle_connection(server, 1000, "sovagrid-agent-local.service")
                self.assertEqual(json.loads(client.recv(1024))["state"], "running")
                policy_read.assert_called_once_with(action.LOCAL_POLICY, action.LOCAL_ENABLE)
        finally:
            client.close()
        server, client = socket.socketpair()
        try:
            client.sendall(request)
            with mock.patch.object(service_broker, "_peer_identity", return_value=(1234, 1000)), \
                 mock.patch.object(service_broker, "_main_pid", return_value=4321), \
                 mock.patch.object(service_broker, "read_container_action_policy") as policy_read, \
                 mock.patch.object(service_broker, "execute_container_action") as execute:
                service_broker.handle_connection(server, 1000, "sovagrid-agent.service")
                self.assertEqual(client.recv(1024), b"")
                policy_read.assert_not_called()
                execute.assert_not_called()
        finally:
            client.close()


class ContainerActionAgentTests(unittest.TestCase):
    def test_marker_is_exact_and_never_falls_through_to_shell(self):
        command = f"{protocol.MARKER} restart docker {IDENT}"
        self.assertEqual(protocol.parse_command(command), ("restart", IDENT))
        with self.assertRaisesRegex(ValueError, "isolated broker"):
            _command_plan(command, 15)
        for invalid in ("echo " + command, command + "; id", command + "\n",
                        command.replace(" restart ", "  restart "),
                        command.replace(" docker ", " podman "),
                        command.replace(IDENT, IDENT[:12]),
                        command.replace(IDENT, IDENT.upper())):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                protocol.parse_command(invalid)

    def test_request_is_canonical_and_reply_is_exact(self):
        reply = {"action": "status", "id": IDENT, "result": "ok", "state": "running"}

        class Connection:
            def __init__(self):
                self.sent = None
                self.path = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def settimeout(self, timeout):
                self.timeout = timeout

            def connect(self, path):
                self.path = path

            def sendall(self, raw):
                self.sent = raw

            def recv(self, _limit):
                return (json.dumps(reply, separators=(",", ":")) + "\n").encode()

        connection = Connection()
        with mock.patch("sovagrid_agent.container_actions.socket.socket", return_value=connection):
            self.assertEqual(protocol.request_broker("status", IDENT, LOCAL_SOCKET_PATH), reply)
        self.assertEqual(connection.path, LOCAL_SOCKET_PATH)
        self.assertEqual(connection.sent,
                         (f'{{"operation":"container_action","action":"status","id":"{IDENT}"}}\n').encode())
        with self.assertRaises(ValueError):
            protocol.request_broker("status", IDENT, "/tmp/foreign.sock")
        for invalid in (reply | {"debug": "secret"},
                        reply | {"id": "c" * 64},
                        reply | {"result": "ok", "state": None},
                        reply | {"result": True}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                protocol.validate_response(invalid, "status", IDENT)

    def test_agent_projects_broker_result_and_lost_mutation_is_uncertain(self):
        class Client:
            def __init__(self, command):
                self.command = command
                self.results = []

            def push_metrics(self, _report):
                pass

            def next_job(self):
                return {"id": "job", "command": self.command}

            def send_result(self, identifier, value):
                self.results.append((identifier, value))

        status = Client(f"{protocol.MARKER} status docker {IDENT}")
        reply = {"action": "status", "id": IDENT, "result": "ok", "state": "running"}
        with mock.patch("sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent._request_container_action_broker", return_value=reply) as request, \
             mock.patch("sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, status)
            request.assert_called_once_with("status", IDENT, SOCKET_PATH)
            shell.assert_not_called()
        self.assertEqual(status.results[0][1]["state"], "succeeded")
        self.assertEqual(json.loads(status.results[0][1]["output"]), reply)
        mutation = Client(f"{protocol.MARKER} stop docker {IDENT}")
        with mock.patch("sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent._request_container_action_broker", side_effect=TimeoutError), \
             mock.patch("sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, mutation)
            shell.assert_not_called()
        self.assertEqual(mutation.results[0][1]["state"], "timed_out")
        self.assertIn("uncertain", mutation.results[0][1]["output"])
        invalid = Client("echo " + f"{protocol.MARKER} stop docker {IDENT}")
        with mock.patch("sovagrid_agent.agent.collect", return_value={}), mock.patch(
                "sovagrid_agent.agent.os.geteuid", return_value=1000), mock.patch(
                "sovagrid_agent.agent.run_command") as shell:
            run_once({"allow_remote_commands": True}, invalid)
            shell.assert_not_called()
        self.assertEqual(invalid.results[0][1]["state"], "failed")


if __name__ == "__main__":
    unittest.main()
