# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded Linux pressure collection and old/new Hub wire compatibility."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from sovagrid_agent.agent import HubClient
from sovagrid_agent.metrics import cpu_snapshot, cpu_times_percent, pressure


class PressureCollectionTests(unittest.TestCase):
    def test_pressure_omits_missing_or_malformed_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "pressure"
            root.mkdir()
            (root / "cpu").write_text("some avg10=0.25 avg60=1.00 avg300=2.50 total=100\n"
                                        "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            (root / "memory").write_text("some avg10=NaN avg60=1.00 avg300=2.00 total=100\n"
                                           "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            (root / "io").write_text("some avg10=1.00 avg60=2.00 avg300=3.00 total=10\n"
                                       "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                                       + "secret=" + "x" * 513)
            result = pressure(directory)
            self.assertEqual(set(result), {"cpu"})
            self.assertEqual(result["cpu"]["some"]["total_us"], 100)
            self.assertEqual(set(result["cpu"]), {"some"})
            (root / "cpu").unlink()
            self.assertIsNone(pressure(directory))

    def test_cpu_counters_exclude_guest_double_count_and_handle_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "stat").write_text("cpu 30 10 10 40 5 2 1 2 100 50\n")
            before = cpu_snapshot(directory)
            self.assertEqual(before, (100, 45, 5, 2))
            self.assertEqual(cpu_times_percent(before, (200, 70, 15, 7)),
                             {"iowait_percent": 10.0, "steal_percent": 5.0})
            self.assertIsNone(cpu_times_percent(before, (90, 40, 4, 1)))
            self.assertIsNone(cpu_times_percent((100, 20), (200, 40)))


class MetricNegotiationTests(unittest.TestCase):
    def setUp(self):
        self.config = {"hub_url": "https://hub.example", "server_id": "server-A"}
        self.report = {"cpu_percent": 5, "details": {"swap": {"total_bytes": 0},
                       "pressure": {"cpu": {"some": {"avg10": 1}}},
                       "cpu_times": {"iowait_percent": 1, "steal_percent": 2}}}

    def test_old_hub_never_receives_new_fields(self):
        sent = []

        def opener(request, **_):
            sent.append(json.loads(request.data))
            return io.BytesIO(b'{"accepted":true}')

        client = HubClient(self.config, "token", opener=opener)
        client.push_metrics(self.report)
        client.push_metrics(self.report)
        self.assertEqual([item["details"] for item in sent],
                         [{"swap": {"total_bytes": 0}}] * 2)
        self.assertIn("pressure", self.report["details"])

    def test_exact_capability_list_enables_only_advertised_details(self):
        sent = []
        replies = [
            b'{"accepted":true,"metric_details":["pressure"]}',
            b'{"accepted":true,"metric_details":["pressure","cpu_times"]}',
            b'{"accepted":true,"metric_details":["pressure","unknown"]}',
            b'{"accepted":true,"metric_details":[["pressure"]]}',
        ]

        def opener(request, **_):
            sent.append(json.loads(request.data))
            return io.BytesIO(replies.pop(0))

        client = HubClient(self.config, "token", opener=opener)
        for _ in range(4):
            client.push_metrics(self.report)
        self.assertEqual(set(sent[0]["details"]), {"swap"})
        self.assertEqual(set(sent[1]["details"]), {"swap", "pressure"})
        self.assertEqual(set(sent[2]["details"]), {"swap", "pressure", "cpu_times"})
        self.assertEqual(set(sent[3]["details"]), {"swap"})
        self.assertEqual(client._metric_details, frozenset())

    def test_hub_rollback_retries_once_with_legacy_payload(self):
        sent = []
        old_hub = False

        def opener(request, **_):
            sent.append(json.loads(request.data))
            if old_hub and "pressure" in sent[-1]["details"]:
                raise urllib.error.HTTPError(request.full_url, 422, "unsupported details", None, io.BytesIO(b"{}"))
            return io.BytesIO(b'{"accepted":true}' if old_hub else
                              b'{"accepted":true,"metric_details":["pressure","cpu_times"]}')

        client = HubClient(self.config, "token", opener=opener)
        client.push_metrics(self.report)
        old_hub = True
        self.assertEqual(client.push_metrics(self.report), {"accepted": True})
        self.assertEqual(["pressure" in item["details"] for item in sent], [False, True, False])
        self.assertEqual(client._metric_details, frozenset())

    def test_new_hub_receives_filesystem_completeness_without_retry(self):
        report = {**self.report, "details": {**self.report["details"],
                  "filesystems": [{"mountpoint": "/", "total_bytes": 100, "available_bytes": 50}],
                  "filesystems_truncated": True}}
        sent = []

        def opener(request, **_):
            sent.append(json.loads(request.data))
            return io.BytesIO(b'{"accepted":true,"metric_details":["pressure","cpu_times"]}')

        client = HubClient(self.config, "token", opener=opener)
        self.assertTrue(client.push_metrics(report)["accepted"])
        self.assertTrue(client.push_metrics(report)["accepted"])
        self.assertEqual(len(sent), 2)
        self.assertTrue(all(item["details"]["filesystems_truncated"] is True for item in sent))
        self.assertIn("pressure", sent[1]["details"])

    def test_old_hub_retries_without_completeness_but_preserves_inventory(self):
        report = {**self.report, "details": {"filesystems": [{"mountpoint": "/", "total_bytes": 100}],
                                            "filesystems_truncated": True,
                                            "swap": {"total_bytes": 0}}}
        sent = []

        def opener(request, **_):
            sent.append(json.loads(request.data))
            if "filesystems_truncated" in sent[-1]["details"]:
                raise urllib.error.HTTPError(request.full_url, 422, "unsupported details", None,
                                             io.BytesIO(b"{}"))
            return io.BytesIO(b'{"accepted":true}')

        client = HubClient(self.config, "token", opener=opener)
        self.assertEqual(client.push_metrics(report), {"accepted": True})
        self.assertEqual(len(sent), 2)
        self.assertTrue(sent[0]["details"]["filesystems_truncated"])
        self.assertEqual(sent[1]["details"], {"filesystems": report["details"]["filesystems"],
                                             "swap": report["details"]["swap"]})
        self.assertTrue(report["details"]["filesystems_truncated"])

    def test_legacy_retry_is_bounded_when_old_hub_still_rejects(self):
        report = {"cpu_percent": 17, "memory_percent": 42,
                  "details": {"filesystems_truncated": False, "load5": 1.25}}
        sent = []

        def opener(request, **_):
            sent.append(json.loads(request.data))
            raise urllib.error.HTTPError(request.full_url, 422, "invalid core metric", None,
                                         io.BytesIO(b"{}"))

        client = HubClient(self.config, "token", opener=opener)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            client.push_metrics(report)
        caught.exception.close()
        self.assertEqual(len(sent), 2)
        self.assertEqual([item["cpu_percent"] for item in sent], [17, 17])
        self.assertEqual([item["memory_percent"] for item in sent], [42, 42])
        self.assertEqual(sent[1]["details"], {"load5": 1.25})


if __name__ == "__main__":
    unittest.main()
