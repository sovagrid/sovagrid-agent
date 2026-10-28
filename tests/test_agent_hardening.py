# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The Agent must not expose its memory to same-UID command children."""

import unittest
from types import SimpleNamespace
from unittest import mock

from sovagrid_agent.__main__ import _protect_agent_process


class AgentHardeningTests(unittest.TestCase):
    def test_dumpability_is_disabled_and_verified_before_jobs(self):
        prctl = mock.Mock(side_effect=(0, 0))
        with mock.patch("sovagrid_agent.__main__.sys.platform", "linux"), mock.patch(
                "sovagrid_agent.__main__.ctypes.CDLL",
                return_value=SimpleNamespace(prctl=prctl)):
            _protect_agent_process()
        self.assertEqual([call.args for call in prctl.call_args_list],
                         [(4, 0, 0, 0, 0), (3, 0, 0, 0, 0)])

    def test_failed_or_ineffective_hardening_stops_agent(self):
        for responses in ((-1,), (0, 1)):
            with self.subTest(responses=responses), mock.patch(
                    "sovagrid_agent.__main__.sys.platform", "linux"), mock.patch(
                    "sovagrid_agent.__main__.ctypes.CDLL",
                    return_value=SimpleNamespace(prctl=mock.Mock(side_effect=responses))):
                with self.assertRaisesRegex(RuntimeError, "hardening failed"):
                    _protect_agent_process()


if __name__ == "__main__":
    unittest.main()
