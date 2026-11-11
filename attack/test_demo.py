"""Unit tests for the stage classification and matrix in demo.py.

These cover the pure logic: that each stage maps an observation to the right
status, and — the point of the rewrite — that an `error` is never silently
rendered as `blocked`.
"""
import json
import unittest
from unittest.mock import patch

import demo
from demo import BLOCKED, ERROR, EXPLOITED, INFO


class TestClassifyRCE(unittest.TestCase):
    def test_command_output_is_exploited(self):
        self.assertEqual(demo.classify_rce(200, "uid=0(root) gid=0"), EXPLOITED)

    def test_rejected_input_is_blocked(self):
        self.assertEqual(demo.classify_rce(400, ""), BLOCKED)

    def test_ran_without_injection_is_blocked(self):
        # Hardened: ping ran via arg vector, no injected command executed.
        self.assertEqual(demo.classify_rce(200, "PING 127.0.0.1 1 packets"), BLOCKED)

    def test_no_response_is_error_not_blocked(self):
        self.assertEqual(demo.classify_rce(None, ""), ERROR)

    def test_server_error_is_error(self):
        self.assertEqual(demo.classify_rce(500, ""), ERROR)


class TestClassifySSRF(unittest.TestCase):
    def test_imds_reached_is_exploited(self):
        body = '{"body":"ami-id\\n169.254.169.254"}'
        self.assertEqual(demo.classify_ssrf(200, body), EXPLOITED)

    def test_no_url_field_rejected_is_blocked(self):
        self.assertEqual(demo.classify_ssrf(422, "field required"), BLOCKED)

    def test_fixed_upstream_response_is_blocked(self):
        body = '{"upstream":"http://receiver...","body":"lab receiver reached"}'
        self.assertEqual(demo.classify_ssrf(200, body), BLOCKED)

    def test_no_response_is_error(self):
        self.assertEqual(demo.classify_ssrf(None, ""), ERROR)


class TestClassifyCanI(unittest.TestCase):
    def test_allowed_is_exploited(self):
        self.assertEqual(demo.classify_can_i(True), EXPLOITED)

    def test_denied_is_blocked(self):
        self.assertEqual(demo.classify_can_i(False), BLOCKED)

    def test_unknown_is_error(self):
        self.assertEqual(demo.classify_can_i(None), ERROR)


class TestClassifySecretTrophy(unittest.TestCase):
    def test_readable_and_present_is_exploited(self):
        self.assertEqual(demo.classify_secret_trophy(True, True), EXPLOITED)

    def test_no_access_is_blocked(self):
        self.assertEqual(demo.classify_secret_trophy(False, True), BLOCKED)

    def test_secret_deleted_is_blocked(self):
        self.assertEqual(demo.classify_secret_trophy(True, False), BLOCKED)

    def test_unknown_is_error(self):
        self.assertEqual(demo.classify_secret_trophy(None, True), ERROR)
        self.assertEqual(demo.classify_secret_trophy(True, None), ERROR)


class TestClassifyLateral(unittest.TestCase):
    def test_no_creds_is_error_not_blocked(self):
        # SSRF held upstream, so the IAM-scope control was never exercised.
        self.assertEqual(demo.classify_lateral(False, None), ERROR)

    def test_creds_and_read_is_exploited(self):
        self.assertEqual(demo.classify_lateral(True, True), EXPLOITED)

    def test_creds_but_denied_is_blocked(self):
        self.assertEqual(demo.classify_lateral(True, False), BLOCKED)

    def test_creds_stolen_but_pivot_unevaluated_is_error_not_blocked(self):
        # The theft succeeded but the pivot attempt itself errored (e.g. no aws
        # CLI). A collection gap, never a verdict that the control held.
        self.assertEqual(demo.classify_lateral(True, None), ERROR)


class TestMatrix(unittest.TestCase):
    def test_build_matrix_joins_by_stage(self):
        baseline = {s[0]: {"status": EXPLOITED} for s in demo.STAGES}
        hardened = {s[0]: {"status": BLOCKED} for s in demo.STAGES}
        hardened["0"] = {"status": INFO}
        rows = demo.build_matrix(baseline, hardened)
        self.assertEqual(len(rows), len(demo.STAGES))
        self.assertEqual(rows[1]["baseline"], EXPLOITED)
        self.assertEqual(rows[1]["hardened"], BLOCKED)

    def test_missing_stage_defaults_to_error_not_blocked(self):
        rows = demo.build_matrix({}, {})
        for r in rows:
            self.assertEqual(r["baseline"], ERROR)
            self.assertEqual(r["hardened"], ERROR)

    def test_render_matrix_contains_all_stages(self):
        rows = demo.build_matrix({}, {})
        text = demo.render_matrix(rows)
        for sid, _, _ in demo.STAGES:
            self.assertIn(f"| {sid} |", text)


class TestStealNodeCredentials(unittest.TestCase):
    """_steal_node_credentials drives the IMDSv2 dance through _ssrf_fetch.
    Mock the SSRF hop, not the network: this is the exact path that shipped
    with stage 3 always wired to None, so it stays covered."""

    def test_full_dance_returns_creds(self):
        responses = iter(["tok123", "ec2-node-role\n", json.dumps(
            {"AccessKeyId": "AKIALAB", "SecretAccessKey": "s3cr3t", "Token": "tok"})])
        with patch("demo._ssrf_fetch", side_effect=lambda *a, **k: next(responses)):
            creds = demo._steal_node_credentials("http://app")
        self.assertEqual(creds["AccessKeyId"], "AKIALAB")

    def test_token_hop_fails_returns_none(self):
        with patch("demo._ssrf_fetch", return_value=None):
            self.assertIsNone(demo._steal_node_credentials("http://app"))

    def test_creds_hop_returns_malformed_json_is_none(self):
        responses = iter(["tok123", "ec2-node-role\n", "not json"])
        with patch("demo._ssrf_fetch", side_effect=lambda *a, **k: next(responses)):
            self.assertIsNone(demo._steal_node_credentials("http://app"))


class TestPivotReadLoot(unittest.TestCase):
    def _creds(self):
        return {"AccessKeyId": "AKIALAB", "SecretAccessKey": "s3cr3t", "Token": "tok"}

    def test_successful_read_is_true(self):
        with patch("demo.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stderr = ""
            self.assertTrue(demo._pivot_read_loot(self._creds()))

    def test_access_denied_is_false_not_none(self):
        with patch("demo.subprocess.run") as run:
            run.return_value.returncode = 254
            run.return_value.stderr = "An error occurred (AccessDeniedException)"
            self.assertFalse(demo._pivot_read_loot(self._creds()))

    def test_cli_missing_is_none_not_a_verdict(self):
        with patch("demo.subprocess.run", side_effect=FileNotFoundError):
            self.assertIsNone(demo._pivot_read_loot(self._creds()))


if __name__ == "__main__":
    unittest.main()
