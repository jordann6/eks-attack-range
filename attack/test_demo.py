"""Unit tests for the stage classification and matrix in demo.py.

These cover the pure logic: that each stage maps an observation to the right
status, and — the point of the rewrite — that an `error` is never silently
rendered as `blocked`.
"""
import unittest

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


if __name__ == "__main__":
    unittest.main()
