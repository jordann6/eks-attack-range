"""Unit tests for the pure half of credential_alert.py (no AWS calls)."""
import base64
import gzip
import json
import unittest

import credential_alert as ca

SA = "system:serviceaccount:summarizer:summarizer"


def ct_event(user="svc-backup-sync", name="GetCallerIdentity", error=None):
    detail = {
        "eventID": "e-1", "eventTime": "2026-11-19T03:04:05Z", "eventName": name,
        "eventSource": "sts.amazonaws.com", "sourceIPAddress": "198.51.100.7",
        "userAgent": "aws-cli/2", "userIdentity": {
            "type": "IAMUser", "userName": user, "accessKeyId": "AKIAEXAMPLEEXAMPLE12",
            "arn": f"arn:aws:iam::111122223333:user/{user}"},
    }
    if error:
        detail["errorCode"] = error
    return {"detail-type": "AWS API Call via CloudTrail", "detail": detail}


def audit(user=SA, resource="secrets", name="prod-db-backup-creds", ns="summarizer",
          verb="get", code=200, ips=("10.0.12.34",), pod=None):
    a = {"auditID": "a-1", "requestReceivedTimestamp": "2026-11-19T03:04:06.123456Z",
         "verb": verb, "user": {"username": user}, "sourceIPs": list(ips),
         "objectRef": {"resource": resource, "namespace": ns, "name": name},
         "responseStatus": {"code": code}, "userAgent": "Python-urllib/3.11"}
    if pod:
        a["user"]["extra"] = {ca.POD_NAME_EXTRA: [pod]}
    return a


def awslogs(messages, message_type="DATA_MESSAGE"):
    payload = {"messageType": message_type, "logGroup": "/aws/eks/attack-range/cluster",
               "logEvents": [{"id": str(i), "timestamp": 0, "message": m} for i, m in enumerate(messages)]}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}


class TestD1CloudTrail(unittest.TestCase):
    def test_decoy_user_call_is_a_record(self):
        r = ca.parse_cloudtrail(ct_event())
        self.assertEqual(r["decoy"], ca.D1)
        self.assertEqual(r["outcome"], "Success")
        self.assertEqual(r["access_key_id"], "AKIAEXAMPLEEXAMPLE12")

    def test_access_denied_is_still_a_record(self):
        self.assertEqual(ca.parse_cloudtrail(ct_event(name="ListBuckets", error="AccessDenied"))["outcome"],
                         "AccessDenied")

    def test_other_user_is_ignored(self):
        self.assertIsNone(ca.parse_cloudtrail(ct_event(user="terraform-user")))

    def test_malformed_event_is_ignored_not_raised(self):
        self.assertIsNone(ca.parse_cloudtrail({}))

    def test_mapped_key_attributes_to_secret_mount(self):
        attr = ca.attribution(ca.parse_cloudtrail(ct_event()), "summarizer/backup-sync-aws")
        self.assertEqual(attr, {"method": "secret-mount", "namespace": "summarizer", "secret": "backup-sync-aws"})

    def test_unmapped_key_is_unattributed_not_guessed(self):
        self.assertEqual(ca.attribution(ca.parse_cloudtrail(ct_event()), None)["method"], "none")


class TestD3D4Audit(unittest.TestCase):
    def test_sa_get_of_decoy_secret_is_d3(self):
        self.assertEqual(ca.classify_audit(audit()), ca.D3)

    def test_operator_apply_of_decoy_secret_is_not_d3(self):
        self.assertIsNone(ca.classify_audit(audit(user="arn:aws:sts::111122223333:assumed-role/admin/x",
                                                  verb="create")))

    def test_control_plane_sa_is_not_d3(self):
        self.assertIsNone(ca.classify_audit(audit(user="system:serviceaccount:kube-system:generic-garbage-collector")))

    def test_list_without_name_is_not_d3(self):
        # The documented blind spot: a list names no Secret, so D3 cannot fire.
        self.assertIsNone(ca.classify_audit(audit(verb="list", name=None)))

    def test_same_name_in_other_namespace_is_not_d3(self):
        self.assertIsNone(ca.classify_audit(audit(ns="default")))

    def test_any_request_as_backup_operator_is_d4_even_403(self):
        a = audit(user=ca.DECOY_SA, verb="list", name=None, code=403)
        self.assertEqual(ca.classify_audit(a), ca.D4)
        self.assertEqual(ca.audit_record(a, ca.D4)["outcome"], "403")

    def test_unrelated_event_is_ignored(self):
        self.assertIsNone(ca.classify_audit(audit(resource="pods", name="web-1")))

    def test_source_ip_attribution_with_pod_name_cross_check(self):
        rec = ca.audit_record(audit(pod="summarizer-abc"), ca.D3)
        self.assertEqual(ca.attribution(rec, None),
                         {"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.12.34",
                          "pod_name": "summarizer-abc"})

    def test_legacy_token_has_ip_only(self):
        rec = ca.audit_record(audit(user=ca.DECOY_SA), ca.D4)
        self.assertNotIn("pod_name", ca.attribution(rec, None))

    def test_no_source_ip_is_unattributed(self):
        rec = ca.audit_record(audit(ips=()), ca.D3)
        self.assertEqual(ca.attribution(rec, None)["method"], "none")


class TestPayload(unittest.TestCase):
    def test_decodes_and_picks_out_decoy_events(self):
        msgs = [json.dumps(audit()), json.dumps(audit(resource="pods", name="x")),
                json.dumps(audit(user=ca.DECOY_SA, code=403))]
        recs = ca.parse_audit_payload(ca.decode_awslogs(awslogs(msgs)))
        self.assertEqual([r["decoy"] for r in recs], [ca.D3, ca.D4])

    def test_control_message_is_never_a_detection(self):
        self.assertEqual(ca.parse_audit_payload(ca.decode_awslogs(awslogs([json.dumps(audit())], "CONTROL_MESSAGE"))), [])

    def test_unparseable_log_line_is_skipped(self):
        self.assertEqual(ca.parse_audit_payload(ca.decode_awslogs(awslogs(["not json"]))), [])


class TestRecordKey(unittest.TestCase):
    def test_key_is_decoy_and_event_day(self):
        self.assertEqual(ca.record_key("D3", "2026-11-19T03:04:06Z"), "alerts/D3/20261119.json")

    def test_missing_time_is_explicit(self):
        self.assertEqual(ca.record_key("D1", ""), "alerts/D1/unknown.json")


if __name__ == "__main__":
    unittest.main()
