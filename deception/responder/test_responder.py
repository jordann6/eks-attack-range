"""Unit tests for the responder's pure resolution logic."""
import unittest

import responder as r


def pod(name, ip="10.0.1.1", phase="Running", secret=None, projected=None):
    vols = []
    if secret:
        vols.append({"name": "v", "secret": {"secretName": secret}})
    if projected:
        vols.append({"name": "p", "projected": {"sources": [{"secret": {"name": projected}}]}})
    return {"metadata": {"name": name}, "spec": {"volumes": vols}, "status": {"phase": phase, "podIP": ip}}


PODS = [pod("summarizer-a", "10.0.1.5", secret="backup-sync-aws"), pod("receiver-b", "10.0.1.6"),
        pod("summarizer-old", "10.0.1.7", phase="Succeeded", secret="backup-sync-aws")]


class TestSecretMount(unittest.TestCase):
    def test_finds_running_pods_mounting_the_secret(self):
        names, _ = r.resolve_targets({"method": "secret-mount", "namespace": "summarizer",
                                      "secret": "backup-sync-aws"}, PODS)
        self.assertEqual(names, ["summarizer-a"])

    def test_projected_volume_counts(self):
        names, _ = r.resolve_targets({"method": "secret-mount", "namespace": "summarizer", "secret": "s"},
                                     [pod("x", projected="s")])
        self.assertEqual(names, ["x"])

    def test_no_mounting_pod_quarantines_nothing(self):
        names, how = r.resolve_targets({"method": "secret-mount", "namespace": "summarizer", "secret": "nope"}, PODS)
        self.assertEqual(names, [])
        self.assertIn("no running pod", how)


class TestSourceIP(unittest.TestCase):
    def test_ip_match(self):
        names, _ = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.1.5"}, PODS)
        self.assertEqual(names, ["summarizer-a"])

    def test_ip_and_pod_name_agree(self):
        names, how = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.1.5",
                                        "pod_name": "summarizer-a"}, PODS)
        self.assertEqual(names, ["summarizer-a"])
        self.assertIn("agree", how)

    def test_conflict_quarantines_nothing(self):
        names, how = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.1.6",
                                        "pod_name": "summarizer-a"}, PODS)
        self.assertEqual(names, [])
        self.assertIn("conflict", how)

    def test_node_ip_matches_no_pod(self):
        # If the API server sees a node IP instead of the pod IP, say so.
        names, how = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.0.50"}, PODS)
        self.assertEqual(names, [])
        self.assertIn("matched no running pod", how)

    def test_pod_name_fallback_when_ip_misses(self):
        names, _ = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.0.50",
                                      "pod_name": "summarizer-a"}, PODS)
        self.assertEqual(names, ["summarizer-a"])

    def test_ip_of_finished_pod_is_ignored(self):
        names, _ = r.resolve_targets({"method": "source-ip", "namespace": "summarizer", "pod_ip": "10.0.1.7"}, PODS)
        self.assertEqual(names, [])


class TestScope(unittest.TestCase):
    def test_unattributed_is_reported(self):
        names, how = r.resolve_targets({"method": "none", "reason": "no map entry"}, PODS)
        self.assertEqual((names, how), ([], "unattributed: no map entry"))

    def test_namespace_outside_scope_is_refused(self):
        names, how = r.resolve_targets({"method": "source-ip", "namespace": "kube-system", "pod_ip": "10.0.1.5"},
                                       PODS, allowed={"summarizer"})
        self.assertEqual(names, [])
        self.assertIn("outside", how)


class TestRecords(unittest.TestCase):
    def test_quarantine_key_mirrors_alert_key(self):
        self.assertEqual(r.quarantine_key("alerts/D3/20261119.json"), "quarantine/D3/20261119.json")

    def test_empty_pods_is_not_quarantined(self):
        rec = r.quarantine_record({"decoy": "D4", "event_id": "a"}, "alerts/D4/x.json", [], "unattributed", 1.0)
        self.assertFalse(rec["quarantined"])


if __name__ == "__main__":
    unittest.main()
