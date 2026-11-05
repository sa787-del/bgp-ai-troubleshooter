import tempfile
import time
import unittest
from pathlib import Path

from api.remediation import RemediationError, RemediationManager


DEVICES = [
    {"id": "r1", "name": "Router 1", "host": "127.0.0.1", "ip": "172.20.20.2", "port": 2221,
     "asn": 65001, "peers": ["172.20.20.3"], "enabled": True},
    {"id": "r2", "name": "Router 2", "host": "127.0.0.1", "ip": "172.20.20.3", "port": 2222,
     "asn": 65002, "peers": ["172.20.20.2"], "enabled": True},
]


def run_for(fault="neighbor_passive", evidence=None):
    if evidence is None:
        evidence = [{"tool": "config", "success": True,
                     "parsed": {"peer_passive_check": {"peer": "172.20.20.3", "local_passive": True,
                                                          "passive": True, "peer_neighbor": "172.20.20.2"}}}]
    return {"device_id": "r1", "peer": "172.20.20.3", "mode": "agent",
            "verdict": {"resolved": True, "fault_class": fault, "evidence": []}, "evidence": evidence}


class RemediationPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = RemediationManager(Path(self.temp.name) / "audit.jsonl")

    def tearDown(self):
        self.temp.cleanup()

    def test_passive_plan_uses_inventory_and_real_evidence(self):
        plan = self.manager.prepare("20261028-123456-123456", run_for(), DEVICES)
        self.assertEqual(plan["fault_class"], "neighbor_passive")
        self.assertEqual([r["id"] for r in plan["routers"]], ["r1", "r2"])
        self.assertEqual(plan["changes"][0], ["router bgp 65001", "no neighbor 172.20.20.3 passive"])
        self.assertEqual(plan["rollback"][1], ["router bgp 65002", "neighbor 172.20.20.2 passive"])
        self.assertTrue(plan["confirmation_required"])

    def test_missing_peer_evidence_is_rejected(self):
        run = run_for(evidence=[{"tool": "config", "parsed": {"peer_passive_check": {"local_passive": True}}}])
        with self.assertRaisesRegex(RemediationError, "Both routers"):
            self.manager.prepare("20261028-123456-123456", run, DEVICES)

    def test_route_policy_plan_uses_only_explicit_operator_inputs(self):
        run = run_for("route_filtered", [{"tool": "bgp_state", "success": True,
                                          "parsed": {"queried_peer_state": "Established",
                                                     "queried_peer_state_reason": "Policy"}}])
        plan = self.manager.prepare("20261028-123456-123456", run, DEVICES,
                                    {"prefix_list_name": "INBOUND_APPROVED", "prefixes": ["10.10.0.0/16"]})
        self.assertEqual(plan["changes"][0], ["ip prefix-list INBOUND_APPROVED seq 10 permit 10.10.0.0/16",
                                              "router bgp 65001", "neighbor 172.20.20.3 prefix-list INBOUND_APPROVED in"])
        self.assertEqual(plan["parameters"]["prefixes"], ["10.10.0.0/16"])
        self.assertTrue(plan["requires_extra_input"])
        documentation_range = self.manager.prepare(
            "20261028-123456-123459", run, DEVICES,
            {"prefix_list_name": "INBOUND_TEST", "prefixes": ["192.0.2.0/24"]})
        self.assertEqual(documentation_range["parameters"]["prefixes"], ["192.0.2.0/24"])

    def test_route_policy_requires_operator_inputs_and_rejects_default_route(self):
        run = run_for("route_filtered", [{"tool": "bgp_state", "success": True,
                                          "parsed": {"queried_peer_state": "Established",
                                                     "queried_peer_state_reason": "Policy"}}])
        with self.assertRaisesRegex(RemediationError, "exact operator-approved prefixes"):
            self.manager.prepare("20261028-123456-123456", run, DEVICES)
        with self.assertRaisesRegex(RemediationError, "not accepted"):
            self.manager.prepare("20261028-123456-123456", run, DEVICES,
                                 {"prefix_list_name": "INBOUND_APPROVED", "prefixes": ["0.0.0.0/0"]})

    def test_unsupported_fault_class_is_rejected(self):
        with self.assertRaisesRegex(RemediationError, "not supported"):
            self.manager.prepare("20261028-123456-123456", run_for("unknown_fault"), DEVICES)

    def test_peer_outside_inventory_is_rejected(self):
        with self.assertRaisesRegex(RemediationError, "distinct enabled router"):
            self.manager.prepare("20261028-123456-123456", run_for(), DEVICES[:1])

    def test_unresolved_diagnosis_cannot_prepare_a_change(self):
        run = run_for()
        run["verdict"]["resolved"] = False
        with self.assertRaisesRegex(RemediationError, "Only a resolved diagnosis"):
            self.manager.prepare("20261028-123456-123456", run, DEVICES)

    def test_missing_asn_is_rejected_before_building_commands(self):
        devices = [dict(device) for device in DEVICES]
        devices[0].pop("asn")
        with self.assertRaisesRegex(RemediationError, "valid ASN"):
            self.manager.prepare("20261028-123456-123456", run_for(), devices)

    def test_modified_plan_digest_is_rejected(self):
        plan = self.manager.prepare("20261028-123456-123456", run_for(), DEVICES)
        with self.assertRaisesRegex(RemediationError, "does not match"):
            self.manager.get_confirmed(plan["plan_id"], "0" * 64)

    def test_expired_plan_is_rejected(self):
        expired = RemediationManager(Path(self.temp.name) / "expired.jsonl", ttl_seconds=-1)
        plan = expired.prepare("20261028-123456-123456", run_for(), DEVICES)
        with self.assertRaisesRegex(RemediationError, "expired"):
            expired.get_confirmed(plan["plan_id"], plan["digest"])

    def test_shutdown_fix_requires_live_admin_shutdown_evidence(self):
        evidence = [{"tool": "bgp_neighbor", "success": True,
                     "parsed": {"configured": True, "admin_shutdown": True}}]
        plan = self.manager.prepare("20261028-123456-123456", run_for("neighbor_shutdown", evidence), DEVICES)
        self.assertEqual(plan["changes"][0], ["router bgp 65001", "no neighbor 172.20.20.3 shutdown"])
        self.assertEqual(plan["rollback"][0], ["router bgp 65001", "neighbor 172.20.20.3 shutdown"])


if __name__ == "__main__":
    unittest.main()
