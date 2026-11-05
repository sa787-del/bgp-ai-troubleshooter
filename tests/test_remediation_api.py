import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from api import main
from api.remediation import RemediationManager
from analyzer.verdict import Verdict
from tools.device_client import DeviceResult, FRRDeviceClient


DEVICES = [
    {"id": "r1", "name": "Router 1", "host": "127.0.0.1", "ip": "172.20.20.2", "port": 2221,
     "asn": 65001, "peers": ["172.20.20.3"], "enabled": True},
    {"id": "r2", "name": "Router 2", "host": "127.0.0.1", "ip": "172.20.20.3", "port": 2222,
     "asn": 65002, "peers": ["172.20.20.2"], "enabled": True},
]
RUN = {"device_id": "r1", "peer": "172.20.20.3", "verdict": {"resolved": True, "fault_class": "neighbor_passive"},
       "evidence": [{"tool": "config", "success": True, "parsed": {"peer_passive_check": {
           "peer": "172.20.20.3", "local_passive": True, "passive": True,
           "peer_neighbor": "172.20.20.2"}}}]}
ROUTE_RUN = {"device_id": "r1", "peer": "172.20.20.3", "verdict": {"resolved": True, "fault_class": "route_filtered"},
             "evidence": [{"tool": "bgp_state", "success": True, "parsed": {
                 "queried_peer_state": "Established", "queried_peer_state_reason": "Policy"}}]}


def state_output(peer, state="Established"):
    return ("IPv4 Unicast Summary (VRF default):\n"
            "BGP router identifier 1.1.1.1, local AS number 65001 vrf-id 0\n"
            "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd PfxSnt Desc\n"
            f"{peer} 4 65002 10 10 0 0 0 00:01:00 {state} 0 N/A\n")


class FakeClient:
    def __init__(self, device, fail_command=False):
        self.device = device
        self.fail_command = fail_command
        self.commands = []
        self.peer_state = "Established"

    def run_vtysh(self, host, command):
        if command.startswith("show bgp ipv4 unicast "):
            prefix = command.removeprefix("show bgp ipv4 unicast ")
            return DeviceResult(host, command, True,
                                f"BGP routing table entry for {prefix}, version 2\n  65002\n    172.20.20.3 from 172.20.20.3\n")
        if command == "show running-config":
            peer = "172.20.20.3" if self.device["id"] == "r1" else "172.20.20.2"
            return DeviceResult(host, command, True, f"router bgp {self.device['asn']}\n neighbor {peer} passive\n")
        peer = "172.20.20.3" if self.device["id"] == "r1" else "172.20.20.2"
        return DeviceResult(host, command, True, state_output(peer, self.peer_state))

    def run_vtysh_commands(self, host, commands):
        self.commands.append(commands)
        if self.fail_command:
            return DeviceResult(host, " ; ".join(commands), False, "", "real SSH error")
        return DeviceResult(host, " ; ".join(commands), True, "Configuration applied")


class RemediationEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = RemediationManager(Path(self.temp.name) / "audit.jsonl")
        self.plan_data = self.manager.prepare("20261028-123456-123456", RUN, DEVICES)
        self.plan = self.manager.get_confirmed(self.plan_data["plan_id"], self.plan_data["digest"])
        self.clients = {d["id"]: FakeClient(d) for d in DEVICES}
        self.patcher = patch.multiple(
            main,
            remediation_manager=self.manager,
            RUN_LOG_DIR=Path(self.temp.name),
            resolve_device=lambda host, port: next(device for device in DEVICES if device["port"] == port),
            _remediation_device=lambda d: self.clients[d["id"]],
        )
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def request(self):
        return main.RemediationActionRequest(digest=self.plan_data["digest"], confirm=True)

    def test_apply_is_idempotent_and_duplicate_does_not_repeat_commands(self):
        first = main.apply_remediation(self.plan.id, self.request())
        second = main.apply_remediation(self.plan.id, self.request())
        self.assertEqual(first["status"], "applied")
        self.assertEqual(second, first)
        self.assertEqual(sum(len(c.commands) for c in self.clients.values()), 2)

    def test_apply_stops_on_real_command_error_and_keeps_error(self):
        self.clients["r2"].fail_command = True
        result = main.apply_remediation(self.plan.id, self.request())
        self.assertEqual(result["status"], "partially_applied")
        self.assertEqual(result["results"][-1]["error"], "real SSH error")
        self.assertEqual(len(self.clients["r1"].commands), 1)
        self.assertEqual(len(self.clients["r2"].commands), 1)
        rolled = main.rollback_remediation(self.plan.id, self.request())
        self.assertEqual(rolled["status"], "rolled_back")
        self.assertEqual(len(self.clients["r1"].commands), 2)
        self.assertEqual(len(self.clients["r2"].commands), 1)

    def test_live_verification_succeeds_only_for_established_peers(self):
        self.plan.status = "applied"
        self.plan.applied_targets = [0, 1]
        result = main.verify_remediation(self.plan.id, self.request())
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["checks"]), 2)

    def test_failed_live_verification_exposes_recorded_rollback(self):
        self.plan.status = "applied"
        self.plan.applied_targets = [0, 1]
        self.clients["r2"].peer_state = "Active"
        result = main.verify_remediation(self.plan.id, self.request())
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "verification_failed")
        self.assertEqual(result["checks"][-1]["state"], "Active")
        rolled = main.rollback_remediation(self.plan.id, self.request())
        self.assertEqual(rolled["status"], "rolled_back")

    def test_route_filtered_plan_applies_only_operator_prefixes_and_verifies_live_routes(self):
        plan_data = self.manager.prepare("20261028-123456-123457", ROUTE_RUN, DEVICES,
                                         {"prefix_list_name": "INBOUND_APPROVED", "prefixes": ["10.10.0.0/16"]})
        self.plan_data = plan_data
        self.plan = self.manager.get_confirmed(plan_data["plan_id"], plan_data["digest"])
        applied = main.apply_remediation(self.plan.id, self.request())
        self.assertEqual(applied["status"], "applied")
        self.assertIn("ip prefix-list INBOUND_APPROVED seq 10 permit 10.10.0.0/16", self.clients["r1"].commands[0])
        verified = main.verify_remediation(self.plan.id, self.request())
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["checks"][0]["learned_from_peer"])

    def test_existing_inbound_route_policy_blocks_route_plan(self):
        plan_data = self.manager.prepare("20261028-123456-123458", ROUTE_RUN, DEVICES,
                                         {"prefix_list_name": "INBOUND_APPROVED", "prefixes": ["10.10.0.0/16"]})
        self.plan_data = plan_data
        self.plan = self.manager.get_confirmed(plan_data["plan_id"], plan_data["digest"])
        self.clients["r1"].run_vtysh = lambda host, command: DeviceResult(
            host, command, True, "neighbor 172.20.20.3 prefix-list EXISTING_POLICY in\n")
        with self.assertRaises(HTTPException) as raised:
            main.apply_remediation(self.plan.id, self.request())
        self.assertEqual(raised.exception.status_code, 409)
        self.assertFalse(any(client.commands for client in self.clients.values()))

    def test_failed_precheck_prevents_any_change(self):
        self.clients["r2"].run_vtysh = lambda host, command: DeviceResult(host, command, True, "router bgp 65002\n")
        with self.assertRaises(HTTPException) as raised:
            main.apply_remediation(self.plan.id, self.request())
        self.assertEqual(raised.exception.status_code, 409)
        self.assertFalse(any(client.commands for client in self.clients.values()))

    def test_changed_inventory_target_rejects_prepared_plan(self):
        changed_devices = [dict(device) for device in DEVICES]
        changed_devices[0]["asn"] = 65100
        with patch.object(main, "resolve_device", side_effect=lambda host, port: next(
                device for device in changed_devices if device["port"] == port)):
            with self.assertRaises(HTTPException) as raised:
                main._resolve_plan_targets(self.plan)
        self.assertEqual(raised.exception.status_code, 409)


class ReadOnlyDiagnosisTests(unittest.TestCase):
    def test_existing_diagnose_endpoint_does_not_apply_remediation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verdict = Verdict(True, "Verified by the diagnosis engine", "Operator-reviewed fix",
                              ["bgp_state"], [{"tool": "bgp_state", "success": True, "parsed": {}}],
                              source="agent", fault_class="neighbor_passive")
            with patch.multiple(main, RUN_LOG_DIR=root, RUN_DATA_DIR=root / "run_data",
                                _new_run_id=lambda: "20261028-123456-123456",
                                resolve_device=lambda host, port: DEVICES[0]), \
                 patch("analyzer.agent.investigate", return_value=verdict) as investigate, \
                 patch.object(main.remediation_manager, "prepare") as prepare, \
                 patch.object(main, "_remediation_device") as remediation_device:
                response = TestClient(main.app).post("/diagnose", json={
                    "question": "Why is the peer down?", "host": "127.0.0.1",
                    "device_port": 2221, "peer": "172.20.20.3", "mode": "agent",
                })
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["run_id"], "20261028-123456-123456")
            investigate.assert_called_once()
            prepare.assert_not_called()
            remediation_device.assert_not_called()
            self.assertTrue((root / "run_20261028-123456-123456.log").is_file())
            self.assertTrue((root / "run_data" / "20261028-123456-123456.json").is_file())


class VtyshCommandTests(unittest.TestCase):
    def test_cli_error_on_stdout_is_reported_as_command_failure(self):
        client = FRRDeviceClient()
        with patch.object(client, "_run", return_value=DeviceResult(
                "127.0.0.1", "no neighbor 172.20.20.3 passive", True,
                "% Unknown command: no neighbor 172.20.20.3 passive")):
            result = client.run_vtysh_commands("127.0.0.1", ["no neighbor 172.20.20.3 passive"])
        self.assertFalse(result.success)
        self.assertEqual(result.error, "% Unknown command: no neighbor 172.20.20.3 passive")


if __name__ == "__main__":
    unittest.main()
