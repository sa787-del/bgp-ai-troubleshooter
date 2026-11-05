"""Allow-listed, run-bound remediation plans. No LLM text is executed."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

PLAN_TTL_SECONDS = 300


class RemediationError(ValueError):
    pass


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError) as exc:
        raise RemediationError("A required router or peer IP is missing or invalid.") from exc


def _asn(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise RemediationError("Router inventory is missing a valid ASN.") from exc
    if not 1 <= number <= 4294967295:
        raise RemediationError("Router inventory contains an invalid ASN.")
    return number


def _public_plan_body(body: dict) -> dict:
    return {key: value for key, value in body.items() if key not in {"id", "digest", "expires_at"}}


@dataclass
class Plan:
    id: str
    digest: str
    expires_at: float
    run_id: str
    fault_class: str
    peer_ip: str
    body: dict
    targets: list[dict]
    apply_commands: list[list[str]]
    rollback_commands: list[list[str]]
    pre_checks: list[dict]
    post_checks: list[dict]
    status: str = "prepared"
    applied_targets: list[int] = field(default_factory=list)
    result: dict | None = None


@dataclass(frozen=True)
class RemediationParameters:
    """Validated values derived only from the run and enabled inventory."""
    local_device_id: str
    peer_ip: str
    local_ip: str
    local_asn: int
    prefix_list_name: str | None = None
    prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationSpec:
    title: str
    expected_effect: str
    targets: list[dict]
    apply_commands: list[list[str]]
    rollback_commands: list[list[str]]


@dataclass(frozen=True)
class RemediationDefinition:
    fault_class: str
    evidence_tool: str
    required_evidence: str
    pre_checks: tuple[str, ...]
    post_checks: tuple[str, ...]
    validate_evidence: Callable[[dict, RemediationParameters], None]
    build: Callable[[RemediationParameters, list[dict]], RemediationSpec]
    requires_confirmation: bool = True
    requires_extra_input: bool = False


def _validate_passive_evidence(parsed: dict, params: RemediationParameters) -> None:
    check = parsed.get("peer_passive_check") or {}
    if (check.get("local_passive") is not True or check.get("passive") is not True
            or _same_ip(check.get("peer"), params.peer_ip) is False
            or _same_ip(check.get("peer_neighbor"), params.local_ip) is False):
        raise RemediationError("Live evidence must confirm matching passive neighbor statements on both routers.")


def _validate_shutdown_evidence(parsed: dict, _params: RemediationParameters) -> None:
    if parsed.get("configured") is not True or parsed.get("admin_shutdown") is not True:
        raise RemediationError("Live neighbor evidence must confirm this configured neighbor is administratively shut down.")


def _validate_route_filtered_evidence(parsed: dict, _params: RemediationParameters) -> None:
    if parsed.get("queried_peer_state") != "Established" or parsed.get("queried_peer_state_reason") != "Policy":
        raise RemediationError("Live BGP evidence must show this peer Established with the Policy reason before a route policy can be proposed.")


def _build_passive_fix(params: RemediationParameters, devices: list[dict]) -> RemediationSpec:
    remote = next((device for device in devices if _same_ip(device.get("ip"), params.peer_ip)), None)
    if not remote or remote["id"] == params.local_device_id:
        raise RemediationError("The peer is not a distinct enabled router in the inventory.")
    local = next(device for device in devices if device["id"] == params.local_device_id)
    local_peers = {_ip(value) for value in (local.get("peers") or [])}
    remote_peers = {_ip(value) for value in (remote.get("peers") or [])}
    if params.peer_ip not in local_peers:
        raise RemediationError("The peer is not listed for this router in the enabled inventory.")
    if params.local_ip not in remote_peers:
        raise RemediationError("The router is not listed as a peer in the remote router's enabled inventory entry.")
    remote_asn = _asn(remote.get("asn"))
    return RemediationSpec(
        title="Allow one router to initiate the BGP session",
        expected_effect="Removes passive mode from both verified peer statements; FRR can then initiate the TCP session.",
        targets=[local, remote],
        apply_commands=[
            ["configure terminal", f"router bgp {params.local_asn}", f"no neighbor {params.peer_ip} passive", "end"],
            ["configure terminal", f"router bgp {remote_asn}", f"no neighbor {params.local_ip} passive", "end"],
        ],
        rollback_commands=[
            ["configure terminal", f"router bgp {params.local_asn}", f"neighbor {params.peer_ip} passive", "end"],
            ["configure terminal", f"router bgp {remote_asn}", f"neighbor {params.local_ip} passive", "end"],
        ],
    )


def _build_shutdown_fix(params: RemediationParameters, devices: list[dict]) -> RemediationSpec:
    local = next(device for device in devices if device["id"] == params.local_device_id)
    return RemediationSpec(
        title="Re-enable the administratively shut down BGP neighbor",
        expected_effect="Removes the confirmed shutdown statement for this neighbor.",
        targets=[local],
        apply_commands=[["configure terminal", f"router bgp {params.local_asn}", f"no neighbor {params.peer_ip} shutdown", "end"]],
        rollback_commands=[["configure terminal", f"router bgp {params.local_asn}", f"neighbor {params.peer_ip} shutdown", "end"]],
    )


def _build_route_policy(params: RemediationParameters, devices: list[dict]) -> RemediationSpec:
    local = next(device for device in devices if device["id"] == params.local_device_id)
    if params.peer_ip not in {_ip(value) for value in (local.get("peers") or [])}:
        raise RemediationError("The peer is not listed for this router in the enabled inventory.")
    if not params.prefix_list_name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", params.prefix_list_name):
        raise RemediationError("Enter a prefix-list name starting with a letter and containing only letters, numbers, underscores, or hyphens (maximum 32 characters).")
    if not 1 <= len(params.prefixes) <= 20:
        raise RemediationError("Enter between 1 and 20 operator-approved IPv4 prefixes.")
    validated = []
    for value in params.prefixes:
        try:
            network = ipaddress.IPv4Network(value, strict=True)
        except (ValueError, TypeError) as exc:
            raise RemediationError(f"Invalid IPv4 network {value!r}; use a network address with CIDR notation, such as 192.0.2.0/24.") from exc
        if network.prefixlen == 0 or network.is_multicast or network.is_unspecified or network.is_loopback or network.is_link_local:
            raise RemediationError(f"Prefix {value!r} is not accepted for an automatic inbound route policy.")
        validated.append(str(network))
    if len(set(validated)) != len(validated):
        raise RemediationError("Remove duplicate prefixes before preparing the plan.")
    prefix_commands = [f"ip prefix-list {params.prefix_list_name} seq {index * 10} permit {prefix}"
                       for index, prefix in enumerate(validated, start=1)]
    return RemediationSpec(
        title="Permit the operator-approved routes from this BGP peer",
        expected_effect="Creates an exact-match inbound prefix list for only the prefixes you entered and attaches it to this peer. Other prefixes remain denied by the list.",
        targets=[local],
        apply_commands=[["configure terminal", *prefix_commands, f"router bgp {params.local_asn}",
                         f"neighbor {params.peer_ip} prefix-list {params.prefix_list_name} in", "end"]],
        rollback_commands=[["configure terminal", f"router bgp {params.local_asn}",
                            f"no neighbor {params.peer_ip} prefix-list {params.prefix_list_name} in",
                            "exit", f"no ip prefix-list {params.prefix_list_name}", "end"]],
    )


REMEDIATION_REGISTRY: dict[str, RemediationDefinition] = {
    "neighbor_passive": RemediationDefinition(
        fault_class="neighbor_passive", evidence_tool="config",
        required_evidence="Both routers' live configs must confirm the same peer statements are passive.",
        pre_checks=("Re-read each target's running BGP config and verify the exact fault is still present.",),
        post_checks=("Re-read BGP state on every target; the peer must be Established.",),
        validate_evidence=_validate_passive_evidence, build=_build_passive_fix,
    ),
    "neighbor_shutdown": RemediationDefinition(
        fault_class="neighbor_shutdown", evidence_tool="bgp_neighbor",
        required_evidence="Live neighbor output must confirm that the configured peer is administratively shut down.",
        pre_checks=("Re-read the target's running BGP config and verify the exact shutdown fault is still present.",),
        post_checks=("Re-read BGP state on the target; the peer must be Established.",),
        validate_evidence=_validate_shutdown_evidence, build=_build_shutdown_fix,
    ),
    "route_filtered": RemediationDefinition(
        fault_class="route_filtered", evidence_tool="bgp_state",
        required_evidence="A live BGP state result for this peer is required.",
        pre_checks=("Re-read the target's running config; reject an existing inbound route policy or a conflicting prefix-list name.",),
        post_checks=("Query every approved prefix from the live BGP table and confirm it is learned from this peer.",),
        validate_evidence=_validate_route_filtered_evidence, build=_build_route_policy,
        requires_extra_input=True,
    ),
}


class RemediationManager:
    """Server-side plan store prevents clients from altering commands/targets."""

    def __init__(self, audit_path: Path, ttl_seconds: int = PLAN_TTL_SECONDS):
        self.audit_path = audit_path
        self.ttl_seconds = ttl_seconds
        self._plans: dict[str, Plan] = {}
        self._lock = threading.RLock()

    def prepare(self, run_id: str, run: dict, devices: list[dict], extra_input: dict | None = None) -> dict:
        verdict = run.get("verdict") or {}
        if verdict.get("resolved") is not True:
            raise RemediationError("Only a resolved diagnosis can be prepared for automatic remediation.")
        fault = verdict.get("fault_class")
        definition = REMEDIATION_REGISTRY.get(fault)
        if not definition:
            raise RemediationError(f"Automatic resolution is not supported for fault class {fault!r}.")
        host_id, peer = run.get("device_id"), run.get("peer")
        local = next((d for d in devices if d.get("id") == host_id), None)
        if not local:
            raise RemediationError("The router from this run is no longer in the enabled inventory.")
        peer_ip = _ip(peer)
        local_ip = _ip(local.get("ip", ""))
        params = RemediationParameters(
            local_device_id=str(local["id"]), peer_ip=peer_ip, local_ip=local_ip,
            local_asn=_asn(local.get("asn")),
        )
        extra_input = extra_input or {}
        if definition.requires_extra_input:
            raw_prefixes = extra_input.get("prefixes")
            name = extra_input.get("prefix_list_name")
            if not isinstance(raw_prefixes, list) or not all(isinstance(value, str) and value.strip() for value in raw_prefixes):
                raise RemediationError("Enter the exact operator-approved prefixes this router should accept from the peer.")
            if not isinstance(name, str) or not name.strip():
                raise RemediationError("Enter a prefix-list name for the proposed inbound policy.")
            params = RemediationParameters(
                local_device_id=params.local_device_id, peer_ip=params.peer_ip, local_ip=params.local_ip,
                local_asn=params.local_asn, prefix_list_name=name.strip(),
                prefixes=tuple(value.strip() for value in raw_prefixes),
            )
        evidence = next((item for item in run.get("evidence", []) if item.get("tool") == definition.evidence_tool), None)
        if not evidence or evidence.get("success") is not True:
            raise RemediationError(definition.required_evidence)
        definition.validate_evidence(evidence.get("parsed") or {}, params)
        spec = definition.build(params, devices)
        targets, apply, rollback = spec.targets, spec.apply_commands, spec.rollback_commands

        body = {
            "run_id": run_id,
            "fault_class": definition.fault_class,
            "title": spec.title,
            "expected_effect": spec.expected_effect,
            "parameters": {
                "local_device_id": params.local_device_id,
                "peer_ip": params.peer_ip,
                "local_ip": params.local_ip,
                "local_asn": params.local_asn,
                "prefix_list_name": params.prefix_list_name,
                "prefixes": list(params.prefixes),
            },
            "routers": [{"id": d["id"], "name": d["name"], "ip": d.get("ip"), "port": d["port"]} for d in targets],
            "changes": [[c for c in commands if c not in {"configure terminal", "end"}] for commands in apply],
            "rollback": [[c for c in commands if c not in {"configure terminal", "end"}] for commands in rollback],
            "pre_checks": list(definition.pre_checks),
            "post_checks": list(definition.post_checks),
            "confirmation_required": definition.requires_confirmation,
            "requires_extra_input": definition.requires_extra_input,
            "expires_in_seconds": self.ttl_seconds,
        }
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        plan_id = secrets.token_urlsafe(32)
        expires = time.time() + self.ttl_seconds
        plan = Plan(plan_id, digest, expires, run_id, definition.fault_class, peer_ip, body, targets, apply, rollback,
                    body["pre_checks"], body["post_checks"])
        with self._lock:
            self._plans[plan_id] = plan
        self._audit({"event": "plan_prepared", "run_id": run_id, "plan_id": plan_id,
                     "fault_class": definition.fault_class, "target_ids": [d["id"] for d in targets]})
        return {"plan_id": plan_id, "digest": digest, "expires_at": expires, **body}

    def get_confirmed(self, plan_id: str, digest: str) -> Plan:
        with self._lock:
            plan = self._plans.get(plan_id)
            if not plan:
                raise RemediationError("Remediation plan was not found or has expired.")
            if time.time() >= plan.expires_at:
                self._plans.pop(plan_id, None)
                raise RemediationError("Remediation plan has expired. Prepare a new plan.")
            if not secrets.compare_digest(plan.digest, digest or ""):
                raise RemediationError("Plan confirmation does not match the prepared plan.")
            return plan

    def audit(self, event: dict):
        self._audit(event)

    def _audit(self, event: dict):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": time.time(), **event}, separators=(",", ":")) + "\n")


def _same_ip(value, expected: str) -> bool:
    try:
        return _ip(value) == expected
    except (ValueError, TypeError):
        return False
