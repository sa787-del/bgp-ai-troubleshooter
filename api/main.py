"""
Tool cohort REST service.

Exposes each tool at the endpoint recorded in the Rules DB so the analyzer can
call tools without knowing SSH/vtysh details.
"""

import json
import logging
import os
import re
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from tools.device_client import FRRDeviceClient

from tools.bgp_state import BGPStateTool
from tools.bgp_neighbor import BGPNeighborTool
from tools.interface import InterfaceTool
from tools.tcp_port import TCPPortTool
from tools.config import ConfigTool
from tools.route_table import RouteTableTool
from tools.route_map import RouteMapTool
from tools.route_to_peer import RouteToPeerTool
from tools.prefix_list import PrefixListTool
from rules_db.rules_db import RulesDB

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
INVENTORY_PATH = Path(os.getenv("DEVICE_INVENTORY_FILE", str(ROOT / "config" / "devices.json")))

app = FastAPI(title="BGP AI Troubleshooter API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

rules_db = RulesDB()

log = logging.getLogger(__name__)
RUN_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
RUN_DATA_DIR = RUN_LOG_DIR / "run_data"
RUN_ID_RE = re.compile(r"\d{8}-\d{6}(?:-\d{6})?")
_diagnosis_lock = threading.Lock()
_remediation_lock = threading.RLock()

from api.remediation import RemediationError, RemediationManager

remediation_manager = RemediationManager(RUN_LOG_DIR / "remediation_audit.jsonl")


class DeviceRequest(BaseModel):
    host: str
    device_port: int = Field(default=2221, ge=1, le=65535)


class BGPStateRequest(DeviceRequest):
    peer: str | None = None


class BGPNeighborRequest(DeviceRequest):
    peer: str


class InterfaceRequest(DeviceRequest):
    interface: str | None = None


class TCPCheckRequest(DeviceRequest):
    peer_ip: str
    port: int = 179


class ConfigDiffRequest(DeviceRequest):
    pass


class RouteTableRequest(DeviceRequest):
    prefix: str | None = None


class RouteMapRequest(DeviceRequest):
    name: str | None = None


class RouteToPeerRequest(DeviceRequest):
    peer: str


class PrefixListRequest(DeviceRequest):
    name: str | None = None
    prefix: str | None = None


class DiagnoseRequest(DeviceRequest):
    question: str = Field(min_length=1)
    peer: str = Field(min_length=1)
    mode: Literal["agent", "rules"] = "agent"


class PrepareRemediationRequest(BaseModel):
    run_id: str
    prefix_list_name: str | None = None
    prefixes: list[str] | None = Field(default=None, max_length=20)


class RemediationActionRequest(BaseModel):
    digest: str = Field(min_length=64, max_length=64)
    confirm: bool


def load_devices() -> list[dict]:
    if not INVENTORY_PATH.is_file():
        raise HTTPException(status_code=500, detail=f"Device inventory file not found: {INVENTORY_PATH}")
    try:
        entries = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Device inventory is unreadable or invalid JSON") from exc
    if not isinstance(entries, list):
        raise HTTPException(status_code=500, detail="Device inventory must be a JSON list")
    required = ("id", "name", "host", "ip", "port")
    devices, ids, targets = [], set(), set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise HTTPException(status_code=500, detail=f"Inventory entry {index} must be an object")
        missing = [key for key in required if key not in entry]
        if missing:
            raise HTTPException(status_code=500, detail=f"Inventory entry {index} is missing: {', '.join(missing)}")
        device = dict(entry)
        device_id, name, host = (str(device[key]).strip() for key in ("id", "name", "host"))
        try:
            port = int(device["port"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=500, detail=f"Invalid SSH port for device {device_id}") from exc
        if not device_id or not name or not host or not 1 <= port <= 65535:
            raise HTTPException(status_code=500, detail=f"Invalid inventory entry at index {index}")
        if device_id in ids:
            raise HTTPException(status_code=500, detail=f"Duplicate device id: {device_id}")
        if (host, port) in targets:
            raise HTTPException(status_code=500, detail=f"Duplicate SSH target: {host}:{port}")
        ids.add(device_id)
        targets.add((host, port))
        device.update({"id": device_id, "name": name, "host": host, "port": port, "enabled": bool(device.get("enabled", True))})
        device.setdefault("peers", [device["peer"]] if device.get("peer") else [])
        devices.append(device)
    return [device for device in devices if device["enabled"]]


def public_device(device: dict) -> dict:
    allowed = ("id", "name", "host", "ip", "port", "asn", "rid", "peer", "peers", "platform", "enabled")
    return {key: device[key] for key in allowed if key in device}


def resolve_device(host: str, port: int) -> dict:
    for device in load_devices():
        if host in {device["host"], str(device.get("ip", ""))} and port == device["port"]:
            return device
    raise HTTPException(status_code=400, detail="Target host/port is not in the enabled device inventory. Update config/devices.json first.")


def run_tool(tool_class, req: DeviceRequest, *args):
    device = resolve_device(req.host, req.device_port)
    password = os.getenv("FRR_SSH_PASSWORD")
    if not password:
        raise HTTPException(status_code=500, detail="FRR_SSH_PASSWORD is not set. Copy .env.example to .env and fill it in.")
    client = FRRDeviceClient(username=os.getenv("FRR_SSH_USERNAME", "admin"), password=password,
                             port=device["port"], timeout=float(os.getenv("FRR_SSH_TIMEOUT", "8")))
    try:
        return tool_class(device_client=client).run(device["host"], *args).to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        log.exception("Tool execution failed: %s", tool_class.__name__)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/devices")
def devices_endpoint():
    return {"devices": [public_device(device) for device in load_devices()]}


@app.post("/tools/bgp/state")
def bgp_state(req: BGPStateRequest):
    return run_tool(BGPStateTool, req, req.peer)


@app.post("/tools/bgp/neighbor")
def bgp_neighbor(req: BGPNeighborRequest):
    return run_tool(BGPNeighborTool, req, req.peer)


@app.post("/tools/interface/detail")
def interface_detail(req: InterfaceRequest):
    return run_tool(InterfaceTool, req, req.interface)


@app.post("/tools/tcp/check")
def tcp_check(req: TCPCheckRequest):
    return run_tool(TCPPortTool, req, req.peer_ip, req.port)


@app.post("/tools/config/diff")
def config_diff(req: ConfigDiffRequest):
    return run_tool(ConfigTool, req)


@app.post("/tools/route/table")
def route_table(req: RouteTableRequest):
    return run_tool(RouteTableTool, req, req.prefix)


@app.post("/tools/route/map")
def route_map(req: RouteMapRequest):
    return run_tool(RouteMapTool, req, req.name)


@app.post("/tools/route/peer")
def route_to_peer(req: RouteToPeerRequest):
    return run_tool(RouteToPeerTool, req, req.peer)


@app.post("/tools/route/prefix-list")
def prefix_list(req: PrefixListRequest):
    return run_tool(PrefixListTool, req, req.name, req.prefix)


# --- Rules DB read endpoints ---

@app.get("/rules/intents")
def list_intents():
    return {"intents": rules_db.list_intents()}


@app.get("/rules/tools")
def list_tools():
    return {"tools": [tool.__dict__ for tool in rules_db.list_tools()]}


@app.get("/rules/catalog")
def catalog():
    return {
        "tools": [tool.__dict__ for tool in rules_db.list_tools()],
        "rules": [rule.__dict__ for rule in rules_db.list_rules()],
    }


@app.get("/rules/{intent}")
def get_rule_for_intent(intent: str):
    tools = rules_db.get_tools_for_intent(intent)
    if not tools:
        raise HTTPException(status_code=404, detail=f"No rule found for intent '{intent}'")
    rule = rules_db.get_rule(intent)
    return {
        "intent": intent,
        "tools": [tool.__dict__ for tool in tools],
        "next_intent_on_fail": rule.next_intent_on_fail,
        "symptoms": rule.symptoms,
        "likely_causes": rule.likely_causes,
        "verification": rule.verification,
    }


def _new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def _verdict_payload(verdict, mode: str) -> dict:
    payload = asdict(verdict)
    if mode == "agent":
        evidence = payload.get("evidence") or []
        steps = payload.get("steps") or []
        if not steps:
            for index, tool in enumerate(payload.get("checked") or []):
                step = {"tool": tool}
                item = evidence[index] if index < len(evidence) else {}
                for field in ("parsed", "raw_output"):
                    if item.get(field) not in (None, ""):
                        step[field] = item[field]
                steps.append(step)
            payload["steps"] = steps
        evidence_index = 0
        for step in steps:
            if "rejected" in step:
                continue
            if evidence_index >= len(evidence):
                break
            item = evidence[evidence_index]
            evidence_index += 1
            for field in ("parsed", "raw_output"):
                if item.get(field) not in (None, ""):
                    step[field] = item[field]
    return payload

@app.post("/diagnose")
def diagnose_endpoint(req: DiagnoseRequest):
    """Call the existing investigator or rules engine and write its real run log."""
    from analyzer.agent import investigate
    from analyzer import llm_client
    from analyzer.rest_client import RestClient
    from analyzer.rules_engine import diagnose

    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    run_id = _new_run_id()
    log_path = RUN_LOG_DIR / f"run_{run_id}.log"
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    run_thread_id = threading.get_ident()
    handler.addFilter(lambda record: threading.get_ident() == run_thread_id)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-24s %(message)s"
    ))
    analyzer_logger = logging.getLogger("analyzer")
    analyzer_logger.setLevel(logging.DEBUG)
    analyzer_logger.addHandler(handler)
    run_logger = logging.getLogger("analyzer.api")
    usage_token = llm_client.start_usage_tracking()
    llm_usage = None

    try:
        with _diagnosis_lock:
            device = resolve_device(req.host, req.device_port)
            run_logger.info(
                "Run started: question=%r host=%s device_port=%s peer=%s mode=%s",
                req.question,
                device.get("ip", device["host"]),
                device["port"],
                req.peer,
                req.mode,
            )
            client = RestClient(
                os.getenv("ANALYZER_API_BASE", "http://localhost:8000").rstrip("/"),
                timeout=int(os.getenv("ANALYZER_TOOL_TIMEOUT", "30")),
            )
            if req.mode == "agent":
                verdict = investigate(
                    client=client,
                    question=req.question.strip(),
                    host=device.get("ip", device["host"]),
                    peer=req.peer.strip(),
                    device_port=device["port"],
                )
            else:
                verdict = diagnose(
                    client=client,
                    question=req.question.strip(),
                    host=device.get("ip", device["host"]),
                    peer=req.peer.strip(),
                    device_port=device["port"],
                )
            llm_usage = llm_client.finish_usage_tracking(usage_token)
            usage_token = None
            payload = _verdict_payload(verdict, req.mode)
            payload["llm_usage"] = llm_usage
            run_logger.info("Verdict: %s", verdict.pretty())
            run_logger.info("Run finished")
            payload["run_id"] = run_id
            RUN_DATA_DIR.mkdir(parents=True, exist_ok=True)
            run_record = {
                "run_id": run_id,
                "device_id": device["id"],
                "peer": req.peer.strip(),
                "mode": req.mode,
                "verdict": {
                    key: payload.get(key) for key in
                    ("resolved", "fault_class", "root_cause", "suggested_fix", "checked", "steps")
                },
                "llm_usage": llm_usage,
                "evidence": [
                    {"tool": item.get("tool"), "success": item.get("success"), "parsed": item.get("parsed")}
                    for item in (payload.get("evidence") or [])
                ],
            }
            data_path = RUN_DATA_DIR / f"{run_id}.json"
            temp_path = data_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(run_record, ensure_ascii=False), encoding="utf-8")
            temp_path.replace(data_path)
            return payload
    except HTTPException:
        run_logger.exception("Run failed")
        raise
    except Exception as exc:
        run_logger.exception("Run failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        if usage_token is not None:
            llm_client.finish_usage_tracking(usage_token)
        analyzer_logger.removeHandler(handler)
        handler.close()


@app.get("/runs")
def list_runs():
    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    runs = sorted(
        (
            path.stem.removeprefix("run_")
            for path in RUN_LOG_DIR.glob("run_*.log")
            if RUN_ID_RE.fullmatch(path.stem.removeprefix("run_"))
        ),
        reverse=True,
    )
    return {"runs": runs}


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    if not RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    path = RUN_LOG_DIR / f"run_{run_id}.log"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    return FileResponse(path, media_type="text/plain", filename=path.name)


@app.get("/usage/llm")
def llm_usage_summary():
    """Aggregate provider-reported LLM tokens from saved diagnosis logs."""
    response_line = re.compile(
        r"LLM response: model=(\S+).*?input_tokens=(\d+|None).*?output_tokens=(\d+|None)"
    )
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
              "call_count": 0, "reported_call_count": 0, "calls_by_model": {}}
    runs_with_calls = 0
    for path in RUN_LOG_DIR.glob("run_*.log"):
        try:
            contents = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = list(response_line.finditer(contents))
        if matches:
            runs_with_calls += 1
        for match in matches:
            model, input_value, output_value = match.groups()
            totals["call_count"] += 1
            model_total = totals["calls_by_model"].setdefault(
                model, {"call_count": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            )
            model_total["call_count"] += 1
            if input_value == "None" or output_value == "None":
                continue
            input_tokens, output_tokens = int(input_value), int(output_value)
            totals["reported_call_count"] += 1
            totals["input_tokens"] += input_tokens
            totals["output_tokens"] += output_tokens
            totals["total_tokens"] += input_tokens + output_tokens
            model_total["input_tokens"] += input_tokens
            model_total["output_tokens"] += output_tokens
            model_total["total_tokens"] += input_tokens + output_tokens
    return {"runs_with_calls": runs_with_calls, **totals}


def _remediation_device(device: dict) -> FRRDeviceClient:
    password = os.getenv("FRR_SSH_PASSWORD")
    if not password:
        raise HTTPException(status_code=500, detail="FRR_SSH_PASSWORD is not set.")
    return FRRDeviceClient(
        username=os.getenv("FRR_SSH_USERNAME", "admin"), password=password,
        port=device["port"], timeout=float(os.getenv("FRR_SSH_TIMEOUT", "8")),
    )


def _resolve_plan_targets(plan) -> list[dict]:
    current = []
    for target in plan.targets:
        device = resolve_device(str(target.get("ip") or target["host"]), int(target["port"]))
        bound_fields = ("id", "name", "host", "ip", "port", "asn", "peers")
        if any(device.get(key) != target.get(key) for key in bound_fields):
            raise HTTPException(status_code=409, detail="Device inventory changed after this plan was prepared.")
        current.append(device)
    return current


def _expected_neighbor_line(plan, index: int) -> tuple[str, str]:
    peer_ip = plan.targets[1 - index]["ip"] if len(plan.targets) == 2 else plan.peer_ip
    action = "passive" if plan.fault_class == "neighbor_passive" else "shutdown"
    return peer_ip, action


def _route_policy_precheck(config: str, peer_ip: str, prefix_list_name: str) -> list[str]:
    peer_policy = re.compile(rf"^\s*neighbor\s+{re.escape(peer_ip)}\s+(?:prefix-list|route-map)\s+\S+\s+in\s*$", re.MULTILINE)
    named_list = re.compile(rf"^\s*ip\s+prefix-list\s+{re.escape(prefix_list_name)}(?:\s|$)", re.MULTILINE)
    attached = peer_policy.findall(config)
    existing_list = named_list.findall(config)
    if attached:
        raise HTTPException(status_code=409, detail=f"Pre-check failed: peer {peer_ip} already has an inbound prefix-list or route-map. Review the existing policy manually; this plan will not replace it.")
    if existing_list:
        raise HTTPException(status_code=409, detail=f"Pre-check failed: prefix-list {prefix_list_name} already exists. Choose another name; this plan will not modify it.")
    peer_lines = [line.strip() for line in config.splitlines() if re.match(rf"^\s*neighbor\s+{re.escape(peer_ip)}\s+", line)]
    return peer_lines


def _matching_neighbor_lines(config: str, peer: str, action: str) -> list[str]:
    pattern = re.compile(rf"^\s*neighbor\s+{re.escape(peer)}\s+{re.escape(action)}\s*$", re.MULTILINE)
    return [match.group(0).strip() for match in pattern.finditer(config)]


@app.post("/remediation/plans")
def prepare_remediation(req: PrepareRemediationRequest):
    if not RUN_ID_RE.fullmatch(req.run_id):
        raise HTTPException(status_code=404, detail=f"Run not found: {req.run_id}")
    path = RUN_DATA_DIR / f"{req.run_id}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No structured real diagnosis data was saved for run {req.run_id}.")
    try:
        run = json.loads(path.read_text(encoding="utf-8"))
        plan = remediation_manager.prepare(req.run_id, run, load_devices(), req.model_dump(exclude={"run_id"}))
        return plan
    except RemediationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read diagnosis record: {exc}") from exc


@app.post("/remediation/plans/{plan_id}/apply")
def apply_remediation(plan_id: str, req: RemediationActionRequest):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required before applying the plan.")
    try:
        plan = remediation_manager.get_confirmed(plan_id, req.digest)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with _remediation_lock:
        if plan.status in {"applied", "verified", "verification_failed", "rolled_back"}:
            return plan.result or {"status": plan.status}
        if plan.status != "prepared":
            raise HTTPException(status_code=409, detail=f"Plan is currently {plan.status}.")
        plan.status = "applying"

    try:
        devices = _resolve_plan_targets(plan)
        backups = []
        # Check every target before changing any router.
        for index, device in enumerate(devices):
            result = _remediation_device(device).run_vtysh(device["host"], "show running-config")
            if not result.success:
                raise HTTPException(status_code=502, detail=result.error or result.output or "Config pre-check failed.")
            if plan.fault_class == "route_filtered":
                parameters = plan.body["parameters"]
                peer_ip = plan.peer_ip
                lines = _route_policy_precheck(result.output, peer_ip, parameters["prefix_list_name"])
                backups.append({"device_id": device["id"], "neighbor": peer_ip,
                                "prefix_list_name": parameters["prefix_list_name"], "relevant_config": lines})
            else:
                peer_ip, action = _expected_neighbor_line(plan, index)
                lines = _matching_neighbor_lines(result.output, peer_ip, action)
                if not lines:
                    raise HTTPException(status_code=409, detail=f"Pre-check failed on {device['name']}: the planned {action} fault is no longer present.")
                backups.append({"device_id": device["id"], "neighbor": peer_ip, "relevant_config": lines})
        backup_dir = RUN_LOG_DIR / "remediations"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / f"{plan.id}.json").write_text(json.dumps({"run_id": plan.run_id, "plan_id": plan.id, "before": backups}), encoding="utf-8")

        results = []
        for index, device in enumerate(devices):
            result = _remediation_device(device).run_vtysh_commands(device["host"], plan.apply_commands[index])
            results.append({"device_id": device["id"], "success": result.success,
                            "command": result.command, "output": result.output, "error": result.error})
            if not result.success:
                break
            plan.applied_targets.append(index)

        status = "applied" if len(plan.applied_targets) == len(devices) else ("partially_applied" if plan.applied_targets else "failed")
        plan.status = status
        plan.result = {"status": status, "results": results, "backup_saved": True}
        remediation_manager.audit({"event": "plan_applied", "run_id": plan.run_id, "plan_id": plan.id,
                                   "status": status, "results": results})
        return plan.result
    except HTTPException as exc:
        plan.status = "failed"
        plan.result = {"status": "failed", "error": exc.detail}
        remediation_manager.audit({"event": "plan_apply_failed", "run_id": plan.run_id,
                                   "plan_id": plan.id, "error": str(exc.detail)})
        raise


@app.post("/remediation/plans/{plan_id}/verify")
def verify_remediation(plan_id: str, req: RemediationActionRequest):
    try:
        plan = remediation_manager.get_confirmed(plan_id, req.digest)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if plan.status == "verified":
        return plan.result
    if plan.status not in {"applied", "verification_failed"}:
        raise HTTPException(status_code=409, detail=f"Cannot verify a plan in status {plan.status}.")
    devices = _resolve_plan_targets(plan)
    checks = []
    from tools.bgp_state import BGPStateTool
    for index, device in enumerate(devices):
        if plan.fault_class == "route_filtered":
            peer_ip = plan.peer_ip
            client = _remediation_device(device)
            for prefix in plan.body["parameters"]["prefixes"]:
                result = client.run_vtysh(device["host"], f"show bgp ipv4 unicast {prefix}")
                learned_from_peer = result.success and bool(re.search(rf"\bfrom\s+{re.escape(peer_ip)}(?:\s|$)", result.output))
                checks.append({"device_id": device["id"], "peer": peer_ip, "prefix": prefix,
                               "success": result.success, "learned_from_peer": learned_from_peer,
                               "error": result.error, "raw_output": result.output})
                if not learned_from_peer:
                    break
            if checks and not checks[-1].get("learned_from_peer"):
                break
        else:
            peer_ip, _ = _expected_neighbor_line(plan, index)
            result = BGPStateTool(device_client=_remediation_device(device)).run(device["host"], peer_ip)
            state = (result.parsed or {}).get("queried_peer_state")
            checks.append({"device_id": device["id"], "peer": peer_ip, "state": state,
                           "success": result.success, "error": result.error, "raw_output": result.raw_output})
            if not result.success or state != "Established":
                break
    if plan.fault_class == "route_filtered":
        prefix_count = len(plan.body["parameters"]["prefixes"])
        verified = len(checks) == prefix_count and all(c.get("success") and c.get("learned_from_peer") for c in checks)
    else:
        verified = len(checks) == len(devices) and all(c.get("success") and c.get("state") == "Established" for c in checks)
    plan.status = "verified" if verified else "verification_failed"
    plan.result = {"status": plan.status, "verified": verified, "checks": checks}
    remediation_manager.audit({"event": "plan_verified", "run_id": plan.run_id, "plan_id": plan.id,
                               "status": plan.status, "checks": checks})
    return plan.result


@app.post("/remediation/plans/{plan_id}/rollback")
def rollback_remediation(plan_id: str, req: RemediationActionRequest):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required before rollback.")
    try:
        plan = remediation_manager.get_confirmed(plan_id, req.digest)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if plan.status == "rolled_back":
        return plan.result or {"status": "rolled_back"}
    if plan.status not in {"applied", "verification_failed", "partially_applied"}:
        raise HTTPException(status_code=409, detail=f"Cannot roll back a plan in status {plan.status}.")
    devices = _resolve_plan_targets(plan)
    results = []
    for index in reversed(plan.applied_targets):
        device = devices[index]
        result = _remediation_device(device).run_vtysh_commands(device["host"], plan.rollback_commands[index])
        results.append({"device_id": device["id"], "success": result.success,
                        "command": result.command, "output": result.output, "error": result.error})
        if not result.success:
            plan.result = {"status": "rollback_failed", "results": results}
            remediation_manager.audit({"event": "rollback_failed", "run_id": plan.run_id,
                                       "plan_id": plan.id, "results": results})
            return plan.result
    plan.status = "rolled_back"
    plan.result = {"status": "rolled_back", "results": results}
    remediation_manager.audit({"event": "rolled_back", "run_id": plan.run_id,
                               "plan_id": plan.id, "results": results})
    return plan.result


@app.get("/health")
def health():
    return {"status": "ok"}




