"""Trend Micro Vision One Connector -- center panels for Workbench,
Endpoints, Suspicious Objects, and Observed Attack Techniques, per
UI_COMPONENT_PLAN.md.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections
import trend_micro_client as tm


def _severity_badge(level: str) -> ui.UINode:
    s = (level or "").lower()
    color = "red" if s == "critical" else ("yellow" if s in ("high", "medium") else "gray")
    return ui.Badge(label=level or "unknown", color=color)


def _scan_action_badge(action: str) -> ui.UINode:
    s = (action or "").lower()
    return ui.Badge(label=action or "log", color="red" if s == "block" else "gray")


@ext.panel("trend_micro_workbench", slot="center", title="Workbench", center_overlay=True)
async def trend_micro_workbench(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
    conn = connections[0]
    try:
        body = await tm.list_workbench_alerts(ctx, conn, status="", top=100)
    except tm.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No Workbench alerts found", icon="ShieldCheck")
    rows = [{
        "alert_id": a.get("id", ""),
        "model": a.get("model", ""),
        "severity": a.get("severity", ""),
        "status": a.get("status", ""),
        "created": str(a.get("createdDateTime", "")),
    } for a in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Workbench", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="alert_id", label="#"),
            ui.DataColumn(key="model", label="Alert"),
            ui.DataColumn(key="severity", label="Severity", render=_severity_badge),
            ui.DataColumn(key="status", label="Status"),
            ui.DataColumn(key="created", label="Created"),
        ]),
    ])


@ext.panel("trend_micro_endpoints", slot="center", title="Endpoints", center_overlay=True)
async def trend_micro_endpoints(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Laptop")
    conn = connections[0]
    try:
        body = await tm.list_endpoints(ctx, conn, top=100)
    except tm.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No endpoints found", icon="Laptop")
    rows = [{
        "endpoint_name": e.get("endpointName", ""),
        "os_name": e.get("osName", ""),
        "isolation_status": e.get("isolationStatus", ""),
        "last_connected": str(e.get("lastConnectedDateTime", "")),
    } for e in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Endpoints", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="endpoint_name", label="Host"),
            ui.DataColumn(key="os_name", label="OS"),
            ui.DataColumn(key="isolation_status", label="Isolation"),
            ui.DataColumn(key="last_connected", label="Last connected"),
        ]),
    ])


@ext.panel("trend_micro_suspicious_objects", slot="center", title="Suspicious Objects", center_overlay=True)
async def trend_micro_suspicious_objects(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ListX")
    conn = connections[0]
    try:
        body = await tm.list_suspicious_objects(ctx, conn, top=100)
    except tm.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No suspicious objects configured", icon="ListX")
    rows = [{
        "value": o.get("value", ""),
        "type": o.get("type", ""),
        "scan_action": o.get("scanAction", ""),
        "risk_level": o.get("riskLevel", ""),
    } for o in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Suspicious Objects", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="value", label="Value"),
            ui.DataColumn(key="type", label="Type"),
            ui.DataColumn(key="scan_action", label="Scan action", render=_scan_action_badge),
            ui.DataColumn(key="risk_level", label="Risk"),
        ]),
    ])


@ext.panel("trend_micro_oat", slot="center", title="Observed Attack Techniques", center_overlay=True)
async def trend_micro_oat(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Crosshair")
    conn = connections[0]
    try:
        body = await tm.list_observed_attack_techniques(ctx, conn, top=100)
    except tm.ClientFail as e:
        return ui.Alert(type="error", message=str(e))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    if not items:
        return ui.Empty(message="No observed attack techniques found", icon="Crosshair")
    rows = [{
        "technique_id": str(t.get("uuid", "")),
        "technique_name": t.get("technique", ""),
        "tactic": t.get("tactic", ""),
        "endpoint": (t.get("endpoint", {}) or {}).get("hostName", ""),
        "detected": str(t.get("detectedDateTime", "")),
    } for t in items]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Observed Attack Techniques", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="technique_id", label="#"),
            ui.DataColumn(key="technique_name", label="Technique"),
            ui.DataColumn(key="tactic", label="Tactic"),
            ui.DataColumn(key="endpoint", label="Endpoint"),
            ui.DataColumn(key="detected", label="Detected"),
        ]),
    ])
