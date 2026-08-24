"""Workbench -- Trend Micro Vision One's core SOC triage queue for
XDR-correlated alerts (their equivalent of Cortex XDR Incidents / Sentinel
Incidents / SentinelOne Threats).
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListWorkbenchAlertsParams, GetWorkbenchAlertParams, UpdateWorkbenchAlertParams,
    WorkbenchAlert, WorkbenchAlertList,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


def _to_alert(d: dict) -> WorkbenchAlert:
    return WorkbenchAlert(
        alert_id=str(d.get("id", "")),
        model=d.get("model", "") or "",
        severity=d.get("severity", "") or "",
        status=d.get("status", "") or "",
        investigation_status=d.get("investigationStatus", "") or "",
        created_date_time=str(d.get("createdDateTime", "")),
    )


@chat.function("list_workbench_alerts", "List Trend Micro Vision One Workbench alerts on the connected tenant, optionally filtered by status.", action_type="read", chain_callable=True, data_model=WorkbenchAlertList, event="trend-micro-vision-one-connector.list_workbench_alerts")
async def list_workbench_alerts(ctx, params: ListWorkbenchAlertsParams) -> ActionResult:
    """List Workbench alerts on the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.list_workbench_alerts(ctx, conn, status=params.status, top=params.limit)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    out = WorkbenchAlertList(items=[_to_alert(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} alert(s).")


@chat.function("get_workbench_alert", "Read one Trend Micro Vision One Workbench alert in full.", action_type="read", chain_callable=True, data_model=WorkbenchAlert, event="trend-micro-vision-one-connector.get_workbench_alert")
async def get_workbench_alert(ctx, params: GetWorkbenchAlertParams) -> ActionResult:
    """Read one Workbench alert in full."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.get_workbench_alert(ctx, conn, params.alert_id)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    if not body:
        return ActionResult.error(f"Alert '{params.alert_id}' not found.")
    return ActionResult.success(data=_to_alert(body), summary=f"Alert {params.alert_id}: {body.get('model', '')}")


@chat.function("update_workbench_alert", "Update a Trend Micro Vision One Workbench alert's status and/or investigation result.", action_type="write", chain_callable=True, data_model=WorkbenchAlert, event="trend-micro-vision-one-connector.update_workbench_alert", effects=["trend_micro.workbench_alert.updated"])
async def update_workbench_alert(ctx, params: UpdateWorkbenchAlertParams) -> ActionResult:
    """Update a Workbench alert's status and/or investigation result."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    update: dict = {}
    if params.status:
        update["status"] = params.status
    if params.investigation_result:
        update["investigationResult"] = params.investigation_result
    if not update:
        return ActionResult.error("Provide status and/or investigation_result to update.")
    try:
        await tm.update_workbench_alert(ctx, conn, params.alert_id, update)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=WorkbenchAlert(alert_id=params.alert_id, status=params.status), summary=f"Updated alert {params.alert_id}.")
