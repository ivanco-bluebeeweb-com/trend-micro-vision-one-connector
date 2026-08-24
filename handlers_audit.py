"""One-call estate health audit -- open Workbench alerts by severity,
isolated endpoints, and active-block Suspicious Objects, same value-add
pattern as audit_sentinelone_tenant / audit_cortex_tenant across this
portfolio.
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import AuditTrendMicroTenantParams, AuditReport, AuditFinding


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


@chat.function("audit_trend_micro_tenant", "Build one aggregated health report across the connected Trend Micro Vision One tenant: open Workbench alerts by severity, isolated endpoints, and active-block Suspicious Objects.", action_type="read", chain_callable=True, data_model=AuditReport, event="trend-micro-vision-one-connector.audit_trend_micro_tenant")
async def audit_trend_micro_tenant(ctx, params: AuditTrendMicroTenantParams) -> ActionResult:
    """Build one aggregated health report across the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    findings: list[AuditFinding] = []
    try:
        alerts_body = await tm.list_workbench_alerts(ctx, conn, status="New", top=100)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    alerts = (alerts_body.get("items", []) or []) if isinstance(alerts_body, dict) else []
    for a in alerts[:20]:
        findings.append(AuditFinding(
            kind="open_alert",
            detail=f"Workbench alert '{a.get('model', '')}' ({a.get('severity', '')}) still open.",
            severity="high" if str(a.get("severity", "")).lower() == "critical" else "medium",
        ))
    try:
        endpoints_body = await tm.list_endpoints(ctx, conn, top=200)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    endpoints = (endpoints_body.get("items", []) or []) if isinstance(endpoints_body, dict) else []
    isolated = [e for e in endpoints if str(e.get("isolationStatus", "")).lower() not in ("", "normal", "unisolated")]
    for e in isolated[:20]:
        findings.append(AuditFinding(
            kind="isolated_endpoint",
            detail=f"Endpoint '{e.get('endpointName', '')}' is currently network-isolated.",
            severity="medium",
        ))
    try:
        objects_body = await tm.list_suspicious_objects(ctx, conn, top=200)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    objects = (objects_body.get("items", []) or []) if isinstance(objects_body, dict) else []
    blocking = [o for o in objects if str(o.get("scanAction", "")).lower() == "block"]
    for o in blocking[:20]:
        findings.append(AuditFinding(
            kind="active_block",
            detail=f"Suspicious object '{o.get('value', '')}' is actively blocked fleet-wide.",
            severity="low",
        ))
    critical_high = [a for a in alerts if str(a.get("severity", "")).lower() in ("critical", "high")]
    report = AuditReport(
        connection_id=conn.get("id", ""),
        open_alerts=len(alerts),
        critical_high_alerts=len(critical_high),
        isolated_endpoints=len(isolated),
        findings=findings,
    )
    return ActionResult.success(data=report, summary=f"{len(alerts)} open alert(s) ({len(critical_high)} critical/high), {len(isolated)} isolated endpoint(s), {len(blocking)} active block(s).")
