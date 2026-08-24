"""Endpoint Security -- isolate/restore network connection and trigger a
scan. Actions return a task id (Vision One's async task pattern) rather
than blocking, since agent-side actions take time to apply.
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListEndpointsParams, TrendMicroEndpoint, EndpointList,
    IsolateEndpointParams, RestoreEndpointParams, ScanEndpointParams, TaskRef,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


def _to_endpoint(d: dict) -> TrendMicroEndpoint:
    return TrendMicroEndpoint(
        agent_guid=d.get("agentGuid", "") or "",
        endpoint_name=d.get("endpointName", "") or "",
        os_name=d.get("osName", "") or "",
        isolation_status=d.get("isolationStatus", "") or "",
        last_connected=str(d.get("lastConnectedDateTime", "")),
    )


@chat.function("list_endpoints", "List endpoints enrolled in the connected Trend Micro Vision One tenant.", action_type="read", chain_callable=True, data_model=EndpointList, event="trend-micro-vision-one-connector.list_endpoints")
async def list_endpoints(ctx, params: ListEndpointsParams) -> ActionResult:
    """List endpoints enrolled in the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.list_endpoints(ctx, conn, top=params.limit)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    out = EndpointList(items=[_to_endpoint(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} endpoint(s).")


@chat.function("isolate_endpoint", "Isolate a Trend Micro Vision One endpoint from the network. The endpoint stays protected but loses almost all network access -- confirm the target host before running.", action_type="write", chain_callable=True, data_model=TaskRef, event="trend-micro-vision-one-connector.isolate_endpoint", effects=["trend_micro.endpoint.isolated"])
async def isolate_endpoint(ctx, params: IsolateEndpointParams) -> ActionResult:
    """Isolate an endpoint from the network."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.isolate_endpoint(ctx, conn, params.endpoint_name, params.description)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    task_id = ""
    if isinstance(body, dict):
        items = body.get("items", []) or []
        if items and isinstance(items[0], dict):
            task_id = items[0].get("task_id", "") or ""
    return ActionResult.success(data=TaskRef(task_id=task_id), summary=f"Isolation requested for endpoint {params.endpoint_name}.")


@chat.function("restore_endpoint", "Restore network connection for a previously isolated Trend Micro Vision One endpoint.", action_type="write", chain_callable=True, data_model=TaskRef, event="trend-micro-vision-one-connector.restore_endpoint", effects=["trend_micro.endpoint.restored"])
async def restore_endpoint(ctx, params: RestoreEndpointParams) -> ActionResult:
    """Restore network connection for a previously isolated endpoint."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.restore_endpoint(ctx, conn, params.endpoint_name, params.description)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    task_id = ""
    if isinstance(body, dict):
        items = body.get("items", []) or []
        if items and isinstance(items[0], dict):
            task_id = items[0].get("task_id", "") or ""
    return ActionResult.success(data=TaskRef(task_id=task_id), summary=f"Restore requested for endpoint {params.endpoint_name}.")


@chat.function("scan_endpoint", "Trigger an on-demand malware scan on a Trend Micro Vision One endpoint.", action_type="write", chain_callable=True, data_model=TaskRef, event="trend-micro-vision-one-connector.scan_endpoint", effects=["trend_micro.endpoint.scanned"])
async def scan_endpoint(ctx, params: ScanEndpointParams) -> ActionResult:
    """Trigger an on-demand scan on an endpoint."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.scan_endpoint(ctx, conn, params.endpoint_name, params.description)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    task_id = ""
    if isinstance(body, dict):
        items = body.get("items", []) or []
        if items and isinstance(items[0], dict):
            task_id = items[0].get("task_id", "") or ""
    return ActionResult.success(data=TaskRef(task_id=task_id), summary=f"Scan requested for endpoint {params.endpoint_name}.")
