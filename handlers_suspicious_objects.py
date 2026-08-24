"""Suspicious Object Lists -- fleet-wide indicator management (hashes, IPs,
domains, URLs). scan_action defaults to 'log' (monitor only) so an
indicator is never silently promoted to an active fleet-wide block -- see
app.py docstring for why.
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListSuspiciousObjectsParams, SuspiciousObject, SuspiciousObjectList,
    CreateSuspiciousObjectParams, RemoveSuspiciousObjectParams, DeleteResult,
)

_VALID_TYPES = {"file_sha1", "file_sha256", "ip", "domain", "url"}
_VALID_ACTIONS = {"log", "block"}


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


def _to_object(d: dict) -> SuspiciousObject:
    return SuspiciousObject(
        value=d.get("value", "") or "",
        obj_type=d.get("type", "") or "",
        scan_action=d.get("scanAction", "") or "",
        risk_level=d.get("riskLevel", "") or "",
        description=d.get("description", "") or "",
    )


@chat.function("list_suspicious_objects", "List Suspicious Objects (fleet-wide indicators) configured on the connected Trend Micro Vision One tenant.", action_type="read", chain_callable=True, data_model=SuspiciousObjectList, event="trend-micro-vision-one-connector.list_suspicious_objects")
async def list_suspicious_objects(ctx, params: ListSuspiciousObjectsParams) -> ActionResult:
    """List Suspicious Objects configured on the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.list_suspicious_objects(ctx, conn, top=params.limit)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    if params.obj_type:
        items = [d for d in items if d.get("type", "") == params.obj_type]
    out = SuspiciousObjectList(items=[_to_object(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} suspicious object(s).")


@chat.function("create_suspicious_object", "Add a Suspicious Object (hash, IP, domain, or URL) to the connected Trend Micro Vision One tenant. scan_action defaults to 'log' (monitor only) -- pass 'block' explicitly to actively deny it fleet-wide.", action_type="write", chain_callable=True, data_model=SuspiciousObject, event="trend-micro-vision-one-connector.create_suspicious_object", effects=["trend_micro.suspicious_object.created"])
async def create_suspicious_object(ctx, params: CreateSuspiciousObjectParams) -> ActionResult:
    """Add a Suspicious Object to the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    obj_type = (params.obj_type or "").strip().lower()
    if obj_type not in _VALID_TYPES:
        return ActionResult.error("obj_type must be one of: " + ", ".join(sorted(_VALID_TYPES)) + ".")
    scan_action = (params.scan_action or "log").strip().lower()
    if scan_action not in _VALID_ACTIONS:
        return ActionResult.error("scan_action must be 'log' or 'block'.")
    try:
        await tm.create_suspicious_object(ctx, conn, params.value, obj_type, scan_action, params.description)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(
        data=SuspiciousObject(value=params.value, obj_type=obj_type, scan_action=scan_action, description=params.description),
        summary=f"Created suspicious object ({scan_action}): {params.value}",
    )


@chat.function("remove_suspicious_object", "Permanently remove a Suspicious Object from the connected Trend Micro Vision One tenant. Cannot be undone.", action_type="write", chain_callable=True, data_model=DeleteResult, event="trend-micro-vision-one-connector.remove_suspicious_object", effects=["trend_micro.suspicious_object.deleted"])
async def remove_suspicious_object(ctx, params: RemoveSuspiciousObjectParams) -> ActionResult:
    """Permanently remove a Suspicious Object. Cannot be undone."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        await tm.remove_suspicious_object(ctx, conn, params.value, params.obj_type)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    return ActionResult.success(data=DeleteResult(deleted=True), summary=f"Removed suspicious object: {params.value}")
