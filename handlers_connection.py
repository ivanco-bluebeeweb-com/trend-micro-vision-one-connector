"""Connection management: connect/disconnect Trend Micro Vision One tenants.
Validates credentials with a real list_workbench_alerts call before saving
(IDEAL_ONBOARDING.md step 2) so a bad token/region is caught at connect time.
"""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import trend_micro_client as tm
from app import ext, chat
from schemas import (
    NoParams, ConnectTrendMicroParams, ProviderConnection, ProviderConnectionList,
    DisconnectTrendMicroParams, DeleteResult,
)

_CONN_SECRET = "trend_micro_connections"
_VALID_REGIONS = {"us", "eu", "in", "au", "sg", "jp"}


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_CONN_SECRET)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, items: list[dict]) -> None:
    await ctx.secrets.set(_CONN_SECRET, json.dumps(items))


async def _resolve_connection(ctx, connection_id: str = "") -> dict | None:
    conns = await _load_connections(ctx)
    if not conns:
        return None
    if connection_id:
        for c in conns:
            if c.get("id") == connection_id:
                return c
        return None
    return conns[0]


def _to_conn_entity(c: dict) -> ProviderConnection:
    return ProviderConnection(
        id=c.get("id", ""),
        title=c.get("label") or c.get("region", ""),
        connected=True,
        detail=c.get("region", ""),
        region=c.get("region", ""),
    )


@chat.function("connect_trend_micro", "Connect your own Trend Micro Vision One tenant (data-center region + Authentication Token), verifying the credentials with a real call before saving.", action_type="write", chain_callable=True, data_model=ProviderConnection, event="trend-micro-vision-one-connector.connect_trend_micro", effects=["trend_micro.connection.created"])
async def connect_trend_micro(ctx, params: ConnectTrendMicroParams) -> ActionResult:
    """Connect your own Trend Micro Vision One tenant."""
    region = (params.region or "").strip().lower()
    if region not in _VALID_REGIONS:
        return ActionResult.error(f"region must be one of: {', '.join(sorted(_VALID_REGIONS))}.")
    candidate = {"region": region, "api_token": params.api_token}
    try:
        await tm.list_workbench_alerts(ctx, candidate, status="", top=1)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    conns = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()),
        "label": params.label or "",
        "region": region,
        "api_token": params.api_token,
    }
    conns.append(entry)
    await _save_connections(ctx, conns)
    return ActionResult.success(data=_to_conn_entity(entry), summary=f"Connected Trend Micro Vision One tenant in region '{region}'.")


@chat.function("list_connections", "List the connected Trend Micro Vision One tenants.", action_type="read", chain_callable=True, data_model=ProviderConnectionList, event="trend-micro-vision-one-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected Trend Micro Vision One tenants."""
    conns = await _load_connections(ctx)
    out = ProviderConnectionList(items=[_to_conn_entity(c) for c in conns])
    return ActionResult.success(data=out, summary=f"{len(out.items)} tenant(s) connected.")


@chat.function("disconnect_trend_micro", "Disconnect a Trend Micro Vision One tenant: deletes the saved Authentication Token. Nothing in Vision One itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="trend-micro-vision-one-connector.disconnect_trend_micro", effects=["trend_micro.connection.deleted"])
async def disconnect_trend_micro(ctx, params: DisconnectTrendMicroParams) -> ActionResult:
    """Disconnect a Trend Micro Vision One tenant."""
    conns = await _load_connections(ctx)
    remaining = [c for c in conns if c.get("id") != params.connection_id]
    if len(remaining) == len(conns):
        return ActionResult.error(f"Connection '{params.connection_id}' not found.")
    await _save_connections(ctx, remaining)
    return ActionResult.success(data=DeleteResult(deleted=True), summary="Disconnected.")
