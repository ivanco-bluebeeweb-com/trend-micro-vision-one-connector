"""Observed Attack Techniques -- ATT&CK-mapped detections surfaced by
Vision One's XDR correlation engine, read-only (there is no "mitigate"
action on an OAT record itself -- response happens via Workbench alerts
or direct endpoint actions).
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import (
    ListObservedAttackTechniquesParams, ObservedAttackTechnique, ObservedAttackTechniqueList,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


def _to_oat(d: dict) -> ObservedAttackTechnique:
    return ObservedAttackTechnique(
        technique_id=str(d.get("uuid", "")),
        technique_name=d.get("technique", "") or "",
        tactic=d.get("tactic", "") or "",
        endpoint_name=(d.get("endpoint", {}) or {}).get("hostName", "") or "",
        detected_date_time=str(d.get("detectedDateTime", "")),
    )


@chat.function("list_attack_techniques", "List ATT&CK-mapped Observed Attack Techniques detected on the connected Trend Micro Vision One tenant.", action_type="read", chain_callable=True, data_model=ObservedAttackTechniqueList, event="trend-micro-vision-one-connector.list_observed_attack_techniques")
async def list_observed_attack_techniques(ctx, params: ListObservedAttackTechniquesParams) -> ActionResult:
    """List Observed Attack Techniques detected on the connected Vision One tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.list_observed_attack_techniques(ctx, conn, top=params.limit)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    out = ObservedAttackTechniqueList(items=[_to_oat(d) for d in items])
    return ActionResult.success(data=out, summary=f"Found {len(out.items)} observed attack technique(s).")
