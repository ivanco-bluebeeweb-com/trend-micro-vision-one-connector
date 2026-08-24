"""Search -- Vision One's XDR data lake query engine (their equivalent of
KQL/Advanced Hunting), querying correlated telemetry across the whole
tenant. Returns raw match rows for a bounded time window.
"""
from __future__ import annotations

import trend_micro_client as tm
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection
from schemas import RunSearchQueryParams, SearchResult, SearchResultRow


def _no_conn() -> ActionResult:
    return ActionResult.error("No Trend Micro Vision One tenant is connected yet.")


@chat.function("run_search_query", "Run a Search query (Vision One's XDR data lake query engine) against the connected tenant's telemetry within a bounded time window.", action_type="read", chain_callable=True, data_model=SearchResult, event="trend-micro-vision-one-connector.run_search_query")
async def run_search_query(ctx, params: RunSearchQueryParams) -> ActionResult:
    """Run a Search query against the connected Vision One tenant's telemetry."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    try:
        body = await tm.run_search_query(ctx, conn, params.query, params.start_time, params.end_time)
    except tm.ClientFail as exc:
        return ActionResult.error(str(exc), retryable=(exc.status in (0, 429, 500, 502, 503)))
    items = (body.get("items", []) or []) if isinstance(body, dict) else []
    rows = [SearchResultRow(fields_json=str(row)) for row in items[:200]]
    return ActionResult.success(data=SearchResult(items=rows), summary=f"Search returned {len(rows)} row(s).")
