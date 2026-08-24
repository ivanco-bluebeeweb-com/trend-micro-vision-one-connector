"""Trend Micro Vision One HTTP client -- Bearer token auth, per-region base
URL. Uses the platform's own `ctx.http` (async), never `requests`. Same
ClientFail/fail() shape as cortex_client.py / sentinelone_client.py.
"""
from __future__ import annotations


class ClientFail(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


def fail(message: str, status: int = 0):
    raise ClientFail(message, status)


_VALID_REGIONS = {"us", "eu", "in", "au", "sg", "jp"}


def _base_url(conn: dict) -> str:
    region = (conn.get("region", "") or "us").strip().lower()
    if region not in _VALID_REGIONS:
        region = "us"
    return f"https://api.{region}.xdr.trendmicro.com/v3.0"


def _headers(conn: dict) -> dict:
    return {
        "Authorization": f"Bearer {conn.get('api_token', '')}",
        "Content-Type": "application/json;charset=utf-8",
    }


async def api_request(ctx, conn: dict, method: str, path: str,
                       params: dict | None = None, json_body: dict | None = None) -> dict:
    url = f"{_base_url(conn)}{path}"
    try:
        resp = await ctx.http.request(method, url, headers=_headers(conn), params=params, json=json_body, timeout=45)
    except Exception as exc:
        fail(f"Request to Trend Micro Vision One failed: {exc}")
        return {}
    if resp.status_code == 401:
        fail("Vision One rejected the credentials (401) -- check the Authentication Token.", 401)
    if resp.status_code == 403:
        fail("Access denied (403) -- this API key's role lacks permission for this action.", 403)
    if resp.status_code == 404:
        fail(f"Not found (404): {resp.text[:300]}", 404)
    if resp.status_code >= 400:
        fail(f"Vision One API error ({resp.status_code}): {resp.text[:300]}", resp.status_code)
    if resp.status_code == 204 or not resp.text:
        return {}
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


# -- Workbench alerts -------------------------------------------------------

async def list_workbench_alerts(ctx, conn: dict, status: str = "", top: int = 50) -> dict:
    params: dict = {"top": min(max(top, 1), 200)}
    filters = []
    if status:
        filters.append(f"status eq '{status}'")
    if filters:
        params["filter"] = " and ".join(filters)
    return await api_request(ctx, conn, "GET", "/workbench/alerts", params=params)


async def get_workbench_alert(ctx, conn: dict, alert_id: str) -> dict:
    return await api_request(ctx, conn, "GET", f"/workbench/alerts/{alert_id}")


async def update_workbench_alert(ctx, conn: dict, alert_id: str, body: dict) -> dict:
    return await api_request(ctx, conn, "PATCH", f"/workbench/alerts/{alert_id}", json_body=body)


# -- Endpoints ----------------------------------------------------------------

async def list_endpoints(ctx, conn: dict, top: int = 50) -> dict:
    return await api_request(ctx, conn, "GET", "/eiqs/endpoints", params={"top": min(max(top, 1), 200)})


async def isolate_endpoint(ctx, conn: dict, endpoint_name: str, description: str = "") -> dict:
    body = [{"endpointName": endpoint_name, "description": description or "Isolated via Imperal"}]
    return await api_request(ctx, conn, "POST", "/response/endpoints/isolate", json_body=body)


async def restore_endpoint(ctx, conn: dict, endpoint_name: str, description: str = "") -> dict:
    body = [{"endpointName": endpoint_name, "description": description or "Restored via Imperal"}]
    return await api_request(ctx, conn, "POST", "/response/endpoints/restore", json_body=body)


async def scan_endpoint(ctx, conn: dict, endpoint_name: str, description: str = "") -> dict:
    body = [{"endpointName": endpoint_name, "description": description or "Scan triggered via Imperal"}]
    return await api_request(ctx, conn, "POST", "/response/endpoints/startMalwareScan", json_body=body)


# -- Suspicious Object Lists ---------------------------------------------------

async def list_suspicious_objects(ctx, conn: dict, top: int = 50) -> dict:
    return await api_request(ctx, conn, "GET", "/threatintel/suspiciousObjects", params={"top": min(max(top, 1), 200)})


async def create_suspicious_object(ctx, conn: dict, value: str, obj_type: str, scan_action: str, description: str = "") -> dict:
    body = [{"type": obj_type, "value": value, "scanAction": scan_action, "description": description or ""}]
    return await api_request(ctx, conn, "POST", "/threatintel/suspiciousObjects", json_body=body)


async def remove_suspicious_object(ctx, conn: dict, value: str, obj_type: str) -> dict:
    body = [{"type": obj_type, "value": value}]
    return await api_request(ctx, conn, "POST", "/threatintel/suspiciousObjects/delete", json_body=body)


# -- Observed Attack Techniques -------------------------------------------------

async def list_observed_attack_techniques(ctx, conn: dict, top: int = 50) -> dict:
    return await api_request(ctx, conn, "GET", "/xdr/oat/detections", params={"top": min(max(top, 1), 200)})


# -- Search (XDR data lake) -----------------------------------------------------

async def run_search_query(ctx, conn: dict, query: str, start_time: str, end_time: str) -> dict:
    body = {"query": query}
    if start_time:
        body["startDateTime"] = start_time
    if end_time:
        body["endDateTime"] = end_time
    return await api_request(ctx, conn, "POST", "/xdr/search", json_body=body)
