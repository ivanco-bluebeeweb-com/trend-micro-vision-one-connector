"""Pydantic params models + SDL entity contracts for Trend Micro Vision One
Connector. Module-scope (V17 federal invariant). Organized by domain to
match handlers_*.py split (connection, workbench, endpoints, suspicious
objects, observed attack techniques, search, audit).
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from imperal_sdk import sdl


class NoParams(BaseModel):
    """Explicit empty params model -- V17 disallows untyped handlers."""
    pass


# -- Connection -----------------------------------------------------------

class ConnectTrendMicroParams(BaseModel):
    label: str = Field("", description="Optional friendly name for this connection.")
    region: str = Field(..., description="Data center region: us, eu, in, au, sg, or jp.")
    api_token: str = Field(..., description="Authentication Token from Administration > API Keys.")


class ProviderConnection(sdl.Entity):
    id: str = ""
    title: str = ""
    connected: bool = False
    detail: str = ""
    region: str = ""


class ProviderConnectionList(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[ProviderConnection] = []


class DisconnectTrendMicroParams(BaseModel):
    connection_id: str = Field(..., description="Connection id from list_connections.")


class DeleteResult(sdl.Entity):
    id: str = ""
    title: str = ""
    deleted: bool = False


# -- Workbench alerts -------------------------------------------------------

class ListWorkbenchAlertsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    status: str = Field("", description="Filter: 'New', 'In Progress', 'Resolved', 'Closed'. Empty = all.")
    limit: int = Field(50, description="Max alerts to return (1-200).")


class WorkbenchAlert(sdl.Entity):
    id: str = ""
    title: str = ""
    alert_id: str = ""
    model: str = ""
    severity: str = ""
    status: str = ""
    investigation_status: str = ""
    created_date_time: str = ""


class WorkbenchAlertList(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[WorkbenchAlert] = []


class GetWorkbenchAlertParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    alert_id: str = Field(..., description="Workbench alert id from list_workbench_alerts.")


class UpdateWorkbenchAlertParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    alert_id: str = Field(..., description="Workbench alert id to update.")
    status: str = Field("", description="New status: 'In Progress', 'True Positive', 'False Positive', 'Closed'.")
    investigation_result: str = Field("", description="Investigation result note, required when closing as True/False Positive.")


# -- Endpoints --------------------------------------------------------------

class ListEndpointsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    limit: int = Field(50, description="Max endpoints to return (1-200).")


class TrendMicroEndpoint(sdl.Entity):
    id: str = ""
    title: str = ""
    agent_guid: str = ""
    endpoint_name: str = ""
    os_name: str = ""
    isolation_status: str = ""
    last_connected: str = ""


class EndpointList(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[TrendMicroEndpoint] = []


class IsolateEndpointParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    endpoint_name: str = Field(..., description="Endpoint hostname or IP to isolate from the network. This blocks nearly all network access -- confirm the target first.")
    description: str = Field("", description="Optional reason recorded with this action.")


class RestoreEndpointParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    endpoint_name: str = Field(..., description="Endpoint hostname or IP to restore network connectivity to.")
    description: str = Field("", description="Optional reason recorded with this action.")


class ScanEndpointParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    endpoint_name: str = Field(..., description="Endpoint hostname or IP to trigger an on-demand scan on.")
    description: str = Field("", description="Optional reason recorded with this action.")


class TaskRef(sdl.Entity):
    id: str = ""
    title: str = ""
    task_id: str = ""


# -- Suspicious Object Lists --------------------------------------------------

class ListSuspiciousObjectsParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    obj_type: str = Field("", description="Filter by type: file_sha1, file_sha256, ip, domain, url. Empty = all.")
    limit: int = Field(50, description="Max objects to return (1-200).")


class SuspiciousObject(sdl.Entity):
    id: str = ""
    title: str = ""
    value: str = ""
    obj_type: str = ""
    scan_action: str = ""
    risk_level: str = ""
    description: str = ""


class SuspiciousObjectList(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[SuspiciousObject] = []


class CreateSuspiciousObjectParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    value: str = Field(..., description="The indicator value, e.g. a SHA-256 hash, IP, domain, or URL.")
    obj_type: str = Field(..., description="Indicator type: file_sha1, file_sha256, ip, domain, or url.")
    scan_action: str = Field("log", description="'log' (monitor only, default) or 'block' (actively deny fleet-wide). Defaults to 'log' so an indicator is never silently blocked -- see app.py docstring.")
    description: str = Field("", description="Optional reason/context recorded with this indicator.")


class RemoveSuspiciousObjectParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    value: str = Field(..., description="The indicator value to remove.")
    obj_type: str = Field(..., description="Indicator type of the value being removed.")


# -- Observed Attack Techniques -----------------------------------------------

class ListObservedAttackTechniquesParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    limit: int = Field(50, description="Max techniques to return (1-200).")


class ObservedAttackTechnique(sdl.Entity):
    id: str = ""
    title: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    endpoint_name: str = ""
    detected_date_time: str = ""


class ObservedAttackTechniqueList(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[ObservedAttackTechnique] = []


# -- Search (XDR data lake) ----------------------------------------------------

class RunSearchQueryParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")
    query: str = Field(..., description="Vision One Search query, e.g. \"eventSubId:101 AND objectFilePath:*.exe\".")
    start_time: str = Field("", description="ISO 8601 start of the search window. Empty = last 24h.")
    end_time: str = Field("", description="ISO 8601 end of the search window. Empty = now.")


class SearchResultRow(sdl.Entity):
    id: str = ""
    title: str = ""
    fields_json: str = ""


class SearchResult(sdl.Entity):
    id: str = ""
    title: str = ""
    items: list[SearchResultRow] = []


# -- Analytics / audit -------------------------------------------------------

class AuditTrendMicroTenantParams(BaseModel):
    connection_id: str = Field("", description="Connection id; omit to use the only connected tenant.")


class AuditFinding(sdl.Entity):
    id: str = ""
    title: str = ""
    kind: str = ""
    detail: str = ""
    severity: str = ""


class AuditReport(sdl.Entity):
    id: str = ""
    title: str = ""
    connection_id: str = ""
    open_alerts: int = 0
    critical_high_alerts: int = 0
    isolated_endpoints: int = 0
    findings: list[AuditFinding] = []
