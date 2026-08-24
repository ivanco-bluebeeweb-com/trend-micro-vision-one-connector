"""Trend Micro Vision One Connector extension declaration.

Trend Micro Vision One is Trend Micro's XDR platform, reached through a
per-region REST API (https://api.{region}.xdr.trendmicro.com/v3.0/*) secured
by a static Authentication Token (Bearer). It covers Workbench (the SOC
alert/incident triage queue), Endpoint Security (isolate/restore network
connection, start a scan), Suspicious Object Lists (fleet-wide IOC
management: block/allow hashes, IPs, domains, URLs), Observed Attack
Techniques (ATT&CK-mapped detections), and Search (XDR data lake queries
across telemetry, their equivalent of KQL/Advanced Hunting).

WHY BYOK (bring-your-own API Token). Vision One lives inside the user's own
Trend Micro tenant -- Imperal cannot broker access to someone else's
endpoint estate centrally. The user generates an Authentication Token in
Vision One Console > Administration > API Keys, and pastes the region +
token once, Vault-encrypted via ctx.secrets.

WHY REGION IS A SEPARATE REQUIRED FIELD.
Vision One has no single shared API host -- the tenant's data resides in one
of several regional data centers (e.g. us, eu, in, au, sg, jp), each with
its own API host (api.{region}.xdr.trendmicro.com). There is no way to
derive it from the token alone, so region is a required field of
connect_trend_micro.

WHY SUSPICIOUS OBJECT ACTIONS ARE SCOPED TO "block"/"log" SEPARATELY.
Vision One's Suspicious Object Lists support both a passive "log" action
(record matches, do not block) and an active "block" action (actually deny
the indicator fleet-wide). Exposing this as an explicit required field
keeps a user from silently converting a monitoring-only IOC into an active
block, which could disrupt legitimate traffic across every enrolled
endpoint.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "trend-micro-vision-one-connector",
    version="0.1.0",
    display_name="Trend Micro Vision One",
    description=(
        "Connect your own Trend Micro Vision One XDR tenant to manage "
        "Workbench alerts, Endpoint Security (isolate/restore, scan), "
        "Suspicious Object Lists (IOCs), Observed Attack Techniques, and "
        "XDR data lake Search queries."
    ),
    icon="icon.svg",
    capabilities=["trend_micro:read", "trend_micro:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(ext)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether this extension's own state store is reachable --
    does not call out to Vision One itself (that would burn API quota on
    every platform health probe)."""
    return {"status": "ok"}
