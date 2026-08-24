"""Trend Micro Vision One Connector panels -- left sidebar, no cards, per
UI_INTERFACE_STANDARD.md convention (same as Cortex XDR/Sentinel/Defender/
SentinelOne). Every input carries its own label with a contextually
specific placeholder; the connect form is stretched to the full sidebar
width; "where do I get an Authentication Token?" instructions live ONLY
in the help overlay, not duplicated here.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections

_REGIONS = [
    {"value": "us", "label": "United States"},
    {"value": "eu", "label": "Europe"},
    {"value": "in", "label": "India"},
    {"value": "au", "label": "Australia"},
    {"value": "sg", "label": "Singapore"},
    {"value": "jp", "label": "Japan"},
]


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__trend_micro_settings"),
    )


@ext.panel("trend_micro_sidebar", slot="left", title="Trend Micro Vision One")
async def trend_micro_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("Где взять Authentication Token?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__trend_micro_connect_help")),
            ui.Form(action="connect_trend_micro", submit_label="Подключить тенант", full_width=True, children=[
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Название (опционально)", variant="label"),
                    ui.Input(name="label", placeholder="Acme SOC Tenant"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Регион", variant="label"),
                    ui.Select(name="region", placeholder="Выберите регион", options=_REGIONS),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Authentication Token", variant="label"),
                    ui.Input(name="api_token", type="password", placeholder="Вставьте Authentication Token"),
                ]),
            ]),
        ])
    conn = connections[0]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text(conn.get("label") or conn.get("region", ""), variant="body"),
        ui.Text(conn.get("region", ""), variant="caption"),
        ui.Divider(),
        ui.Button("Workbench", variant="ghost", full_width=True, icon="ShieldAlert",
                  on_click=ui.Call("__panel__trend_micro_workbench")),
        ui.Button("Endpoints", variant="ghost", full_width=True, icon="Laptop",
                  on_click=ui.Call("__panel__trend_micro_endpoints")),
        ui.Button("Suspicious Objects", variant="ghost", full_width=True, icon="ListX",
                  on_click=ui.Call("__panel__trend_micro_suspicious_objects")),
        ui.Button("Observed Attack Techniques", variant="ghost", full_width=True, icon="Crosshair",
                  on_click=ui.Call("__panel__trend_micro_oat")),
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("trend_micro_connect_help", slot="overlay", title="Где взять Authentication Token?")
async def trend_micro_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Markdown(text=(
        "**Как получить Authentication Token Trend Micro Vision One:**\n\n"
        "1. Откройте консоль Vision One вашего тенанта.\n"
        "2. Перейдите в **Administration > API Keys**.\n"
        "3. Нажмите **Add API Key**, выберите роль с нужными правами (Workbench, Endpoint Security, "
        "Suspicious Object Management и т.д.) и создайте ключ.\n"
        "4. Скопируйте токен — он показывается только один раз.\n"
        "5. Определите **регион** своего тенанта по адресу консоли "
        "(например `https://api.eu.xdr.trendmicro.com` → регион `eu`).\n\n"
        "**Важно про Suspicious Objects:** при добавлении индикатора scan_action по умолчанию "
        "`log` (только мониторинг). Явно укажите `block`, чтобы индикатор активно блокировался "
        "на всём парке устройств — это осознанное отдельное действие, а не побочный эффект."
    ))
