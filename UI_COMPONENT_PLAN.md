# Trend Micro Vision One Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `trend-micro-vision-one-connector`
(Workbench alerts, Endpoint Security, Suspicious Object Lists, Observed Attack
Techniques, Search).

## 0. Когда написан этот документ
Написан ДО `panels.py` — по правилу APP_PREPARATION_STANDARD.md §9: план
компонентов сначала, реализация строго по нему.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left, not connected) | `ui.Stack`(v, align="stretch") + `ui.Button`("Где взять API token?" → help overlay) + `ui.Form`(connect_trend_micro) с лейблами на каждом `ui.Input`/`ui.Select` | Без карточек — паттерн Cortex XDR/SentinelOne/Sentinel. Форма растянута на всю ширину сайдбара. |
| Connect form fields | labelled `ui.Input`(label, placeholder "Acme SOC Tenant") + labelled `ui.Select`(region, options us/eu/in/au/sg/jp, placeholder "Выберите регион") + labelled `ui.Input`(api_token, type="password") | region — явный выбор из списка, не текстовое поле, т.к. значения фиксированы и ограничены (см. IDEAL_ONBOARDING.md п.1). |
| Help overlay | `ext.panel(slot="overlay")` + `ui.Markdown`(путь Administration > API Keys, разница log vs block) | Единственное место с инструкциями — не дублируется в сайдбаре. |
| Sidebar (connected) | `ui.Stack`(v) + `ui.Text`(region) + `ui.Divider` + `_settings_button()` последним | Disconnect живёт только в App settings. |
| Empty (center) | `ui.Empty`(message="Nothing to show here") | Канонический пустой центр, `center_overlay=True`. |
| Workbench alerts (center) | `ui.Stack` + `ui.Header` + `ui.DataTable`(alert_id, model, severity Badge, status, created_at) | Таблица — рабочая очередь SOC, тот же паттерн, что Cortex/SentinelOne. |
| Endpoints (center) | `ui.DataTable`(endpoint_name, os_name, isolation_status Badge, last_connected) | Fleet-обзор состояния конечных точек. |
| Suspicious Objects (center) | `ui.DataTable`(value, type, scan_action Badge (block=error/log=default), risk_level) | Список активных IOC-правил. |
| Observed Attack Techniques (center) | `ui.DataTable`(technique_id, technique_name, tactic, endpoint, detected_at) | ATT&CK-карта детекций. |
| App settings (center overlay) | `ui.Stack`(v) + список подключений + `ui.Button`("Disconnect", variant="destructive") на каждый | Единственное место, где живёт disconnect. |

## 2. Как строится интерфейс на этом этапе
`panels.py` (sidebar + help overlay) и `panels_center.py` (Workbench/Endpoints/
Suspicious Objects) пишутся сразу после `schemas.py`/`handlers_connection.py` —
не откладываются до конца сборки приложения, ровно по требованию: "уже строй
какой-либо вообще интерфейс" во время создания приложения, а не после.
