# Runbook: read_asset_inventory

* **Repositorio propietario**: `argos-cyber-tools`
* **Herramienta MCP asociada**: `read_asset_inventory` v1.0.0 (`tool_catalog/definitions/read_asset_inventory.yaml`)
* **Estado**: BORRADOR — código real y ahora probado; sin sign-off formal (esta tool no lo requiere: `approval_required=false`, ver más abajo).
* **Aprobado por**: N/A — `read-only` nunca pasa por el flujo de Approval (ver "Precondiciones").
* **Fecha de aprobación / última simulación**: N/A (sin approval) / 2026-08-17, `tests/mcp_servers/test_read_servers.py` (en memoria).

Esta tool NO sigue la plantilla estándar (`argos-control/templates/runbook/runbook-template.md`)
sección por sección — esa plantilla asume `dry-run → approval → execute →
verify → rollback`, y `read_asset_inventory` no ejecuta nada, no cambia
estado y no tiene rollback que documentar. Se adapta explícitamente en
vez de rellenar secciones que no aplican con "N/A" sin explicación.

## Cuándo se usa

Consulta de inventario de activos (`AssetSnapshot`) para que
`argos-core/services/recommendation` o un operador puedan ver qué activos
existen antes de razonar sobre exposición o priorización — sin esto, C-06
no tiene con qué trabajar.

## Modo soportado

- [x] read-only (único modo — `tool_catalog/definitions/read_asset_inventory.yaml: mode: [read-only]`)
- [ ] dry-run — no aplica
- [ ] execute — no aplica

## Precondiciones y límites

* **Scope requerido**: `cyber.read.assets` — `mcp_gateway.Gateway.authorize()`
  lo exige igual que a cualquier otra tool; sin ese scope, `DENY` con
  motivo `"scope 'cyber.read.assets' no concedido al llamante"`.
* **Sin target allowlist**: `target_allowlist_required: false` — leer
  inventario no está acotado a un target concreto (a diferencia de
  `isolate_kubernetes_workload`).
* **Sin Approval**: `approval_required: false`. `authorize()` solo evalúa
  la rama de Approval cuando `action == "execute"` — `read-only` nunca la
  alcanza, ni con el código de esta tool ni con ningún otro. Probado
  explícitamente en `tests/authorization/test_gateway.py::test_unsupported_action_for_tool_is_denied`
  (pide `action="execute"` sobre esta tool y confirma que se rechaza por
  "no soportada", no por falta de Approval — el modo en sí no existe).
* **Timeout**: 10 segundos.
* **Sin rollback**: `rollback_supported: false` — no hay estado que
  revertir, no se ejecuta nada.

## Cómo funciona

`mcp_servers/assets.InMemoryAssetServer.list_assets(namespace=None)` — el
servidor MCP real. **No inventa datos**: expone exactamente lo que se le
cargó (`self.assets`), nunca genera un `AssetSnapshot` sintético para
rellenar un namespace vacío (`list_assets(namespace="algo-inexistente")`
devuelve `[]`, no un placeholder). El cliente real hacia `argos-core`
(vía API o NATS, para que `assets` refleje el estado real en vez de una
lista cargada a mano) es interfaz pendiente de ARG-023 — hoy se usa con
datos precargados en tests/desarrollo.

## Evidencia producida

Ninguna (`evidence_required: false`) — una lectura no cambia estado, no
hay nada que verificar después.

## Cobertura de test

`tests/mcp_servers/test_read_servers.py` (añadido en esta sesión — antes
`InMemoryAssetServer` tenía código real sin ningún test directo,
verificado por ausencia total de resultados para `list_assets` en
`tests/`): filtro por namespace, namespace vacío devuelve `[]` sin
inventar nada, servidor sin datos cargados devuelve `[]` sin error.
