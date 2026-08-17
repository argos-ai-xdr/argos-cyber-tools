# tool_catalog/

| Carpeta | Contenido |
| --- | --- |
| [`schemas/tool-definition.schema.json`](schemas/tool-definition.schema.json) | Todo campo obligatorio y explícito; fuerza `approval_required`/`target_allowlist_required` para `high`/`critical` y `evidence_required` para cualquier modo `execute` |
| [`definitions/`](definitions/) | 5 herramientas reales: 2 de contención (`isolate_kubernetes_workload`, `scale_to_zero`), 1 de monitorización (`increase_monitoring`), 2 de solo lectura |
| [`risk-levels/README.md`](risk-levels/README.md) | Qué implica cada `risk_level` |
| [`signatures/`](signatures/) | Manifiesto de integridad SHA-256 real; firma criptográfica (Cosign) pendiente de ARG-002 |
| [`version_ledger.py`](version_ledger.py) | ADR-053: detecta Version Downgrade — un tool cuya versión baja respecto a la máxima vista antes, aunque su hash de integridad sea válido |

`mcp_gateway` y `policies/approval` importan `tool_catalog.get_tool(name)` — nunca hardcodean sus propias reglas de "qué herramienta necesita aprobación".

## ToolManifest v1 (ADR-053, prompt maestro "SECURE TOOL LIFECYCLE")

Cada definición declara `side_effect_class` (`READ_ONLY` / `DRY_RUN` /
`REVERSIBLE_WRITE` / `IRREVERSIBLE` / `DESTRUCTIVE`, las 5 categorías
exactas del prompt) y `rate_limit.calls_per_minute`. `mcp_gateway.Gateway.authorize()`
aplica dos reglas nuevas sobre estos campos:

* Cualquier tool `IRREVERSIBLE`/`DESTRUCTIVE` se deniega incondicionalmente
  en el P0 actual — el catálogo puede declarar uno (el schema lo permite),
  pero el gateway nunca lo autoriza, sin importar scope/target/approval.
  Los 5 tools reales de hoy son `READ_ONLY` o `REVERSIBLE_WRITE`.
* Cada llamada (autorizada o no) cuenta contra el `rate_limit` del tool en
  una ventana deslizante de 60s (`mcp_gateway.RateLimiter`, en memoria de
  un único proceso — mismo caveat que `ApprovalStore`, ARG-020).

Huecos reales, explícitamente no construidos todavía: **Tool Shadowing**
(detectar un tool nuevo con identidad/nombre que suplanta a uno
existente) y **Capability Escalation** (un tool que en runtime excede el
`capabilities` que declaró) — ninguno de los dos tiene un mecanismo real
hoy, no confundir con la detección de manipulación de archivo que sí
existe (`signatures/`) ni con el rate limiting/DENY de arriba.
