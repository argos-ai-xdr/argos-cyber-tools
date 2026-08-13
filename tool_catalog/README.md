# tool_catalog/

| Carpeta | Contenido |
| --- | --- |
| [`schemas/tool-definition.schema.json`](schemas/tool-definition.schema.json) | Todo campo obligatorio y explícito; fuerza `approval_required`/`target_allowlist_required` para `high`/`critical` y `evidence_required` para cualquier modo `execute` |
| [`definitions/`](definitions/) | 5 herramientas reales: 2 de contención (`isolate_kubernetes_workload`, `scale_to_zero`), 1 de monitorización (`increase_monitoring`), 2 de solo lectura |
| [`risk-levels/README.md`](risk-levels/README.md) | Qué implica cada `risk_level` |
| [`signatures/`](signatures/) | Manifiesto de integridad SHA-256 real; firma criptográfica (Cosign) pendiente de ARG-002 |

`mcp_gateway` y `policies/approval` importan `tool_catalog.get_tool(name)` — nunca hardcodean sus propias reglas de "qué herramienta necesita aprobación".
