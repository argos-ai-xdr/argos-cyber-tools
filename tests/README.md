# tests

33 casos. Requieren `argos-contracts-scenarios` como hermano o `ARGOS_CONTRACTS_PATH` (ver `../docs/development.md`) — se saltan automáticamente si no lo encuentran.

| Carpeta | Contenido |
| --- | --- |
| `contract/` | El catálogo completo carga y valida; herramientas `high`/`critical` fuerzan `approval_required`+`allowlist`; `ActionResult` real valida contra el schema |
| `authorization/` | `mcp_gateway` — 8 casos: scope, allowlist, modo no soportado, approval faltante/válida, herramienta desconocida, y una comprobación estructural de 50 llamadas de que la credencial descendente nunca es el token del llamante |
| `anti-replay/` | `policies/approval` — replay, TTL expirado, `plan_hash` alterado, autoaprobación (solicitante y ejecutor), decisión `REJECT`, IDs distintos no interfieren entre sí |
| `idempotency/` | Misma `idempotency_key` no repite el efecto (aislamiento K8s y `scale_to_zero`); dry-run no consume la idempotencia del execute real |
| `rollback/` | Ciclo completo aislar→revertir→verificar (y su equivalente en `scale_to_zero`); `mark_rolled_back` no muta el `ActionResult` original |
| `adversarial/` | Fixtures **reales** de `argos-contracts-scenarios/fixtures/adversarial/` (F09): tool-poisoning y out-of-range verificados contra el `Gateway` de este repositorio, no solo contra el ground truth documentado en el otro |

Ejecutar: `make test` o `pytest`.
