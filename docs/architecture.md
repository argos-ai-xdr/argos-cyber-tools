# Arquitectura de argos-cyber-tools

Implementa los planos P3 (parcial: `mcp_gateway`) y P4 (SOAR/enforcement) de `argos-control/architecture/logical/planos.md`.

## Flujo de una acción (ADR-003, ADR-005, ADR-011)

```
argos-core/services/recommendation ──▶ mcp_gateway ──▶ policies (OPA)
                                                              │
                                        DENY ◀────────────────┤
                                        ALLOW_DRY_RUN ────────┼──▶ executors (dry_run=True)
                                        APPROVAL_REQUIRED ────┘
                                                              │
argos-smartops (operador humano) ──▶ policies/approval ──────┘
                                                              │
                                        Approval válida ──────▶ executors (dry_run=False)
                                                              │
                                        verificación ─────────▶ rollback (si falla)
                                                              │
                                        siempre ───────────────▶ ActionResult
```

El LLM nunca aparece a la derecha de `mcp_gateway`: solo produce `Recommendation`, nunca invoca un `executor` directamente.

## Reglas que no se pueden romper

* `mcp_gateway` es el único punto de entrada; ningún `executor` acepta llamadas que no vengan de él.
* Ninguna `Approval` se acepta dos veces (anti-replay) ni tras `expires_at` (TTL).
* `Approval.plan_hash` debe coincidir exactamente con la acción ejecutada — cualquier modificación posterior a la aprobación invalida la ejecución.
* Todo `executor` con `idempotent: true` en su `tool_catalog` no duplica el efecto ante un reintento con la misma `idempotency_key`.
* Todo `executor` con `rollback_supported: true` tiene una estrategia real en `rollback/`, no solo documentada.

Ver `argos-control/architecture/data-flows/end-to-end-flow.md` para el flujo completo, incluida la parte que vive en `argos-core` y `argos-smartops`.
