# Runbook: scale_to_zero

* **Repositorio propietario**: `argos-cyber-tools`
* **Herramienta MCP asociada**: `scale_to_zero` v1.0.0 (`tool_catalog/definitions/scale_to_zero.yaml`)
* **Estado**: BORRADOR — código y simulación en memoria reales y probados; falta sign-off formal de SOC/Cyber contra un cyber-range REAL desplegado (mismo bloqueo que ENV-QUAL-01, ver `argos-validation/traceability.yaml` gate G6/ARG-023).
* **Aprobado por**: PENDIENTE — requiere sign-off real de SOC/Cyber (rol `soc-approver` / RACI `SOC`, `argos-control/governance/raci/raci.md`). No se inventa un nombre ni una fecha.
* **Fecha de aprobación / última simulación**: ver "Historial de simulación" abajo — todas en memoria (`FakeReplicaState`), no contra un cluster real.

## Cuándo se usa

Segunda alternativa de contención para severidad `critical` propuesta por `argos-core/services/recommendation` cuando aislar por red (`isolate_kubernetes_workload`) no es la opción elegida — mismo nivel de riesgo (`risk_level: high`), ambas modifican el estado de un workload.

## Modos soportados

- [x] read-only (otras tools del catálogo, no esta)
- [x] dry-run
- [x] execute (reversible)

## Precondiciones y límites (obligatorio, DoR)

* **Target allowlist**: `policies/target-allowlists/scale_to_zero.yaml` — hoy solo `deployment/gseg-simulado`. Fuera de esa lista, `mcp_gateway.Gateway.authorize()` devuelve `OUT_OF_SCOPE`.
* **Impacto máximo**: escala el `Deployment` objetivo a 0 réplicas; `FakeReplicaState` recuerda el recuento ORIGINAL (asumido 1 si el target no se ha visto antes — en producción vendría de `AssetSnapshot`/K8s API real, pendiente de ARG-021 contra un cluster real) para que el rollback restaure el valor correcto, no un valor fijo.
* **Timeout**: 30 segundos (`tool_catalog/definitions/scale_to_zero.yaml: timeout_seconds`).
* **Kill switch**: `argos-platform/cyber-range/kill-switch/kill-switch.sh` — independiente de este runbook.
* **Idempotencia**: `idempotency_key` obligatoria; un reintento con la misma clave devuelve el mismo `ActionResult` sin volver a escalar (`executors.IdempotencyStore`, probado en `tests/idempotency/test_executor_idempotency.py`).

## Pasos

1. **Dry-run**: `ScaleToZeroExecutor.scale_to_zero(dry_run=True, ...)` — no toca `FakeReplicaState`; `changed_resources=[]`.
2. **Aprobación (HITL)**: mismas reglas que `isolate_kubernetes_workload` — rol `soc-approver`, `plan_hash=(tool, target, action, params)` verificado en argos-cyber-tools, TTL fijado por quien aprueba en `expires_at`.
3. **Ejecución**: `ScaleToZeroExecutor.scale_to_zero(dry_run=False, ...)` → `FakeReplicaState.scale_to_zero(target)` guarda `(réplicas_originales, 0)`; `changed_resources=[target]`.
4. **Verificación**: el executor comprueba `state.current_replicas(target) == 0` antes de devolver `verification.passed`; `rollback/verification.verify_replicas_restored` es el chequeo independiente tras el rollback (compara contra `original_replicas`, no contra un valor fijo).
5. **Rollback** (si falla la verificación o se activa el kill switch): `rollback.strategies.rollback_scale_to_zero(...)` restaura `FakeReplicaState` a `(réplicas_originales, réplicas_originales)` — probado en `tests/rollback/test_rollback_cycle.py::test_scale_to_zero_then_rollback_restores_original_replicas` (escala a 0 desde 4 réplicas, rollback confirma que vuelve exactamente a 4, no a un valor por defecto).

## Evidencia producida

Mismos campos de `ActionResult` que `isolate_kubernetes_workload` (ver ese runbook) — `changed_resources` aquí es el propio `target` (Deployment), no un nombre de `NetworkPolicy`.

## Historial de simulación (rollback rehearsal)

| Fecha | Resultado | Evidencia (run_id) |
| --- | --- | --- |
| Continuo (cada `pytest`) | Escalar a 0 desde 4 réplicas → rollback → réplicas restauradas a 4 (no a un valor por defecto): PASA | `tests/rollback/test_rollback_cycle.py::test_scale_to_zero_then_rollback_restores_original_replicas` (en memoria, `FakeReplicaState`, test unitario sin `run_id` de escenario) |

Solo una simulación registrada hasta ahora (a diferencia de `isolate_kubernetes_workload`, que ya tiene dos) — falta una segunda antes de poder marcarse `APROBADO POR SOC/CYBER` incluso a nivel de simulación en memoria, según la regla del propio template ("al menos dos veces").
