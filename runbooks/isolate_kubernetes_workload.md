# Runbook: isolate_kubernetes_workload

* **Repositorio propietario**: `argos-cyber-tools`
* **Herramienta MCP asociada**: `isolate_kubernetes_workload` v1.0.0 (`tool_catalog/definitions/isolate_kubernetes_workload.yaml`)
* **Estado**: BORRADOR — el código y la simulación en memoria son reales y probados; falta el sign-off formal de SOC/Cyber contra un cyber-range REAL desplegado (bloqueado por lo mismo que ENV-QUAL-01, ver `argos-validation/traceability.yaml` gate G6/ARG-023).
* **Aprobado por**: PENDIENTE — requiere sign-off real de SOC/Cyber (rol `soc-approver` / RACI `SOC`, `argos-control/governance/raci/raci.md`). No se inventa un nombre ni una fecha.
* **Fecha de aprobación / última simulación**: ver "Historial de simulación" abajo — todas las simulaciones registradas son en memoria (`FakeClusterState`), no contra un cluster real.

## Cuándo se usa

Contención de un workload de Kubernetes cuando `argos-core/services/recommendation` propone aislamiento por severidad `high`/`critical` (mismo ejemplo canónico del documento maestro v0.5, sección "Definición obligatoria de cada tool"). Coincide con `argos-contracts-scenarios/scenarios/ARGOS-CYB-01/policies/isolate-kubernetes-workload.rego`.

## Modos soportados

- [x] read-only (`read_asset_inventory`, `read_vulnerability_findings` — otras tools del catálogo, no esta)
- [x] dry-run
- [x] execute (reversible)

## Precondiciones y límites (obligatorio, DoR)

* **Target allowlist**: `policies/target-allowlists/isolate_kubernetes_workload.yaml` — hoy solo `deployment/gseg-simulado`. Cualquier otro target produce `OUT_OF_SCOPE` en `mcp_gateway.Gateway.authorize()` (ver `graph/attack_path.py`, probado en `tests/graph/test_attack_path.py::test_target_outside_allowlist_is_out_of_scope`).
* **Impacto máximo**: aplica una `CiliumNetworkPolicy` de aislamiento sobre el target (`ciliumnetworkpolicy/<nombre>-isolate`); no elimina ni escala el workload, no toca otros servicios del namespace.
* **Timeout**: 30 segundos (`tool_catalog/definitions/isolate_kubernetes_workload.yaml: timeout_seconds`).
* **Kill switch**: `argos-platform/cyber-range/kill-switch/kill-switch.sh` — corta egress no esencial y escala a cero TODO el namespace `argos-cyber-range`, independiente de este runbook (scenario.yaml: "el operador dispone de kill switch y rollback independiente del agente").
* **Idempotencia**: `idempotency_key` obligatoria (schema `action-result/v1`); `executors.IdempotencyStore` (en memoria hoy) devuelve el mismo `ActionResult` sin reaplicar el efecto ante un reintento con la misma clave — probado en `tests/idempotency/test_executor_idempotency.py`.

## Pasos

1. **Dry-run**: `KubernetesExecutor.isolate_workload(dry_run=True, ...)` — no aplica ninguna `CiliumNetworkPolicy`; `changed_resources=[]`, `verification.passed=True` (nada que verificar).
2. **Aprobación (HITL)**: rol requerido `soc-approver` (único rol real reconocido, `require_role("soc-approver")` en `argos-smartops/api/approvals.py`); `Approval.decision=APPROVE`, sin caducar, `plan_hash` calculado como `(tool, target, action, params)` idéntico en emisor (argos-smartops) y validador (argos-cyber-tools) — ver `policies/approval/compute_plan_hash`. TTL lo fija quien aprueba en `expires_at` (no hay una duración fija en código; el fixture real usa 15 minutos, `fixtures/smoke/approval/approval-001.json`).
3. **Ejecución**: `KubernetesExecutor.isolate_workload(dry_run=False, ...)` aplica `FakeClusterState.apply_isolation(target)` → `changed_resources=["ciliumnetworkpolicy/<target>-isolate"]`.
4. **Verificación**: el propio executor comprueba `cluster.is_isolated(target)` antes de devolver `verification.passed`; `rollback/verification.verify_isolation_removed` es el chequeo INDEPENDIENTE tras un rollback (no confía en el campo `verification` del ActionResult sin recomputarlo).
5. **Rollback** (si falla la verificación o se activa el kill switch): `rollback.strategies.rollback_isolation(...)` — revierte `FakeClusterState`, produce un ActionResult nuevo con su propio `id`; `rollback.strategies.mark_rolled_back(original, rb)` marca el ActionResult original como `status=rolled_back` con `rollback_ref=<id del ActionResult de rollback>` (nunca el mismo `action_id`, ambos comparten `action_id` pero `rollback_ref` apunta al registro concreto — bug real encontrado y corregido, ver `tests/rollback/test_rollback_cycle.py::test_mark_rolled_back_updates_status_and_reference`).

## Evidencia producida

`ActionResult` (`action_id`, `idempotency_key`, `dry_run`, `started_at`/`ended_at`, `status`, `changed_resources`, `verification.passed`/`detail`, `rollback_ref`) validado contra `argos-contracts-scenarios/schemas/action-result/v1.schema.json` en el propio executor antes de devolverlo (`InvalidActionResult` si no valida — nunca se devuelve un ActionResult inválido).

## Historial de simulación (rollback rehearsal)

| Fecha | Resultado | Evidencia (run_id) |
| --- | --- | --- |
| Continuo (cada `pytest`) | Aislar → verificar aislado → rollback → verificar removido: PASA | `tests/rollback/test_rollback_cycle.py::test_isolate_then_rollback_restores_state` (en memoria, `FakeClusterState`, sin `run_id` de escenario — es un test unitario, no un run de suite) |
| 2026-08-17 (sesión de desarrollo) | Aislar `deployment/gseg-simulado` → rollback → `verification.passed=true` | `run-smoke-001`, fixture congelado en `argos-contracts-scenarios/fixtures/smoke/action-result/action-result-002-rollback.json` (generado invocando este mismo código real, no fabricado a mano) |

Ambas simulaciones son en memoria (`FakeClusterState`), no contra un cluster real desplegado — la "última simulación" con validez para aprobar S6 en el sentido del documento maestro (contra el cyber-range real) sigue pendiente de ENV-QUAL-01.
