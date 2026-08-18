"""mcp_gateway.controlled_execution: R0-01, §11-13 (reconciliación global
A→L, 2026-08-17). Antes de este módulo, `Gateway.authorize()` y los
executors (`executors/kubernetes.py`, `executors/scale_to_zero.py`,
`executors/increase_monitoring.py`) eran ambos reales y probados, pero
NADA en el repositorio los conectaba — ningún código de producción
llamaba a `authorize()` y luego, condicionado a `allowed=True`,
invocaba al executor. `KubernetesExecutor.isolate_workload()` (y
equivalentes) son directamente invocables sin pasar por ningún gate.

`execute_with_authorization` es el único punto de entrada real que
conecta ambos lados: autoriza PRIMERO, y solo invoca `executor_call` si
`authorization.allowed`. Ninguna otra función de este repositorio debe
volverse el camino real hacia un executor con `dry_run=False` — los
tests de este módulo (`tests/authorization/test_controlled_execution.py`)
prueban con espías que `executor_call` nunca se invoca cuando la
autorización se deniega (`executor_call_count == 0`).
"""
from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Callable

from mcp_gateway import AuthorizationResult, Gateway, ToolCallRequest

ExecutorCall = Callable[..., dict]


@dataclasses.dataclass(frozen=True)
class ExecutionOutcome:
    authorized: bool
    authorization: AuthorizationResult
    result: dict | None  # ActionResult payload del executor, solo si authorized


def execute_with_authorization(
    gateway: Gateway,
    request: ToolCallRequest,
    *,
    executor_call: ExecutorCall,
    run_id: str,
    idempotency_key: str,
    action_id: str,
    current_plan_hash: str | None = None,
    now: datetime.datetime | None = None,
) -> ExecutionOutcome:
    """`executor_call` es un método de executor real (p. ej.
    `KubernetesExecutor(contracts_path).isolate_workload`) con la firma
    común `(*, run_id, target, dry_run, idempotency_key, action_id) ->
    dict` que comparten los tres executors reales de este repositorio.
    `dry_run` se deriva de `request.action` -- nunca es un parámetro
    aparte que un llamante pudiera desincronizar de lo que Gateway
    realmente autorizó."""
    authorization = gateway.authorize(request, current_plan_hash=current_plan_hash, now=now)
    if not authorization.allowed:
        return ExecutionOutcome(authorized=False, authorization=authorization, result=None)

    result = executor_call(
        run_id=run_id,
        target=request.target,
        dry_run=request.action != "execute",
        idempotency_key=idempotency_key,
        action_id=action_id,
    )
    return ExecutionOutcome(authorized=True, authorization=authorization, result=result)
