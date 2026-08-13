"""Estrategia de rollback real por herramienta: opera sobre el MISMO estado
(`FakeClusterState`/`FakeReplicaState`) que modificó el executor, así que un
test puede comprobar de verdad que el estado queda como al principio, no
solo que se llamó a una función (documento maestro v0.5: "el rollback se
prueba, no solo se documenta").
"""
from __future__ import annotations

import datetime

from executors import (
    IdempotencyStore,
    InvalidActionResult,
    build_envelope,
    build_registry,
    new_id_prefixed,
    validate_payload,
)
from executors.kubernetes import FakeClusterState
from executors.scale_to_zero import FakeReplicaState


def rollback_isolation(
    contracts_path,
    cluster: FakeClusterState,
    *,
    run_id: str,
    target: str,
    idempotency_key: str,
    action_id: str,
    idempotency: IdempotencyStore | None = None,
) -> dict:
    idempotency = idempotency or IdempotencyStore()
    cached = idempotency.get(idempotency_key)
    if cached is not None:
        return cached

    was_isolated = cluster.is_isolated(target)
    started_at = datetime.datetime.now(datetime.UTC).isoformat()
    changed_resources = []
    if was_isolated:
        policy_name = cluster.isolated[target]
        cluster.remove_isolation(target)
        changed_resources = [policy_name]
    ended_at = datetime.datetime.now(datetime.UTC).isoformat()

    result_id = new_id_prefixed("act")
    payload = {
        "action_id": action_id,
        "idempotency_key": idempotency_key,
        "dry_run": False,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": "succeeded",
        "changed_resources": changed_resources,
        "verification": {
            "passed": not cluster.is_isolated(target),
            "detail": f"aislamiento revertido para {target}" if was_isolated else "no había aislamiento que revertir",
        },
    }
    envelope = build_envelope(payload, producer="kubernetes-executor-rollback", run_id=run_id, message_id=result_id)
    full_payload = {**envelope, **payload}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "action-result", full_payload)
    if errors:
        raise InvalidActionResult(errors)

    idempotency.remember(idempotency_key, full_payload)
    return full_payload


def rollback_scale_to_zero(
    contracts_path,
    state: FakeReplicaState,
    *,
    run_id: str,
    target: str,
    idempotency_key: str,
    action_id: str,
    idempotency: IdempotencyStore | None = None,
) -> dict:
    idempotency = idempotency or IdempotencyStore()
    cached = idempotency.get(idempotency_key)
    if cached is not None:
        return cached

    original = state.original_replicas(target)
    started_at = datetime.datetime.now(datetime.UTC).isoformat()
    state.replicas[target] = (original, original)  # restaura al valor original conocido
    ended_at = datetime.datetime.now(datetime.UTC).isoformat()

    result_id = new_id_prefixed("act")
    payload = {
        "action_id": action_id,
        "idempotency_key": idempotency_key,
        "dry_run": False,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": "succeeded",
        "changed_resources": [target],
        "verification": {
            "passed": state.current_replicas(target) == original,
            "detail": f"réplicas restauradas a {original} para {target}",
        },
    }
    envelope = build_envelope(payload, producer="scale-to-zero-executor-rollback", run_id=run_id, message_id=result_id)
    full_payload = {**envelope, **payload}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "action-result", full_payload)
    if errors:
        raise InvalidActionResult(errors)

    idempotency.remember(idempotency_key, full_payload)
    return full_payload


def mark_rolled_back(contracts_path, original_action_result: dict, rollback_action_result: dict) -> dict:
    """Devuelve una COPIA del ActionResult original con status='rolled_back'
    y rollback_ref apuntando al ActionResult de rollback — el original en sí
    no se muta (ya pudo quedar escrito en evidence_writer).

    rollback_ref usa el "id" del envelope (único por ActionResult), no
    "action_id": action_id es la referencia COMPARTIDA a la decisión que se
    ejecuta (original, reintentos y rollback usan el mismo action_id — ver
    executors/README.md), así que usarlo como rollback_ref producía un
    valor idéntico al action_id del propio original: una referencia que no
    apuntaba a ningún registro en concreto. Encontrado porque el test
    existente pasaba el MISMO action_id a la acción original y a su
    rollback (caso realista), lo que ocultaba que ambos valores coincidían.
    """
    updated = {**original_action_result, "status": "rolled_back", "rollback_ref": rollback_action_result["id"]}

    registry = build_registry(contracts_path)
    errors = validate_payload(contracts_path, registry, "action-result", updated)
    if errors:
        raise InvalidActionResult(errors)
    return updated
