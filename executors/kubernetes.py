"""Executor de isolate_kubernetes_workload. Sin clúster real disponible en
este bootstrap (argos-platform lo provee, ARG-003): FakeClusterState
simula el efecto de aplicar una CiliumNetworkPolicy con un diccionario en
memoria real — no un mock que finge, un estado que de verdad cambia y que
rollback/ puede de verdad revertir y verificar.
"""
from __future__ import annotations

import dataclasses
import datetime

from executors import (
    IdempotencyStore,
    InvalidActionResult,
    build_envelope,
    build_registry,
    new_id_prefixed,
    validate_payload,
)


@dataclasses.dataclass
class FakeClusterState:
    """Estado real en memoria del cyber-range simulado. isolated: target ->
    nombre de la CiliumNetworkPolicy aplicada."""

    isolated: dict[str, str] = dataclasses.field(default_factory=dict)

    def apply_isolation(self, target: str) -> str:
        policy_name = f"ciliumnetworkpolicy/{target.split('/')[-1]}-isolate"
        self.isolated[target] = policy_name
        return policy_name

    def remove_isolation(self, target: str) -> None:
        self.isolated.pop(target, None)

    def is_isolated(self, target: str) -> bool:
        return target in self.isolated


class KubernetesExecutor:
    def __init__(self, contracts_path, cluster_state: FakeClusterState | None = None, idempotency: IdempotencyStore | None = None):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self.cluster = cluster_state or FakeClusterState()
        self._idempotency = idempotency or IdempotencyStore()

    def isolate_workload(self, *, run_id: str, target: str, dry_run: bool, idempotency_key: str, action_id: str) -> dict:
        cached = self._idempotency.get(idempotency_key)
        if cached is not None:
            return cached  # reintento: no se reejecuta el efecto (AC13)

        started_at = datetime.datetime.now(datetime.UTC).isoformat()
        changed_resources: list[str] = []
        if not dry_run:
            policy_name = self.cluster.apply_isolation(target)
            changed_resources = [policy_name]
        ended_at = datetime.datetime.now(datetime.UTC).isoformat()

        result_id = new_id_prefixed("act")
        payload = {
            "action_id": action_id,
            "idempotency_key": idempotency_key,
            "dry_run": dry_run,
            "started_at": started_at,
            "ended_at": ended_at,
            "status": "succeeded",
            "changed_resources": changed_resources,
            "verification": {
                "passed": dry_run or self.cluster.is_isolated(target),
                "detail": "dry-run: sin cambios aplicados" if dry_run else f"aislamiento confirmado para {target}",
            },
        }
        envelope = build_envelope(payload, producer="kubernetes-executor", run_id=run_id, message_id=result_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "action-result", full_payload)
        if errors:
            raise InvalidActionResult(errors)

        self._idempotency.remember(idempotency_key, full_payload)
        return full_payload
