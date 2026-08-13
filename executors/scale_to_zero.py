"""Executor de scale_to_zero. Misma simulación de estado real en memoria que
executors/kubernetes.py — FakeReplicaState guarda el recuento de réplicas
"antes" para que rollback/ pueda restaurarlo de verdad, no solo documentarlo.
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
class FakeReplicaState:
    """target -> (réplicas_originales, réplicas_actuales). Un target no
    visto antes se asume con 1 réplica original (documentado — en
    producción esto vendría de AssetSnapshot/K8s API, ARG-021)."""

    replicas: dict[str, tuple[int, int]] = dataclasses.field(default_factory=dict)

    def scale_to_zero(self, target: str) -> int:
        original, _ = self.replicas.get(target, (1, 1))
        self.replicas[target] = (original, 0)
        return original

    def current_replicas(self, target: str) -> int:
        return self.replicas.get(target, (1, 1))[1]

    def original_replicas(self, target: str) -> int:
        return self.replicas.get(target, (1, 1))[0]


class ScaleToZeroExecutor:
    def __init__(self, contracts_path, replica_state: FakeReplicaState | None = None, idempotency: IdempotencyStore | None = None):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self.state = replica_state or FakeReplicaState()
        self._idempotency = idempotency or IdempotencyStore()

    def scale_to_zero(self, *, run_id: str, target: str, dry_run: bool, idempotency_key: str, action_id: str) -> dict:
        cached = self._idempotency.get(idempotency_key)
        if cached is not None:
            return cached

        started_at = datetime.datetime.now(datetime.UTC).isoformat()
        changed_resources: list[str] = []
        if not dry_run:
            self.state.scale_to_zero(target)
            changed_resources = [target]
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
                "passed": dry_run or self.state.current_replicas(target) == 0,
                "detail": "dry-run: sin cambios aplicados" if dry_run else f"réplicas en 0 para {target}",
            },
        }
        envelope = build_envelope(payload, producer="scale-to-zero-executor", run_id=run_id, message_id=result_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "action-result", full_payload)
        if errors:
            raise InvalidActionResult(errors)

        self._idempotency.remember(idempotency_key, full_payload)
        return full_payload
