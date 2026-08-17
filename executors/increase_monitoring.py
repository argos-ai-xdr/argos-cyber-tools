"""Executor de increase_monitoring. Hasta ahora declarado en el catálogo
(tool_catalog/definitions/increase_monitoring.yaml: mode=[dry-run, execute],
approval_required=false — mcp_gateway.Gateway.authorize ya lo autorizaba)
pero sin ningún código que lo ejecutara de verdad (ver executors/README.md).

Backend elegido: Wazuh (única fuente de telemetría con adapter real en
argos-core hoy — normalizer/correlator ya consumen sus eventos). "Elevar
verbosidad" se modela como subir el nivel de log del agente Wazuh del
target de "normal" a "verbose" — mismo nivel de fidelidad que
FakeClusterState/FakeReplicaState: no hay Wazuh real desplegado
(ARG-003), pero el estado en memoria cambia de verdad y rollback/ lo
revierte y lo verifica de verdad, no un mock que finge.
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

_NORMAL = "normal"
_VERBOSE = "verbose"


@dataclasses.dataclass
class FakeMonitoringState:
    """target -> (nivel_original, nivel_actual). Un target no visto antes
    se asume en nivel "normal" (mismo criterio documentado que
    FakeReplicaState para réplicas no vistas)."""

    levels: dict[str, tuple[str, str]] = dataclasses.field(default_factory=dict)

    def increase_monitoring(self, target: str) -> str:
        original, _ = self.levels.get(target, (_NORMAL, _NORMAL))
        self.levels[target] = (original, _VERBOSE)
        return original

    def current_level(self, target: str) -> str:
        return self.levels.get(target, (_NORMAL, _NORMAL))[1]

    def original_level(self, target: str) -> str:
        return self.levels.get(target, (_NORMAL, _NORMAL))[0]


class IncreaseMonitoringExecutor:
    def __init__(self, contracts_path, monitoring_state: FakeMonitoringState | None = None, idempotency: IdempotencyStore | None = None):
        self._contracts_path = contracts_path
        self._registry = build_registry(contracts_path)
        self.state = monitoring_state or FakeMonitoringState()
        self._idempotency = idempotency or IdempotencyStore()

    def increase_monitoring(self, *, run_id: str, target: str, dry_run: bool, idempotency_key: str, action_id: str) -> dict:
        cached = self._idempotency.get(idempotency_key)
        if cached is not None:
            return cached  # reintento: no se reejecuta el efecto (AC13)

        started_at = datetime.datetime.now(datetime.UTC).isoformat()
        changed_resources: list[str] = []
        if not dry_run:
            self.state.increase_monitoring(target)
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
                "passed": dry_run or self.state.current_level(target) == _VERBOSE,
                "detail": "dry-run: sin cambios aplicados" if dry_run else f"verbosidad elevada a '{_VERBOSE}' para {target}",
            },
        }
        envelope = build_envelope(payload, producer="increase-monitoring-executor", run_id=run_id, message_id=result_id)
        full_payload = {**envelope, **payload}

        errors = validate_payload(self._contracts_path, self._registry, "action-result", full_payload)
        if errors:
            raise InvalidActionResult(errors)

        self._idempotency.remember(idempotency_key, full_payload)
        return full_payload
