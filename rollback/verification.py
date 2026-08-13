"""Verificación post-rollback: comprueba el estado real (no confía en el
campo `verification` del propio ActionResult sin recomputarlo) — un segundo
chequeo independiente antes de dar por buena la reversión.
"""
from __future__ import annotations

from executors.kubernetes import FakeClusterState
from executors.scale_to_zero import FakeReplicaState


def verify_isolation_removed(cluster: FakeClusterState, target: str) -> bool:
    return not cluster.is_isolated(target)


def verify_replicas_restored(state: FakeReplicaState, target: str) -> bool:
    return state.current_replicas(target) == state.original_replicas(target)
