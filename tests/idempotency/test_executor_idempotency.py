from __future__ import annotations

from executors.kubernetes import KubernetesExecutor
from executors.scale_to_zero import ScaleToZeroExecutor


def test_same_idempotency_key_does_not_reapply_isolation(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    first = executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-1", action_id="pol-1"
    )
    applied_after_first = dict(executor.cluster.isolated)

    second = executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-1", action_id="pol-1"
    )

    assert first == second  # mismo ActionResult, no uno nuevo
    assert executor.cluster.isolated == applied_after_first  # el estado no cambió una segunda vez


def test_different_idempotency_key_is_treated_as_new_action(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    first = executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-a", action_id="pol-1"
    )
    second = executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-b", action_id="pol-1"
    )
    assert first["id"] != second["id"]


def test_scale_to_zero_idempotency_preserves_original_replica_count(contracts_path):
    executor = ScaleToZeroExecutor(contracts_path)
    executor.state.replicas["deployment/y"] = (5, 5)

    executor.scale_to_zero(run_id="r2", target="deployment/y", dry_run=False, idempotency_key="k-c", action_id="pol-2")
    assert executor.state.original_replicas("deployment/y") == 5

    # Reintento con la misma clave no debe volver a tocar el estado.
    before = dict(executor.state.replicas)
    executor.scale_to_zero(run_id="r2", target="deployment/y", dry_run=False, idempotency_key="k-c", action_id="pol-2")
    assert executor.state.replicas == before


def test_dry_run_never_consumes_idempotency_for_the_real_action(contracts_path):
    """dry_run=True y dry_run=False con distinta idempotency_key son
    acciones distintas — un dry-run no debe bloquear el execute real."""
    executor = KubernetesExecutor(contracts_path)
    executor.isolate_workload(run_id="r1", target="deployment/z", dry_run=True, idempotency_key="k-dry", action_id="pol-1")
    assert not executor.cluster.is_isolated("deployment/z")

    executor.isolate_workload(run_id="r1", target="deployment/z", dry_run=False, idempotency_key="k-real", action_id="pol-1")
    assert executor.cluster.is_isolated("deployment/z")
