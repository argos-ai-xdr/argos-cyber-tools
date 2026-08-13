from __future__ import annotations

from executors.kubernetes import KubernetesExecutor
from executors.scale_to_zero import ScaleToZeroExecutor
from rollback.strategies import mark_rolled_back, rollback_isolation, rollback_scale_to_zero
from rollback.verification import verify_isolation_removed, verify_replicas_restored


def test_isolate_then_rollback_restores_state(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-1", action_id="pol-1"
    )
    assert executor.cluster.is_isolated("deployment/x")

    rb = rollback_isolation(
        contracts_path, executor.cluster, run_id="r1", target="deployment/x", idempotency_key="k-1-rb", action_id="pol-1"
    )
    assert verify_isolation_removed(executor.cluster, "deployment/x")
    assert rb["changed_resources"]  # de verdad revirtió algo, no una lista vacía


def test_rollback_when_nothing_was_isolated_is_a_noop_not_an_error(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    rb = rollback_isolation(
        contracts_path, executor.cluster, run_id="r1", target="deployment/never-isolated", idempotency_key="k-2-rb", action_id="pol-2"
    )
    assert rb["changed_resources"] == []
    assert rb["verification"]["passed"] is True


def test_mark_rolled_back_updates_status_and_reference(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    action = executor.isolate_workload(
        run_id="r1", target="deployment/x", dry_run=False, idempotency_key="k-3", action_id="pol-3"
    )
    rb = rollback_isolation(
        contracts_path, executor.cluster, run_id="r1", target="deployment/x", idempotency_key="k-3-rb", action_id="pol-3"
    )
    updated = mark_rolled_back(contracts_path, action, rb)

    assert updated["status"] == "rolled_back"
    # rollback_ref debe ser el "id" único de rb, no su action_id: original y
    # rollback comparten el MISMO action_id ("pol-3" en ambos, caso real),
    # así que si rollback_ref fuera rb["action_id"] coincidiría con el
    # action_id del propio original y no apuntaría a ningún registro
    # concreto (bug real encontrado así).
    assert updated["rollback_ref"] == rb["id"]
    assert updated["rollback_ref"] != updated["action_id"]
    assert action["status"] == "succeeded"  # el original NO se mutó


def test_scale_to_zero_then_rollback_restores_original_replicas(contracts_path):
    executor = ScaleToZeroExecutor(contracts_path)
    executor.state.replicas["deployment/y"] = (4, 4)

    executor.scale_to_zero(run_id="r2", target="deployment/y", dry_run=False, idempotency_key="k-4", action_id="pol-4")
    assert executor.state.current_replicas("deployment/y") == 0

    rollback_scale_to_zero(
        contracts_path, executor.state, run_id="r2", target="deployment/y", idempotency_key="k-4-rb", action_id="pol-4"
    )
    assert verify_replicas_restored(executor.state, "deployment/y")
    assert executor.state.current_replicas("deployment/y") == 4
