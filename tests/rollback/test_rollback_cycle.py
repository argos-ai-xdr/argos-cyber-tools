from __future__ import annotations

from executors.increase_monitoring import IncreaseMonitoringExecutor
from executors.kubernetes import KubernetesExecutor
from executors.scale_to_zero import ScaleToZeroExecutor
from rollback.strategies import (
    mark_rolled_back,
    rollback_increase_monitoring,
    rollback_isolation,
    rollback_scale_to_zero,
)
from rollback.verification import (
    verify_isolation_removed,
    verify_monitoring_restored,
    verify_replicas_restored,
)


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

    rb = rollback_scale_to_zero(
        contracts_path, executor.state, run_id="r2", target="deployment/y", idempotency_key="k-4-rb", action_id="pol-4"
    )
    assert verify_replicas_restored(executor.state, "deployment/y")
    assert executor.state.current_replicas("deployment/y") == 4
    assert rb["changed_resources"] == ["deployment/y"]  # de verdad revirtió algo


def test_rollback_scale_to_zero_when_nothing_was_scaled_is_a_noop_not_a_false_change(contracts_path):
    """Regresión real: rollback_scale_to_zero reportaba changed_resources=[target]
    incondicionalmente, incluso para un target que nunca se había escalado
    a cero — una afirmación falsa en la evidencia (el estado antes y
    después es idéntico, 1 réplica). Mismo principio que
    test_rollback_when_nothing_was_isolated_is_a_noop_not_an_error para
    isolation, que sí lo comprobaba; scale_to_zero no tenía el equivalente."""
    executor = ScaleToZeroExecutor(contracts_path)
    rb = rollback_scale_to_zero(
        contracts_path, executor.state, run_id="r2", target="deployment/never-scaled", idempotency_key="k-5-rb", action_id="pol-5"
    )
    assert rb["changed_resources"] == []
    assert rb["verification"]["passed"] is True


def test_increase_monitoring_then_rollback_restores_original_level(contracts_path):
    executor = IncreaseMonitoringExecutor(contracts_path)
    executor.increase_monitoring(run_id="r3", target="deployment/z", dry_run=False, idempotency_key="k-6", action_id="pol-6")
    assert executor.state.current_level("deployment/z") == "verbose"

    rb = rollback_increase_monitoring(
        contracts_path, executor.state, run_id="r3", target="deployment/z", idempotency_key="k-6-rb", action_id="pol-6"
    )
    assert verify_monitoring_restored(executor.state, "deployment/z")
    assert executor.state.current_level("deployment/z") == "normal"
    assert rb["changed_resources"] == ["deployment/z"]  # de verdad revirtió algo


def test_rollback_increase_monitoring_when_nothing_was_increased_is_a_noop_not_a_false_change(contracts_path):
    """Mismo principio que test_rollback_scale_to_zero_when_nothing_was_scaled_is_a_noop_not_a_false_change:
    un target cuya verbosidad nunca se elevó no debe reportar
    changed_resources=[target] -- el estado antes y después es idéntico."""
    executor = IncreaseMonitoringExecutor(contracts_path)
    rb = rollback_increase_monitoring(
        contracts_path, executor.state, run_id="r3", target="deployment/never-increased", idempotency_key="k-7-rb", action_id="pol-7"
    )
    assert rb["changed_resources"] == []
    assert rb["verification"]["passed"] is True


def test_increase_monitoring_dry_run_does_not_change_state(contracts_path):
    executor = IncreaseMonitoringExecutor(contracts_path)
    result = executor.increase_monitoring(run_id="r3", target="deployment/z2", dry_run=True, idempotency_key="k-8", action_id="pol-8")
    assert result["dry_run"] is True
    assert result["changed_resources"] == []
    assert executor.state.current_level("deployment/z2") == "normal"


def test_increase_monitoring_retry_with_same_idempotency_key_does_not_reapply_effect(contracts_path):
    executor = IncreaseMonitoringExecutor(contracts_path)
    first = executor.increase_monitoring(run_id="r3", target="deployment/z3", dry_run=False, idempotency_key="k-9", action_id="pol-9")
    second = executor.increase_monitoring(run_id="r3", target="deployment/z3", dry_run=False, idempotency_key="k-9", action_id="pol-9")
    assert first == second
