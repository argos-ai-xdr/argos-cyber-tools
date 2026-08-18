"""Cierre de ARG-020/CH-07 (ADR-068 CHAOS-16): DurableApprovalStore debe
demostrar, ejecutando de verdad, exactamente lo que ApprovalStore (en
memoria) NO podía: el estado de consumo sobrevive a un reinicio de
proceso. "Reinicio" se modela honestamente como cerrar la conexión (o
simplemente abandonarla, simulando un crash) y abrir una instancia NUEVA
de `DurableApprovalStore` apuntando al MISMO fichero -- mismo criterio
que ya se usó para "reinicio" de `Gateway` en
tests/adversarial/test_chaos_16_gateway_restart_r0_01_regression.py.
"""
from __future__ import annotations

import datetime
import threading

import pytest

from policies.approval import ApprovalRejected, compute_plan_hash, compute_signature_ref
from policies.approval.durable_store import ApprovalStorageUnavailable, DurableApprovalStore


def _plan_hash():
    return compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")


def _approval(approval_id, plan_hash, now, **overrides):
    base = {
        "approval_id": approval_id,
        "approver_id": "soc-1",
        "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref(approval_id, plan_hash),
    }
    base.update(overrides)
    return base


def _now():
    return datetime.datetime.now(datetime.UTC)


# ---------------------------------------------------------------------------
# El invariante central: consume -> "reinicio" -> replay -> DENY.
# ---------------------------------------------------------------------------


def test_consume_then_restart_then_replay_is_denied(tmp_path):
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    approval = _approval("appr-durable-1", plan_hash, now)

    store_before_restart = DurableApprovalStore(db_path)
    store_before_restart.validate_and_consume(
        approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now
    )
    store_before_restart.close()

    # "Reinicio": instancia COMPLETAMENTE NUEVA sobre el mismo fichero --
    # ningún objeto Python compartido con la instancia anterior.
    store_after_restart = DurableApprovalStore(db_path)
    with pytest.raises(ApprovalRejected, match="replay"):
        store_after_restart.validate_and_consume(
            approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now
        )


def test_consume_then_crash_without_close_then_restart_then_replay_is_denied(tmp_path):
    """Variante más honesta de "reinicio": ni siquiera se cierra la
    conexión limpiamente (simulando un crash real, no un shutdown
    ordenado) -- SQLite en modo WAL sigue garantizando durabilidad tras
    COMMIT (autocommit aquí, isolation_level=None) sin depender de que el
    proceso anterior cerrara nada correctamente."""
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    approval = _approval("appr-durable-2", plan_hash, now)

    store_before_crash = DurableApprovalStore(db_path)
    store_before_crash.validate_and_consume(
        approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now
    )
    # Sin close() -- el objeto simplemente se abandona, como tras un crash.
    del store_before_crash

    store_after_restart = DurableApprovalStore(db_path)
    with pytest.raises(ApprovalRejected, match="replay"):
        store_after_restart.validate_and_consume(
            approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now
        )


def test_two_concurrent_consumers_exactly_one_succeeds(tmp_path):
    """Consumo atómico real, no solo declarado: dos hilos intentando
    consumir la MISMA Approval concurrentemente contra el MISMO fichero
    -- exactamente uno tiene éxito, el otro recibe replay. Nunca ambos
    éxito."""
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    approval = _approval("appr-durable-concurrent", plan_hash, now)

    # Pre-crear el fichero/esquema antes de lanzar los hilos, para que la
    # carrera sea sobre el INSERT, no sobre el CREATE TABLE.
    DurableApprovalStore(db_path).close()

    results: list[str] = []
    lock = threading.Lock()

    def _attempt():
        store = DurableApprovalStore(db_path)
        try:
            store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)
            outcome = "SUCCESS"
        except ApprovalRejected:
            outcome = "REPLAY_DENIED"
        finally:
            store.close()
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=_attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("SUCCESS") == 1
    assert results.count("REPLAY_DENIED") == 4


def test_expired_approval_is_denied_even_after_restart(tmp_path):
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    expired = _approval(
        "appr-durable-expired", plan_hash, now, expires_at=(now - datetime.timedelta(seconds=1)).isoformat()
    )

    DurableApprovalStore(db_path).close()  # crea el esquema
    store_after_restart = DurableApprovalStore(db_path)
    with pytest.raises(ApprovalRejected, match="TTL expirado"):
        store_after_restart.validate_and_consume(
            expired, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now
        )


def test_same_approval_id_different_action_is_denied_by_signature_mismatch(tmp_path):
    """"Mismo nonce, acción distinta": el approval_id es el mismo, pero
    firmado para un plan_hash que ya no coincide con la acción actual --
    denegado por firma, independientemente de si ya se consumió o no."""
    db_path = tmp_path / "approvals.db"
    now = _now()
    plan_hash_original = _plan_hash()
    approval = _approval("appr-durable-diffaction", plan_hash_original, now)

    different_plan_hash = compute_plan_hash(tool="scale_to_zero", target="deployment/gseg-simulado", action="execute")

    store = DurableApprovalStore(db_path)
    with pytest.raises(ApprovalRejected, match="no coincide"):
        store.validate_and_consume(
            approval, current_plan_hash=different_plan_hash, requester_id="r", executor_id="e", now=now
        )


# ---------------------------------------------------------------------------
# Fail-closed ante el propio almacén -- nunca fallback a memoria.
# ---------------------------------------------------------------------------


def test_storage_unavailable_denies_never_falls_back_to_memory(tmp_path):
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    approval = _approval("appr-durable-unavailable", plan_hash, now)

    store = DurableApprovalStore(db_path)
    store.close()  # simula el almacén dejando de responder

    with pytest.raises(ApprovalStorageUnavailable):
        store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)


def test_storage_unavailable_is_an_approval_rejected_subclass():
    """mcp_gateway.Gateway.authorize ya captura ApprovalRejected -- esto
    prueba que NO hace falta código nuevo en el gateway para que un fallo
    de almacén se trate como DENY: ApprovalStorageUnavailable hereda de
    ApprovalRejected."""
    assert issubclass(ApprovalStorageUnavailable, ApprovalRejected)


def test_storage_comes_back_after_being_unavailable(tmp_path):
    """Tras un fallo del almacén, una instancia NUEVA (reconexión, no
    fallback) contra el mismo fichero vuelve a funcionar con normalidad
    -- el fallo previo no deja el sistema permanentemente denegado."""
    db_path = tmp_path / "approvals.db"
    plan_hash = _plan_hash()
    now = _now()
    approval = _approval("appr-durable-recovers", plan_hash, now)

    broken_store = DurableApprovalStore(db_path)
    broken_store.close()
    with pytest.raises(ApprovalStorageUnavailable):
        broken_store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)

    recovered_store = DurableApprovalStore(db_path)  # "el almacén vuelve" -- reconexión real, no fallback
    recovered_store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)
    assert recovered_store.is_consumed("appr-durable-recovers") is True


# ---------------------------------------------------------------------------
# Defensa en profundidad: DurableApprovalStore cierra el replay tras
# reinicio, pero el binding de R0-01-RESIDUAL (envelope_hash<->plan_hash en
# mcp_gateway._check_safety_chain) es una capa INDEPENDIENTE -- se
# comprueba antes de llegar siquiera a validate_and_consume. Confirma que
# usar el almacén durable no debilita, ni por accidente, esa otra
# protección: "misma Approval + SafetyEnvelope/incidente distinto" sigue
# denegado, con o sin reinicio de por medio.
# ---------------------------------------------------------------------------


def test_durable_store_does_not_weaken_cross_incident_binding_after_restart(tmp_path, contracts_path):
    from executors.kubernetes import KubernetesExecutor
    from mcp_gateway import Gateway, ToolCallRequest
    from mcp_gateway.controlled_execution import execute_with_authorization

    tool, target, action = "isolate_kubernetes_workload", "deployment/gseg-simulado", "execute"

    def _envelope(incident_ref, envelope_hash):
        now = _now()
        return {
            "envelope_id": f"safenv-{incident_ref}", "incident_ref": incident_ref,
            "target_set": [target], "allowed_actions": [action], "forbidden_actions": [],
            "required_runbook": f"runbooks/{tool}.md", "rollback_ref": f"rollback/{tool}",
            "valid_until": (now + datetime.timedelta(minutes=15)).isoformat(),
            "envelope_hash": envelope_hash, "signature": "sha256:" + "b" * 64,
        }

    def _verification(envelope):
        return {"state": "VERIFIED", "envelope_hash": envelope["envelope_hash"], "tool_name": tool, "target": target}

    envelope_a = _envelope("incident-A", "sha256:" + "a" * 64)
    envelope_b = _envelope("incident-B", "sha256:" + "b" * 64)
    plan_hash_a = compute_plan_hash(tool=tool, target=target, action=action, params={"safety_envelope_hash": envelope_a["envelope_hash"]})
    approval_a = _approval("appr-durable-crossincident", plan_hash_a, _now())

    db_path = tmp_path / "approvals.db"
    executor = KubernetesExecutor(contracts_path)

    # Instancia 1: Gateway durable, consume Approval A legítimamente bajo
    # el propio incidente A.
    gateway_1 = Gateway(target_allowlists={tool: {target}}, approval_store=DurableApprovalStore(db_path))
    request_a = ToolCallRequest(
        tool_name=tool, target=target, action=action, subject="langgraph", caller_token="t",
        granted_scopes=frozenset({"cyber.response.execute"}),
        approval=approval_a, safety_envelope=envelope_a, verification_result=_verification(envelope_a),
    )
    outcome_a = execute_with_authorization(
        gateway_1, request_a, executor_call=executor.isolate_workload,
        run_id="r-1", idempotency_key="k-1", action_id="a-1", current_plan_hash=plan_hash_a,
    )
    assert outcome_a.authorized is True

    # "Reinicio" + intento de reutilizar la MISMA Approval A bajo el
    # SafetyEnvelope/incidente B -- ni el reinicio del almacén durable ni
    # el binding de R0-01-RESIDUAL lo permiten, por razones independientes
    # (replay Y envelope_hash no coincide).
    gateway_2 = Gateway(target_allowlists={tool: {target}}, approval_store=DurableApprovalStore(db_path))
    request_b = ToolCallRequest(
        tool_name=tool, target=target, action=action, subject="langgraph", caller_token="t",
        granted_scopes=frozenset({"cyber.response.execute"}),
        approval=approval_a, safety_envelope=envelope_b, verification_result=_verification(envelope_b),
    )
    outcome_b = execute_with_authorization(
        gateway_2, request_b, executor_call=executor.isolate_workload,
        run_id="r-2", idempotency_key="k-2", action_id="a-2", current_plan_hash=plan_hash_a,
    )
    assert outcome_b.authorized is False
    assert "R0-01-RESIDUAL" in outcome_b.authorization.reason
