"""CHAOS-16 (ADR-068, argos-control): regresión local de "reinicio del
mcp_gateway a mitad de flujo" sin necesitar un clúster de caos real --
`Gateway`/`ApprovalStore` son procesos en memoria, así que "reinicio" se
modela honestamente como crear una instancia NUEVA de `Gateway` (mismo
efecto que perder todo el estado en memoria de un proceso reiniciado).

Dos preguntas distintas, con resultados distintos -- no se asume que
ambas se comporten igual solo porque las dos involucran un "reinicio":

1. ¿Sobrevive al reinicio el binding de R0-01-RESIDUAL (envelope_hash <->
   plan_hash) contra reutilización cross-incident? SÍ, y por diseño: es
   una comprobación puramente derivada de los datos de CADA solicitud
   (`_check_safety_chain` + el chequeo de `expected_plan_hash`), no
   depende de ningún estado que un reinicio pueda perder.

2. ¿Sobrevive al reinicio el anti-replay de `approval_id` (una Approval
   YA CONSUMIDA en la instancia anterior)? NO -- `ApprovalStore._consumed`
   es un `set()` en memoria de ESA instancia; una instancia nueva empieza
   vacía. Esto NO es una regresión de R0-01/R0-01-RESIDUAL: es el riesgo
   operacional YA documentado en `mcp_gateway.ApprovalStore`
   ("en producción esto vive en un almacén compartido entre réplicas del
   gateway... no en memoria de un único proceso", ARG-020) -- pero hasta
   ahora nadie lo había demostrado ejecutando el reinicio de verdad. Se
   deja aquí como test QUE FALLA A PROPÓSITO documentado (xfail), no
   oculto ni silenciado, para que ARG-020 (almacén compartido real) tenga
   una regresión que lo confirme cuando se cierre.
"""
from __future__ import annotations

import datetime

import pytest

from mcp_gateway import Gateway, ToolCallRequest
from mcp_gateway.controlled_execution import execute_with_authorization
from policies.approval import compute_plan_hash, compute_signature_ref

_TOOL = "isolate_kubernetes_workload"
_TARGET = "deployment/gseg-simulado"
_ACTION = "execute"


def _envelope(*, incident_ref: str, envelope_hash: str) -> dict:
    now = datetime.datetime.now(datetime.UTC)
    return {
        "envelope_id": f"safenv-{incident_ref}",
        "incident_ref": incident_ref,
        "target_set": [_TARGET],
        "allowed_actions": [_ACTION],
        "forbidden_actions": [],
        "required_runbook": f"runbooks/{_TOOL}.md",
        "rollback_ref": f"rollback/{_TOOL}",
        "valid_until": (now + datetime.timedelta(minutes=15)).isoformat(),
        "envelope_hash": envelope_hash,
        "signature": "sha256:" + "b" * 64,
    }


def _verification(envelope: dict, *, state: str = "VERIFIED") -> dict:
    return {"state": state, "envelope_hash": envelope["envelope_hash"], "tool_name": _TOOL, "target": _TARGET}


def _plan_hash_for(envelope_hash: str) -> str:
    return compute_plan_hash(tool=_TOOL, target=_TARGET, action=_ACTION, params={"safety_envelope_hash": envelope_hash})


def _approval(*, approval_id: str, plan_hash: str) -> dict:
    now = datetime.datetime.now(datetime.UTC)
    return {
        "approval_id": approval_id,
        "approver_id": "soc-1",
        "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref(approval_id, plan_hash),
    }


class _Spy:
    def __init__(self) -> None:
        self.call_count = 0

    def __call__(self, **kwargs: object) -> dict:
        self.call_count += 1
        return {"id": "act-spy", "status": "success"}


def _request(*, envelope: dict, verification: dict, approval: dict) -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=_TOOL, target=_TARGET, action=_ACTION,
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        approval=approval, safety_envelope=envelope, verification_result=verification,
    )


def test_chaos_16_restart_does_not_allow_cross_incident_reuse():
    """Pregunta 1: SÍ sobrevive al reinicio -- Envelope A + Approval A
    (nunca consumida) presentados bajo el contexto de un incidente B
    DISTINTO, en una instancia de Gateway COMPLETAMENTE NUEVA (post-
    reinicio), siguen denegándose. El binding de R0-01-RESIDUAL no
    depende de memoria de proceso."""
    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_b = _verification(envelope_b)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-chaos16-1", plan_hash=plan_hash_a)

    # "Reinicio": instancia de Gateway completamente nueva, sin relación
    # con ninguna instancia anterior -- ni siquiera llegó a autorizarse
    # nada antes de esto.
    gateway_after_restart = Gateway(target_allowlists={_TOOL: {_TARGET}})
    request = _request(envelope=envelope_b, verification=verification_b, approval=approval_a)
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway_after_restart, request, executor_call=spy,
        run_id="r-chaos16-1", idempotency_key="k-chaos16-1", action_id="a-chaos16-1",
        current_plan_hash=plan_hash_a,
    )

    assert outcome.authorized is False
    assert "R0-01-RESIDUAL" in outcome.authorization.reason
    assert spy.call_count == 0


@pytest.mark.xfail(
    reason=(
        "ARG-020 (almacén de ApprovalStore compartido real, no en memoria de un único "
        "proceso) sigue sin cerrarse -- un reinicio real del gateway pierde el conjunto "
        "de approval_id consumidos y permite reejecutar una Approval ya gastada, "
        "mientras siga sin expirar. Riesgo operacional YA documentado en "
        "mcp_gateway.ApprovalStore; este test lo confirma ejecutando el reinicio de "
        "verdad en vez de solo citarlo. Debe empezar a pasar (quitar xfail) cuando "
        "ARG-020 introduzca un almacén compartido real."
    ),
    strict=True,
)
def test_chaos_16_restart_loses_approval_replay_protection_known_gap(contracts_path):
    """Pregunta 2: NO sobrevive al reinicio -- una Approval YA CONSUMIDA
    con éxito en la instancia anterior de Gateway puede volver a
    consumirse en una instancia NUEVA (post-reinicio), porque
    ApprovalStore._consumed es memoria de proceso, no un almacén
    compartido. xfail intencional (no oculto): confirma el gap conocido,
    no lo silencia."""
    from executors.kubernetes import KubernetesExecutor

    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    verification_a = _verification(envelope_a)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-chaos16-2", plan_hash=plan_hash_a)

    # Instancia 1 (antes del reinicio): consume la Approval legítimamente.
    gateway_before_restart = Gateway(target_allowlists={_TOOL: {_TARGET}})
    executor = KubernetesExecutor(contracts_path)
    request = _request(envelope=envelope_a, verification=verification_a, approval=approval_a)
    outcome_before = execute_with_authorization(
        gateway_before_restart, request, executor_call=executor.isolate_workload,
        run_id="r-chaos16-2a", idempotency_key="k-chaos16-2a", action_id="a-chaos16-2a",
        current_plan_hash=plan_hash_a,
    )
    assert outcome_before.authorized is True

    # "Reinicio": instancia 2, ApprovalStore nuevo -- sin memoria de que
    # appr-chaos16-2 ya se consumió.
    gateway_after_restart = Gateway(target_allowlists={_TOOL: {_TARGET}})
    outcome_after = execute_with_authorization(
        gateway_after_restart, request, executor_call=executor.isolate_workload,
        run_id="r-chaos16-2b", idempotency_key="k-chaos16-2b", action_id="a-chaos16-2b",
        current_plan_hash=plan_hash_a,
    )

    # Comportamiento DESEADO (lo que este test afirma que DEBERÍA pasar,
    # y por lo que falla hoy con xfail): el reinicio no debería permitir
    # reconsumir la misma Approval.
    assert outcome_after.authorized is False


# ---------------------------------------------------------------------------
# Cierre real de CH-07/ARG-020 (2026-08-18): el MISMO escenario que el test
# xfail de arriba, pero inyectando DurableApprovalStore (SQLite) en vez del
# ApprovalStore en memoria por defecto -- CH-07 pasa de KNOWN_FAILING a
# PASS cuando el Gateway usa un almacén durable. No se modifica
# mcp_gateway.Gateway para esto -- ya aceptaba `approval_store` inyectado
# (ApprovalStoreProtocol); solo cambia QUÉ almacén se le pasa.
# ---------------------------------------------------------------------------


def test_chaos_16_ch07_closed_with_durable_approval_store(tmp_path, contracts_path):
    from executors.kubernetes import KubernetesExecutor
    from policies.approval.durable_store import DurableApprovalStore

    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    verification_a = _verification(envelope_a)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-chaos16-3", plan_hash=plan_hash_a)
    request = _request(envelope=envelope_a, verification=verification_a, approval=approval_a)

    db_path = tmp_path / "approvals.db"
    executor = KubernetesExecutor(contracts_path)

    # Instancia 1 (antes del reinicio): Gateway con DurableApprovalStore,
    # consume la Approval legítimamente.
    gateway_before_restart = Gateway(
        target_allowlists={_TOOL: {_TARGET}}, approval_store=DurableApprovalStore(db_path)
    )
    outcome_before = execute_with_authorization(
        gateway_before_restart, request, executor_call=executor.isolate_workload,
        run_id="r-chaos16-3a", idempotency_key="k-chaos16-3a", action_id="a-chaos16-3a",
        current_plan_hash=plan_hash_a,
    )
    assert outcome_before.authorized is True

    # "Reinicio": Gateway COMPLETAMENTE NUEVO, con un DurableApprovalStore
    # TAMBIÉN nuevo -- pero apuntando al MISMO fichero SQLite. Ningún
    # objeto Python se comparte con la instancia anterior.
    gateway_after_restart = Gateway(
        target_allowlists={_TOOL: {_TARGET}}, approval_store=DurableApprovalStore(db_path)
    )
    outcome_after = execute_with_authorization(
        gateway_after_restart, request, executor_call=executor.isolate_workload,
        run_id="r-chaos16-3b", idempotency_key="k-chaos16-3b", action_id="a-chaos16-3b",
        current_plan_hash=plan_hash_a,
    )

    # CH-07: PASS -- a diferencia del test xfail de arriba (ApprovalStore
    # en memoria), aquí el reinicio SÍ deniega correctamente el replay.
    assert outcome_after.authorized is False
    assert "replay" in outcome_after.authorization.reason
