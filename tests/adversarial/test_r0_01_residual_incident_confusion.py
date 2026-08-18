"""R0-01-RESIDUAL, sonda adversarial (2026-08-18): antes de aceptar la
severidad "no crítico" declarada inicialmente en
argos-control/architecture/implementation-readiness.md §13, se ejecutó el
ataque real en vez de inferirlo por inspección estática (petición explícita
del usuario tras revisar el cierre de R0-01).

Escenario: dos incidentes distintos, A y B, que por coincidencia comparten
tool/target/action (`isolate_kubernetes_workload` sobre
`deployment/gseg-simulado`, `execute`). Cada uno produce su propio
SafetyEnvelope/VerificationResult (incident_ref distinto, envelope_hash
distinto) y su propia Approval humana.

**Resultado real de la primera corrida de esta sonda (antes del fix,
commit previo a este)**: `test_probe_envelope_b_plus_approval_a_...`
EJECUTABA de verdad -- `executor.cluster.is_isolated(...)` era `True` y
`spy.call_count == 1` con una Approval firmada para el contexto de
seguridad de A, usada bajo el contexto de B. Confirmó
empíricamente el hallazgo del usuario: "cualquier combinación cruzada
ejecuta -> CRITICAL/R0", no "no crítico". Se corrigió de inmediato en
`mcp_gateway.Gateway.authorize()` (vínculo `current_plan_hash` <->
`envelope_hash`, ver su docstring) en el MISMO commit que esta sonda --
nunca se publicó un estado vulnerable. Las aserciones de este archivo
reflejan el estado POST-fix; se conserva la sonda (no se borra) porque es
la prueba de que el cierre es real, no solo documental.

Se usa `execute_with_authorization` con un `_Spy` real (cuenta invocaciones,
no un mock que finja) contra un `Gateway` COMPARTIDO entre llamadas -- el
despliegue previsto (proceso de gateway persistente, no uno nuevo por
solicitud; crear un `Gateway()` nuevo por llamada resetea el `ApprovalStore`
en memoria y es un riesgo operacional YA documentado, ARG-020 -- no es lo
que esta sonda investiga).
"""
from __future__ import annotations

import datetime

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


# ---------------------------------------------------------------------------
# Combo 2 (el que importaba): Envelope B + Verifier B + Approval A, con
# Approval A firmada honestamente para el envelope_hash de A -- el llamante
# más simple ("naive replay": pasa el mismo current_plan_hash que ya tenía
# para A, sin adaptarlo a B).
# ---------------------------------------------------------------------------


def test_probe_naive_replay_of_approval_a_under_envelope_b_is_denied_zero_execute(contracts_path):
    from executors.kubernetes import KubernetesExecutor

    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_b = _verification(envelope_b)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-incident-a", plan_hash=plan_hash_a)

    request = _request(envelope=envelope_b, verification=verification_b, approval=approval_a)

    gateway = Gateway(target_allowlists={_TOOL: {_TARGET}})
    executor = KubernetesExecutor(contracts_path)
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.isolate_workload,
        run_id="r-probe-1", idempotency_key="k-probe-1", action_id="a-probe-1",
        current_plan_hash=plan_hash_a,  # el llamante pasa el plan_hash de A tal cual, sin adaptarlo
    )

    assert outcome.authorized is False
    assert "R0-01-RESIDUAL" in outcome.authorization.reason
    assert not executor.cluster.is_isolated(_TARGET)


def test_probe_adaptive_attacker_recomputes_plan_hash_for_b_but_signature_still_fails():
    """Variante más fuerte: el llamante SÍ recalcula `current_plan_hash`
    vinculado a `envelope_hash` de B (la fórmula es pública y determinista,
    no un secreto) -- pero `Approval A.signature_ref` fue firmada por el
    aprobador humano contra el plan_hash de A, no el de B. No puede
    coincidir con ambos a la vez sin que el aprobador haya visto y firmado
    específicamente el envelope_hash de B."""
    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_b = _verification(envelope_b)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    plan_hash_b = _plan_hash_for(envelope_b["envelope_hash"])
    approval_a = _approval(approval_id="appr-incident-a-adaptive", plan_hash=plan_hash_a)

    request = _request(envelope=envelope_b, verification=verification_b, approval=approval_a)

    gateway = Gateway(target_allowlists={_TOOL: {_TARGET}})
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway, request, executor_call=spy,
        run_id="r-probe-2", idempotency_key="k-probe-2", action_id="a-probe-2",
        current_plan_hash=plan_hash_b,  # ahora SÍ coincide con el envelope de la solicitud...
    )

    assert outcome.authorized is False
    assert "Approval rechazada" in outcome.authorization.reason  # ...pero ya no con la firma de Approval A
    assert spy.call_count == 0


def test_probe_approval_correctly_bound_to_its_own_envelope_still_executes(contracts_path):
    """Control positivo: el mismo combo, pero con Approval B firmada de
    verdad para envelope_hash de B -- confirma que el fix no rompe el
    camino feliz real, solo el cruzado."""
    from executors.kubernetes import KubernetesExecutor

    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_b = _verification(envelope_b)
    plan_hash_b = _plan_hash_for(envelope_b["envelope_hash"])
    approval_b = _approval(approval_id="appr-incident-b", plan_hash=plan_hash_b)

    request = _request(envelope=envelope_b, verification=verification_b, approval=approval_b)

    gateway = Gateway(target_allowlists={_TOOL: {_TARGET}})
    executor = KubernetesExecutor(contracts_path)
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.isolate_workload,
        run_id="r-probe-3", idempotency_key="k-probe-3", action_id="a-probe-3",
        current_plan_hash=plan_hash_b,
    )

    assert outcome.authorized is True
    assert executor.cluster.is_isolated(_TARGET)


# ---------------------------------------------------------------------------
# Combo 3 (control negativo, ya cubierto por test_gateway.py pero repetido
# aquí con el vocabulario A/B de la sonda para que la suite sea
# autocontenida): Envelope A + Verifier B + Approval A -- el propio
# VerificationResult referencia un envelope_hash distinto al SafetyEnvelope
# suministrado.
# ---------------------------------------------------------------------------


def test_probe_envelope_a_plus_verifier_b_is_denied_zero_execute():
    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_b = _verification(envelope_b)  # referencia el hash de B, no de A
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-incident-a-3", plan_hash=plan_hash_a)

    request = _request(envelope=envelope_a, verification=verification_b, approval=approval_a)

    gateway = Gateway(target_allowlists={_TOOL: {_TARGET}})
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway, request, executor_call=spy,
        run_id="r-probe-4", idempotency_key="k-probe-4", action_id="a-probe-4",
        current_plan_hash=plan_hash_a,
    )

    assert outcome.authorized is False
    assert spy.call_count == 0


# ---------------------------------------------------------------------------
# Combo 4: Approval A reutilizada tras haber sido consumida por el
# incidente A, ahora contra el contexto de seguridad de B -- con un Gateway
# COMPARTIDO (el ApprovalStore persiste entre llamadas, el despliegue
# previsto). Denegado por dos motivos independientes tras el fix: el
# binding de envelope_hash (ver arriba) Y el anti-replay de approval_id
# (preexistente); esta prueba fija cuál gana cuando ambos aplican.
# ---------------------------------------------------------------------------


def test_probe_consumed_approval_cannot_be_replayed_across_incidents_with_shared_gateway():
    envelope_a = _envelope(incident_ref="incident-A", envelope_hash="sha256:" + "a" * 64)
    envelope_b = _envelope(incident_ref="incident-B", envelope_hash="sha256:" + "b" * 64)
    verification_a = _verification(envelope_a)
    verification_b = _verification(envelope_b)
    plan_hash_a = _plan_hash_for(envelope_a["envelope_hash"])
    approval_a = _approval(approval_id="appr-incident-a-4", plan_hash=plan_hash_a)

    gateway = Gateway(target_allowlists={_TOOL: {_TARGET}})  # UNA instancia, compartida entre A y B

    # Paso 1: incidente A consume legítimamente su propia Approval.
    request_a = _request(envelope=envelope_a, verification=verification_a, approval=approval_a)
    spy_a = _Spy()
    outcome_a = execute_with_authorization(
        gateway, request_a, executor_call=spy_a,
        run_id="r-probe-5a", idempotency_key="k-probe-5a", action_id="a-probe-5a",
        current_plan_hash=plan_hash_a,
    )
    assert outcome_a.authorized is True
    assert spy_a.call_count == 1

    # Paso 2: intento de reutilizar el MISMO objeto Approval (mismo
    # approval_id) para ejecutar bajo el contexto de seguridad de B.
    request_b = _request(envelope=envelope_b, verification=verification_b, approval=approval_a)
    spy_b = _Spy()
    outcome_b = execute_with_authorization(
        gateway, request_b, executor_call=spy_b,
        run_id="r-probe-5b", idempotency_key="k-probe-5b", action_id="a-probe-5b",
        current_plan_hash=plan_hash_a,  # mismo valor que en el paso 1
    )

    # El binding de envelope_hash deniega primero (plan_hash_a no coincide
    # con el envelope_hash de B) -- nunca se llega a evaluar el anti-replay
    # de approval_id en este combo concreto.
    assert outcome_b.authorized is False
    assert "R0-01-RESIDUAL" in outcome_b.authorization.reason
    assert spy_b.call_count == 0
