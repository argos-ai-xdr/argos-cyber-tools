from __future__ import annotations

import datetime

from graph.attack_path import validate_attack_path
from graph.escalation import EscalationFinding
from mcp_gateway import Gateway


def _safety_envelope(*, tool_name: str, target: str) -> dict:
    """Mismo fixture mínimo que tests/authorization/test_gateway.py --
    R0-01 exige esta cadena para action=execute independientemente de
    Approval."""
    now = datetime.datetime.now(datetime.UTC)
    return {
        "envelope_id": "safenv-attack-path-1",
        "incident_ref": "inc-attack-path-1",
        "target_set": [target],
        "allowed_actions": ["execute"],
        "forbidden_actions": [],
        "required_runbook": f"runbooks/{tool_name}.md",
        "rollback_ref": f"rollback/{tool_name}",
        "valid_until": (now + datetime.timedelta(minutes=15)).isoformat(),
        "envelope_hash": "sha256:" + "a" * 64,
        "signature": "sha256:" + "b" * 64,
    }


def _verification_result(envelope: dict, *, tool_name: str, target: str) -> dict:
    return {"state": "VERIFIED", "envelope_hash": envelope["envelope_hash"], "tool_name": tool_name, "target": target}

_FINDING = EscalationFinding(
    subject="argos-cyber-range/gseg-simulado-sa",
    path="ServiceAccount -> RoleBinding/ClusterRole -> wildcard total",
    rule=None,  # type: ignore[arg-type]  # no relevante para estos tests
    reason="wildcard total",
    severity="critical",
)


def test_execute_without_safety_chain_is_validated_not_bypassed():
    """R0-01: sin SafetyEnvelope/VerificationResult, el gateway deniega
    antes de llegar siquiera a la comprobación de Approval -- sigue
    siendo VALIDATED (el gate contiene el impacto), no OUT_OF_SCOPE."""
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    result = validate_attack_path(
        _FINDING,
        tool_name="isolate_kubernetes_workload",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.execute"}),
        gateway=gateway,
    )
    assert result.decision == "VALIDATED"
    assert "SafetyEnvelope" in result.reason


def test_execute_with_safety_chain_but_without_approval_is_validated_not_bypassed():
    """El caso esperado y correcto: aunque el RBAC del subject sea
    excesivo (finding) Y la cadena de seguridad esté completa, el
    tool_catalog/policies real sigue exigiendo Approval para
    isolate_kubernetes_workload — el gate de aprobación humana no se
    salta."""
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    envelope = _safety_envelope(tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    result = validate_attack_path(
        _FINDING,
        tool_name="isolate_kubernetes_workload",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.execute"}),
        gateway=gateway,
        safety_envelope=envelope,
        verification_result=verification,
    )
    assert result.decision == "VALIDATED"
    assert "Approval" in result.reason


def test_target_outside_allowlist_is_out_of_scope():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    result = validate_attack_path(
        _FINDING,
        tool_name="isolate_kubernetes_workload",
        target="namespace/production-payments",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.execute"}),
        gateway=gateway,
    )
    assert result.decision == "OUT_OF_SCOPE"


def test_missing_scope_is_out_of_scope():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    result = validate_attack_path(
        _FINDING,
        tool_name="isolate_kubernetes_workload",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset(),
        gateway=gateway,
    )
    assert result.decision == "OUT_OF_SCOPE"


def test_unknown_tool_is_out_of_scope_not_an_exception():
    gateway = Gateway()
    result = validate_attack_path(
        _FINDING,
        tool_name="delete_everything",
        target="anything",
        subject_id="attacker",
        granted_scopes=frozenset({"cyber.response.execute"}),
        gateway=gateway,
    )
    assert result.decision == "OUT_OF_SCOPE"


def test_tool_without_approval_requirement_is_validated_by_safety_chain_since_r0_01():
    """increase_monitoring (tool_catalog/definitions/increase_monitoring.yaml)
    tiene approval_required=false — antes de R0-01, un subject con el
    scope correcto conseguía execute sin NINGUNA barrera, y este mismo
    test lo marcaba correctamente como GATE_BYPASSED (fallo real de
    defensa en profundidad, documentado deliberadamente). R0-01 cierra
    exactamente ese hueco: SafetyEnvelope/VerificationResult son ahora
    obligatorios para action=execute sin importar approval_required, así
    que la misma llamada ya NO se autoriza sin ninguna barrera."""
    gateway = Gateway()
    result = validate_attack_path(
        _FINDING,
        tool_name="increase_monitoring",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.monitor"}),
        gateway=gateway,
    )
    assert result.decision == "VALIDATED"
    assert "SafetyEnvelope" in result.reason


def test_tool_without_approval_requirement_still_auto_authorizes_once_safety_chain_is_satisfied():
    """Hallazgo real que SIGUE siendo cierto tras R0-01, documentado (no
    oculto): con una cadena de seguridad completa y válida,
    increase_monitoring se autoriza SIN Approval humana -- diseño
    deliberado y ya ratificado (ADR-056, risk_level=medium, no modifica
    el workload). validate_attack_path lo reporta como GATE_BYPASSED
    porque, en efecto, ninguna Approval contuvo la ejecución -- la
    contención real para este tool vive enteramente en Safety Kernel/
    Independent Verifier, no en HITL."""
    gateway = Gateway()
    envelope = _safety_envelope(tool_name="increase_monitoring", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="increase_monitoring", target="deployment/gseg-simulado")
    result = validate_attack_path(
        _FINDING,
        tool_name="increase_monitoring",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.monitor"}),
        gateway=gateway,
        safety_envelope=envelope,
        verification_result=verification,
    )
    assert result.decision == "GATE_BYPASSED"
