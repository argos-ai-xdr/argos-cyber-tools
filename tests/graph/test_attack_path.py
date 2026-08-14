from __future__ import annotations

from graph.attack_path import validate_attack_path
from graph.escalation import EscalationFinding
from mcp_gateway import Gateway

_FINDING = EscalationFinding(
    subject="argos-cyber-range/gseg-simulado-sa",
    path="ServiceAccount -> RoleBinding/ClusterRole -> wildcard total",
    rule=None,  # type: ignore[arg-type]  # no relevante para estos tests
    reason="wildcard total",
    severity="critical",
)


def test_execute_without_approval_is_validated_not_bypassed():
    """El caso esperado y correcto: aunque el RBAC del subject sea
    excesivo (finding), el tool_catalog/policies real sigue exigiendo
    Approval para isolate_kubernetes_workload — el gate no se salta."""
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


def test_tool_without_approval_requirement_is_reported_as_gate_bypassed():
    """increase_monitoring (tool_catalog/definitions/increase_monitoring.yaml)
    tiene approval_required=false y mode incluye execute — un subject con
    el scope correcto SÍ consigue execute sin Approval. Esto no es un bug
    de graph/: es el comportamiento ya documentado y deliberado del
    catálogo (ver executors/README.md, sin executor todavía). La prueba
    demuestra que validate_attack_path lo detecta y lo marca
    correctamente como GATE_BYPASSED en vez de esconderlo como VALIDATED."""
    gateway = Gateway()
    result = validate_attack_path(
        _FINDING,
        tool_name="increase_monitoring",
        target="deployment/gseg-simulado",
        subject_id="gseg-simulado-sa",
        granted_scopes=frozenset({"cyber.response.monitor"}),
        gateway=gateway,
    )
    assert result.decision == "GATE_BYPASSED"
